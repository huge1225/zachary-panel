package security

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"nexus-panel/pkg/protocol"
)

var (
	// safeHostRegex strictly allows valid domain/IPv4/IPv6 characters and blocks shell/config injection characters.
	safeHostRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-_:\[\]]+$`)

	// Protected local ports that the Agent must never bind to, even if instructed.
	protectedListenPorts = map[int]bool{
		21:   true, // FTP
		22:   true, // SSH
		23:   true, // Telnet
		25:   true, // SMTP
		53:   true, // DNS
		3306: true, // MySQL
		5432: true, // PostgreSQL
		6379: true, // Redis
	}

	// Private / Reserved CIDR blocks blocked from user forwarding (Anti-SSRF & Cloud Metadata protection)
	blockedCIDRs []*net.IPNet
)

func init() {
	cidrs := []string{
		"0.0.0.0/8",       // Current network
		"10.0.0.0/8",      // RFC1918 Private network
		"100.64.0.0/10",   // Shared Address Space (CGNAT / Cloud internal)
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local & Cloud Metadata Service (169.254.169.254)
		"172.16.0.0/12",   // RFC1918 Private network
		"192.0.0.0/24",    // IETF Protocol Assignments
		"192.168.0.0/16",  // RFC1918 Private network
		"198.18.0.0/15",   // Benchmarking
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved
		"::1/128",         // IPv6 Loopback
		"fc00::/7",        // IPv6 Unique Local Address
		"fe80::/10",       // IPv6 Link-Local
		"ff00::/8",        // IPv6 Multicast
		"64:ff9b:1::/48",  // NAT64 local-use prefix (RFC 8215), translation target unknown
		"2001::/32",       // Teredo
		"2001:db8::/32",   // IPv6 documentation
		"100::/64",        // IPv6 discard-only
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
	}
	for _, c := range cidrs {
		if _, ipNet, err := net.ParseCIDR(c); err == nil {
			blockedCIDRs = append(blockedCIDRs, ipNet)
		}
	}
}

// Policy configures the Agent's local security policy.
type Policy struct {
	AllowPrivateTargets bool // False in production to block SSRF to local/LAN/Cloud metadata IPs
	MinListenPort       int  // Default 1024 (never bind privileged ports)
	MaxListenPort       int  // Default 65535
	MaxConnsPerClientIP int  // Per-source-IP concurrent connection cap
}

var DefaultPolicy = Policy{
	AllowPrivateTargets: false,
	MinListenPort:       1024,
	MaxListenPort:       65535,
	MaxConnsPerClientIP: 256,
}

// ValidateListenPort ensures a rule does not bind privileged or critical host service ports.
func ValidateListenPort(port int, policy Policy) error {
	minP := policy.MinListenPort
	if minP <= 0 {
		minP = 1024
	}
	if port < minP || port > 65535 {
		return fmt.Errorf("security violation: listen port %d outside safe unprivileged range (%d-65535)", port, minP)
	}
	if protectedListenPorts[port] {
		return fmt.Errorf("security violation: listen port %d is a protected system service port", port)
	}
	return nil
}

// ValidateTargetAddress checks an upstream "host:port" for command/config injection and SSRF blocked IPs.
func ValidateTargetAddress(addr string, allowPrivate bool) error {
	addr = strings.TrimSpace(addr)
	if addr == "" || len(addr) > 253 {
		return fmt.Errorf("invalid target address length")
	}
	if !safeHostRegex.MatchString(addr) {
		return fmt.Errorf("security violation: target address %q contains illegal characters", addr)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target host:port %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portStr)
	}

	// Block dangerous destination ports (SMTP spam port 25)
	if port == 25 || port == 465 || port == 587 {
		return fmt.Errorf("security violation: outbound SMTP ports (25/465/587) are blocked to prevent spam abuse")
	}

	// If host is a literal IP, immediately validate against SSRF blocklist
	if ip := net.ParseIP(host); ip != nil {
		if err := ValidateResolvedIP(ip, allowPrivate); err != nil {
			return err
		}
	} else {
		lowerHost := strings.ToLower(host)
		if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") || strings.HasSuffix(lowerHost, ".internal") {
			if !allowPrivate {
				return fmt.Errorf("security violation: internal hostname %q is prohibited", host)
			}
		}
	}
	return nil
}

// ValidateResolvedIP checks whether a resolved net.IP falls into loopback, metadata, or private ranges.
func ValidateResolvedIP(ip net.IP, allowPrivate bool) error {
	if ip == nil {
		return fmt.Errorf("nil IP address")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		if !allowPrivate {
			return fmt.Errorf("security violation: target IP %s is loopback/link-local/unspecified (SSRF blocked)", ip.String())
		}
	}
	if !allowPrivate {
		if ip.IsPrivate() {
			return fmt.Errorf("security violation: target IP %s is an RFC1918/RFC4193 private address (SSRF blocked)", ip.String())
		}
		for _, block := range blockedCIDRs {
			if block.Contains(ip) {
				return fmt.Errorf("security violation: target IP %s belongs to restricted internal/metadata CIDR %s", ip.String(), block.String())
			}
		}
		// IPv6 forms that embed an IPv4 address (NAT64 / 6to4 / IPv4-compatible) are translated to IPv4 by the
		// network and must be validated as that IPv4 address.
		if embedded := embeddedIPv4(ip); embedded != nil {
			if err := ValidateResolvedIP(embedded, false); err != nil {
				return fmt.Errorf("security violation: target IP %s embeds restricted IPv4 %s", ip.String(), embedded.String())
			}
		}
		// The node's own (public) addresses reach local services that are firewalled only for inbound
		// traffic, bypass kernel forwarding accounting and allow forwarding loops.
		if isLocalInterfaceIP(ip) {
			return fmt.Errorf("security violation: target IP %s is an address of this node (SSRF blocked)", ip.String())
		}
	}
	return nil
}

// localAddrCache caches the host's interface addresses (refreshed periodically, interfaces may change).
var localAddrCache struct {
	mu      sync.Mutex
	addrs   map[string]bool
	fetched time.Time
}

// localInterfaceAddrs is replaceable in tests.
var localInterfaceAddrs = net.InterfaceAddrs

func isLocalInterfaceIP(ip net.IP) bool {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()
	if localAddrCache.addrs == nil || time.Since(localAddrCache.fetched) > 30*time.Second {
		addrs, err := localInterfaceAddrs()
		if err != nil {
			// Fail closed: without the interface list we cannot tell local from remote, retry on the next call.
			localAddrCache.addrs = nil
			return true
		}
		m := make(map[string]bool)
		for _, a := range addrs {
			var aip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aip = v.IP
			case *net.IPAddr:
				aip = v.IP
			}
			if aip == nil {
				continue
			}
			if v4 := aip.To4(); v4 != nil {
				aip = v4
			}
			m[aip.String()] = true
		}
		localAddrCache.addrs, localAddrCache.fetched = m, time.Now()
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return localAddrCache.addrs[ip.String()]
}

var (
	nat64WellKnown = mustCIDR("64:ff9b::/96")
	sixToFour      = mustCIDR("2002::/16")
	ipv4Compatible = mustCIDR("::/96")
)

func mustCIDR(c string) *net.IPNet {
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		panic(err)
	}
	return n
}

// embeddedIPv4 extracts the IPv4 address carried inside NAT64 (64:ff9b::/96), 6to4 (2002::/16) and
// IPv4-compatible (::/96) IPv6 addresses.
func embeddedIPv4(ip net.IP) net.IP {
	if ip.To4() != nil || len(ip) != net.IPv6len {
		return nil
	}
	switch {
	case nat64WellKnown.Contains(ip), ipv4Compatible.Contains(ip):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	case sixToFour.Contains(ip):
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	return nil
}

// ValidateRuleSpec performs a comprehensive security audit on a RuleSpec before any EngineDriver executes it.
func ValidateRuleSpec(spec protocol.RuleSpec, policy Policy) error {
	if err := ValidateListenPort(spec.ListenPort, policy); err != nil {
		return err
	}
	if len(spec.Targets) == 0 || len(spec.Targets) > 32 {
		return fmt.Errorf("invalid target count (%d)", len(spec.Targets))
	}

	// Ingress role connects to Master-paired Egress internal IP, which may legitimately be an IEPL internal IP.
	// Relay and Egress roles connect to user-supplied destinations and MUST enforce strict Anti-SSRF unless overridden.
	allowPrivate := policy.AllowPrivateTargets || (spec.Role == protocol.RoleIngress)

	for _, t := range spec.Targets {
		if err := ValidateTargetAddress(t.Address, allowPrivate); err != nil {
			return err
		}
	}

	if spec.Tunnel != nil {
		if spec.Tunnel.SNI != "" && !safeHostRegex.MatchString(spec.Tunnel.SNI) {
			return fmt.Errorf("security violation: invalid tunnel SNI %q", spec.Tunnel.SNI)
		}
		if len(spec.Tunnel.CertPEM) > 16*1024 {
			return fmt.Errorf("security violation: tunnel certificate too large")
		}
		if spec.Role != protocol.RoleRelay && spec.Tunnel.SecretKey == "" {
			return fmt.Errorf("security violation: tunnel rule without secret key")
		}
	}
	switch spec.Protocol {
	case "", "tcp", "udp", "both":
	default:
		return fmt.Errorf("invalid protocol %q", spec.Protocol)
	}
	switch spec.LoadBalance {
	case "", "round_robin", "failover", "random":
	default:
		return fmt.Errorf("invalid load balance strategy %q", spec.LoadBalance)
	}
	return nil
}

// SafeDialTCP resolves the target address and verifies every resolved IP against SSRF & DNS Rebinding
// before opening the outbound TCP socket.
func SafeDialTCP(ctx context.Context, addr string, timeout time.Duration, allowPrivate bool) (net.Conn, error) {
	if err := ValidateTargetAddress(addr, allowPrivate); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	// Anti-DNS Rebinding check: verify resolved IP right before dialing
	var safeIP net.IP
	for _, ip := range ips {
		if err := ValidateResolvedIP(ip, allowPrivate); err == nil {
			safeIP = ip
			break
		}
	}
	if safeIP == nil {
		return nil, fmt.Errorf("security violation: DNS resolution of %q pointed to restricted internal IP %s (DNS rebinding blocked)", host, ips[0].String())
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(safeIP.String(), portStr))
}

// ResolveTargets resolves every hostname target to a concrete IP that passes the SSRF policy and returns a copy
// of the targets with literal IPs. External engines (gost / realm) only ever receive these pinned IPs, so a
// hostname that (re-)resolves to loopback / metadata / private ranges cannot be used to bypass the sandbox.
func ResolveTargets(ctx context.Context, targets []protocol.TargetEndpoint, allowPrivate bool) ([]protocol.TargetEndpoint, error) {
	out := make([]protocol.TargetEndpoint, 0, len(targets))
	for _, t := range targets {
		if err := ValidateTargetAddress(t.Address, allowPrivate); err != nil {
			return nil, err
		}
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(t.Address))
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			out = append(out, t)
			continue
		}
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("DNS resolution failed for %s: %v", host, err)
		}
		var chosen net.IP
		for _, ip := range ips {
			if ValidateResolvedIP(ip, allowPrivate) != nil {
				continue
			}
			if chosen == nil || (chosen.To4() == nil && ip.To4() != nil) {
				chosen = ip // prefer IPv4 for widest engine compatibility
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("security violation: DNS resolution of %q pointed to restricted internal IP %s (blocked)", host, ips[0].String())
		}
		pinned := t
		pinned.Address = net.JoinHostPort(chosen.String(), portStr)
		out = append(out, pinned)
	}
	return out, nil
}

type ipGuardEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// IPConnGuard protects the Agent against single-IP connection flood & file descriptor exhaustion.
type IPConnGuard struct {
	mu          sync.Mutex
	activePerIP map[string]int
	ratePerIP   map[string]*ipGuardEntry
	maxActive   int
	lastGC      time.Time
}

func NewIPConnGuard(maxActivePerIP int) *IPConnGuard {
	if maxActivePerIP <= 0 {
		maxActivePerIP = 256
	}
	return &IPConnGuard{
		activePerIP: make(map[string]int),
		ratePerIP:   make(map[string]*ipGuardEntry),
		maxActive:   maxActivePerIP,
		lastGC:      time.Now(),
	}
}

// gcLocked drops limiter state of source IPs that have been idle for a while so the map cannot grow without bound.
func (g *IPConnGuard) gcLocked(now time.Time) {
	if now.Sub(g.lastGC) < time.Minute && len(g.ratePerIP) < 50000 {
		return
	}
	for host, e := range g.ratePerIP {
		if g.activePerIP[host] == 0 && now.Sub(e.lastSeen) > 5*time.Minute {
			delete(g.ratePerIP, host)
		}
	}
	g.lastGC = now
}

// Acquire checks if a client IP is allowed to open a new connection (rate <= 50 conn/s, active <= maxActive).
func (g *IPConnGuard) Acquire(remoteAddr net.Addr) (release func(), allowed bool) {
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	g.gcLocked(now)
	e, ok := g.ratePerIP[host]
	if !ok {
		e = &ipGuardEntry{lim: rate.NewLimiter(rate.Limit(50), 100)}
		g.ratePerIP[host] = e
	}
	e.lastSeen = now
	if !e.lim.Allow() {
		return nil, false
	}

	if g.activePerIP[host] >= g.maxActive {
		return nil, false
	}
	g.activePerIP[host]++

	return func() {
		g.mu.Lock()
		g.activePerIP[host]--
		if g.activePerIP[host] <= 0 {
			delete(g.activePerIP, host)
		}
		g.mu.Unlock()
	}, true
}
