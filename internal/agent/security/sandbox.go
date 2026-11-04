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
		"0.0.0.0/8",          // Current network
		"10.0.0.0/8",         // RFC1918 Private network
		"100.64.0.0/10",      // Shared Address Space (CGNAT / Cloud internal)
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local & Cloud Metadata Service (169.254.169.254)
		"172.16.0.0/12",      // RFC1918 Private network
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.168.0.0/16",     // RFC1918 Private network
		"198.18.0.0/15",      // Benchmarking
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"::1/128",            // IPv6 Loopback
		"fc00::/7",           // IPv6 Unique Local Address
		"fe80::/10",          // IPv6 Link-Local
		"ff00::/8",           // IPv6 Multicast
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

// IPConnGuard protects the Agent against single-IP connection flood & file descriptor exhaustion.
type IPConnGuard struct {
	mu          sync.Mutex
	activePerIP map[string]int
	ratePerIP   map[string]*rate.Limiter
	maxActive   int
}

func NewIPConnGuard(maxActivePerIP int) *IPConnGuard {
	if maxActivePerIP <= 0 {
		maxActivePerIP = 256
	}
	return &IPConnGuard{
		activePerIP: make(map[string]int),
		ratePerIP:   make(map[string]*rate.Limiter),
		maxActive:   maxActivePerIP,
	}
}

// Acquire checks if a client IP is allowed to open a new connection (rate <= 50 conn/s, active <= maxActive).
func (g *IPConnGuard) Acquire(remoteAddr net.Addr) (release func(), allowed bool) {
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	lim, ok := g.ratePerIP[host]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(50), 100)
		g.ratePerIP[host] = lim
	}
	if !lim.Allow() {
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
