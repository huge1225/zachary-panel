package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nexus-panel/internal/agent/limiter"
	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// CustomTunnelWrapper allows plugging in a self-developed encryption/obfuscation stream layer
// on top of the (already TLS-encrypted) tunnel connection when spec.Tunnel.Transport == "custom".
type CustomTunnelWrapper interface {
	WrapClientConn(raw net.Conn, cfg *protocol.TunnelConfig) (net.Conn, error)
	WrapServerConn(raw net.Conn, cfg *protocol.TunnelConfig) (net.Conn, error)
}

type nativeRuleInstance struct {
	key            string
	spec           protocol.RuleSpec
	cancel         context.CancelFunc
	tcpListener    net.Listener
	udpConn        *net.UDPConn
	tracker        *limiter.RuleStatsTracker
	rrIndex        uint64
	clientTLS      *tls.Config // Ingress only: pinned Egress certificate
	aclMode        string      // "off" | "allow" | "deny"
	aclNets        []*net.IPNet
	unhealthyUntil []int64 // atomic UnixNano per target index
}

func parseACLCIDRs(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "/") {
			if _, ipNet, err := net.ParseCIDR(token); err == nil && ipNet != nil {
				nets = append(nets, ipNet)
			}
			continue
		}
		if ip := net.ParseIP(token); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		}
	}
	return nets
}

func (inst *nativeRuleInstance) isAllowedRemoteAddr(addr net.Addr) bool {
	if (inst.aclMode != "allow" && inst.aclMode != "deny") || len(inst.aclNets) == 0 {
		return true
	}
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		if addr != nil {
			if h, _, err := net.SplitHostPort(addr.String()); err == nil {
				ip = net.ParseIP(h)
			} else {
				ip = net.ParseIP(addr.String())
			}
		}
	}
	if ip == nil {
		return inst.aclMode != "allow"
	}
	matched := false
	for _, n := range inst.aclNets {
		if n.Contains(ip) {
			matched = true
			break
		}
	}
	if inst.aclMode == "allow" {
		return matched
	}
	return !matched
}

// NativeEngine implements EngineDriver in pure Go with zero external binary dependencies.
// It also serves as the base framework for self-developed tunnel protocols.
//
// Tunnel security model (Ingress <-> Egress):
//   - every tunnel transport is carried over TLS 1.2+; the Egress presents its persistent node certificate and
//     the Ingress verifies it against the PEM pinned by Master (no InsecureSkipVerify, fail closed);
//   - inside TLS the Ingress sends an HMAC auth header (rule secret + timestamp + nonce, replay-protected);
//   - UDP is framed inside the same encrypted tunnel instead of being sent as plaintext datagrams.
type NativeEngine struct {
	mu                 sync.RWMutex
	policy             security.Policy
	connGuard          *security.IPConnGuard
	udpIPGuard         *security.IPConnGuard
	egressHandshakeSem chan struct{}
	activeUDPSessions  int64
	rules              map[string]*nativeRuleInstance
	serverTLSConf      *tls.Config
	customWrapper      CustomTunnelWrapper
}

// NewNativeEngine creates a ready-to-use NativeEngine. cert is the node's persistent tunnel identity used when
// acting as an Egress; if nil, Egress tunnel rules are rejected.
func NewNativeEngine(pol security.Policy, cert *security.TunnelCert) *NativeEngine {
	var tlsCfg *tls.Config
	if cert != nil {
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert.TLS},
			MinVersion:   tls.VersionTLS12,
		}
	}
	maxUDPIPs := pol.MaxUDPSessionsPerIP
	if maxUDPIPs <= 0 {
		maxUDPIPs = 64
	}
	return &NativeEngine{
		policy:             pol,
		connGuard:          security.NewIPConnGuard(pol.MaxConnsPerClientIP),
		udpIPGuard:         security.NewIPConnGuard(maxUDPIPs),
		egressHandshakeSem: make(chan struct{}, 512),
		rules:              make(map[string]*nativeRuleInstance),
		serverTLSConf:      tlsCfg,
	}
}

// SetCustomTunnelWrapper registers a user-developed custom protocol stream wrapper.
func (e *NativeEngine) SetCustomTunnelWrapper(w CustomTunnelWrapper) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customWrapper = w
}

func (e *NativeEngine) getCustomWrapper() CustomTunnelWrapper {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.customWrapper
}

func (e *NativeEngine) Name() protocol.EngineType {
	return protocol.EngineNative
}

func (e *NativeEngine) Available() bool {
	return true // Always available on all platforms
}

func isTunnelEgress(spec protocol.RuleSpec) bool {
	return spec.Role == protocol.RoleEgress && spec.Tunnel != nil
}

func isTunnelIngress(spec protocol.RuleSpec) bool {
	return spec.Role == protocol.RoleIngress && spec.Tunnel != nil
}

func wantsTCP(spec protocol.RuleSpec) bool {
	return spec.Protocol == "tcp" || spec.Protocol == "both" || spec.Protocol == ""
}

func wantsUDP(spec protocol.RuleSpec) bool {
	return spec.Protocol == "udp" || spec.Protocol == "both"
}

func (e *NativeEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	key := RuleKey(spec.RuleID, spec.Role)

	// Stop existing instance if updating
	_ = e.RemoveRule(key, spec.RuleID, spec.Role)

	if len(spec.Targets) == 0 {
		return fmt.Errorf("rule %s has no targets configured", key)
	}
	if (isTunnelEgress(spec) || isTunnelIngress(spec)) && spec.Tunnel.SecretKey == "" {
		return fmt.Errorf("rule %s: tunnel secret key missing", key)
	}

	aclMode := strings.ToLower(strings.TrimSpace(spec.AccessMode))
	aclNets := parseACLCIDRs(spec.AccessCIDRs)

	inst := &nativeRuleInstance{
		key:            key,
		spec:           spec,
		tracker:        limiter.NewRuleStatsTracker(spec.SpeedLimitMbps),
		aclMode:        aclMode,
		aclNets:        aclNets,
		unhealthyUntil: make([]int64, len(spec.Targets)),
	}
	if isTunnelIngress(spec) {
		clientTLS, err := security.TunnelClientTLSConfig(spec.Tunnel.CertPEM)
		if err != nil {
			return fmt.Errorf("rule %s: %w", key, err)
		}
		inst.clientTLS = clientTLS
	}
	if isTunnelEgress(spec) && e.serverTLSConf == nil {
		return fmt.Errorf("rule %s: local tunnel certificate unavailable, refusing to start egress", key)
	}

	ruleCtx, cancel := context.WithCancel(ctx)
	inst.cancel = cancel

	listenHost := spec.ListenHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	bindAddr := net.JoinHostPort(listenHost, fmt.Sprintf("%d", spec.ListenPort))

	// TCP listener: relay/ingress when protocol includes tcp; egress tunnels always (UDP is framed inside TLS)
	if isTunnelEgress(spec) || wantsTCP(spec) {
		var ln net.Listener
		var err error
		if isTunnelEgress(spec) {
			ln, err = tls.Listen("tcp", bindAddr, e.serverTLSConf)
		} else {
			ln, err = net.Listen("tcp", bindAddr)
		}
		if err != nil {
			cancel()
			return fmt.Errorf("native engine TCP listen %s failed: %w", bindAddr, err)
		}
		inst.tcpListener = ln
		go e.serveTCP(ruleCtx, inst)
	}

	// UDP listener only on the user-facing side (relay / ingress)
	if !isTunnelEgress(spec) && wantsUDP(spec) {
		udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
		if err != nil {
			if inst.tcpListener != nil {
				_ = inst.tcpListener.Close()
			}
			cancel()
			return err
		}
		uConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			if inst.tcpListener != nil {
				_ = inst.tcpListener.Close()
			}
			cancel()
			return fmt.Errorf("native engine UDP listen %s failed: %w", bindAddr, err)
		}
		inst.udpConn = uConn
		go e.serveUDP(ruleCtx, inst)
	}

	// Background active health probe for multi-target TCP rules
	if !isTunnelIngress(spec) && len(spec.Targets) > 1 && wantsTCP(spec) {
		go e.healthProbeLoop(ruleCtx, inst)
	}

	e.mu.Lock()
	e.rules[key] = inst
	e.mu.Unlock()

	log.Printf("[NativeEngine] Applied rule %s (%s) listening on %s -> %d targets (limit=%d Mbps, acl=%s)",
		key, spec.Name, bindAddr, len(spec.Targets), spec.SpeedLimitMbps, aclMode)
	return nil
}

func setTCPKeepAlive(c net.Conn) {
	var tc *net.TCPConn
	switch v := c.(type) {
	case *net.TCPConn:
		tc = v
	case *tls.Conn:
		if raw, ok := v.NetConn().(*net.TCPConn); ok {
			tc = raw
		}
	}
	if tc != nil {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func (e *NativeEngine) serveTCP(ctx context.Context, inst *nativeRuleInstance) {
	maxConns := inst.spec.MaxConns
	if maxConns <= 0 {
		maxConns = 8192
	}
	for {
		conn, err := inst.tcpListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}
		setTCPKeepAlive(conn)

		if !isTunnelEgress(inst.spec) && !inst.isAllowedRemoteAddr(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}

		if maxConns > 0 && atomic.LoadInt64(&inst.tracker.ActiveConns) >= int64(maxConns) {
			_ = conn.Close()
			continue
		}

		releaseIP := func() {}
		if !isTunnelEgress(inst.spec) {
			var allowed bool
			releaseIP, allowed = e.connGuard.Acquire(conn.RemoteAddr())
			if !allowed {
				_ = conn.Close()
				continue
			}
		}

		atomic.AddInt64(&inst.tracker.ActiveConns, 1)
		go e.handleTCPConn(ctx, inst, conn, releaseIP)
	}
}

func (e *NativeEngine) handleTCPConn(ctx context.Context, inst *nativeRuleInstance, clientConn net.Conn, releaseIP func()) {
	defer func() {
		releaseIP()
		_ = clientConn.Close()
		atomic.AddInt64(&inst.tracker.ActiveConns, -1)
	}()

	if isTunnelEgress(inst.spec) {
		if e.egressHandshakeSem != nil {
			select {
			case e.egressHandshakeSem <- struct{}{}:
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		releaseHS := sync.OnceFunc(func() {
			if e.egressHandshakeSem != nil {
				<-e.egressHandshakeSem
			}
		})
		defer releaseHS()

		// Complete the TLS handshake explicitly with a deadline so idle scanners cannot pin goroutines
		if tc, ok := clientConn.(*tls.Conn); ok {
			hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := tc.HandshakeContext(hsCtx)
			cancel()
			if err != nil {
				return
			}
		}
		// Optional self-developed obfuscation layer inside TLS
		if inst.spec.Tunnel.Transport == "custom" {
			if w := e.getCustomWrapper(); w != nil {
				wrapped, err := w.WrapServerConn(clientConn, inst.spec.Tunnel)
				if err != nil {
					return
				}
				clientConn = wrapped
			}
		}
		// HMAC pre-shared key tunnel authentication (replay-protected) blocks port scanners & traffic theft
		mode, err := security.VerifyTunnelAuthHeader(clientConn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey)
		if err != nil {
			log.Printf("[NativeEngine] Blocked unauthorized Egress connection from %s on rule #%d: %v",
				clientConn.RemoteAddr().String(), inst.spec.RuleID, err)
			return
		}
		// Release pre-auth handshake slot once authenticated so long-lived legitimate tunnels never exhaust it
		releaseHS()
		if mode == security.TunnelModeUDP {
			if wantsUDP(inst.spec) {
				e.serveTunnelUDP(ctx, inst, clientConn)
			}
			return
		}
		if !wantsTCP(inst.spec) {
			return
		}
	}

	targetConn, err := e.dialUpstream(ctx, inst, security.TunnelModeTCP)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Upload direction: client -> upstream
	go func() {
		defer wg.Done()
		_ = limiter.CopyWithStats(ctx, targetConn, clientConn, inst.tracker.Limiter, &inst.tracker.UploadBytes)
		closeWrite(targetConn)
	}()

	// Download direction: upstream -> client
	go func() {
		defer wg.Done()
		_ = limiter.CopyWithStats(ctx, clientConn, targetConn, inst.tracker.Limiter, &inst.tracker.DownBytes)
		closeWrite(clientConn)
	}()

	wg.Wait()
}

func closeWrite(c net.Conn) {
	switch tc := c.(type) {
	case *net.TCPConn:
		_ = tc.CloseWrite()
	case *tls.Conn:
		_ = tc.CloseWrite()
	}
}

func (e *NativeEngine) healthProbeLoop(ctx context.Context, inst *nativeRuleInstance) {
	allowPrivate := e.policy.AllowPrivateTargets || (inst.spec.Role == protocol.RoleIngress)
	probeOnce := func() {
		for idx, t := range inst.spec.Targets {
			c, err := security.SafeDialTCP(ctx, t.Address, 1500*time.Millisecond, allowPrivate)
			if err != nil {
				atomic.StoreInt64(&inst.unhealthyUntil[idx], time.Now().Add(15*time.Second).UnixNano())
			} else {
				_ = c.Close()
				atomic.StoreInt64(&inst.unhealthyUntil[idx], 0)
			}
		}
	}
	probeOnce()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeOnce()
		}
	}
}

// dialUpstream connects to the next target. For Ingress tunnel rules it establishes the pinned TLS tunnel to the
// Egress node and authenticates with the given stream mode.
func (e *NativeEngine) dialUpstream(ctx context.Context, inst *nativeRuleInstance, mode byte) (net.Conn, error) {
	targets := inst.spec.Targets
	n := len(targets)
	if n == 0 {
		return nil, fmt.Errorf("no targets")
	}

	startIdx := int(atomic.AddUint64(&inst.rrIndex, 1)-1) % n
	if inst.spec.LoadBalance == "failover" {
		startIdx = 0
	}

	allowPrivate := e.policy.AllowPrivateTargets || (inst.spec.Role == protocol.RoleIngress)
	nowNano := time.Now().UnixNano()

	// Order candidates: healthy targets first (starting from startIdx), then unhealthy targets as fallback
	candidates := make([]int, 0, n)
	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		if idx < len(inst.unhealthyUntil) && atomic.LoadInt64(&inst.unhealthyUntil[idx]) <= nowNano {
			candidates = append(candidates, idx)
		}
	}
	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		if idx < len(inst.unhealthyUntil) && atomic.LoadInt64(&inst.unhealthyUntil[idx]) > nowNano {
			candidates = append(candidates, idx)
		}
	}

	var lastErr error
	for _, idx := range candidates {
		addr := targets[idx].Address

		// Use Anti-SSRF & Anti-DNS-Rebinding safe dialer
		rawConn, err := security.SafeDialTCP(ctx, addr, 5*time.Second, allowPrivate)
		if err != nil {
			if idx < len(inst.unhealthyUntil) {
				atomic.StoreInt64(&inst.unhealthyUntil[idx], time.Now().Add(12*time.Second).UnixNano())
			}
			lastErr = err
			continue
		}
		if idx < len(inst.unhealthyUntil) {
			atomic.StoreInt64(&inst.unhealthyUntil[idx], 0)
		}
		if !isTunnelIngress(inst.spec) {
			return rawConn, nil
		}

		// Ingress: every tunnel transport is wrapped in TLS that only trusts the pinned Egress certificate
		tlsConn := tls.Client(rawConn, inst.clientTLS.Clone())
		hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = tlsConn.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			_ = rawConn.Close()
			lastErr = fmt.Errorf("tunnel TLS verification failed: %w", err)
			continue
		}
		var conn net.Conn = tlsConn

		// Optional self-developed protocol layer inside TLS
		if inst.spec.Tunnel.Transport == "custom" {
			if w := e.getCustomWrapper(); w != nil {
				wrapped, wErr := w.WrapClientConn(conn, inst.spec.Tunnel)
				if wErr != nil {
					_ = conn.Close()
					lastErr = wErr
					continue
				}
				conn = wrapped
			}
		}

		// Write HMAC pre-shared key tunnel auth header to authenticate with Egress
		if err := security.WriteTunnelAuthHeader(conn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey, mode); err != nil {
			_ = conn.Close()
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, lastErr
}

// --- UDP ---

const (
	maxUDPSessions    = 2048
	maxUDPGlobal      = 8192
	udpIdleTimeout    = 60 * time.Second
	udpReadPollWindow = 15 * time.Second
	udpQueueLength    = 256
	maxUDPFrameSize   = 65535
)

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPFrameSize)
		return &b
	},
}

func acquireUDPBuf() *[]byte {
	return udpBufPool.Get().(*[]byte)
}

func releaseUDPBuf(b *[]byte) {
	if b != nil {
		udpBufPool.Put(b)
	}
}

// ActiveUDPSessions returns the total number of live UDP sessions across all rules on this NativeEngine.
func (e *NativeEngine) ActiveUDPSessions() int64 {
	return atomic.LoadInt64(&e.activeUDPSessions)
}

// udpUpstream abstracts a plain UDP socket or a UDP-over-TLS framed tunnel stream.
type udpUpstream interface {
	WritePacket(p []byte) error
	ReadPacket(buf []byte) (int, error)
	Close() error
}

type plainUDPUpstream struct{ c *net.UDPConn }

func (u *plainUDPUpstream) WritePacket(p []byte) error { _, err := u.c.Write(p); return err }
func (u *plainUDPUpstream) ReadPacket(buf []byte) (int, error) {
	_ = u.c.SetReadDeadline(time.Now().Add(udpReadPollWindow))
	n, _, err := u.c.ReadFromUDP(buf)
	return n, err
}
func (u *plainUDPUpstream) Close() error { return u.c.Close() }

// framedUpstream carries datagrams as [2-byte big-endian length][payload] over an encrypted stream.
type framedUpstream struct {
	c       net.Conn
	writeMu sync.Mutex
}

func (f *framedUpstream) WritePacket(p []byte) error {
	if len(p) > maxUDPFrameSize {
		return fmt.Errorf("datagram too large")
	}
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	_ = f.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := f.c.Write(frame)
	return err
}

func (f *framedUpstream) ReadPacket(buf []byte) (int, error) {
	var hdr [2]byte
	_ = f.c.SetReadDeadline(time.Now().Add(udpReadPollWindow))
	// Read first byte so a poll timeout never leaves a half-consumed frame header on the stream.
	if _, err := io.ReadFull(f.c, hdr[:1]); err != nil {
		return 0, err
	}
	_ = f.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(f.c, hdr[1:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("frame too large")
	}
	if _, err := io.ReadFull(f.c, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (f *framedUpstream) Close() error { return f.c.Close() }

func (e *NativeEngine) resolveSafeUDP(ctx context.Context, inst *nativeRuleInstance, addr string) (*net.UDPAddr, error) {
	allowPrivate := e.policy.AllowPrivateTargets || (inst.spec.Role == protocol.RoleIngress)
	if err := security.ValidateTargetAddress(addr, allowPrivate); err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("invalid UDP target port %q", portStr)
	}
	var chosen net.IP
	if ip := net.ParseIP(host); ip != nil {
		if err := security.ValidateResolvedIP(ip, allowPrivate); err != nil {
			return nil, err
		}
		chosen = ip
	} else {
		resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, lErr := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
		cancel()
		if lErr != nil || len(ips) == 0 {
			return nil, fmt.Errorf("UDP DNS resolution failed for %s: %w", host, lErr)
		}
		for _, ip := range ips {
			if security.ValidateResolvedIP(ip, allowPrivate) == nil {
				chosen = ip
				break
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("security violation: UDP DNS resolution of %q pointed to restricted IP %s", host, ips[0].String())
		}
	}
	return &net.UDPAddr{IP: chosen, Port: portNum}, nil
}

func (e *NativeEngine) openUDPUpstream(ctx context.Context, inst *nativeRuleInstance) (udpUpstream, error) {
	if isTunnelIngress(inst.spec) {
		conn, err := e.dialUpstream(ctx, inst, security.TunnelModeUDP)
		if err != nil {
			return nil, err
		}
		return &framedUpstream{c: conn}, nil
	}
	rAddr, err := e.resolveSafeUDP(ctx, inst, inst.spec.Targets[0].Address)
	if err != nil {
		return nil, err
	}
	upConn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, err
	}
	return &plainUDPUpstream{c: upConn}, nil
}

type udpSession struct {
	queue    chan []byte
	done     chan struct{}
	lastSeen int64
}

func (e *NativeEngine) serveUDP(ctx context.Context, inst *nativeRuleInstance) {
	var sessions sync.Map
	var sessionCount int64
	readBufPtr := acquireUDPBuf()
	defer releaseUDPBuf(readBufPtr)
	buf := *readBufPtr

	maxRuleCap := e.policy.MaxUDPSessionsPerRule
	if maxRuleCap <= 0 {
		maxRuleCap = maxUDPSessions
	}
	if inst.spec.MaxConns > 0 && inst.spec.MaxConns < maxRuleCap {
		maxRuleCap = inst.spec.MaxConns
	}
	maxGlobalCap := e.policy.MaxUDPSessionsGlobal
	if maxGlobalCap <= 0 {
		maxGlobalCap = maxUDPGlobal
	}
	idleSec := int64(udpIdleTimeout.Seconds())

	for {
		n, clientAddr, err := inst.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		if !inst.isAllowedRemoteAddr(clientAddr) {
			continue
		}

		clientKey := clientAddr.String()
		val, ok := sessions.Load(clientKey)
		var sess *udpSession
		if !ok {
			// Enforce 3-tier UDP session caps (per-rule, node-global, per-source-IP) BEFORE charging upload bytes
			// or blocking the shared UDP read loop on rate.Limiter.WaitN.
			if atomic.AddInt64(&sessionCount, 1) > int64(maxRuleCap) {
				atomic.AddInt64(&sessionCount, -1)
				continue
			}
			if atomic.AddInt64(&e.activeUDPSessions, 1) > int64(maxGlobalCap) {
				atomic.AddInt64(&e.activeUDPSessions, -1)
				atomic.AddInt64(&sessionCount, -1)
				continue
			}
			releaseUDPIP, allowed := e.udpIPGuard.Acquire(clientAddr)
			if !allowed {
				atomic.AddInt64(&e.activeUDPSessions, -1)
				atomic.AddInt64(&sessionCount, -1)
				continue
			}

			sess = &udpSession{
				queue:    make(chan []byte, udpQueueLength),
				done:     make(chan struct{}),
				lastSeen: time.Now().Unix(),
			}
			sessions.Store(clientKey, sess)
			atomic.AddInt64(&inst.tracker.ActiveConns, 1)

			go func(cAddr *net.UDPAddr, s *udpSession, key string, relIP func()) {
				defer func() {
					close(s.done)
					sessions.Delete(key)
					relIP()
					atomic.AddInt64(&inst.tracker.ActiveConns, -1)
					atomic.AddInt64(&e.activeUDPSessions, -1)
					atomic.AddInt64(&sessionCount, -1)
				}()
				up, err := e.openUDPUpstream(ctx, inst)
				if err != nil {
					log.Printf("[NativeEngine] UDP upstream for rule %s unavailable: %v", inst.key, err)
					return
				}
				defer up.Close()

				// writer: client datagrams -> upstream
				go func() {
					for {
						select {
						case p := <-s.queue:
							if inst.tracker.Limiter != nil && len(p) > 0 {
								if inst.tracker.Limiter.WaitN(ctx, len(p)) != nil {
									_ = up.Close()
									return
								}
							}
							if up.WritePacket(p) != nil {
								_ = up.Close()
								return
							}
							inst.tracker.AddUpload(int64(len(p)))
						case <-s.done:
							return
						case <-ctx.Done():
							_ = up.Close()
							return
						}
					}
				}()

				// reader: upstream datagrams -> client
				rBufPtr := acquireUDPBuf()
				defer releaseUDPBuf(rBufPtr)
				rBuf := *rBufPtr
				for {
					rn, rErr := up.ReadPacket(rBuf)
					if rErr != nil {
						var netErr net.Error
						if errors.As(rErr, &netErr) && netErr.Timeout() {
							if time.Now().Unix()-atomic.LoadInt64(&s.lastSeen) < idleSec {
								continue
							}
						}
						return
					}
					// Even if upstream sends unilateral keepalives, evict sessions where the client left > udpIdleTimeout ago.
					if time.Now().Unix()-atomic.LoadInt64(&s.lastSeen) >= idleSec {
						return
					}
					if inst.tracker.Limiter != nil && rn > 0 {
						if inst.tracker.Limiter.WaitN(ctx, rn) != nil {
							return
						}
					}
					wn, wErr := inst.udpConn.WriteToUDP(rBuf[:rn], cAddr)
					if wn > 0 {
						inst.tracker.AddDownload(int64(wn))
					}
					if wErr != nil {
						return
					}
				}
			}(clientAddr, sess, clientKey, releaseUDPIP)
		} else {
			sess = val.(*udpSession)
			atomic.StoreInt64(&sess.lastSeen, time.Now().Unix())
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case sess.queue <- pkt:
		default: // queue full: drop datagram without charging unforwarded bytes
		}
	}
}

// serveTunnelUDP runs on the Egress side for an authenticated UDP-mode tunnel stream: it unpacks framed
// datagrams, forwards them to the rule's (SSRF-validated) target and frames the replies back.
func (e *NativeEngine) serveTunnelUDP(ctx context.Context, inst *nativeRuleInstance, tunnelConn net.Conn) {
	rAddr, err := e.resolveSafeUDP(ctx, inst, inst.spec.Targets[0].Address)
	if err != nil {
		log.Printf("[NativeEngine] Blocked unsafe UDP target on rule %s: %v", inst.key, err)
		return
	}
	upConn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return
	}
	defer upConn.Close()
	tunnel := &framedUpstream{c: tunnelConn}

	var lastClientSeen int64
	atomic.StoreInt64(&lastClientSeen, time.Now().Unix())
	idleSec := int64(udpIdleTimeout.Seconds())

	go func() {
		defer tunnelConn.Close()
		rBufPtr := acquireUDPBuf()
		defer releaseUDPBuf(rBufPtr)
		rBuf := *rBufPtr
		for {
			_ = upConn.SetReadDeadline(time.Now().Add(udpReadPollWindow))
			rn, _, rErr := upConn.ReadFromUDP(rBuf)
			if rErr != nil {
				var netErr net.Error
				if errors.As(rErr, &netErr) && netErr.Timeout() {
					if time.Now().Unix()-atomic.LoadInt64(&lastClientSeen) < idleSec {
						continue
					}
				}
				return
			}
			if time.Now().Unix()-atomic.LoadInt64(&lastClientSeen) >= idleSec {
				return
			}
			if inst.tracker.Limiter != nil && rn > 0 {
				if inst.tracker.Limiter.WaitN(ctx, rn) != nil {
					return
				}
			}
			if tunnel.WritePacket(rBuf[:rn]) != nil {
				return
			}
			inst.tracker.AddDownload(int64(rn))
		}
	}()

	bufPtr := acquireUDPBuf()
	defer releaseUDPBuf(bufPtr)
	buf := *bufPtr
	for {
		n, rErr := tunnel.ReadPacket(buf)
		if rErr != nil {
			var netErr net.Error
			if errors.As(rErr, &netErr) && netErr.Timeout() {
				if time.Now().Unix()-atomic.LoadInt64(&lastClientSeen) < idleSec {
					continue
				}
			}
			return
		}
		atomic.StoreInt64(&lastClientSeen, time.Now().Unix())
		if inst.tracker.Limiter != nil && n > 0 {
			if inst.tracker.Limiter.WaitN(ctx, n) != nil {
				return
			}
		}
		if _, wErr := upConn.Write(buf[:n]); wErr != nil {
			return
		}
		inst.tracker.AddUpload(int64(n))
	}
}

func (e *NativeEngine) RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error {
	e.mu.Lock()
	inst, exists := e.rules[ruleKey]
	if exists {
		delete(e.rules, ruleKey)
	}
	e.mu.Unlock()

	if !exists {
		return nil
	}

	inst.cancel()
	if inst.tcpListener != nil {
		_ = inst.tcpListener.Close()
	}
	if inst.udpConn != nil {
		_ = inst.udpConn.Close()
	}
	return nil
}

func (e *NativeEngine) CollectDeltas() []protocol.RuleTrafficDelta {
	e.mu.RLock()
	defer e.mu.RUnlock()

	deltas := make([]protocol.RuleTrafficDelta, 0, len(e.rules))
	for _, inst := range e.rules {
		up, down, active := inst.tracker.SwapDeltas()
		deltas = append(deltas, protocol.RuleTrafficDelta{
			RuleID:      inst.spec.RuleID,
			Role:        inst.spec.Role,
			Engine:      protocol.EngineNative,
			UploadBytes: up,
			DownBytes:   down,
			ActiveConns: active,
		})
	}
	return deltas
}

func (e *NativeEngine) ActiveRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func (e *NativeEngine) Close() error {
	e.mu.Lock()
	keys := make([]string, 0, len(e.rules))
	for k := range e.rules {
		keys = append(keys, k)
	}
	e.mu.Unlock()

	for _, k := range keys {
		_ = e.RemoveRule(k, 0, "")
	}
	return nil
}
