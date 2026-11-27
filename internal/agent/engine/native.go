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
	"sort"
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
	sniBindAddr    string // non-empty when attached to a shared sniHostRouter
	udpConn        *net.UDPConn
	tracker        *limiter.RuleStatsTracker
	rrIndex        uint64
	clientTLS      *tls.Config   // default pinned next-hop/egress TLS config
	targetTLS      []*tls.Config // per-target pinned TLS configs for multi-egress bandwidth aggregation
	aclMode        string        // "off" | "allow" | "deny"
	aclNets        []*net.IPNet
	unhealthyUntil []int64 // atomic UnixNano per target index
	rttNanos       []int64 // atomic smoothed RTT (ns) per target index for least_rtt selection
	muxPool        *muxClientPool
	bondHub        *bondServerHub
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
// It supports single-hop direct relay, arbitrary N-hop encrypted tunnel chains (RoleIngress -> RoleHop -> RoleEgress),
// multi-egress bandwidth aggregation (weighted / least_rtt / failover), multiplexed connection pooling (EnableMux),
// single-stream multi-link chunk striping (EnableBonding), end-to-end PROXY Protocol v1/v2 client IP preservation,
// non-decrypting TLS SNI / HTTP Host shared-port routing (MatchDomains), and OutboundIP source binding.
type NativeEngine struct {
	mu                 sync.RWMutex
	policy             security.Policy
	connGuard          *security.IPConnGuard
	udpIPGuard         *security.IPConnGuard
	egressHandshakeSem chan struct{}
	activeUDPSessions  int64
	rules              map[string]*nativeRuleInstance
	sniRouters         map[string]*sniHostRouter
	serverTLSConf      *tls.Config
	customWrapper      CustomTunnelWrapper
}

// NewNativeEngine creates a ready-to-use NativeEngine. cert is the node's persistent tunnel identity used when
// acting as a Hop or Egress; if nil, Hop/Egress tunnel rules are rejected.
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
		sniRouters:         make(map[string]*sniHostRouter),
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
	return true
}

func isTunnelServer(spec protocol.RuleSpec) bool {
	return protocol.IsTunnelServerRole(spec.Role) && spec.Tunnel != nil
}

func isTunnelClient(spec protocol.RuleSpec) bool {
	return protocol.IsTunnelClientRole(spec.Role) && spec.Tunnel != nil
}

func isTunnelEgress(spec protocol.RuleSpec) bool {
	return spec.Role == protocol.RoleEgress && spec.Tunnel != nil
}

func isTunnelIngress(spec protocol.RuleSpec) bool {
	return spec.Role == protocol.RoleIngress && spec.Tunnel != nil
}

func effectiveProxyProto(spec protocol.RuleSpec) int {
	if spec.ProxyProto == 1 || spec.ProxyProto == 2 {
		return spec.ProxyProto
	}
	if spec.Tunnel != nil && (spec.Tunnel.ProxyProto == 1 || spec.Tunnel.ProxyProto == 2) {
		return spec.Tunnel.ProxyProto
	}
	return 0
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
	if (isTunnelServer(spec) || isTunnelClient(spec)) && spec.Tunnel.SecretKey == "" {
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
		rttNanos:       make([]int64, len(spec.Targets)),
	}
	if isTunnelClient(spec) {
		inst.targetTLS = make([]*tls.Config, len(spec.Targets))
		if strings.TrimSpace(spec.Tunnel.CertPEM) != "" {
			clientTLS, err := security.TunnelClientTLSConfig(spec.Tunnel.CertPEM)
			if err != nil {
				return fmt.Errorf("rule %s: %w", key, err)
			}
			inst.clientTLS = clientTLS
		}
		for i, t := range spec.Targets {
			pemStr := strings.TrimSpace(t.CertPEM)
			if pemStr == "" {
				if inst.clientTLS == nil {
					return fmt.Errorf("rule %s target #%d (%s): pinned tunnel certificate missing", key, i, t.Address)
				}
				inst.targetTLS[i] = inst.clientTLS
				continue
			}
			tTLS, err := security.TunnelClientTLSConfig(pemStr)
			if err != nil {
				return fmt.Errorf("rule %s target #%d: %w", key, i, err)
			}
			inst.targetTLS[i] = tTLS
		}
		if spec.Tunnel.EnableMux {
			inst.muxPool = newMuxClientPool()
		}
	}
	if isTunnelServer(spec) {
		if e.serverTLSConf == nil {
			return fmt.Errorf("rule %s: local tunnel certificate unavailable, refusing to start %s", key, spec.Role)
		}
		inst.bondHub = newBondServerHub()
	}

	ruleCtx, cancel := context.WithCancel(ctx)
	inst.cancel = cancel

	listenHost := spec.ListenHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	bindAddr := net.JoinHostPort(listenHost, fmt.Sprintf("%d", spec.ListenPort))

	// Shared-port SNI / HTTP Host L7 demux routing (available on user-facing TCP rules: Relay or Ingress)
	if !isTunnelServer(spec) && strings.TrimSpace(spec.MatchDomains) != "" {
		e.mu.Lock()
		rt, exists := e.sniRouters[bindAddr]
		if !exists {
			var err error
			rt, err = newSNIHostRouter(bindAddr, e)
			if err != nil {
				e.mu.Unlock()
				cancel()
				return err
			}
			e.sniRouters[bindAddr] = rt
		}
		if err := rt.Register(key, ruleCtx, inst); err != nil {
			if len(rt.routes) == 0 {
				rt.Unregister(key)
				delete(e.sniRouters, bindAddr)
			}
			e.mu.Unlock()
			cancel()
			return err
		}
		inst.sniBindAddr = bindAddr
		e.rules[key] = inst
		e.mu.Unlock()

		if len(spec.Targets) > 1 {
			go e.healthProbeLoop(ruleCtx, inst)
		}
		log.Printf("[NativeEngine] Applied SNI/Host shared-port rule %s (%s) on %s (domains=%s)",
			key, spec.Name, bindAddr, spec.MatchDomains)
		return nil
	}

	// Dedicated TCP listener: relay/ingress when protocol includes tcp; hop/egress tunnels always (UDP is framed inside TLS)
	if isTunnelServer(spec) || wantsTCP(spec) {
		var ln net.Listener
		var err error
		if isTunnelServer(spec) {
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

	// UDP listener only on the user-facing edge (relay / ingress)
	if !isTunnelServer(spec) && wantsUDP(spec) {
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

	// Background active health & RTT probe for multi-target TCP / multi-egress tunnel rules
	if len(spec.Targets) > 1 && (wantsTCP(spec) || isTunnelClient(spec)) {
		go e.healthProbeLoop(ruleCtx, inst)
	}

	e.mu.Lock()
	e.rules[key] = inst
	e.mu.Unlock()

	log.Printf("[NativeEngine] Applied rule %s (%s, role=%s) listening on %s -> %d targets (limit=%d Mbps, acl=%s)",
		key, spec.Name, spec.Role, bindAddr, len(spec.Targets), spec.SpeedLimitMbps, aclMode)
	return nil
}

// Also hook goutils in gost.go where caPath is created: check gost.go!
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

// dispatchMatchedTCPConn runs ACL, MaxConns, IPConnGuard, and stream forwarding on an already-accepted (or SNI-routed) edge connection.
func (e *NativeEngine) dispatchMatchedTCPConn(ctx context.Context, inst *nativeRuleInstance, conn net.Conn, preRelease ...func()) {
	var releaseIP func()
	if len(preRelease) > 0 && preRelease[0] != nil {
		releaseIP = preRelease[0]
	}
	if !isTunnelServer(inst.spec) && !inst.isAllowedRemoteAddr(conn.RemoteAddr()) {
		if releaseIP != nil {
			releaseIP()
		}
		_ = conn.Close()
		return
	}

	maxConns := inst.spec.MaxConns
	if maxConns <= 0 {
		maxConns = 8192
	}
	if maxConns > 0 && atomic.LoadInt64(&inst.tracker.ActiveConns) >= int64(maxConns) {
		if releaseIP != nil {
			releaseIP()
		}
		_ = conn.Close()
		return
	}

	if releaseIP == nil {
		releaseIP = func() {}
		if !isTunnelServer(inst.spec) {
			var allowed bool
			releaseIP, allowed = e.connGuard.Acquire(conn.RemoteAddr())
			if !allowed {
				_ = conn.Close()
				return
			}
		}
	}

	atomic.AddInt64(&inst.tracker.ActiveConns, 1)
	go e.handleTCPConn(ctx, inst, conn, releaseIP)
}

func (e *NativeEngine) serveTCP(ctx context.Context, inst *nativeRuleInstance) {
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
		e.dispatchMatchedTCPConn(ctx, inst, conn)
	}
}

func (e *NativeEngine) handleTCPConn(ctx context.Context, inst *nativeRuleInstance, clientConn net.Conn, releaseIP func()) {
	ownershipTransferred := false
	defer func() {
		releaseIP()
		if !ownershipTransferred {
			_ = clientConn.Close()
		}
		atomic.AddInt64(&inst.tracker.ActiveConns, -1)
	}()

	if isTunnelServer(inst.spec) {
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

		if tc, ok := clientConn.(*tls.Conn); ok {
			hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := tc.HandshakeContext(hsCtx)
			cancel()
			if err != nil {
				return
			}
		}
		if inst.spec.Tunnel.Transport == "custom" {
			if w := e.getCustomWrapper(); w != nil {
				wrapped, err := w.WrapServerConn(clientConn, inst.spec.Tunnel)
				if err != nil {
					return
				}
				clientConn = wrapped
			}
		}
		mode, err := security.VerifyTunnelAuthHeader(clientConn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey)
		if err != nil {
			log.Printf("[NativeEngine] Blocked unauthorized %s connection from %s on rule #%d: %v",
				inst.spec.Role, clientConn.RemoteAddr().String(), inst.spec.RuleID, err)
			return
		}
		releaseHS()

		switch mode {
		case security.TunnelModeMux:
			ownershipTransferred = true
			muxSess := newMuxSession(clientConn, false, func(st *muxStream, subMode byte, origClientAddr string) {
				atomic.AddInt64(&inst.tracker.ActiveConns, 1)
				defer func() {
					_ = st.Close()
					atomic.AddInt64(&inst.tracker.ActiveConns, -1)
				}()
				e.serveAuthenticatedTunnelStream(ctx, inst, st, subMode, origClientAddr)
			})
			select {
			case <-ctx.Done():
				_ = muxSess.Close()
			case <-muxSess.closedCh:
			}
			return

		case security.TunnelModeBond:
			if inst.bondHub == nil {
				return
			}
			bc, subMode, origClientAddr, ready, bErr := inst.bondHub.AcceptMember(clientConn)
			if bErr != nil {
				return
			}
			ownershipTransferred = true
			if !ready {
				// Non-final member link is now owned by pendingBondGroup / bondedConn
				return
			}
			defer bc.Close()
			e.serveAuthenticatedTunnelStream(ctx, inst, bc, subMode, origClientAddr)
			return

		case security.TunnelModeTCPMeta:
			origAddr, mErr := security.ReadTunnelClientMeta(clientConn)
			if mErr != nil {
				return
			}
			e.serveAuthenticatedTunnelStream(ctx, inst, clientConn, security.TunnelModeTCP, origAddr)
			return

		case security.TunnelModeUDPMeta:
			origAddr, mErr := security.ReadTunnelClientMeta(clientConn)
			if mErr != nil {
				return
			}
			e.serveAuthenticatedTunnelStream(ctx, inst, clientConn, security.TunnelModeUDP, origAddr)
			return

		default:
			e.serveAuthenticatedTunnelStream(ctx, inst, clientConn, mode, "")
			return
		}
	}

	// Edge Relay or Ingress connection
	origClientAddr := ""
	if clientConn.RemoteAddr() != nil {
		origClientAddr = clientConn.RemoteAddr().String()
	}

	targetConn, err := e.dialUpstream(ctx, inst, security.TunnelModeTCP, origClientAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Direct Relay PROXY Protocol injection (for Tunnel rules, Egress injects PROXY Protocol at the final hop)
	if !isTunnelClient(inst.spec) {
		if ppVer := effectiveProxyProto(inst.spec); ppVer > 0 {
			if err := WriteProxyProtocolHeader(targetConn, ppVer, "tcp", origClientAddr); err != nil {
				return
			}
		}
	}

	e.spliceBidirectional(ctx, inst, clientConn, targetConn)
}

func (e *NativeEngine) serveAuthenticatedTunnelStream(
	ctx context.Context,
	inst *nativeRuleInstance,
	streamConn net.Conn,
	subMode byte,
	origClientAddr string,
) {
	// Intermediate Hop Role: relay encrypted stream onward to next hop / egress pool without plaintext exposure!
	if isTunnelClient(inst.spec) {
		nextConn, err := e.dialUpstream(ctx, inst, subMode, origClientAddr)
		if err != nil {
			return
		}
		defer nextConn.Close()
		e.spliceBidirectional(ctx, inst, streamConn, nextConn)
		return
	}

	// Final Egress Role: unpack UDP or forward TCP to final target (injecting PROXY Protocol if configured)
	if subMode == security.TunnelModeUDP {
		if wantsUDP(inst.spec) {
			e.serveTunnelUDP(ctx, inst, streamConn)
		}
		return
	}
	if !wantsTCP(inst.spec) {
		return
	}

	targetConn, err := e.dialUpstream(ctx, inst, security.TunnelModeTCP, origClientAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	if ppVer := effectiveProxyProto(inst.spec); ppVer > 0 {
		if err := WriteProxyProtocolHeader(targetConn, ppVer, "tcp", origClientAddr); err != nil {
			return
		}
	}

	e.spliceBidirectional(ctx, inst, streamConn, targetConn)
}

func (e *NativeEngine) spliceBidirectional(ctx context.Context, inst *nativeRuleInstance, clientConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = limiter.CopyWithStats(ctx, targetConn, clientConn, inst.tracker.Limiter, &inst.tracker.UploadBytes)
		closeWrite(targetConn)
	}()

	go func() {
		defer wg.Done()
		_ = limiter.CopyWithStats(ctx, clientConn, targetConn, inst.tracker.Limiter, &inst.tracker.DownBytes)
		closeWrite(clientConn)
	}()

	wg.Wait()
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (e *NativeEngine) healthProbeLoop(ctx context.Context, inst *nativeRuleInstance) {
	allowPrivate := e.policy.AllowPrivateTargets || isTunnelClient(inst.spec)
	probeOnce := func() {
		for idx, t := range inst.spec.Targets {
			t0 := time.Now()
			c, err := security.SafeDialTCPWithSource(ctx, t.Address, inst.spec.OutboundIP, 1500*time.Millisecond, allowPrivate)
			if err != nil {
				atomic.StoreInt64(&inst.unhealthyUntil[idx], time.Now().Add(15*time.Second).UnixNano())
			} else {
				rtt := time.Since(t0).Nanoseconds()
				_ = c.Close()
				atomic.StoreInt64(&inst.unhealthyUntil[idx], 0)
				old := atomic.LoadInt64(&inst.rttNanos[idx])
				if old <= 0 {
					atomic.StoreInt64(&inst.rttNanos[idx], rtt)
				} else {
					atomic.StoreInt64(&inst.rttNanos[idx], (old*3+rtt)/4)
				}
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

// orderedTargetCandidates returns target indices ordered according to health, primary vs backup role, and LoadBalance strategy.
func (e *NativeEngine) orderedTargetCandidates(inst *nativeRuleInstance) []int {
	targets := inst.spec.Targets
	n := len(targets)
	if n == 1 {
		return []int{0}
	}
	nowNano := time.Now().UnixNano()
	var healthyPrimary, healthyBackup, unhealthy []int
	for i := 0; i < n; i++ {
		isHealthy := i >= len(inst.unhealthyUntil) || atomic.LoadInt64(&inst.unhealthyUntil[i]) <= nowNano
		if !isHealthy {
			unhealthy = append(unhealthy, i)
		} else if targets[i].Backup {
			healthyBackup = append(healthyBackup, i)
		} else {
			healthyPrimary = append(healthyPrimary, i)
		}
	}
	// If all non-backup targets were marked Backup, treat healthyBackup as primary
	if len(healthyPrimary) == 0 && len(healthyBackup) > 0 {
		healthyPrimary = healthyBackup
		healthyBackup = nil
	}

	orderGroup := func(group []int) []int {
		if len(group) <= 1 {
			return group
		}
		out := make([]int, len(group))
		copy(out, group)
		switch inst.spec.LoadBalance {
		case "failover":
			return out

		case "least_rtt":
			sort.SliceStable(out, func(i, j int) bool {
				ri := atomic.LoadInt64(&inst.rttNanos[out[i]])
				rj := atomic.LoadInt64(&inst.rttNanos[out[j]])
				if ri == 0 && rj > 0 {
					return true
				}
				if rj == 0 && ri > 0 {
					return false
				}
				return ri < rj
			})
			return out

		case "weighted":
			totalW := uint64(0)
			for _, idx := range out {
				w := targets[idx].Weight
				if w <= 0 {
					w = 100
				}
				if w > 10000 {
					w = 10000
				}
				totalW += uint64(w)
			}
			pick := (atomic.AddUint64(&inst.rrIndex, 1) - 1) % totalW
			chosenPos := 0
			acc := uint64(0)
			for pos, idx := range out {
				w := targets[idx].Weight
				if w <= 0 {
					w = 100
				}
				if w > 10000 {
					w = 10000
				}
				acc += uint64(w)
				if pick < acc {
					chosenPos = pos
					break
				}
			}
			rotated := make([]int, 0, len(out))
			for i := 0; i < len(out); i++ {
				rotated = append(rotated, out[(chosenPos+i)%len(out)])
			}
			return rotated

		case "random":
			start := int(atomic.AddUint64(&inst.rrIndex, 2654435761) % uint64(len(out)))
			rotated := make([]int, 0, len(out))
			for i := 0; i < len(out); i++ {
				rotated = append(rotated, out[(start+i)%len(out)])
			}
			return rotated

		default: // round_robin
			start := int((atomic.AddUint64(&inst.rrIndex, 1) - 1) % uint64(len(out)))
			rotated := make([]int, 0, len(out))
			for i := 0; i < len(out); i++ {
				rotated = append(rotated, out[(start+i)%len(out)])
			}
			return rotated
		}
	}

	candidates := make([]int, 0, n)
	candidates = append(candidates, orderGroup(healthyPrimary)...)
	candidates = append(candidates, orderGroup(healthyBackup)...)
	candidates = append(candidates, unhealthy...)
	return candidates
}

// dialRawAuthenticatedTunnel opens a single TLS-pinned, HMAC-authenticated tunnel connection to target[idx] with wireMode.
func (e *NativeEngine) dialRawAuthenticatedTunnel(ctx context.Context, inst *nativeRuleInstance, idx int, wireMode byte) (net.Conn, error) {
	allowPrivate := e.policy.AllowPrivateTargets || isTunnelClient(inst.spec)
	addr := inst.spec.Targets[idx].Address

	t0 := time.Now()
	rawConn, err := security.SafeDialTCPWithSource(ctx, addr, inst.spec.OutboundIP, 5*time.Second, allowPrivate)
	if err != nil {
		if idx < len(inst.unhealthyUntil) {
			atomic.StoreInt64(&inst.unhealthyUntil[idx], time.Now().Add(12*time.Second).UnixNano())
		}
		return nil, err
	}
	rtt := time.Since(t0).Nanoseconds()
	if idx < len(inst.unhealthyUntil) {
		atomic.StoreInt64(&inst.unhealthyUntil[idx], 0)
	}
	if idx < len(inst.rttNanos) {
		old := atomic.LoadInt64(&inst.rttNanos[idx])
		if old <= 0 {
			atomic.StoreInt64(&inst.rttNanos[idx], rtt)
		} else {
			atomic.StoreInt64(&inst.rttNanos[idx], (old*3+rtt)/4)
		}
	}

	var tlsConf *tls.Config
	if idx < len(inst.targetTLS) && inst.targetTLS[idx] != nil {
		tlsConf = inst.targetTLS[idx]
	} else {
		tlsConf = inst.clientTLS
	}
	if tlsConf == nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("missing pinned TLS config for target #%d", idx)
	}

	tlsConn := tls.Client(rawConn, tlsConf.Clone())
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = tlsConn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tunnel TLS verification failed: %w", err)
	}
	var conn net.Conn = tlsConn

	if inst.spec.Tunnel.Transport == "custom" {
		if w := e.getCustomWrapper(); w != nil {
			wrapped, wErr := w.WrapClientConn(conn, inst.spec.Tunnel)
			if wErr != nil {
				_ = conn.Close()
				return nil, wErr
			}
			conn = wrapped
		}
	}

	if err := security.WriteTunnelAuthHeader(conn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey, wireMode); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialUpstream connects to the next upstream target (plain socket for Relay/Egress, or authenticated TLS/Mux/Bonded
// tunnel stream for Ingress/Hop).
func (e *NativeEngine) dialUpstream(ctx context.Context, inst *nativeRuleInstance, subMode byte, origClientAddr string) (net.Conn, error) {
	if len(inst.spec.Targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	candidates := e.orderedTargetCandidates(inst)
	allowPrivate := e.policy.AllowPrivateTargets || isTunnelClient(inst.spec)

	if !isTunnelClient(inst.spec) {
		var lastErr error
		for _, idx := range candidates {
			addr := inst.spec.Targets[idx].Address
			t0 := time.Now()
			rawConn, err := security.SafeDialTCPWithSource(ctx, addr, inst.spec.OutboundIP, 5*time.Second, allowPrivate)
			if err != nil {
				if idx < len(inst.unhealthyUntil) {
					atomic.StoreInt64(&inst.unhealthyUntil[idx], time.Now().Add(12*time.Second).UnixNano())
				}
				lastErr = err
				continue
			}
			rtt := time.Since(t0).Nanoseconds()
			if idx < len(inst.unhealthyUntil) {
				atomic.StoreInt64(&inst.unhealthyUntil[idx], 0)
			}
			if idx < len(inst.rttNanos) {
				old := atomic.LoadInt64(&inst.rttNanos[idx])
				if old <= 0 {
					atomic.StoreInt64(&inst.rttNanos[idx], rtt)
				} else {
					atomic.StoreInt64(&inst.rttNanos[idx], (old*3+rtt)/4)
				}
			}
			return rawConn, nil
		}
		return nil, lastErr
	}

	clientMeta := ""
	if effectiveProxyProto(inst.spec) > 0 && origClientAddr != "" {
		clientMeta = origClientAddr
	}

	// Mode A: Single-stream multi-link chunk striping (EnableBonding)
	// Note: All member links of a single bonded stream MUST land on the SAME next-hop/egress node so bondServerHub reassembles them!
	if inst.spec.Tunnel.EnableBonding {
		links := inst.spec.Tunnel.BondLinks
		if links <= 0 {
			links = 4
		}
		var lastErr error
		for _, idx := range candidates {
			targetIdx := idx
			bc, err := dialBondedStream(ctx, links, subMode, clientMeta, func(dCtx context.Context, _ int) (net.Conn, error) {
				return e.dialRawAuthenticatedTunnel(dCtx, inst, targetIdx, security.TunnelModeBond)
			})
			if err == nil {
				return bc, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}

	// Mode B: Persistent multiplexed connection pool (EnableMux)
	if inst.spec.Tunnel.EnableMux && inst.muxPool != nil {
		var lastErr error
		for _, idx := range candidates {
			targetIdx := idx
			st, err := inst.muxPool.OpenStream(ctx, targetIdx, subMode, clientMeta, func(dCtx context.Context) (net.Conn, error) {
				return e.dialRawAuthenticatedTunnel(dCtx, inst, targetIdx, security.TunnelModeMux)
			})
			if err == nil {
				return st, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}

	// Mode C: Standard dedicated TLS tunnel connection
	wireMode := subMode
	if clientMeta != "" {
		if subMode == security.TunnelModeUDP {
			wireMode = security.TunnelModeUDPMeta
		} else {
			wireMode = security.TunnelModeTCPMeta
		}
	}
	var lastErr error
	for _, idx := range candidates {
		conn, err := e.dialRawAuthenticatedTunnel(ctx, inst, idx, wireMode)
		if err != nil {
			lastErr = err
			continue
		}
		if clientMeta != "" {
			if err := security.WriteTunnelClientMeta(conn, clientMeta); err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
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

func (e *NativeEngine) resolveSafeUDP(ctx context.Context, inst *nativeRuleInstance, addr string) (*net.UDPAddr, *net.UDPAddr, error) {
	allowPrivate := e.policy.AllowPrivateTargets || isTunnelClient(inst.spec)
	if err := security.ValidateTargetAddress(addr, allowPrivate); err != nil {
		return nil, nil, err
	}
	localIP, err := security.ValidateOutboundIP(inst.spec.OutboundIP, allowPrivate)
	if err != nil {
		return nil, nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, nil, fmt.Errorf("invalid UDP target port %q", portStr)
	}
	var chosen net.IP
	if ip := net.ParseIP(host); ip != nil {
		if localIP != nil && (localIP.To4() != nil) != (ip.To4() != nil) {
			return nil, nil, fmt.Errorf("UDP outbound_ip %s family mismatch with target %s", localIP.String(), ip.String())
		}
		if err := security.ValidateResolvedIP(ip, allowPrivate); err != nil {
			return nil, nil, err
		}
		chosen = ip
	} else {
		resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, lErr := net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
		cancel()
		if lErr != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("UDP DNS resolution failed for %s: %w", host, lErr)
		}
		for _, ip := range ips {
			if localIP != nil && (localIP.To4() != nil) != (ip.To4() != nil) {
				continue
			}
			if security.ValidateResolvedIP(ip, allowPrivate) == nil {
				chosen = ip
				break
			}
		}
		if chosen == nil {
			return nil, nil, fmt.Errorf("security violation: UDP DNS resolution of %q pointed to restricted IP %s", host, ips[0].String())
		}
	}
	var lAddr *net.UDPAddr
	if localIP != nil {
		lAddr = &net.UDPAddr{IP: localIP}
	}
	return lAddr, &net.UDPAddr{IP: chosen, Port: portNum}, nil
}

func (e *NativeEngine) openUDPUpstream(ctx context.Context, inst *nativeRuleInstance, origClientAddr string) (udpUpstream, error) {
	if isTunnelClient(inst.spec) {
		conn, err := e.dialUpstream(ctx, inst, security.TunnelModeUDP, origClientAddr)
		if err != nil {
			return nil, err
		}
		return &framedUpstream{c: conn}, nil
	}
	candidates := e.orderedTargetCandidates(inst)
	var lastErr error
	for _, idx := range candidates {
		lAddr, rAddr, err := e.resolveSafeUDP(ctx, inst, inst.spec.Targets[idx].Address)
		if err != nil {
			lastErr = err
			continue
		}
		upConn, err := net.DialUDP("udp", lAddr, rAddr)
		if err != nil {
			lastErr = err
			continue
		}
		return &plainUDPUpstream{c: upConn}, nil
	}
	return nil, lastErr
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
				up, err := e.openUDPUpstream(ctx, inst, key)
				if err != nil {
					log.Printf("[NativeEngine] UDP upstream for rule %s unavailable: %v", inst.key, err)
					return
				}
				defer up.Close()

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
		default:
		}
	}
}

func (e *NativeEngine) serveTunnelUDP(ctx context.Context, inst *nativeRuleInstance, tunnelConn net.Conn) {
	candidates := e.orderedTargetCandidates(inst)
	var upConn *net.UDPConn
	var lastErr error
	for _, idx := range candidates {
		lAddr, rAddr, err := e.resolveSafeUDP(ctx, inst, inst.spec.Targets[idx].Address)
		if err != nil {
			lastErr = err
			continue
		}
		c, err := net.DialUDP("udp", lAddr, rAddr)
		if err != nil {
			lastErr = err
			continue
		}
		upConn = c
		break
	}
	if upConn == nil {
		log.Printf("[NativeEngine] Blocked or unreachable UDP target on rule %s: %v", inst.key, lastErr)
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
		if inst.sniBindAddr != "" {
			if rt, ok := e.sniRouters[inst.sniBindAddr]; ok {
				if rt.Unregister(ruleKey) {
					delete(e.sniRouters, inst.sniBindAddr)
				}
			}
		}
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
	if inst.muxPool != nil {
		inst.muxPool.CloseAll()
	}
	if inst.bondHub != nil {
		inst.bondHub.CloseAll()
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
