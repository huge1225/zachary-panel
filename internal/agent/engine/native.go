package engine

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
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
	key         string
	spec        protocol.RuleSpec
	cancel      context.CancelFunc
	tcpListener net.Listener
	udpConn     *net.UDPConn
	tracker     *limiter.RuleStatsTracker
	rrIndex     uint64
	clientTLS   *tls.Config // Ingress only: pinned Egress certificate
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
	mu            sync.RWMutex
	policy        security.Policy
	connGuard     *security.IPConnGuard
	rules         map[string]*nativeRuleInstance
	serverTLSConf *tls.Config
	customWrapper CustomTunnelWrapper
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
	return &NativeEngine{
		policy:        pol,
		connGuard:     security.NewIPConnGuard(pol.MaxConnsPerClientIP),
		rules:         make(map[string]*nativeRuleInstance),
		serverTLSConf: tlsCfg,
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

	inst := &nativeRuleInstance{
		key:     key,
		spec:    spec,
		tracker: limiter.NewRuleStatsTracker(spec.SpeedLimitMbps),
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

	e.mu.Lock()
	e.rules[key] = inst
	e.mu.Unlock()

	log.Printf("[NativeEngine] Applied rule %s (%s) listening on %s -> %d targets (limit=%d Mbps)",
		key, spec.Name, bindAddr, len(spec.Targets), spec.SpeedLimitMbps)
	return nil
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

		if inst.spec.MaxConns > 0 && atomic.LoadInt64(&inst.tracker.ActiveConns) >= int64(inst.spec.MaxConns) {
			_ = conn.Close()
			continue
		}

		releaseIP, allowed := e.connGuard.Acquire(conn.RemoteAddr())
		if !allowed {
			_ = conn.Close()
			continue
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

	var lastErr error
	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		addr := targets[idx].Address

		// Use Anti-SSRF & Anti-DNS-Rebinding safe dialer
		rawConn, err := security.SafeDialTCP(ctx, addr, 5*time.Second, allowPrivate)
		if err != nil {
			lastErr = err
			continue
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
	maxUDPSessions  = 2048
	udpIdleTimeout  = 60 * time.Second
	udpQueueLength  = 256
	maxUDPFrameSize = 65535
)

// udpUpstream abstracts a plain UDP socket or a UDP-over-TLS framed tunnel stream.
type udpUpstream interface {
	WritePacket(p []byte) error
	ReadPacket(buf []byte) (int, error)
	Close() error
}

type plainUDPUpstream struct{ c *net.UDPConn }

func (u *plainUDPUpstream) WritePacket(p []byte) error { _, err := u.c.Write(p); return err }
func (u *plainUDPUpstream) ReadPacket(buf []byte) (int, error) {
	_ = u.c.SetReadDeadline(time.Now().Add(udpIdleTimeout))
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
	_ = f.c.SetReadDeadline(time.Now().Add(udpIdleTimeout))
	if _, err := io.ReadFull(f.c, hdr[:]); err != nil {
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

func (e *NativeEngine) resolveSafeUDP(inst *nativeRuleInstance, addr string) (*net.UDPAddr, error) {
	allowPrivate := e.policy.AllowPrivateTargets || (inst.spec.Role == protocol.RoleIngress)
	if err := security.ValidateTargetAddress(addr, allowPrivate); err != nil {
		return nil, err
	}
	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	// Enforce Anti-SSRF & Anti-DNS-Rebinding on resolved UDP IP
	if err := security.ValidateResolvedIP(rAddr.IP, allowPrivate); err != nil {
		return nil, err
	}
	return rAddr, nil
}

func (e *NativeEngine) openUDPUpstream(ctx context.Context, inst *nativeRuleInstance) (udpUpstream, error) {
	if isTunnelIngress(inst.spec) {
		conn, err := e.dialUpstream(ctx, inst, security.TunnelModeUDP)
		if err != nil {
			return nil, err
		}
		return &framedUpstream{c: conn}, nil
	}
	rAddr, err := e.resolveSafeUDP(inst, inst.spec.Targets[0].Address)
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
	buf := make([]byte, maxUDPFrameSize)

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

		inst.tracker.AddUpload(int64(n))
		if inst.tracker.Limiter != nil {
			_ = inst.tracker.Limiter.WaitN(ctx, n)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		clientKey := clientAddr.String()
		val, ok := sessions.Load(clientKey)
		var sess *udpSession
		if !ok {
			if atomic.LoadInt64(&sessionCount) >= maxUDPSessions {
				continue
			}
			sess = &udpSession{
				queue:    make(chan []byte, udpQueueLength),
				done:     make(chan struct{}),
				lastSeen: time.Now().Unix(),
			}
			sessions.Store(clientKey, sess)
			atomic.AddInt64(&sessionCount, 1)

			go func(cAddr *net.UDPAddr, s *udpSession, key string) {
				defer func() {
					close(s.done)
					sessions.Delete(key)
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
							if up.WritePacket(p) != nil {
								_ = up.Close()
								return
							}
						case <-s.done:
							return
						case <-ctx.Done():
							_ = up.Close()
							return
						}
					}
				}()

				// reader: upstream datagrams -> client
				rBuf := make([]byte, maxUDPFrameSize)
				for {
					rn, rErr := up.ReadPacket(rBuf)
					if rErr != nil {
						return
					}
					if inst.tracker.Limiter != nil {
						_ = inst.tracker.Limiter.WaitN(ctx, rn)
					}
					wn, wErr := inst.udpConn.WriteToUDP(rBuf[:rn], cAddr)
					if wn > 0 {
						inst.tracker.AddDownload(int64(wn))
					}
					if wErr != nil {
						return
					}
				}
			}(clientAddr, sess, clientKey)
		} else {
			sess = val.(*udpSession)
			atomic.StoreInt64(&sess.lastSeen, time.Now().Unix())
		}

		select {
		case sess.queue <- pkt:
		default: // queue full: drop datagram (UDP semantics)
		}
	}
}

// serveTunnelUDP runs on the Egress side for an authenticated UDP-mode tunnel stream: it unpacks framed
// datagrams, forwards them to the rule's (SSRF-validated) target and frames the replies back.
func (e *NativeEngine) serveTunnelUDP(ctx context.Context, inst *nativeRuleInstance, tunnelConn net.Conn) {
	rAddr, err := e.resolveSafeUDP(inst, inst.spec.Targets[0].Address)
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

	go func() {
		defer tunnelConn.Close()
		rBuf := make([]byte, maxUDPFrameSize)
		for {
			_ = upConn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			rn, _, rErr := upConn.ReadFromUDP(rBuf)
			if rErr != nil {
				return
			}
			if inst.tracker.Limiter != nil {
				_ = inst.tracker.Limiter.WaitN(ctx, rn)
			}
			if tunnel.WritePacket(rBuf[:rn]) != nil {
				return
			}
			inst.tracker.AddDownload(int64(rn))
		}
	}()

	buf := make([]byte, maxUDPFrameSize)
	for {
		n, rErr := tunnel.ReadPacket(buf)
		if rErr != nil {
			return
		}
		if inst.tracker.Limiter != nil {
			_ = inst.tracker.Limiter.WaitN(ctx, n)
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
