package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"nexus-panel/internal/agent/limiter"
	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// CustomTunnelWrapper allows plugging in a self-developed encryption/obfuscation stream layer
// on top of net.Conn when spec.Tunnel.Transport == "custom".
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
}

// NativeEngine implements EngineDriver in pure Go with zero external binary dependencies.
// It also serves as the base framework for self-developed tunnel protocols.
type NativeEngine struct {
	mu            sync.RWMutex
	policy        security.Policy
	connGuard     *security.IPConnGuard
	rules         map[string]*nativeRuleInstance
	serverTLSConf *tls.Config
	customWrapper CustomTunnelWrapper
}

// NewNativeEngine creates a ready-to-use NativeEngine with ephemeral self-signed TLS certs for tunnel encryption.
func NewNativeEngine(policies ...security.Policy) *NativeEngine {
	pol := security.DefaultPolicy
	if len(policies) > 0 {
		pol = policies[0]
	}
	tlsCfg, _ := generateSelfSignedTLSConfig()
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

func (e *NativeEngine) Name() protocol.EngineType {
	return protocol.EngineNative
}

func (e *NativeEngine) Available() bool {
	return true // Always available on all platforms
}

func (e *NativeEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	key := RuleKey(spec.RuleID, spec.Role)

	// Stop existing instance if updating
	_ = e.RemoveRule(key, spec.RuleID, spec.Role)

	if len(spec.Targets) == 0 {
		return fmt.Errorf("rule %s has no targets configured", key)
	}

	ruleCtx, cancel := context.WithCancel(ctx)
	inst := &nativeRuleInstance{
		key:     key,
		spec:    spec,
		cancel:  cancel,
		tracker: limiter.NewRuleStatsTracker(spec.SpeedLimitMbps),
	}

	listenHost := spec.ListenHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	bindAddr := fmt.Sprintf("%s:%d", listenHost, spec.ListenPort)

	// Start TCP listener if protocol is tcp or both
	if spec.Protocol == "tcp" || spec.Protocol == "both" || spec.Protocol == "" {
		var ln net.Listener
		var err error
		if spec.Role == protocol.RoleEgress && spec.Tunnel != nil && spec.Tunnel.Transport == "tls" && e.serverTLSConf != nil {
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

	// Start UDP relay if protocol is udp or both
	if spec.Protocol == "udp" || spec.Protocol == "both" {
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

	// If Egress role, enforce HMAC pre-shared key tunnel authentication to block port scanners & traffic theft
	if inst.spec.Role == protocol.RoleEgress && inst.spec.Tunnel != nil && inst.spec.Tunnel.SecretKey != "" {
		if err := security.VerifyTunnelAuthHeader(clientConn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey); err != nil {
			log.Printf("[NativeEngine] Blocked unauthorized Egress connection from %s on rule #%d: %v",
				clientConn.RemoteAddr().String(), inst.spec.RuleID, err)
			return
		}
	}

	// If Egress role with custom tunnel wrapper, unwrap incoming stream
	if inst.spec.Role == protocol.RoleEgress && inst.spec.Tunnel != nil && inst.spec.Tunnel.Transport == "custom" && e.customWrapper != nil {
		wrapped, err := e.customWrapper.WrapServerConn(clientConn, inst.spec.Tunnel)
		if err != nil {
			return
		}
		clientConn = wrapped
	}

	targetConn, err := e.dialUpstream(ctx, inst)
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
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// Download direction: upstream -> client
	go func() {
		defer wg.Done()
		_ = limiter.CopyWithStats(ctx, clientConn, targetConn, inst.tracker.Limiter, &inst.tracker.DownBytes)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (e *NativeEngine) dialUpstream(ctx context.Context, inst *nativeRuleInstance) (net.Conn, error) {
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

		conn := rawConn
		// If Ingress role with TLS tunnel transport, wrap the verified TCP socket in TLS
		if inst.spec.Role == protocol.RoleIngress && inst.spec.Tunnel != nil && inst.spec.Tunnel.Transport == "tls" {
			sni := inst.spec.Tunnel.SNI
			if sni == "" {
				sni = "nexus-tunnel.internal"
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				lastErr = err
				continue
			}
			conn = tlsConn
		}

		// If Ingress role with custom self-developed tunnel protocol
		if inst.spec.Role == protocol.RoleIngress && inst.spec.Tunnel != nil && inst.spec.Tunnel.Transport == "custom" && e.customWrapper != nil {
			wrapped, wErr := e.customWrapper.WrapClientConn(conn, inst.spec.Tunnel)
			if wErr != nil {
				_ = conn.Close()
				lastErr = wErr
				continue
			}
			conn = wrapped
		}

		// If Ingress role, write HMAC pre-shared key tunnel auth header to authenticate with Egress
		if inst.spec.Role == protocol.RoleIngress && inst.spec.Tunnel != nil && inst.spec.Tunnel.SecretKey != "" {
			if err := security.WriteTunnelAuthHeader(conn, inst.spec.RuleID, inst.spec.Tunnel.SecretKey); err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
		}

		return conn, nil
	}
	return nil, lastErr
}

func (e *NativeEngine) serveUDP(ctx context.Context, inst *nativeRuleInstance) {
	type udpSession struct {
		upstream *net.UDPConn
		lastSeen int64
	}
	const maxUDPSessions = 2048
	var sessions sync.Map
	var sessionCount int64
	allowPrivate := e.policy.AllowPrivateTargets || (inst.spec.Role == protocol.RoleIngress)
	buf := make([]byte, 65535)

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

		clientKey := clientAddr.String()
		val, ok := sessions.Load(clientKey)
		var sess *udpSession
		if !ok {
			if atomic.LoadInt64(&sessionCount) >= maxUDPSessions {
				continue
			}
			targetAddrStr := inst.spec.Targets[0].Address
			rAddr, err := net.ResolveUDPAddr("udp", targetAddrStr)
			if err != nil {
				continue
			}
			// Enforce Anti-SSRF & Anti-DNS-Rebinding on resolved UDP IP
			if err := security.ValidateResolvedIP(rAddr.IP, allowPrivate); err != nil {
				log.Printf("[NativeEngine] Blocked unsafe UDP target IP %s on rule %s: %v", rAddr.IP.String(), inst.key, err)
				continue
			}
			upConn, err := net.DialUDP("udp", nil, rAddr)
			if err != nil {
				continue
			}
			sess = &udpSession{upstream: upConn, lastSeen: time.Now().Unix()}
			sessions.Store(clientKey, sess)
			atomic.AddInt64(&sessionCount, 1)

			go func(cAddr *net.UDPAddr, s *udpSession, key string) {
				defer func() {
					_ = s.upstream.Close()
					sessions.Delete(key)
					atomic.AddInt64(&sessionCount, -1)
				}()
				rBuf := make([]byte, 65535)
				for {
					_ = s.upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, _, rErr := s.upstream.ReadFromUDP(rBuf)
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

		_, _ = sess.upstream.Write(buf[:n])
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

func generateSelfSignedTLSConfig() (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nexus-tunnel.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour * 10),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
