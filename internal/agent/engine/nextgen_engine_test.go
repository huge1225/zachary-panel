package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

func pickFreeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func makeSelfSignedBackendTLS(t *testing.T, dnsName string) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// 1. Multi-Hop Chain (Ingress -> Hop_0 -> Hop_1 -> Egress -> Backend) with PROXY Protocol v2 & UDP-over-Chain
func TestMultiHopChainTCPAndUDPWithProxyProtoV2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pol := security.Policy{AllowPrivateTargets: true, MinListenPort: 1024, MaxListenPort: 65535, MaxConnsPerClientIP: 128}
	certHop0, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certHop1, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certEgress, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certRogue, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	engIn := NewNativeEngine(pol, nil)
	engHop0 := NewNativeEngine(pol, certHop0)
	engHop1 := NewNativeEngine(pol, certHop1)
	engEg := NewNativeEngine(pol, certEgress)
	defer engIn.Close()
	defer engHop0.Close()
	defer engHop1.Close()
	defer engEg.Close()

	// Backend TCP server expecting PROXY Protocol v2 header + payload
	tcpBackend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpBackend.Close()
	go func() {
		for {
			c, err := tcpBackend.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				ver, srcAddr, _, pErr := ParseProxyProtocolHeader(br)
				if pErr != nil {
					return
				}
				msg, _ := br.ReadString('\n')
				_, _ = fmt.Fprintf(conn, "v=%d|src=%s|echo=%s", ver, srcAddr, msg)
			}(c)
		}
	}()

	// Backend UDP echo server on the same port as TCP backend? Let's bind UDP on the exact same port so Targets[0] serves "both"!
	targetPort := tcpBackend.Addr().(*net.TCPAddr).Port
	udpBackend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: targetPort})
	if err != nil {
		t.Fatal(err)
	}
	defer udpBackend.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := udpBackend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpBackend.WriteToUDP([]byte("udp4hop:"+string(buf[:n])), raddr)
		}
	}()

	pIn := pickFreeTestPort(t)
	pHop0 := pickFreeTestPort(t)
	pHop1 := pickFreeTestPort(t)
	pEg := pickFreeTestPort(t)
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Apply downstream -> upstream: Egress -> Hop1 -> Hop0 -> Ingress
	if err := engEg.ApplyRule(ctx, protocol.RuleSpec{
		RuleID:     77,
		Role:       protocol.RoleEgress,
		Engine:     protocol.EngineNative,
		Protocol:   "both",
		ListenHost: "127.0.0.1",
		ListenPort: pEg,
		Targets:    []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", targetPort)}},
		ProxyProto: 2,
		Tunnel:     &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, ProxyProto: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engHop1.ApplyRule(ctx, protocol.RuleSpec{
		RuleID:     77,
		Role:       protocol.RoleHop(1),
		Engine:     protocol.EngineNative,
		Protocol:   "both",
		ListenHost: "127.0.0.1",
		ListenPort: pHop1,
		Targets:    []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", pEg), CertPEM: certEgress.CertPEM}},
		ProxyProto: 2,
		Tunnel:     &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, ProxyProto: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engHop0.ApplyRule(ctx, protocol.RuleSpec{
		RuleID:     77,
		Role:       protocol.RoleHop(0),
		Engine:     protocol.EngineNative,
		Protocol:   "both",
		ListenHost: "127.0.0.1",
		ListenPort: pHop0,
		Targets:    []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", pHop1), CertPEM: certHop1.CertPEM}},
		ProxyProto: 2,
		Tunnel:     &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, ProxyProto: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engIn.ApplyRule(ctx, protocol.RuleSpec{
		RuleID:     77,
		Role:       protocol.RoleIngress,
		Engine:     protocol.EngineNative,
		Protocol:   "both",
		ListenHost: "127.0.0.1",
		ListenPort: pIn,
		Targets:    []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", pHop0), CertPEM: certHop0.CertPEM}},
		OutboundIP: "127.0.0.1",
		ProxyProto: 2,
		Tunnel:     &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, ProxyProto: 2},
	}); err != nil {
		t.Fatal(err)
	}

	// Verify TCP over 4-node chain + authentic original client IP:Port preserved via PROXY Protocol v2!
	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pIn), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	expectedClientAddr := clientConn.LocalAddr().String()
	_, _ = clientConn.Write([]byte("hello-multihop\n"))
	reply, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("v=2|src=%s|echo=hello-multihop\n", expectedClientAddr)
	if string(reply) != want {
		t.Fatalf("multi-hop TCP PROXY v2 mismatch:\ngot:  %q\nwant: %q", string(reply), want)
	}

	// Verify UDP datagram over the same 4-node encrypted chain!
	uCli, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: pIn})
	if err != nil {
		t.Fatal(err)
	}
	defer uCli.Close()
	_, _ = uCli.Write([]byte("ping-udp"))
	_ = uCli.SetReadDeadline(time.Now().Add(3 * time.Second))
	uBuf := make([]byte, 256)
	un, err := uCli.Read(uBuf)
	if err != nil {
		t.Fatalf("multi-hop UDP failed: %v", err)
	}
	if string(uBuf[:un]) != "udp4hop:ping-udp" {
		t.Fatalf("unexpected UDP reply: %q", string(uBuf[:un]))
	}

	// Security check: pinning wrong hop certificate on Hop0 -> Hop1 must fail closed!
	if err := engHop0.ApplyRule(ctx, protocol.RuleSpec{
		RuleID:     77,
		Role:       protocol.RoleHop(0),
		Engine:     protocol.EngineNative,
		Protocol:   "tcp",
		ListenHost: "127.0.0.1",
		ListenPort: pHop0,
		Targets:    []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", pHop1), CertPEM: certRogue.CertPEM}},
		Tunnel:     &protocol.TunnelConfig{Transport: "tls", SecretKey: secret},
	}); err != nil {
		t.Fatal(err)
	}
	badConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pIn), 2*time.Second)
	if err == nil {
		_ = badConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, _ = badConn.Write([]byte("should-fail\n"))
		gotBad, _ := io.ReadAll(badConn)
		_ = badConn.Close()
		if len(gotBad) > 0 {
			t.Fatalf("expected MITM/rogue hop cert to fail closed, got %q", string(gotBad))
		}
	}
}

// 2. Bandwidth Aggregation: EnableMux (40 concurrent streams) & EnableBonding (4-link 512 KiB striped SHA-256) & Multi-Egress Failover
func TestMuxPoolAndBondedSingleStreamAndMultiEgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pol := security.Policy{AllowPrivateTargets: true, MinListenPort: 1024, MaxListenPort: 65535, MaxConnsPerClientIP: 256}
	certEg1, _ := security.LoadOrCreateTunnelCert(t.TempDir())
	certEg2, _ := security.LoadOrCreateTunnelCert(t.TempDir())

	engIn := NewNativeEngine(pol, nil)
	engEg1 := NewNativeEngine(pol, certEg1)
	engEg2 := NewNativeEngine(pol, certEg2)
	defer engIn.Close()
	defer engEg1.Close()
	defer engEg2.Close()

	// Echo backend that reads until EOF, computes length + SHA256 or echoes exact bytes back
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	var backendHits int64
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&backendHits, 1)
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	pEg1 := pickFreeTestPort(t)
	pEg2 := pickFreeTestPort(t)
	pMuxIn := pickFreeTestPort(t)
	pBondIn := pickFreeTestPort(t)
	secret := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	for _, item := range []struct {
		eng  *NativeEngine
		port int
		id   uint64
	}{
		{engEg1, pEg1, 88},
		{engEg2, pEg2, 88},
		{engEg1, pickFreeTestPort(t), 89},
	} {
		_ = item
	}

	if err := engEg1.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 88, Role: protocol.RoleEgress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: pEg1,
		Targets: []protocol.TargetEndpoint{{Address: echoLn.Addr().String()}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, EnableMux: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engEg2.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 88, Role: protocol.RoleEgress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: pEg2,
		Targets: []protocol.TargetEndpoint{{Address: echoLn.Addr().String()}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, EnableMux: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Multi-Egress weighted + EnableMux pool across TWO distinct Egress nodes (with distinct pinned certs!)
	if err := engIn.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 88, Role: protocol.RoleIngress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: pMuxIn, LoadBalance: "weighted",
		Targets: []protocol.TargetEndpoint{
			{Address: fmt.Sprintf("127.0.0.1:%d", pEg1), Weight: 200, CertPEM: certEg1.CertPEM},
			{Address: fmt.Sprintf("127.0.0.1:%d", pEg2), Weight: 100, CertPEM: certEg2.CertPEM},
		},
		Tunnel: &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, EnableMux: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Fire 32 concurrent streams over EnableMux + Multi-Egress
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pMuxIn), 3*time.Second)
			if dErr != nil {
				errCh <- dErr
				return
			}
			defer c.Close()
			payload := bytes.Repeat([]byte(fmt.Sprintf("mux-stream-%02d|", idx)), 512)
			if _, wErr := c.Write(payload); wErr != nil {
				errCh <- wErr
				return
			}
			_ = c.(*net.TCPConn).CloseWrite()
			got, rErr := io.ReadAll(c)
			if rErr != nil {
				errCh <- rErr
				return
			}
			if !bytes.Equal(got, payload) {
				errCh <- fmt.Errorf("mux stream %d payload mismatch (got %d want %d)", idx, len(got), len(payload))
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatalf("mux concurrent test error: %v", e)
	}

	// Verify automatic Multi-Egress Failover when Eg1 is stopped!
	_ = engEg1.Close()
	cFailover, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pMuxIn), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cFailover.Write([]byte("survived-egress1-outage"))
	_ = cFailover.(*net.TCPConn).CloseWrite()
	gotFO, err := io.ReadAll(cFailover)
	_ = cFailover.Close()
	if err != nil || string(gotFO) != "survived-egress1-outage" {
		t.Fatalf("multi-egress failover failed: err=%v got=%q", err, string(gotFO))
	}

	// Now test EnableBonding (4-link chunk-striped single stream carrying 512 KiB random data)
	pEgBond := pickFreeTestPort(t)
	if err := engEg2.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 89, Role: protocol.RoleEgress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: pEgBond,
		Targets: []protocol.TargetEndpoint{{Address: echoLn.Addr().String()}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, EnableBonding: true, BondLinks: 4},
	}); err != nil {
		t.Fatal(err)
	}
	if err := engIn.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 89, Role: protocol.RoleIngress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: pBondIn,
		Targets: []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", pEgBond), CertPEM: certEg2.CertPEM}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: secret, EnableBonding: true, BondLinks: 4},
	}); err != nil {
		t.Fatal(err)
	}

	bigBlob := make([]byte, 512*1024) // 512 KiB = 32 chunks striped across 4 parallel TLS links!
	if _, err := rand.Read(bigBlob); err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(bigBlob)

	bCli, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pBondIn), 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer bCli.Close()
	go func() {
		_, _ = bCli.Write(bigBlob)
		_ = bCli.(*net.TCPConn).CloseWrite()
	}()
	echoedBlob, err := io.ReadAll(bCli)
	if err != nil {
		t.Fatalf("bonded stream read failed: %v", err)
	}
	gotSum := sha256.Sum256(echoedBlob)
	if gotSum != wantSum {
		t.Fatalf("bonded 4-link 512KiB SHA-256 mismatch (len=%d)", len(echoedBlob))
	}
}

// 3. Shared-Port Non-Decrypting TLS ClientHello SNI & HTTP Host Demux Router + Overlap Protection
func TestSharedPortSNIAndHTTPHostRouting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pol := security.Policy{AllowPrivateTargets: true, MinListenPort: 1024, MaxListenPort: 65535, MaxConnsPerClientIP: 128}
	eng := NewNativeEngine(pol, nil)
	defer eng.Close()

	// Backend 1: End-to-end TLS server for app1.example.com (router never decrypts TLS!)
	tlsConf1 := makeSelfSignedBackendTLS(t, "app1.example.com")
	lnTLS1, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf1)
	if err != nil {
		t.Fatal(err)
	}
	defer lnTLS1.Close()
	go func() {
		for {
			c, err := lnTLS1.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("TLS-BACKEND-1"))
			}(c)
		}
	}()

	// Backend 2: Plain HTTP server for *.tenant2.example.com
	lnHTTP2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnHTTP2.Close()
	go func() {
		for {
			c, err := lnHTTP2.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				_, _ = br.ReadString('\n')
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nHTTP-BACKEND-2"))
			}(c)
		}
	}()

	sharedPort := pickFreeTestPort(t)

	// Rule 101 & Rule 102 share the EXACT SAME ListenPort!
	if err := eng.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 101, Role: protocol.RoleRelay, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: sharedPort, MatchDomains: "app1.example.com",
		Targets: []protocol.TargetEndpoint{{Address: lnTLS1.Addr().String()}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := eng.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 102, Role: protocol.RoleRelay, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: sharedPort, MatchDomains: "*.tenant2.example.com",
		Targets: []protocol.TargetEndpoint{{Address: lnHTTP2.Addr().String()}},
	}); err != nil {
		t.Fatal(err)
	}

	// Overlapping domain on the same shared port MUST be rejected!
	if err := eng.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 103, Role: protocol.RoleRelay, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: sharedPort, MatchDomains: "api.tenant2.example.com",
		Targets: []protocol.TargetEndpoint{{Address: lnHTTP2.Addr().String()}},
	}); err == nil {
		t.Fatal("expected overlapping domain api.tenant2.example.com against *.tenant2.example.com to be rejected")
	}

	// Test 1: Real TLS ClientHello with ServerName "app1.example.com" -> routed to TLS Backend 1 without MITM!
	tlsCli, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sharedPort), &tls.Config{
		ServerName:         "app1.example.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("SNI TLS dial failed: %v", err)
	}
	if tlsCli.ConnectionState().PeerCertificates[0].Subject.CommonName != "app1.example.com" {
		t.Fatalf("unexpected backend TLS cert CN: %s", tlsCli.ConnectionState().PeerCertificates[0].Subject.CommonName)
	}
	b1Out, _ := io.ReadAll(tlsCli)
	_ = tlsCli.Close()
	if string(b1Out) != "TLS-BACKEND-1" {
		t.Fatalf("expected TLS-BACKEND-1, got %q", string(b1Out))
	}

	// Test 2: HTTP request with Host: portal.tenant2.example.com -> routed to HTTP Backend 2!
	httpCli, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sharedPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = httpCli.Write([]byte("GET / HTTP/1.1\r\nHost: portal.tenant2.example.com:8443\r\nConnection: close\r\n\r\n"))
	b2Out, _ := io.ReadAll(httpCli)
	_ = httpCli.Close()
	if !strings.HasSuffix(string(b2Out), "HTTP-BACKEND-2") {
		t.Fatalf("expected HTTP-BACKEND-2, got %q", string(b2Out))
	}

	// Test 3: Unmatched SNI / Host is dropped cleanly
	unmatchedCli, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sharedPort), 2*time.Second)
	if err == nil {
		_, _ = unmatchedCli.Write([]byte("GET / HTTP/1.1\r\nHost: unknown.invalid\r\n\r\n"))
		_ = unmatchedCli.SetReadDeadline(time.Now().Add(1 * time.Second))
		uOut, _ := io.ReadAll(unmatchedCli)
		_ = unmatchedCli.Close()
		if len(uOut) > 0 {
			t.Fatalf("expected empty response for unmatched Host, got %q", string(uOut))
		}
	}
}

func TestNftablesOutboundIPSNATScript(t *testing.T) {
	rules := []nftResolvedRule{{
		key:     "12:relay",
		spec:    protocol.RuleSpec{RuleID: 12, Role: protocol.RoleRelay, Protocol: "both", ListenPort: 25000, OutboundIP: "198.51.100.25"},
		dstIP:   "1.1.1.1",
		dstPort: 443,
	}}
	script := buildNftForwardScript(rules, nftCounterState{})
	if !strings.Contains(script, "snat ip to 198.51.100.25") {
		t.Fatalf("expected snat ip to 198.51.100.25 in nftables script:\n%s", script)
	}
}

func TestNextGenDataPlaneSecurityHardening(t *testing.T) {
	// 1. PROXY v1 oversized header without newline must fail at <= 108 bytes without reading remaining stream
	oversized := append([]byte("PROXY TCP4 "), bytes.Repeat([]byte("A"), 4096)...)
	br := bufio.NewReaderSize(bytes.NewReader(oversized), 64)
	if _, _, _, err := ParseProxyProtocolHeader(br); err == nil {
		t.Fatalf("expected error on oversized newline-free PROXY v1 header")
	}
	// Invalid IP / port in PROXY v1 must fail
	badIP := bufio.NewReader(strings.NewReader("PROXY TCP4 not_an_ip 1.1.1.1 1234 443\r\n"))
	if _, _, _, err := ParseProxyProtocolHeader(badIP); err == nil {
		t.Fatalf("expected error on invalid PROXY v1 IP")
	}
	badPort := bufio.NewReader(strings.NewReader("PROXY TCP4 203.0.113.5 1.1.1.1 99999 443\r\n"))
	if _, _, _, err := ParseProxyProtocolHeader(badPort); err == nil {
		t.Fatalf("expected error on out-of-range PROXY v1 port")
	}

	// 2. ValidateOutboundIP must block IPv6-embedded loopback (NAT64 / 6to4) when allowPrivate=false
	for _, tricky := range []string{"127.0.0.1", "169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		if _, err := security.ValidateOutboundIP(tricky, false); err == nil {
			t.Fatalf("expected ValidateOutboundIP(%q, false) to fail", tricky)
		}
	}

	// 3. 6-link bondedConn heavy out-of-order backpressure (> 64 chunks) + truncated member link EOF must never deadlock
	const links = 6
	cA := make([]net.Conn, links)
	cB := make([]net.Conn, links)
	for i := 0; i < links; i++ {
		cA[i], cB[i] = net.Pipe()
	}
	bondSend := newBondedConn(cA)
	bondRecv := newBondedConn(cB)
	defer bondSend.Close()
	defer bondRecv.Close()

	// Send 3 MiB (~192 chunks > 64 reorder window across 6 links) before draining to stress spaceCond.Broadcast()
	payload := make([]byte, 3*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := bondSend.Write(payload)
		if err == nil {
			err = bondSend.CloseWrite()
		}
		writeDone <- err
	}()
	time.Sleep(40 * time.Millisecond) // allow multiple linkReaders to block on spaceCond.Wait()
	_ = bondRecv.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(bondRecv)
	if err != nil {
		t.Fatalf("6-link bonded backpressure read failed: %v", err)
	}
	if wErr := <-writeDone; wErr != nil {
		t.Fatalf("6-link bonded write failed: %v", wErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("6-link bonded payload mismatch (got %d want %d)", len(got), len(payload))
	}

	// Truncated member link EOF after faster links delivered FIN must not hang Read()
	tA0, tB0 := net.Pipe()
	tA1, tB1 := net.Pipe()
	truncRecv := newBondedConn([]net.Conn{tB0, tB1})
	defer truncRecv.Close()
	go func() {
		// Link 0 delivers FIN(seq=2) cleanly while Link 1 closes abruptly without delivering seq=0..1!
		var finHdr [bondChunkHeaderSize]byte
		finHdr[0] = bondFlagFIN
		finHdr[8] = 2
		_, _ = tA0.Write(finHdr[:])
		_ = tA0.Close()
		_ = tA1.Close()
	}()
	_ = truncRecv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	_, truncErr := truncRecv.Read(buf)
	if truncErr != io.EOF {
		t.Fatalf("expected prompt EOF on truncated member link, got %v", truncErr)
	}

	// 4. GostEngine per-target CA pinning & IPv6 listenHost formatting
	cert1, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ge := NewGostEngine(t.TempDir(), cert1)
	cfgBytes, err := ge.buildGostConfig(protocol.RuleSpec{
		RuleID:     99,
		Role:       protocol.RoleIngress,
		ListenHost: "2001:db8::10",
		ListenPort: 28080,
		Targets: []protocol.TargetEndpoint{
			{Address: "[2001:db8::20]:31001", CertPEM: cert1.CertPEM},
			{Address: "[2001:db8::30]:31002", CertPEM: cert2.CertPEM},
		},
		Tunnel: &protocol.TunnelConfig{Transport: "tls", SecretKey: "s"},
	}, []string{"/tmp/ca-0.pem", "/tmp/ca-1.pem"})
	if err != nil {
		t.Fatalf("buildGostConfig failed: %v", err)
	}
	cfgStr := string(cfgBytes)
	if !strings.Contains(cfgStr, `"[2001:db8::10]:28080"`) || !strings.Contains(cfgStr, `"/tmp/ca-0.pem"`) || !strings.Contains(cfgStr, `"/tmp/ca-1.pem"`) {
		t.Fatalf("unexpected gost config output:\n%s", cfgStr)
	}
}
