package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := l.Addr().(*net.TCPAddr).Port
	// make sure the UDP port is free too
	u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		return freePort(t)
	}
	u.Close()
	return p
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteTo(buf[:n], addr)
		}
	}()
	return c.LocalAddr().String()
}

var testPolicy = security.Policy{AllowPrivateTargets: true, MinListenPort: 1024, MaxListenPort: 65535, MaxConnsPerClientIP: 64}

const testSecret = "0123456789abcdef0123456789abcdef"

func tcpRoundTrip(addr string, msg string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func udpRoundTrip(addr string, msg string) (string, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	buf := make([]byte, 2048)
	for i := 0; i < 5; i++ { // UDP is lossy while the tunnel is being established; retry a few times
		_ = c.SetDeadline(time.Now().Add(1 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			return "", err
		}
		n, err := c.Read(buf)
		if err == nil {
			return string(buf[:n]), nil
		}
	}
	return "", fmt.Errorf("no udp reply")
}

func setupTunnel(t *testing.T, ingressCertPEM string) (ingressPort int, egressEng, ingressEng *NativeEngine) {
	t.Helper()
	tcpEcho := startTCPEcho(t)
	udpEcho := startUDPEcho(t)
	_ = udpEcho

	cert, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if ingressCertPEM == "" {
		ingressCertPEM = cert.CertPEM
	}
	egressEng = NewNativeEngine(testPolicy, cert)
	ingressEng = NewNativeEngine(testPolicy, nil)
	t.Cleanup(func() { egressEng.Close(); ingressEng.Close() })

	relayPort := freePort(t)
	ctx := context.Background()
	// Egress forwards TCP to tcpEcho; UDP datagrams go to the same host:port number on UDP, so use separate rules.
	err = egressEng.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 1, Name: "eg", Role: protocol.RoleEgress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: relayPort,
		Targets: []protocol.TargetEndpoint{{Address: tcpEcho}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	ingressPort = freePort(t)
	err = ingressEng.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 1, Name: "in", Role: protocol.RoleIngress, Engine: protocol.EngineNative, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: ingressPort,
		Targets: []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", relayPort)}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret, CertPEM: ingressCertPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestNativeTunnelTCP(t *testing.T) {
	port, egress, ingress := setupTunnel(t, "")
	got, err := tcpRoundTrip(fmt.Sprintf("127.0.0.1:%d", port), "hello-tunnel")
	if err != nil || got != "hello-tunnel" {
		t.Fatalf("tunnel round trip failed: %q %v", got, err)
	}
	time.Sleep(100 * time.Millisecond)
	var total int64
	for _, d := range ingress.CollectDeltas() {
		total += d.UploadBytes + d.DownBytes
	}
	if total <= 0 {
		t.Fatalf("ingress traffic not accounted")
	}
	_ = egress
}

func TestNativeTunnelRejectsWrongCert(t *testing.T) {
	other, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	port, _, _ := setupTunnel(t, other.CertPEM)
	if got, err := tcpRoundTrip(fmt.Sprintf("127.0.0.1:%d", port), "x"); err == nil {
		t.Fatalf("tunnel with unpinned cert must fail, got %q", got)
	}
}

func TestNativeIngressRequiresCert(t *testing.T) {
	eng := NewNativeEngine(testPolicy, nil)
	defer eng.Close()
	err := eng.ApplyRule(context.Background(), protocol.RuleSpec{
		RuleID: 2, Role: protocol.RoleIngress, Protocol: "tcp", ListenHost: "127.0.0.1", ListenPort: freePort(t),
		Targets: []protocol.TargetEndpoint{{Address: "127.0.0.1:9"}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret},
	})
	if err == nil {
		t.Fatal("ingress without pinned cert must fail closed")
	}
}

func TestNativeTunnelUDP(t *testing.T) {
	udpEcho := startUDPEcho(t)
	cert, err := security.LoadOrCreateTunnelCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	egress := NewNativeEngine(testPolicy, cert)
	ingress := NewNativeEngine(testPolicy, nil)
	defer egress.Close()
	defer ingress.Close()
	relayPort, inPort := freePort(t), freePort(t)
	ctx := context.Background()
	if err := egress.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 3, Role: protocol.RoleEgress, Protocol: "udp", ListenHost: "127.0.0.1", ListenPort: relayPort,
		Targets: []protocol.TargetEndpoint{{Address: udpEcho}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ingress.ApplyRule(ctx, protocol.RuleSpec{
		RuleID: 3, Role: protocol.RoleIngress, Protocol: "udp", ListenHost: "127.0.0.1", ListenPort: inPort,
		Targets: []protocol.TargetEndpoint{{Address: fmt.Sprintf("127.0.0.1:%d", relayPort)}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret, CertPEM: cert.CertPEM},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := udpRoundTrip(fmt.Sprintf("127.0.0.1:%d", inPort), "udp-over-tls")
	if err != nil || got != "udp-over-tls" {
		t.Fatalf("udp tunnel failed: %q %v", got, err)
	}
}

func TestNativeRelayBlocksPrivateTargetByDefault(t *testing.T) {
	echo := startTCPEcho(t)
	eng := NewNativeEngine(security.DefaultPolicy, nil)
	defer eng.Close()
	port := freePort(t)
	_ = eng.ApplyRule(context.Background(), protocol.RuleSpec{
		RuleID: 4, Role: protocol.RoleRelay, Protocol: "tcp", ListenHost: "127.0.0.1", ListenPort: port,
		Targets: []protocol.TargetEndpoint{{Address: echo}},
	})
	if got, err := tcpRoundTrip(fmt.Sprintf("127.0.0.1:%d", port), "x"); err == nil {
		t.Fatalf("relay to loopback must be blocked by default policy, got %q", got)
	}
}

func TestManagerForcesNativeForTunnelOnRealm(t *testing.T) {
	m, err := NewManager(t.TempDir(), testPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	echo := startTCPEcho(t)
	port := freePort(t)
	err = m.ApplyRule(context.Background(), protocol.RuleSpec{
		RuleID: 5, Role: protocol.RoleEgress, Engine: protocol.EngineRealm, Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: port,
		Targets: []protocol.TargetEndpoint{{Address: echo}},
		Tunnel:  &protocol.TunnelConfig{Transport: "tls", SecretKey: testSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e := m.BoundEngine(5, protocol.RoleEgress); e != protocol.EngineNative {
		t.Fatalf("tunnel egress on realm must be bound to native, got %s", e)
	}
	if m.TunnelCertPEM() == "" {
		t.Fatal("manager must expose tunnel cert")
	}
}
