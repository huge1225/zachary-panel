package security

import (
	"context"
	"io"
	"net"
	"testing"

	"nexus-panel/pkg/protocol"
)

// captureHeader writes a valid tunnel auth header through a pipe and returns the raw bytes.
func captureHeader(t *testing.T, ruleID uint64, secret string, mode byte) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	errCh := make(chan error, 1)
	go func() { errCh <- WriteTunnelAuthHeader(a, ruleID, secret, mode) }()
	buf := make([]byte, TunnelAuthHeaderSize)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read header: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write header: %v", err)
	}
	return buf
}

func verifyRaw(t *testing.T, raw []byte, ruleID uint64, secret string) (byte, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _, _ = a.Write(raw) }()
	return VerifyTunnelAuthHeader(b, ruleID, secret)
}

func TestTunnelAuthAcceptAndReplay(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	raw := captureHeader(t, 7, secret, TunnelModeUDP)

	mode, err := verifyRaw(t, raw, 7, secret)
	if err != nil || mode != TunnelModeUDP {
		t.Fatalf("expected valid header, got mode=%d err=%v", mode, err)
	}
	if _, err := verifyRaw(t, raw, 7, secret); err == nil {
		t.Fatal("replayed header must be rejected")
	}
}

func TestTunnelAuthWrongSecretOrRule(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	raw := captureHeader(t, 9, secret, TunnelModeTCP)
	if _, err := verifyRaw(t, raw, 9, "another-secret-another-secret-00"); err == nil {
		t.Fatal("wrong secret must be rejected")
	}
	raw2 := captureHeader(t, 9, secret, TunnelModeTCP)
	if _, err := verifyRaw(t, raw2, 10, secret); err == nil {
		t.Fatal("header for another rule must be rejected")
	}
	// tampered mode byte
	raw3 := captureHeader(t, 9, secret, TunnelModeTCP)
	raw3[24] = TunnelModeUDP
	if _, err := verifyRaw(t, raw3, 9, secret); err == nil {
		t.Fatal("tampered mode must be rejected")
	}
}

func TestValidateTargetAddressBlocksInternal(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:22", "[::1]:80", "0.0.0.0:80", "192.168.1.1:443"} {
		if err := ValidateTargetAddress(addr, false); err == nil {
			t.Errorf("%s should be blocked", addr)
		}
	}
	if err := ValidateTargetAddress("8.8.8.8:53", false); err != nil {
		t.Errorf("public IP should be allowed: %v", err)
	}
	if err := ValidateTargetAddress("127.0.0.1:80", true); err != nil {
		t.Errorf("private allowed when policy permits: %v", err)
	}
}

func TestResolveTargetsBlocksLocalhostName(t *testing.T) {
	_, err := ResolveTargets(context.Background(), []protocol.TargetEndpoint{{Address: "localhost:80"}}, false)
	if err == nil {
		t.Fatal("hostname resolving to loopback must be blocked")
	}
	out, err := ResolveTargets(context.Background(), []protocol.TargetEndpoint{{Address: "localhost:80"}}, true)
	if err != nil {
		t.Fatalf("allowed with private policy: %v", err)
	}
	host, _, _ := net.SplitHostPort(out[0].Address)
	if net.ParseIP(host) == nil {
		t.Fatalf("target must be pinned to literal IP, got %s", out[0].Address)
	}
}

func TestValidateListenPort(t *testing.T) {
	if err := ValidateListenPort(22, DefaultPolicy); err == nil {
		t.Error("privileged port must be rejected")
	}
	if err := ValidateListenPort(70000, DefaultPolicy); err == nil {
		t.Error("out-of-range port must be rejected")
	}
	if err := ValidateListenPort(20000, DefaultPolicy); err != nil {
		t.Errorf("valid port rejected: %v", err)
	}
}

func TestTunnelCertPersistAndPin(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreateTunnelCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreateTunnelCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c1.CertPEM != c2.CertPEM {
		t.Fatal("certificate should be persisted and reused")
	}
	if err := ValidateTunnelCertPEM(c1.CertPEM); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if err := ValidateTunnelCertPEM("garbage"); err == nil {
		t.Fatal("garbage cert must be rejected")
	}
	if _, err := TunnelClientTLSConfig(""); err == nil {
		t.Fatal("empty pinned cert must fail closed")
	}
}

func TestEmbeddedIPv4Blocked(t *testing.T) {
	for _, a := range []string{"[64:ff9b::7f00:1]:80", "[64:ff9b::a9fe:a9fe]:80", "[2002:a00:1::1]:80", "[::127.0.0.1]:80", "[64:ff9b:1::1]:80", "[2001::1]:80"} {
		if err := ValidateTargetAddress(a, false); err == nil {
			t.Errorf("%s should be blocked", a)
		}
	}
	if err := ValidateTargetAddress("[64:ff9b::808:808]:53", false); err != nil {
		t.Errorf("NAT64 of a public IPv4 should be allowed: %v", err)
	}
	if err := ValidateTargetAddress("[2606:4700:4700::1111]:53", false); err != nil {
		t.Errorf("public IPv6 should be allowed: %v", err)
	}
}

// NEW-C: targets resolving to the node's own interface addresses are blocked unless private targets are allowed.
func TestLocalInterfaceTargetBlocked(t *testing.T) {
	orig := localInterfaceAddrs
	defer func() {
		localInterfaceAddrs = orig
		localAddrCache.mu.Lock()
		localAddrCache.addrs = nil
		localAddrCache.mu.Unlock()
	}()
	localInterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("8.8.4.4"), Mask: net.CIDRMask(32, 32)}}, nil
	}
	localAddrCache.mu.Lock()
	localAddrCache.addrs = nil
	localAddrCache.mu.Unlock()
	if err := ValidateResolvedIP(net.ParseIP("8.8.4.4"), false); err == nil {
		t.Fatal("node's own address must be rejected")
	}
	if err := ValidateResolvedIP(net.ParseIP("8.8.4.4"), true); err != nil {
		t.Fatalf("allowPrivate must permit own address: %v", err)
	}
	if err := ValidateResolvedIP(net.ParseIP("8.8.8.8"), false); err != nil {
		t.Fatalf("other public address rejected: %v", err)
	}
}
