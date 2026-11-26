package engine

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

func TestPhase1ValidateRuleSpecRoleAndListenHost(t *testing.T) {
	pol := security.DefaultPolicy
	pol.AllowPrivateTargets = true

	valid := protocol.RuleSpec{
		RuleID:     101,
		Role:       protocol.RoleRelay,
		Protocol:   "tcp",
		ListenHost: "127.0.0.1",
		ListenPort: 22001,
		Targets:    []protocol.TargetEndpoint{{Address: "127.0.0.1:8080"}},
	}
	if err := security.ValidateRuleSpec(valid, pol); err != nil {
		t.Fatalf("expected valid RuleSpec to pass, got %v", err)
	}

	badRoles := []protocol.RuleRole{
		"../../etc/cron.d/pwn",
		"relay\"\nflush ruleset\n#",
		"unknown_role",
	}
	for _, br := range badRoles {
		s := valid
		s.Role = br
		if err := security.ValidateRuleSpec(s, pol); err == nil {
			t.Fatalf("expected malicious role %q to be rejected", br)
		}
	}

	badHosts := []string{
		"localhost",
		"0.0.0.0; rm -rf /",
		"example.com",
	}
	for _, bh := range badHosts {
		s := valid
		s.ListenHost = bh
		if err := security.ValidateRuleSpec(s, pol); err == nil {
			t.Fatalf("expected non-IP ListenHost %q to be rejected", bh)
		}
	}
}

func TestPhase1UDPSessionCapsAndNoUnbilledFloodDrain(t *testing.T) {
	// Start local UDP echo target
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP echo failed: %v", err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := echoConn.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	// Reserve a free UDP listen port
	probeUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probeUDP.LocalAddr().(*net.UDPAddr).Port
	_ = probeUDP.Close()

	pol := security.DefaultPolicy
	pol.AllowPrivateTargets = true
	pol.MaxUDPSessionsPerRule = 2
	pol.MaxUDPSessionsGlobal = 3
	pol.MaxUDPSessionsPerIP = 2

	eng := NewNativeEngine(pol, nil)
	defer eng.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	spec := protocol.RuleSpec{
		RuleID:     501,
		Role:       protocol.RoleRelay,
		Engine:     protocol.EngineNative,
		Protocol:   "udp",
		ListenHost: "127.0.0.1",
		ListenPort: listenPort,
		Targets:    []protocol.TargetEndpoint{{Address: echoConn.LocalAddr().String()}},
	}
	if err := eng.ApplyRule(ctx, spec); err != nil {
		t.Fatalf("ApplyRule UDP failed: %v", err)
	}

	relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listenPort}

	openClient := func() *net.UDPConn {
		c, dErr := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, relayAddr)
		if dErr != nil {
			t.Fatalf("DialUDP failed: %v", dErr)
		}
		return c
	}

	c1 := openClient()
	defer c1.Close()
	c2 := openClient()
	defer c2.Close()

	// Sessions 1 and 2 are within cap=2 and must echo cleanly
	for idx, c := range []*net.UDPConn{c1, c2} {
		msg := []byte("hello-udp")
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("client %d write failed: %v", idx, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		reply := make([]byte, 32)
		n, err := c.Read(reply)
		if err != nil || string(reply[:n]) != "hello-udp" {
			t.Fatalf("client %d expected echo, got %q err=%v", idx, string(reply[:n]), err)
		}
	}

	if got := eng.ActiveUDPSessions(); got != 2 {
		t.Fatalf("expected 2 active UDP sessions, got %d", got)
	}

	// Drain baseline deltas from c1 and c2
	_ = eng.CollectDeltas()

	// Session 3 exceeds MaxUDPSessionsPerRule=2 (and MaxUDPSessionsPerIP=2): must be dropped AND must NOT bill upload bytes!
	c3 := openClient()
	defer c3.Close()
	floodPayload := []byte(strings.Repeat("F", 1024))
	for i := 0; i < 10; i++ {
		_, _ = c3.Write(floodPayload)
	}
	_ = c3.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	tmp := make([]byte, 64)
	if n, rErr := c3.Read(tmp); rErr == nil && n > 0 {
		t.Fatalf("expected 3rd UDP session beyond cap to be dropped, but got %d bytes", n)
	}

	if got := eng.ActiveUDPSessions(); got != 2 {
		t.Fatalf("expected active UDP sessions to remain capped at 2, got %d", got)
	}

	deltas := eng.CollectDeltas()
	for _, d := range deltas {
		if d.RuleID == 501 && d.UploadBytes > 0 {
			t.Fatalf("unaccepted flood UDP packets must NOT be charged to UploadBytes, got %d", d.UploadBytes)
		}
	}
}

func TestPhase1NftCounterPrecisionAndTransientErrorPreservation(t *testing.T) {
	// 1. Exact 64-bit integer counter parsing beyond float64 53-bit mantissa
	const exactLarge int64 = 9007199254740997 // 2^53 + 5 (loses precision if cast through float64!)
	js := `{"nftables":[{"rule":{"comment":"nexus_up:42:relay","expr":[{"counter":{"packets":100,"bytes":9007199254740997}}]}}]}`
	got := parseNftCounters([]byte(js))
	if got["nexus_up:42:relay"] != exactLarge {
		t.Fatalf("expected exact int64 counter %d, got %d", exactLarge, got["nexus_up:42:relay"])
	}

	// 2. Transient nft command failure must NOT reset lastUp/lastDown to 0
	n := NewNftablesEngine()
	n.binPath = "/nonexistent/nft-binary-for-test"
	n.rules["42:relay"] = protocol.RuleSpec{RuleID: 42, Role: protocol.RoleRelay, ListenPort: 20500}
	n.lastUp["42:relay"] = 500_000_000
	n.lastDown["42:relay"] = 800_000_000

	deltas := n.CollectDeltas()
	if len(deltas) != 0 {
		t.Fatalf("expected nil/empty deltas on transient nft error, got %+v", deltas)
	}
	if n.lastUp["42:relay"] != 500_000_000 || n.lastDown["42:relay"] != 800_000_000 {
		t.Fatalf("transient nft failure corrupted lastUp/lastDown: up=%d down=%d", n.lastUp["42:relay"], n.lastDown["42:relay"])
	}
}
