package engine

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nexus-panel/pkg/protocol"
)

func TestBuildNftForwardScript(t *testing.T) {
	rules := []nftResolvedRule{{
		key:     "7:relay",
		spec:    protocol.RuleSpec{RuleID: 7, Role: protocol.RoleRelay, Protocol: "both", ListenPort: 20000, SpeedLimitMbps: 8},
		dstIP:   "1.2.3.4",
		dstPort: 443,
	}}
	script := buildNftForwardScript(rules, nftCounterState{"nexus_up:7:relay": 5000})

	mustContain := []string{
		// DNAT only for traffic addressed to this host (no hijacking of routed / container traffic)
		"fib daddr type local tcp dport 20000 dnat ip to 1.2.3.4:443",
		"fib daddr type local udp dport 20000 dnat ip to 1.2.3.4:443",
		// per-packet accounting in a filter forward chain, split by direction
		"type filter hook forward priority filter",
		"ct direction original counter packets 0 bytes 5000 comment \"nexus_up:7:relay\"",
		"ct direction reply counter comment \"nexus_down:7:relay\"",
		// per-rule rate limit: 8 Mbps = 1000 kbytes/s
		"limit lim_up_7_relay {\n    rate over 1000 kbytes/second burst 2000 kbytes\n  }",
		"ct direction original limit name \"lim_up_7_relay\" drop",
		"ct direction reply limit name \"lim_down_7_relay\" drop",
		// stateful objects are re-created on every rebuild
		"delete table inet nexus_forward",
		// masquerade scoped to this rule's flows only
		"ct status dnat ct original proto-dst 20000 ip daddr 1.2.3.4 tcp dport 443 masquerade",
	}
	for _, m := range mustContain {
		if !strings.Contains(script, m) {
			t.Errorf("script missing %q\n%s", m, script)
		}
	}
	if n := strings.Count(script, "limit lim_up_7_relay {"); n != 1 {
		t.Errorf("tcp and udp must share one limit object per direction, got %d", n)
	}
	if strings.Contains(script, "    ct status dnat masquerade") {
		t.Error("unscoped masquerade must not be emitted")
	}
}

func TestParseNftCounters(t *testing.T) {
	js := `{"nftables":[{"metainfo":{}},{"rule":{"comment":"nexus_up:1:relay","expr":[{"match":{}},{"counter":{"packets":3,"bytes":1500}}]}},{"rule":{"comment":"nexus_down:1:relay","expr":[{"counter":{"packets":2,"bytes":900}}]}}]}`
	got := parseNftCounters([]byte(js))
	if got["nexus_up:1:relay"] != 1500 || got["nexus_down:1:relay"] != 900 {
		t.Fatalf("unexpected counters: %v", got)
	}
}

func TestProbeLocalPortFree(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if err := probeLocalPortFree("tcp", port); err == nil {
		t.Fatal("port with a local listener must be rejected")
	}
	l.Close()
	if err := probeLocalPortFree("tcp", port); err != nil {
		t.Fatalf("free port rejected: %v", err)
	}
}

// carriedTotals sums the initial counter bytes per comment in a rendered script (what the kernel would start with).
func carriedTotals(script string) map[string]int64 {
	re := regexp.MustCompile(`counter packets 0 bytes (\d+) comment "([^"]+)"`)
	res := map[string]int64{}
	for _, m := range re.FindAllStringSubmatch(script, -1) {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		res[m[2]] += n
	}
	return res
}

// NEW-B: rebuilding the table repeatedly must keep the carried totals stable for protocol "both".
func TestNftCarryOverStableForBoth(t *testing.T) {
	rules := []nftResolvedRule{{key: "9:relay", spec: protocol.RuleSpec{RuleID: 9, Role: protocol.RoleRelay, Protocol: "both", ListenPort: 20001},
		dstIP: "1.2.3.4", dstPort: 443}}
	state := nftCounterState{"nexus_up:9:relay": 1000, "nexus_down:9:relay": 3000}
	for i := 0; i < 3; i++ {
		state = nftCounterState(carriedTotals(buildNftForwardScript(rules, state)))
	}
	if state["nexus_up:9:relay"] != 1000 || state["nexus_down:9:relay"] != 3000 {
		t.Fatalf("carried counters drifted after rebuilds: %v", state)
	}
}

// NEW-A: counters left by a previous process must not be carried into the first table built by this process.
func TestNftFirstBuildDoesNotCarry(t *testing.T) {
	n := NewNftablesEngine()
	if n.carryReady {
		t.Fatal("a fresh engine must not carry over kernel counters")
	}
	c := newPortTrafficCounter()
	if c.carryReady {
		t.Fatal("a fresh port counter must not carry over kernel counters")
	}
}

func TestBuildNftAcctScript(t *testing.T) {
	entries := map[string]acctEntry{
		"3:relay": {Port: 40003, Proto: "both"},
		"4:relay": {Port: 40004, Proto: "tcp"},
		"5:relay": {Port: 40005, Proto: "udp"},
	}
	script := buildNftAcctScript(entries, nftCounterState{"acct_up:3:relay": 99, "acct_down:5:relay": 77})
	for _, m := range []string{
		"fib daddr type local tcp dport 40003 ct state established,related ct direction original counter packets 0 bytes 99 comment \"acct_up:3:relay\"",
		"fib daddr type local udp dport 40003 ct state established,related ct direction original counter comment \"acct_up:3:relay\"",
		"tcp sport 40003 ct state established,related ct direction reply counter comment \"acct_down:3:relay\"",
		"fib daddr type local tcp dport 40004 ct state established,related ct direction original counter comment \"acct_up:4:relay\"",
		"fib daddr type local udp dport 40005 ct state established,related ct direction original counter comment \"acct_up:5:relay\"",
		"udp sport 40005 ct state established,related ct direction reply counter packets 0 bytes 77 comment \"acct_down:5:relay\"",
	} {
		if !strings.Contains(script, m) {
			t.Errorf("acct script missing %q\n%s", m, script)
		}
	}
	// TCP-only rule must not emit UDP rules, and UDP-only rule must not emit TCP rules
	if strings.Contains(script, "udp dport 40004") || strings.Contains(script, "udp sport 40004") {
		t.Errorf("tcp-only rule emitted udp accounting rule:\n%s", script)
	}
	if strings.Contains(script, "tcp dport 40005") || strings.Contains(script, "tcp sport 40005") {
		t.Errorf("udp-only rule emitted tcp accounting rule:\n%s", script)
	}

	// Verify carried totals remain invariant across multiple rebuilds for tcp, udp, and both
	state := nftCounterState{"acct_up:3:relay": 500, "acct_down:3:relay": 800, "acct_up:5:relay": 200, "acct_down:5:relay": 300}
	for i := 0; i < 3; i++ {
		state = nftCounterState(carriedTotals(buildNftAcctScript(entries, state)))
	}
	if state["acct_up:3:relay"] != 500 || state["acct_down:3:relay"] != 800 || state["acct_up:5:relay"] != 200 || state["acct_down:5:relay"] != 300 {
		t.Fatalf("acct carried counters drifted across rebuilds: %v", state)
	}
}
