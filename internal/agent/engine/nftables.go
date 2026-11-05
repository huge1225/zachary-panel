package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// NftablesEngine implements kernel-level DNAT/SNAT port forwarding using Linux `nftables`.
//
// Design (security & billing):
//   - DNAT only matches packets addressed to this host (`fib daddr type local`), so routed / container traffic that
//     happens to use the same destination port is never hijacked;
//   - before applying, the agent probes the port and refuses rules whose port is already used by a local service
//     (nft DNAT would otherwise silently take over e.g. an SSH daemon on a high port);
//   - traffic is counted in a filter `forward` chain on every packet of the DNAT-ed connection (nat chains only see
//     the first packet), split into upload (original direction) and download (reply direction);
//   - an optional per-rule byte-rate limit is enforced with `limit rate over … drop`;
//   - counters are carried over when the table is rebuilt so rule changes never reset billing.
type NftablesEngine struct {
	mu        sync.RWMutex
	policy    security.Policy
	binPath   string
	rules     map[string]protocol.RuleSpec
	lastUp    map[string]int64 // ruleKey -> last cumulative upload bytes read from kernel counter
	lastDown  map[string]int64 // ruleKey -> last cumulative download bytes read from kernel counter
	portProbe func(proto string, port int) error
	// carryReady is set once this process has built the table; only then are kernel counters carried over.
	carryReady bool
}

func NewNftablesEngine(policies ...security.Policy) *NftablesEngine {
	pol := security.DefaultPolicy
	if len(policies) > 0 {
		pol = policies[0]
	}
	var bin string
	if runtime.GOOS == "linux" {
		bin, _ = exec.LookPath("nft")
	}
	return &NftablesEngine{
		policy:    pol,
		binPath:   bin,
		rules:     make(map[string]protocol.RuleSpec),
		lastUp:    make(map[string]int64),
		lastDown:  make(map[string]int64),
		portProbe: probeLocalPortFree,
	}
}

func (n *NftablesEngine) Name() protocol.EngineType {
	return protocol.EngineNftables
}

func (n *NftablesEngine) Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if n.binPath != "" {
		return true
	}
	bin, err := exec.LookPath("nft")
	if err == nil {
		n.binPath = bin
		return true
	}
	return false
}

// probeLocalPortFree verifies no local service is bound to the port (nft DNAT never reports EADDRINUSE itself).
func probeLocalPortFree(proto string, port int) error {
	addr := net.JoinHostPort("", strconv.Itoa(port))
	switch proto {
	case "udp":
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fmt.Errorf("udp port %d is already in use by a local service", port)
		}
		return c.Close()
	default:
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("tcp port %d is already in use by a local service", port)
		}
		return l.Close()
	}
}

// cleanupStaleKernelTables removes the agent's nftables tables left behind by a previous process.
func cleanupStaleKernelTables() {
	if runtime.GOOS != "linux" {
		return
	}
	bin, err := exec.LookPath("nft")
	if err != nil {
		return
	}
	for _, table := range []string{"nexus_forward", "nexus_acct"} {
		_ = exec.Command(bin, "delete", "table", "inet", table).Run()
	}
}

// nftLimitName derives a valid nft object name from a rule key and direction.
func nftLimitName(dir, key string) string {
	var b strings.Builder
	b.WriteString("lim_" + dir + "_")
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func nftProtos(spec protocol.RuleSpec) []string {
	switch spec.Protocol {
	case "udp":
		return []string{"udp"}
	case "both":
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}

func (n *NftablesEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	if !n.Available() {
		return fmt.Errorf("nftables is only available on Linux with 'nft' binary installed")
	}
	key := RuleKey(spec.RuleID, spec.Role)

	n.mu.Lock()
	defer n.mu.Unlock()
	if old, exists := n.rules[key]; !exists || old.ListenPort != spec.ListenPort || old.Protocol != spec.Protocol {
		for _, proto := range nftProtos(spec) {
			if err := n.portProbe(proto, spec.ListenPort); err != nil {
				return fmt.Errorf("rule %s: %w", key, err)
			}
		}
	}
	prev, had := n.rules[key]
	n.rules[key] = spec
	if err := n.syncTableLocked(); err != nil {
		if had {
			n.rules[key] = prev
		} else {
			delete(n.rules, key)
		}
		return err
	}
	return nil
}

func (n *NftablesEngine) RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.rules[ruleKey]; !ok {
		return nil
	}
	delete(n.rules, ruleKey)
	delete(n.lastUp, ruleKey)
	delete(n.lastDown, ruleKey)
	return n.syncTableLocked()
}

// nftRuleTarget picks the first resolved IPv4 target that passes the sandbox (DNAT in this table is IPv4 only).
func (n *NftablesEngine) nftRuleTarget(key string, spec protocol.RuleSpec) (string, int, bool) {
	if len(spec.Targets) == 0 {
		return "", 0, false
	}
	host, portStr, err := net.SplitHostPort(spec.Targets[0].Address)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if ips, err = net.LookupIP(host); err != nil {
		return "", 0, false
	}
	allowPrivate := n.policy.AllowPrivateTargets || (spec.Role == protocol.RoleIngress)
	for _, ip := range ips {
		if ip.To4() == nil {
			continue
		}
		if err := security.ValidateResolvedIP(ip, allowPrivate); err != nil {
			log.Printf("[NftablesEngine] Security blocked resolved IP %s for rule %s: %v", ip.String(), key, err)
			continue
		}
		return ip.To4().String(), port, true
	}
	return "", 0, false
}

// nftCounterState holds carried-over kernel counter values keyed by rule comment.
type nftCounterState map[string]int64

func counterExpr(state nftCounterState, comment string) string {
	if b := state[comment]; b > 0 {
		return fmt.Sprintf("counter packets 0 bytes %d", b)
	}
	return "counter"
}

type nftResolvedRule struct {
	key     string
	spec    protocol.RuleSpec
	dstIP   string
	dstPort int
}

// buildNftForwardScript renders the complete nexus_forward table. It is a pure function for testability.
func buildNftForwardScript(rules []nftResolvedRule, state nftCounterState) string {
	var s strings.Builder
	// The table is deleted and re-created atomically (one nft transaction) so stateful limit objects are rebuilt
	// with the current rates; counters are carried explicitly via state.
	s.WriteString("table inet nexus_forward {}\n")
	s.WriteString("delete table inet nexus_forward\n")
	s.WriteString("table inet nexus_forward {\n")

	// One named limit per rule and direction, shared by the tcp and udp rules so protocol "both" cannot use
	// twice the configured bandwidth.
	for _, r := range rules {
		if r.spec.SpeedLimitMbps <= 0 {
			continue
		}
		kb := r.spec.SpeedLimitMbps * 125 // Mbps -> kbytes/second
		for _, dir := range []string{"up", "down"} {
			fmt.Fprintf(&s, "  limit %s {\n    rate over %d kbytes/second burst %d kbytes\n  }\n", nftLimitName(dir, r.key), kb, kb*2)
		}
	}

	s.WriteString("  chain prerouting {\n")
	s.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, r := range rules {
		for _, proto := range nftProtos(r.spec) {
			fmt.Fprintf(&s, "    fib daddr type local %s dport %d dnat ip to %s:%d comment \"nexus:%s\"\n",
				proto, r.spec.ListenPort, r.dstIP, r.dstPort, r.key)
		}
	}
	s.WriteString("  }\n")

	// Per-packet accounting & rate limiting for DNAT-ed flows. Matching both the original destination port and the
	// reply source (the pinned target) ensures only this rule's connections are counted.
	s.WriteString("  chain forward {\n")
	s.WriteString("    type filter hook forward priority filter; policy accept;\n")
	for _, r := range rules {
		for i, proto := range nftProtos(r.spec) {
			match := fmt.Sprintf("meta l4proto %s ct status dnat ct original proto-dst %d ct reply ip saddr %s ct reply proto-src %d",
				proto, r.spec.ListenPort, r.dstIP, r.dstPort)
			for _, dir := range []string{"original", "reply"} {
				if r.spec.SpeedLimitMbps > 0 {
					limDir := "up"
					if dir == "reply" {
						limDir = "down"
					}
					fmt.Fprintf(&s, "    %s ct direction %s limit name \"%s\" drop\n", match, dir, nftLimitName(limDir, r.key))
				}
				label := "nexus_up:"
				if dir == "reply" {
					label = "nexus_down:"
				}
				comment := label + r.key
				// tcp and udp rules share a comment and are summed on read; the carried total goes onto the first
				// protocol's rule only, otherwise every rebuild would multiply it.
				ctr := "counter"
				if i == 0 {
					ctr = counterExpr(state, comment)
				}
				fmt.Fprintf(&s, "    %s ct direction %s %s comment \"%s\"\n", match, dir, ctr, comment)
			}
		}
	}
	s.WriteString("  }\n")

	s.WriteString("  chain postrouting {\n")
	s.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	// Only masquerade connections DNAT-ed by one of our rules; never rewrite unrelated host traffic.
	for _, r := range rules {
		for _, proto := range nftProtos(r.spec) {
			fmt.Fprintf(&s, "    meta l4proto %s ct status dnat ct original proto-dst %d ip daddr %s %s dport %d masquerade\n",
				proto, r.spec.ListenPort, r.dstIP, proto, r.dstPort)
		}
	}
	s.WriteString("  }\n")
	s.WriteString("}\n")
	return s.String()
}

func (n *NftablesEngine) syncTableLocked() error {
	keys := make([]string, 0, len(n.rules))
	for k := range n.rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	resolved := make([]nftResolvedRule, 0, len(keys))
	for _, key := range keys {
		spec := n.rules[key]
		ip, port, ok := n.nftRuleTarget(key, spec)
		if !ok {
			continue
		}
		resolved = append(resolved, nftResolvedRule{key: key, spec: spec, dstIP: ip, dstPort: port})
	}

	// Carry over current kernel counters so rebuilding the table never resets billing. Counters left behind by a
	// previous agent process (crash / restart without Close) are NOT carried: lastUp/lastDown start empty, so they
	// would be reported (and billed) a second time.
	state := nftCounterState{}
	if n.carryReady {
		state = nftCounterState(readNftCounters(n.binPath, "nexus_forward"))
	}
	script := buildNftForwardScript(resolved, state)

	cmd := exec.Command(n.binPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply failed: %v (%s)", err, stderr.String())
	}
	n.carryReady = true

	log.Printf("[NftablesEngine] Applied %d kernel forwarding rules to table inet nexus_forward", len(resolved))
	return nil
}

// readNftCounters returns cumulative counter bytes keyed by rule comment for the given inet table.
func readNftCounters(bin, table string) map[string]int64 {
	res := make(map[string]int64)
	if bin == "" {
		return res
	}
	out, err := exec.Command(bin, "-j", "list", "table", "inet", table).Output()
	if err != nil {
		return res
	}
	return parseNftCounters(out)
}

func parseNftCounters(out []byte) map[string]int64 {
	res := make(map[string]int64)
	var parsed struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return res
	}
	for _, item := range parsed.Nftables {
		ruleObj, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		comment, _ := ruleObj["comment"].(string)
		if comment == "" {
			continue
		}
		exprs, _ := ruleObj["expr"].([]any)
		for _, ex := range exprs {
			exMap, ok := ex.(map[string]any)
			if !ok {
				continue
			}
			if ctr, ok := exMap["counter"].(map[string]any); ok {
				if bFloat, ok := ctr["bytes"].(float64); ok {
					res[comment] += int64(bFloat)
				}
			}
		}
	}
	return res
}

// CollectDeltas reads the per-direction kernel counters and calculates byte deltas.
func (n *NftablesEngine) CollectDeltas() []protocol.RuleTrafficDelta {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.rules) == 0 || !n.Available() {
		return nil
	}
	totals := readNftCounters(n.binPath, "nexus_forward")

	var deltas []protocol.RuleTrafficDelta
	for key, spec := range n.rules {
		curUp, curDown := totals["nexus_up:"+key], totals["nexus_down:"+key]
		up, down := curUp-n.lastUp[key], curDown-n.lastDown[key]
		if up < 0 {
			up = curUp
		}
		if down < 0 {
			down = curDown
		}
		n.lastUp[key], n.lastDown[key] = curUp, curDown
		if up > 0 || down > 0 {
			deltas = append(deltas, protocol.RuleTrafficDelta{
				RuleID:      spec.RuleID,
				Role:        spec.Role,
				Engine:      protocol.EngineNftables,
				UploadBytes: up,
				DownBytes:   down,
			})
		}
	}
	return deltas
}

func (n *NftablesEngine) ActiveRuleCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.rules)
}

func (n *NftablesEngine) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.Available() {
		return nil
	}
	_ = exec.Command(n.binPath, "delete", "table", "inet", "nexus_forward").Run()
	return nil
}

// NftSelfCheck renders sample nexus_forward / nexus_acct tables (both protocols, speed limit, carried counters) and
// validates them with `nft -c` (dry run, nothing is applied). Run it once on each new node / kernel / nft version.
func NftSelfCheck() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("nftables is only available on Linux")
	}
	bin, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("'nft' binary not found: install the nftables package")
	}
	sample := []nftResolvedRule{
		{key: "1:relay", spec: protocol.RuleSpec{RuleID: 1, Role: protocol.RoleRelay, Protocol: "both", ListenPort: 40001, SpeedLimitMbps: 100},
			dstIP: "203.0.113.10", dstPort: 443},
		{key: "2:relay", spec: protocol.RuleSpec{RuleID: 2, Role: protocol.RoleRelay, Protocol: "tcp", ListenPort: 40002},
			dstIP: "203.0.113.11", dstPort: 8443},
	}
	scripts := map[string]string{
		"nexus_forward": buildNftForwardScript(sample, nftCounterState{"nexus_up:1:relay": 1234, "nexus_down:1:relay": 5678}),
		"nexus_acct":    buildNftAcctScript(map[string]int{"3:relay": 40003}, nftCounterState{"acct_up:3:relay": 99}),
	}
	for _, name := range []string{"nexus_forward", "nexus_acct"} {
		cmd := exec.Command(bin, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(scripts[name])
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			hint := ""
			if os.Geteuid() != 0 {
				hint = "\n(hint: nft -c needs root / CAP_NET_ADMIN, re-run with sudo before treating this as a rule error)"
			}
			return fmt.Errorf("table %s rejected by nft: %v\n%s%s\n--- script ---\n%s", name, err, stderr.String(), hint, scripts[name])
		}
	}
	return nil
}
