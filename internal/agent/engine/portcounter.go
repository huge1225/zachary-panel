package engine

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
)

type acctEntry struct {
	Port  int
	Proto string // "tcp" | "udp" | "both"
}

func acctProtos(proto string) []string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "udp":
		return []string{"udp"}
	case "both":
		return []string{"tcp", "udp"}
	default:
		return []string{"tcp"}
	}
}

// PortTrafficCounter provides zero-copy kernel byte accounting for external binary engines (GOST / Realm)
// by maintaining a read-only nftables accounting table (`inet nexus_acct`) on Linux.
// It never alters packet routing (accept policy only), so Realm and GOST run at full native speed
// while the Agent still harvests exact per-port Upload / Download byte deltas.
type PortTrafficCounter struct {
	mu       sync.Mutex
	nftBin   string
	ports    map[string]acctEntry // ruleKey -> bound port & protocol
	lastUp   map[string]int64     // ruleKey -> cumulative upload bytes
	lastDown map[string]int64     // ruleKey -> cumulative download bytes
	// carryReady is set once this process has built the table. The accounting table survives agent restarts, and
	// counters left by a previous process must not be carried (lastUp/lastDown start empty, so they would be
	// reported and billed again).
	carryReady bool
}

var sharedPortCounter = newPortTrafficCounter()

func newPortTrafficCounter() *PortTrafficCounter {
	var bin string
	if runtime.GOOS == "linux" {
		bin, _ = exec.LookPath("nft")
	}
	return &PortTrafficCounter{
		nftBin:   bin,
		ports:    make(map[string]acctEntry),
		lastUp:   make(map[string]int64),
		lastDown: make(map[string]int64),
	}
}

func (c *PortTrafficCounter) TrackPort(ruleKey string, port int, proto string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if port <= 0 {
		return
	}
	c.ports[ruleKey] = acctEntry{Port: port, Proto: proto}
	c.syncNftTableLocked()
}

func (c *PortTrafficCounter) UntrackPort(ruleKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.ports[ruleKey]; !ok {
		return
	}
	delete(c.ports, ruleKey)
	delete(c.lastUp, ruleKey)
	delete(c.lastDown, ruleKey)
	c.syncNftTableLocked()
}

func (c *PortTrafficCounter) syncNftTableLocked() {
	if c.nftBin == "" {
		return
	}
	// Carry over the current cumulative counters: the table is rebuilt on every rule change and must never reset
	// billing for other rules on this node. The carried total is placed on the first protocol rule emitted.
	state := nftCounterState{}
	if c.carryReady {
		if cur, err := readNftCountersChecked(c.nftBin, "nexus_acct"); err == nil {
			state = nftCounterState(cur)
		} else {
			for k, v := range c.lastUp {
				state["acct_up:"+sanitizeNftComment(k)] = v
			}
			for k, v := range c.lastDown {
				state["acct_down:"+sanitizeNftComment(k)] = v
			}
		}
	}
	script := buildNftAcctScript(c.ports, state)

	cmd := exec.Command(c.nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if cmd.Run() == nil {
		c.carryReady = true
	}
}

// HarvestDeltas queries the kernel accounting table and returns incremental (uploadDelta, downloadDelta) per ruleKey.
func (c *PortTrafficCounter) HarvestDeltas(keys []string) map[string][2]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	res := make(map[string][2]int64, len(keys))
	if c.nftBin == "" || len(c.ports) == 0 {
		return res
	}

	totals, err := readNftCountersChecked(c.nftBin, "nexus_acct")
	if err != nil {
		// Transient nft failure: do NOT overwrite lastUp/lastDown with 0.
		return res
	}

	for _, k := range keys {
		safeKey := sanitizeNftComment(k)
		curU := totals["acct_up:"+safeKey]
		curD := totals["acct_down:"+safeKey]
		u := curU - c.lastUp[k]
		if u < 0 {
			u = curU
		}
		if u > maxAgentDeltaBytes {
			u = maxAgentDeltaBytes
		}
		d := curD - c.lastDown[k]
		if d < 0 {
			d = curD
		}
		if d > maxAgentDeltaBytes {
			d = maxAgentDeltaBytes
		}
		c.lastUp[k] = curU
		c.lastDown[k] = curD
		res[k] = [2]int64{u, d}
	}
	return res
}

// buildNftAcctScript renders the read-only accounting table for external engines. Pure function for testability.
// Only bound protocols are tracked, and conntrack state + direction filters ensure unauthenticated one-way SYN/UDP
// floods to closed/unanswered ports and unrelated host-initiated ephemeral sockets cannot drain tenant/node quotas.
func buildNftAcctScript(ports map[string]acctEntry, state nftCounterState) string {
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("table inet nexus_acct {}\n")
	sb.WriteString("flush table inet nexus_acct\n")
	sb.WriteString("table inet nexus_acct {\n")
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority filter; policy accept;\n")
	for _, key := range keys {
		entry := ports[key]
		safeKey := sanitizeNftComment(key)
		comment := "acct_up:" + safeKey
		for i, proto := range acctProtos(entry.Proto) {
			ctr := "counter"
			if i == 0 {
				ctr = counterExpr(state, comment)
			}
			sb.WriteString(fmt.Sprintf("    fib daddr type local %s dport %d ct state established,related ct direction original %s comment \"%s\"\n",
				proto, entry.Port, ctr, comment))
		}
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority filter; policy accept;\n")
	for _, key := range keys {
		entry := ports[key]
		safeKey := sanitizeNftComment(key)
		comment := "acct_down:" + safeKey
		for i, proto := range acctProtos(entry.Proto) {
			ctr := "counter"
			if i == 0 {
				ctr = counterExpr(state, comment)
			}
			sb.WriteString(fmt.Sprintf("    %s sport %d ct state established,related ct direction reply %s comment \"%s\"\n",
				proto, entry.Port, ctr, comment))
		}
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	return sb.String()
}
