package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// PortTrafficCounter provides zero-copy kernel byte accounting for external binary engines (GOST / Realm)
// by maintaining a read-only nftables accounting table (`inet nexus_acct`) on Linux.
// It never alters packet routing (accept policy only), so Realm and GOST run at full native speed
// while the Agent still harvests exact per-port Upload / Download byte deltas.
type PortTrafficCounter struct {
	mu        sync.Mutex
	nftBin    string
	ports     map[string]int   // ruleKey -> listenPort
	lastUp    map[string]int64 // ruleKey -> cumulative upload bytes
	lastDown  map[string]int64 // ruleKey -> cumulative download bytes
}

var sharedPortCounter = newPortTrafficCounter()

func newPortTrafficCounter() *PortTrafficCounter {
	var bin string
	if runtime.GOOS == "linux" {
		bin, _ = exec.LookPath("nft")
	}
	return &PortTrafficCounter{
		nftBin:   bin,
		ports:    make(map[string]int),
		lastUp:   make(map[string]int64),
		lastDown: make(map[string]int64),
	}
}

func (c *PortTrafficCounter) TrackPort(ruleKey string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if port <= 0 {
		return
	}
	c.ports[ruleKey] = port
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
	var sb strings.Builder
	sb.WriteString("table inet nexus_acct {}\n")
	sb.WriteString("flush table inet nexus_acct\n")
	sb.WriteString("table inet nexus_acct {\n")
	sb.WriteString("  chain input {\n")
	sb.WriteString("    type filter hook input priority -150; policy accept;\n")
	for key, port := range c.ports {
		sb.WriteString(fmt.Sprintf("    tcp dport %d counter comment \"acct_up:%s\"\n", port, key))
		sb.WriteString(fmt.Sprintf("    udp dport %d counter comment \"acct_up:%s\"\n", port, key))
	}
	sb.WriteString("  }\n")
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority -150; policy accept;\n")
	for key, port := range c.ports {
		sb.WriteString(fmt.Sprintf("    tcp sport %d counter comment \"acct_down:%s\"\n", port, key))
		sb.WriteString(fmt.Sprintf("    udp sport %d counter comment \"acct_down:%s\"\n", port, key))
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	cmd := exec.Command(c.nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(sb.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()
}

// HarvestDeltas queries the kernel accounting table and returns incremental (uploadDelta, downloadDelta) per ruleKey.
func (c *PortTrafficCounter) HarvestDeltas(keys []string) map[string][2]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	res := make(map[string][2]int64, len(keys))
	if c.nftBin == "" || len(c.ports) == 0 {
		return res
	}

	out, err := exec.Command(c.nftBin, "-j", "list", "table", "inet", "nexus_acct").Output()
	if err != nil {
		return res
	}

	var parsed struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return res
	}

	curUp := make(map[string]int64)
	curDown := make(map[string]int64)

	for _, item := range parsed.Nftables {
		ruleObj, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		comment, _ := ruleObj["comment"].(string)
		if !strings.HasPrefix(comment, "acct_up:") && !strings.HasPrefix(comment, "acct_down:") {
			continue
		}
		var bytesVal int64
		exprs, _ := ruleObj["expr"].([]any)
		for _, ex := range exprs {
			if exMap, ok := ex.(map[string]any); ok {
				if ctr, ok := exMap["counter"].(map[string]any); ok {
					if bFloat, ok := ctr["bytes"].(float64); ok {
						bytesVal += int64(bFloat)
					}
				}
			}
		}
		if strings.HasPrefix(comment, "acct_up:") {
			key := strings.TrimPrefix(comment, "acct_up:")
			curUp[key] += bytesVal
		} else {
			key := strings.TrimPrefix(comment, "acct_down:")
			curDown[key] += bytesVal
		}
	}

	for _, k := range keys {
		u := curUp[k] - c.lastUp[k]
		if u < 0 {
			u = curUp[k]
		}
		d := curDown[k] - c.lastDown[k]
		if d < 0 {
			d = curDown[k]
		}
		c.lastUp[k] = curUp[k]
		c.lastDown[k] = curDown[k]
		res[k] = [2]int64{u, d}
	}
	return res
}
