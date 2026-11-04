package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// NftablesEngine implements kernel-level DNAT/SNAT port forwarding using Linux `nftables`.
// It attaches named / commented counters to each rule so traffic bytes are accurately harvested from the kernel.
type NftablesEngine struct {
	mu        sync.RWMutex
	policy    security.Policy
	binPath   string
	rules     map[string]protocol.RuleSpec
	lastBytes map[string]int64 // ruleKey -> last total bytes read from kernel counter
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
		lastBytes: make(map[string]int64),
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

func (n *NftablesEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	if !n.Available() {
		return fmt.Errorf("nftables is only available on Linux with 'nft' binary installed")
	}
	key := RuleKey(spec.RuleID, spec.Role)

	n.mu.Lock()
	n.rules[key] = spec
	err := n.syncTableLocked()
	n.mu.Unlock()
	return err
}

func (n *NftablesEngine) RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.rules[ruleKey]; !ok {
		return nil
	}
	delete(n.rules, ruleKey)
	delete(n.lastBytes, ruleKey)
	return n.syncTableLocked()
}

func (n *NftablesEngine) syncTableLocked() error {
	var script strings.Builder
	script.WriteString("table inet nexus_forward {}\n")
	script.WriteString("flush table inet nexus_forward\n")
	script.WriteString("table inet nexus_forward {\n")
	script.WriteString("  chain prerouting {\n")
	script.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")

	for key, spec := range n.rules {
		if len(spec.Targets) == 0 {
			continue
		}
		targetAddr := spec.Targets[0].Address
		host, port, err := net.SplitHostPort(targetAddr)
		if err != nil {
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			continue
		}
		allowPrivate := n.policy.AllowPrivateTargets || (spec.Role == protocol.RoleIngress)
		if err := security.ValidateResolvedIP(ips[0], allowPrivate); err != nil {
			log.Printf("[NftablesEngine] Security blocked resolved IP %s for rule %s: %v", ips[0].String(), key, err)
			continue
		}
		dstIP := ips[0].String()

		protos := []string{"tcp"}
		if spec.Protocol == "udp" {
			protos = []string{"udp"}
		} else if spec.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}

		for _, proto := range protos {
			script.WriteString(fmt.Sprintf(
				"    %s dport %d counter dnat ip to %s:%s comment \"nexus:%s\"\n",
				proto, spec.ListenPort, dstIP, port, key,
			))
		}
	}

	script.WriteString("  }\n")
	script.WriteString("  chain postrouting {\n")
	script.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	script.WriteString("    masquerade\n")
	script.WriteString("  }\n")
	script.WriteString("}\n")

	cmd := exec.Command(n.binPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply failed: %v (%s)", err, stderr.String())
	}

	log.Printf("[NftablesEngine] Applied %d kernel forwarding rules to table inet nexus_forward", len(n.rules))
	return nil
}

// CollectDeltas reads kernel counters via `nft -j list table inet nexus_forward` and calculates byte deltas.
func (n *NftablesEngine) CollectDeltas() []protocol.RuleTrafficDelta {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.rules) == 0 || !n.Available() {
		return nil
	}

	cmd := exec.Command(n.binPath, "-j", "list", "table", "inet", "nexus_forward")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var parsed struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil
	}

	currentTotals := make(map[string]int64)
	for _, item := range parsed.Nftables {
		ruleObj, ok := item["rule"].(map[string]any)
		if !ok {
			continue
		}
		comment, _ := ruleObj["comment"].(string)
		if !strings.HasPrefix(comment, "nexus:") {
			continue
		}
		key := strings.TrimPrefix(comment, "nexus:")
		exprs, _ := ruleObj["expr"].([]any)
		for _, ex := range exprs {
			exMap, ok := ex.(map[string]any)
			if !ok {
				continue
			}
			if ctr, ok := exMap["counter"].(map[string]any); ok {
				if bFloat, ok := ctr["bytes"].(float64); ok {
					currentTotals[key] += int64(bFloat)
				}
			}
		}
	}

	var deltas []protocol.RuleTrafficDelta
	for key, spec := range n.rules {
		cur := currentTotals[key]
		prev := n.lastBytes[key]
		delta := cur - prev
		if delta < 0 {
			delta = cur
		}
		n.lastBytes[key] = cur
		if delta > 0 {
			deltas = append(deltas, protocol.RuleTrafficDelta{
				RuleID:      spec.RuleID,
				Role:        spec.Role,
				Engine:      protocol.EngineNftables,
				UploadBytes: delta / 2,
				DownBytes:   delta - (delta / 2),
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
