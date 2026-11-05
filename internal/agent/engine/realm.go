package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// RealmEngine manages the external `realm` binary for high-performance TCP/UDP relay.
type RealmEngine struct {
	mu         sync.RWMutex
	binPath    string
	configPath string
	rules      map[string]protocol.RuleSpec
	cmd        *exec.Cmd
	cancel     context.CancelFunc
}

// NewRealmEngine creates the realm driver. workDir must be a private (0700) directory owned by the agent.
func NewRealmEngine(workDir string) *RealmEngine {
	bin, _ := exec.LookPath("realm")
	cfgDir := workDir
	return &RealmEngine{
		binPath:    bin,
		configPath: filepath.Join(cfgDir, "realm-config.json"),
		rules:      make(map[string]protocol.RuleSpec),
	}
}

func (r *RealmEngine) Name() protocol.EngineType {
	return protocol.EngineRealm
}

func (r *RealmEngine) Available() bool {
	if r.binPath != "" {
		return true
	}
	bin, err := exec.LookPath("realm")
	if err == nil {
		r.binPath = bin
		return true
	}
	return false
}

func (r *RealmEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	if !r.Available() {
		return fmt.Errorf("realm binary not found in PATH")
	}

	key := RuleKey(spec.RuleID, spec.Role)
	r.mu.Lock()
	r.rules[key] = spec
	err := r.reloadLocked()
	r.mu.Unlock()
	if err == nil {
		sharedPortCounter.TrackPort(key, spec.ListenPort)
	}
	return err
}

func (r *RealmEngine) RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error {
	r.mu.Lock()
	if _, ok := r.rules[ruleKey]; !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.rules, ruleKey)
	err := r.reloadLocked()
	r.mu.Unlock()

	sharedPortCounter.UntrackPort(ruleKey)
	return err
}

func (r *RealmEngine) reloadLocked() error {
	// Stop current realm process if running
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
		r.cmd = nil
	}

	if len(r.rules) == 0 {
		return nil
	}

	var endpoints []map[string]any
	for _, spec := range r.rules {
		if len(spec.Targets) == 0 {
			continue
		}
		listenHost := spec.ListenHost
		if listenHost == "" {
			listenHost = "0.0.0.0"
		}
		listenAddr := fmt.Sprintf("%s:%d", listenHost, spec.ListenPort)

		var extraRemotes []string
		for i := 1; i < len(spec.Targets); i++ {
			extraRemotes = append(extraRemotes, spec.Targets[i].Address)
		}

		ep := map[string]any{
			"listen": listenAddr,
			"remote": spec.Targets[0].Address,
			"network": map[string]any{
				"no_tcp":  spec.Protocol == "udp",
				"use_udp": spec.Protocol == "udp" || spec.Protocol == "both",
			},
		}
		if len(extraRemotes) > 0 {
			ep["extra_remotes"] = extraRemotes
			ep["balance"] = "roundrobin: " + strings.Repeat("1, ", len(extraRemotes)) + "1"
		}
		endpoints = append(endpoints, ep)
	}

	cfgPayload := map[string]any{
		"log": map[string]any{
			"level":  "warn",
			"output": "stdout",
		},
		"endpoints": endpoints,
	}

	data, err := json.MarshalIndent(cfgPayload, "", "  ")
	if err != nil {
		return err
	}
	if err := security.WriteFileAtomic(r.configPath, data, 0600); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, r.binPath, "-c", r.configPath)
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start realm: %w", err)
	}

	r.cmd = cmd
	r.cancel = cancel
	go r.superviseRealm(ctx, cmd)
	log.Printf("[RealmEngine] Reloaded realm (PID %d) with %d active rules", cmd.Process.Pid, len(r.rules))
	return nil
}

// superviseRealm monitors the active realm process and automatically restarts it if it crashes unexpectedly.
func (r *RealmEngine) superviseRealm(ctx context.Context, watchedCmd *exec.Cmd) {
	if watchedCmd != nil {
		_ = watchedCmd.Wait()
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != watchedCmd || ctx.Err() != nil || len(r.rules) == 0 {
		return
	}
	log.Printf("[RealmEngine] Detected unexpected realm exit, self-healing process...")
	_ = r.reloadLocked()
}

func (r *RealmEngine) CollectDeltas() []protocol.RuleTrafficDelta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.rules) == 0 {
		return nil
	}
	keys := make([]string, 0, len(r.rules))
	for k := range r.rules {
		keys = append(keys, k)
	}
	portDeltas := sharedPortCounter.HarvestDeltas(keys)

	var deltas []protocol.RuleTrafficDelta
	for k, spec := range r.rules {
		d := portDeltas[k]
		deltas = append(deltas, protocol.RuleTrafficDelta{
			RuleID:      spec.RuleID,
			Role:        spec.Role,
			Engine:      protocol.EngineRealm,
			UploadBytes: d[0],
			DownBytes:   d[1],
		})
	}
	return deltas
}

func (r *RealmEngine) ActiveRuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

func (r *RealmEngine) Close() error {
	r.mu.Lock()
	keys := make([]string, 0, len(r.rules))
	for k := range r.rules {
		keys = append(keys, k)
	}
	r.rules = make(map[string]protocol.RuleSpec)
	err := r.reloadLocked()
	r.mu.Unlock()

	for _, k := range keys {
		sharedPortCounter.UntrackPort(k)
	}
	return err
}
