package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

// RuleKey uniquely identifies a rule instance on an Agent (since a node could theoretically be both ingress and egress in self-loop testing).
func RuleKey(ruleID uint64, role protocol.RuleRole) string {
	if role == "" {
		role = protocol.RoleRelay
	}
	return fmt.Sprintf("%d:%s", ruleID, role)
}

// EngineDriver is the unified interface for all forwarding engines:
// - "native": Built-in pure Go TCP/UDP + extensible custom tunnel protocol
// - "gost":   GOST v3 multi-hop tunnel & relay engine
// - "realm":  High-performance Realm relay engine
// - "nftables": Linux kernel-space nftables DNAT/SNAT zero-copy forwarding
type EngineDriver interface {
	// Name returns the unique engine identifier matching protocol.EngineType.
	Name() protocol.EngineType
	// Available checks whether the host OS / external binary / kernel module supports this engine.
	Available() bool
	// ApplyRule starts or hot-updates a forwarding rule on this engine.
	ApplyRule(ctx context.Context, spec protocol.RuleSpec) error
	// RemoveRule stops and cleans up a rule identified by ruleKey.
	RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error
	// CollectDeltas returns incremental traffic stats for all rules running in this engine and resets deltas.
	CollectDeltas() []protocol.RuleTrafficDelta
	// ActiveRuleCount returns the number of active rules managed by this engine.
	ActiveRuleCount() int
	// Close gracefully shuts down all rules managed by this engine.
	Close() error
}

// Manager coordinates multiple EngineDrivers, persists local rule snapshots across service restarts,
// and routes rules according to the panel's selection.
type Manager struct {
	mu            sync.RWMutex
	policy        security.Policy
	snapshotPath  string
	tunnelCert    *security.TunnelCert
	drivers       map[protocol.EngineType]EngineDriver
	ruleBinding   map[string]protocol.EngineType // ruleKey -> EngineType currently running it
	activeSpecs   map[string]protocol.RuleSpec   // desired spec as received from Master
	resolvedSpecs map[string]protocol.RuleSpec   // spec actually handed to external engines (targets pinned to IPs)
}

// NewManager initializes the EngineManager and registers all built-in and external drivers.
// stateDir is a private (0700) directory owned by the agent that stores the rule snapshot, the node's tunnel
// TLS identity and external engine configuration files. It must not be a world-writable location such as /tmp.
func NewManager(stateDir string, policies ...security.Policy) (*Manager, error) {
	pol := security.DefaultPolicy
	if len(policies) > 0 {
		pol = policies[0]
	}
	if stateDir == "" {
		return nil, fmt.Errorf("agent state directory is required")
	}
	if err := security.EnsurePrivateDir(stateDir); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	gostDir := filepath.Join(stateDir, "gost")
	realmDir := filepath.Join(stateDir, "realm")
	for _, d := range []string{gostDir, realmDir} {
		if err := security.EnsurePrivateDir(d); err != nil {
			return nil, fmt.Errorf("state dir: %w", err)
		}
	}
	cert, err := security.LoadOrCreateTunnelCert(stateDir)
	if err != nil {
		return nil, fmt.Errorf("tunnel certificate: %w", err)
	}

	m := &Manager{
		policy:        pol,
		snapshotPath:  filepath.Join(stateDir, "rules-snapshot.json"),
		tunnelCert:    cert,
		drivers:       make(map[protocol.EngineType]EngineDriver),
		ruleBinding:   make(map[string]protocol.EngineType),
		activeSpecs:   make(map[string]protocol.RuleSpec),
		resolvedSpecs: make(map[string]protocol.RuleSpec),
	}

	// Register all 4 engine drivers
	m.RegisterDriver(NewNativeEngine(pol, cert))
	m.RegisterDriver(NewGostEngine(gostDir, cert))
	m.RegisterDriver(NewRealmEngine(realmDir))
	m.RegisterDriver(NewNftablesEngine(pol))

	return m, nil
}

// TunnelCertPEM returns this node's tunnel certificate (public part) which Master pins on Ingress nodes.
func (m *Manager) TunnelCertPEM() string {
	if m.tunnelCert == nil {
		return ""
	}
	return m.tunnelCert.CertPEM
}

// BoundEngine returns the engine currently running the given rule (empty if not running).
func (m *Manager) BoundEngine(ruleID uint64, role protocol.RuleRole) protocol.EngineType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ruleBinding[RuleKey(ruleID, role)]
}

// RegisterDriver adds or overrides an EngineDriver (facilitates custom self-developed engines).
func (m *Manager) RegisterDriver(d EngineDriver) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drivers[d.Name()] = d
}

// SupportedEngines returns the list of engines available on the current host machine.
func (m *Manager) SupportedEngines() []protocol.EngineType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []protocol.EngineType
	// Keep deterministic order
	order := []protocol.EngineType{
		protocol.EngineNative,
		protocol.EngineGost,
		protocol.EngineRealm,
		protocol.EngineNftables,
	}
	for _, et := range order {
		if d, ok := m.drivers[et]; ok && d.Available() {
			list = append(list, et)
		}
	}
	return list
}

// needsPinnedTargets reports whether an engine hands targets to an external program / kernel that would
// re-resolve hostnames itself (bypassing the agent's anti-SSRF dial checks).
func needsPinnedTargets(e protocol.EngineType) bool {
	return e == protocol.EngineGost || e == protocol.EngineRealm || e == protocol.EngineNftables
}

// supportsEncryptedTunnel reports whether an engine implements the authenticated + encrypted tunnel transport.
func supportsEncryptedTunnel(e protocol.EngineType) bool {
	return e == protocol.EngineNative || e == protocol.EngineGost
}

// ApplyRule dispatches a RuleSpec to its designated EngineDriver.
// If the rule previously ran on a different engine (e.g. switched from realm to gost on the panel),
// Manager stops it on the old engine first before starting it on the new engine.
func (m *Manager) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyRuleLocked(ctx, spec)
}

func (m *Manager) applyRuleLocked(ctx context.Context, spec protocol.RuleSpec) error {
	if spec.Engine == "" {
		spec.Engine = protocol.EngineNative
	}
	if spec.Role == "" {
		spec.Role = protocol.RoleRelay
	}
	isTunnelRole := spec.Role == protocol.RoleIngress || spec.Role == protocol.RoleEgress

	// realm / nftables cannot speak the authenticated encrypted tunnel protocol; tunnel legs always run on the
	// native engine instead so traffic between Ingress and Egress is never sent in clear text.
	if isTunnelRole && !supportsEncryptedTunnel(spec.Engine) {
		log.Printf("[EngineManager] Engine %q has no encrypted tunnel support, using %q for rule #%d (%s)",
			spec.Engine, protocol.EngineNative, spec.RuleID, spec.Role)
		spec.Engine = protocol.EngineNative
	}

	// Enforce Agent-side security sandbox validation (Anti-SSRF, Protected Port Guard, Injection Filter)
	if err := security.ValidateRuleSpec(spec, m.policy); err != nil {
		log.Printf("[EngineManager] SECURITY REJECTED rule #%d (%s): %v", spec.RuleID, spec.Name, err)
		return err
	}

	key := RuleKey(spec.RuleID, spec.Role)

	driver, ok := m.drivers[spec.Engine]
	if !ok || !driver.Available() {
		if isTunnelRole {
			// Never silently downgrade a tunnel leg to a different engine: the peer node expects the same transport.
			return fmt.Errorf("engine %q is not available on this node", spec.Engine)
		}
		// Fallback to native engine if external binary isn't installed on this node, with warning log
		log.Printf("[EngineManager] Requested engine %q not available on host, falling back to %q for rule %s",
			spec.Engine, protocol.EngineNative, key)
		driver = m.drivers[protocol.EngineNative]
		spec.Engine = protocol.EngineNative
	}

	runSpec := spec
	if needsPinnedTargets(spec.Engine) {
		allowPrivate := m.policy.AllowPrivateTargets || spec.Role == protocol.RoleIngress
		pinned, err := security.ResolveTargets(ctx, spec.Targets, allowPrivate)
		if err != nil {
			log.Printf("[EngineManager] SECURITY REJECTED rule #%d (%s): %v", spec.RuleID, spec.Name, err)
			return err
		}
		runSpec.Targets = pinned
	}

	// If rule was running on another engine, stop it first
	if prevEngine, exists := m.ruleBinding[key]; exists && prevEngine != spec.Engine {
		if oldDriver, ok := m.drivers[prevEngine]; ok {
			_ = oldDriver.RemoveRule(key, spec.RuleID, spec.Role)
		}
		delete(m.ruleBinding, key)
		delete(m.activeSpecs, key)
		delete(m.resolvedSpecs, key)
	}

	if err := driver.ApplyRule(ctx, runSpec); err != nil {
		return err
	}

	m.ruleBinding[key] = spec.Engine
	m.activeSpecs[key] = spec
	m.resolvedSpecs[key] = runSpec
	m.saveSnapshotLocked()
	return nil
}

// RemoveRule stops a rule on whichever engine is currently hosting it.
func (m *Manager) RemoveRule(ruleID uint64, role protocol.RuleRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := RuleKey(ruleID, role)
	engType, exists := m.ruleBinding[key]
	if !exists {
		return nil
	}

	delete(m.ruleBinding, key)
	delete(m.activeSpecs, key)
	delete(m.resolvedSpecs, key)
	m.saveSnapshotLocked()

	if driver, ok := m.drivers[engType]; ok {
		return driver.RemoveRule(key, ruleID, role)
	}
	return nil
}

// saveSnapshotLocked atomically persists all active rules to local disk so that if the Agent service
// or host machine restarts, all rules are immediately restarted on boot even before Master reconnects.
func (m *Manager) saveSnapshotLocked() {
	if m.snapshotPath == "" {
		return
	}
	specs := make([]protocol.RuleSpec, 0, len(m.activeSpecs))
	for _, s := range m.activeSpecs {
		specs = append(specs, s)
	}
	data, err := json.MarshalIndent(specs, "", "  ")
	if err != nil {
		return
	}
	if err := security.WriteFileAtomic(m.snapshotPath, data, 0600); err != nil {
		log.Printf("[EngineManager] Failed to persist rule snapshot: %v", err)
	}
}

// RestoreSnapshot loads the last persisted rule snapshot from disk on Agent service startup and starts all rules.
func (m *Manager) RestoreSnapshot(ctx context.Context) int {
	// Kernel tables left by a previous process (crash / OOM / lost snapshot) would keep forwarding rules the agent no
	// longer knows about, unbilled. Start from a clean slate; the snapshot below re-creates what is still desired.
	cleanupStaleKernelTables()
	if m.snapshotPath == "" {
		return 0
	}
	data, err := os.ReadFile(m.snapshotPath)
	if err != nil || len(data) == 0 {
		return 0
	}
	var specs []protocol.RuleSpec
	if err := json.Unmarshal(data, &specs); err != nil || len(specs) == 0 {
		return 0
	}
	restored := 0
	for _, spec := range specs {
		if err := m.ApplyRule(ctx, spec); err == nil {
			restored++
		}
	}
	if restored > 0 {
		log.Printf("[EngineManager] Auto-restored and restarted %d forwarding rules from local snapshot", restored)
	}
	return restored
}

// effectiveEngine mirrors the engine substitution performed in applyRuleLocked so that reconciliation compares
// like with like.
func effectiveEngine(spec protocol.RuleSpec) protocol.EngineType {
	e := spec.Engine
	if e == "" {
		e = protocol.EngineNative
	}
	if (spec.Role == protocol.RoleIngress || spec.Role == protocol.RoleEgress) && !supportsEncryptedTunnel(e) {
		e = protocol.EngineNative
	}
	return e
}

// sameRuleSpec compares two RuleSpecs for functional equivalence so periodic reconciliation
// does not tear down active connections on unchanged rules unless forceRestart is requested.
func sameRuleSpec(a, b protocol.RuleSpec) bool {
	if a.RuleID != b.RuleID || a.Role != b.Role || effectiveEngine(a) != effectiveEngine(b) ||
		a.Protocol != b.Protocol || a.ListenHost != b.ListenHost || a.ListenPort != b.ListenPort ||
		a.LoadBalance != b.LoadBalance || a.SpeedLimitMbps != b.SpeedLimitMbps || a.MaxConns != b.MaxConns ||
		len(a.Targets) != len(b.Targets) {
		return false
	}
	for i := range a.Targets {
		if a.Targets[i] != b.Targets[i] {
			return false
		}
	}
	if (a.Tunnel == nil) != (b.Tunnel == nil) {
		return false
	}
	if a.Tunnel != nil && b.Tunnel != nil && *a.Tunnel != *b.Tunnel {
		return false
	}
	return true
}

func sameTargets(a, b []protocol.TargetEndpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SyncAll reconciles the desired list of RuleSpecs with currently running rules.
// When forceRestart is false, already-running rules with identical configuration are kept alive without interruption.
func (m *Manager) SyncAll(ctx context.Context, desired []protocol.RuleSpec, forceRestart ...bool) []protocol.RuleStatusAckPayload {
	force := len(forceRestart) > 0 && forceRestart[0]
	desiredKeys := make(map[string]bool, len(desired))
	var acks []protocol.RuleStatusAckPayload

	for _, spec := range desired {
		if spec.Role == "" {
			spec.Role = protocol.RoleRelay
		}
		key := RuleKey(spec.RuleID, spec.Role)
		desiredKeys[key] = true

		if !force {
			m.mu.RLock()
			existing, exists := m.activeSpecs[key]
			resolved := m.resolvedSpecs[key]
			engine := m.ruleBinding[key]
			m.mu.RUnlock()
			if exists && sameRuleSpec(existing, spec) {
				unchanged := true
				if needsPinnedTargets(engine) {
					// Hostname targets on external engines are pinned to IPs; re-resolve and re-apply only when the
					// DNS answer changed (still validated against the sandbox policy).
					allowPrivate := m.policy.AllowPrivateTargets || spec.Role == protocol.RoleIngress
					pinned, err := security.ResolveTargets(ctx, spec.Targets, allowPrivate)
					if err == nil && !sameTargets(pinned, resolved.Targets) {
						unchanged = false
					}
				}
				if unchanged {
					acks = append(acks, protocol.RuleStatusAckPayload{
						RuleID:  spec.RuleID,
						Role:    spec.Role,
						Engine:  engine,
						Success: true,
					})
					continue
				}
			}
		}

		err := m.ApplyRule(ctx, spec)
		m.mu.RLock()
		engine := m.ruleBinding[key]
		m.mu.RUnlock()
		if engine == "" {
			engine = spec.Engine
		}
		ack := protocol.RuleStatusAckPayload{
			RuleID:  spec.RuleID,
			Role:    spec.Role,
			Engine:  engine,
			Success: err == nil,
		}
		if err != nil {
			ack.Error = err.Error()
		}
		acks = append(acks, ack)
	}

	// Remove stale rules no longer in desired list
	m.mu.RLock()
	var stale []protocol.RuleSpec
	for key, spec := range m.activeSpecs {
		if !desiredKeys[key] {
			stale = append(stale, spec)
		}
	}
	m.mu.RUnlock()

	for _, s := range stale {
		_ = m.RemoveRule(s.RuleID, s.Role)
	}

	return acks
}

// CollectAllDeltas gathers incremental traffic statistics across all registered engines.
func (m *Manager) CollectAllDeltas() (deltas []protocol.RuleTrafficDelta, totalRules int, totalConns int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, d := range m.drivers {
		if !d.Available() {
			continue
		}
		totalRules += d.ActiveRuleCount()
		engineDeltas := d.CollectDeltas()
		for _, dt := range engineDeltas {
			totalConns += dt.ActiveConns
			if dt.UploadBytes > 0 || dt.DownBytes > 0 || dt.ActiveConns > 0 {
				deltas = append(deltas, dt)
			}
		}
	}
	return deltas, totalRules, totalConns
}

// Close shuts down all engine drivers cleanly.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.drivers {
		_ = d.Close()
	}
	return nil
}
