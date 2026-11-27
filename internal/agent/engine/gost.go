package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/pkg/protocol"
)

type gostRuleProcess struct {
	spec       protocol.RuleSpec
	configPath string
	caPaths    []string
	cmd        *exec.Cmd
	cancel     context.CancelFunc
}

// GostEngine drives external `gost` (GOST v3) binary processes for rules configured with EngineGost.
// Tunnel transports are always TLS-based (tls / wss / quic) with certificate verification against the
// Egress certificate pinned by Master.
type GostEngine struct {
	mu      sync.RWMutex
	binPath string
	workDir string
	cert    *security.TunnelCert
	procs   map[string]*gostRuleProcess
}

// NewGostEngine creates the gost driver. workDir must be a private (0700) directory; cert is the node's tunnel
// identity used when acting as an Egress (may be nil, in which case Egress tunnel rules are rejected).
func NewGostEngine(workDir string, cert *security.TunnelCert) *GostEngine {
	bin, _ := exec.LookPath("gost")
	return &GostEngine{
		binPath: bin,
		workDir: workDir,
		cert:    cert,
		procs:   make(map[string]*gostRuleProcess),
	}
}

func (g *GostEngine) Name() protocol.EngineType {
	return protocol.EngineGost
}

func (g *GostEngine) Available() bool {
	if g.binPath != "" {
		return true
	}
	bin, err := exec.LookPath("gost")
	if err == nil {
		g.binPath = bin
		return true
	}
	return false
}

func cleanupGostFiles(paths []string) {
	for _, p := range paths {
		if p != "" {
			_ = os.Remove(p)
		}
	}
}

func (g *GostEngine) ApplyRule(ctx context.Context, spec protocol.RuleSpec) error {
	if !g.Available() {
		return fmt.Errorf("gost binary not found in PATH")
	}
	if g.workDir == "" {
		return fmt.Errorf("gost work directory not configured")
	}
	key := RuleKey(spec.RuleID, spec.Role)
	_ = g.RemoveRule(key, spec.RuleID, spec.Role)

	var caPaths []string
	if protocol.IsTunnelClientRole(spec.Role) && spec.Tunnel != nil {
		if len(spec.Targets) == 0 {
			return fmt.Errorf("rule %s: no tunnel targets configured", key)
		}
		caPaths = make([]string, len(spec.Targets))
		for idx, t := range spec.Targets {
			rawPEM := strings.TrimSpace(t.CertPEM)
			if rawPEM == "" {
				rawPEM = strings.TrimSpace(spec.Tunnel.CertPEM)
			}
			if rawPEM == "" {
				cleanupGostFiles(caPaths)
				return fmt.Errorf("rule %s: next-hop tunnel certificate unavailable for target %d", key, idx)
			}
			if err := security.ValidateTunnelCertPEM(rawPEM); err != nil {
				cleanupGostFiles(caPaths)
				return fmt.Errorf("rule %s: target %d tunnel certificate invalid: %w", key, idx, err)
			}
			if !strings.HasSuffix(rawPEM, "\n") {
				rawPEM += "\n"
			}
			p := filepath.Join(g.workDir, fmt.Sprintf("gost-rule-%d-%s-ca-%d.pem", spec.RuleID, spec.Role, idx))
			if err := security.WriteFileAtomic(p, []byte(rawPEM), 0600); err != nil {
				cleanupGostFiles(caPaths)
				return err
			}
			caPaths[idx] = p
		}
	}

	cfgData, err := g.buildGostConfig(spec, caPaths)
	if err != nil {
		cleanupGostFiles(caPaths)
		return err
	}

	cfgFile := filepath.Join(g.workDir, fmt.Sprintf("gost-rule-%d-%s.json", spec.RuleID, spec.Role))
	if err := security.WriteFileAtomic(cfgFile, cfgData, 0600); err != nil {
		cleanupGostFiles(caPaths)
		return err
	}

	procCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(procCtx, g.binPath, "-C", cfgFile)
	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(cfgFile)
		cleanupGostFiles(caPaths)
		return fmt.Errorf("failed to start gost for rule %s: %w", key, err)
	}

	proc := &gostRuleProcess{
		spec:       spec,
		configPath: cfgFile,
		caPaths:    caPaths,
		cmd:        cmd,
		cancel:     cancel,
	}
	g.mu.Lock()
	g.procs[key] = proc
	g.mu.Unlock()

	acctProto := "tcp"
	if protocol.IsTunnelServerRole(spec.Role) && spec.Tunnel != nil && gostTunnelTransport(spec.Tunnel.Transport) == "quic" {
		acctProto = "udp"
	}
	sharedPortCounter.TrackPort(key, spec.ListenPort, acctProto)
	go g.superviseProcess(procCtx, key, proc)

	log.Printf("[GostEngine] Started gost process (PID %d) for rule %s on port %d", cmd.Process.Pid, key, spec.ListenPort)
	return nil
}

// superviseProcess monitors a gost child process and restarts it automatically if it crashes unexpectedly.
func (g *GostEngine) superviseProcess(ctx context.Context, key string, proc *gostRuleProcess) {
	for {
		if proc.cmd != nil {
			_ = proc.cmd.Wait()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		g.mu.Lock()
		cur, exists := g.procs[key]
		if !exists || cur != proc || ctx.Err() != nil {
			g.mu.Unlock()
			return
		}
		restarted := exec.CommandContext(ctx, g.binPath, "-C", proc.configPath)
		if err := restarted.Start(); err != nil {
			g.mu.Unlock()
			log.Printf("[GostEngine] Supervisor failed to restart gost for rule %s: %v", key, err)
			continue
		}
		proc.cmd = restarted
		pid := restarted.Process.Pid
		g.mu.Unlock()
		log.Printf("[GostEngine] Supervisor self-healed gost process (new PID %d) for rule %s", pid, key)
	}
}

// gostTunnelTransport maps the panel transport to an encrypted gost listener/dialer type.
// Plaintext options ("raw", "ws", "kcp", "custom", ...) are upgraded to their TLS counterparts.
func gostTunnelTransport(t string) string {
	switch t {
	case "ws", "wss":
		return "wss"
	case "quic":
		return "quic"
	default:
		return "tls"
	}
}

// buildGostConfig generates a GOST v3 JSON configuration for Relay, Ingress, intermediate Hop, or Egress.
func (g *GostEngine) buildGostConfig(spec protocol.RuleSpec, caPaths []string) ([]byte, error) {
	listenAddr := fmt.Sprintf(":%d", spec.ListenPort)
	if cleanHost := strings.Trim(strings.TrimSpace(spec.ListenHost), "[]"); cleanHost != "" {
		listenAddr = net.JoinHostPort(cleanHost, strconv.Itoa(spec.ListenPort))
	}

	pp := spec.ProxyProto
	if pp == 0 && spec.Tunnel != nil {
		pp = spec.Tunnel.ProxyProto
	}

	var nodes []map[string]any
	for i, t := range spec.Targets {
		n := map[string]any{
			"name": fmt.Sprintf("target-%d", i),
			"addr": t.Address,
		}
		if (spec.Role == protocol.RoleRelay || spec.Role == protocol.RoleEgress) && (pp == 1 || pp == 2) {
			n["metadata"] = map[string]any{
				"proxyProtocol": fmt.Sprintf("%d", pp),
			}
		}
		nodes = append(nodes, n)
	}

	isServer := protocol.IsTunnelServerRole(spec.Role) && spec.Tunnel != nil
	isClient := protocol.IsTunnelClientRole(spec.Role) && spec.Tunnel != nil

	handlerType := "tcp"
	listenerMap := map[string]any{"type": "tcp"}
	if isServer {
		if g.cert == nil {
			return nil, fmt.Errorf("local tunnel certificate unavailable, refusing to start %s", spec.Role)
		}
		handlerType = "relay"
		listenerMap = map[string]any{
			"type": gostTunnelTransport(spec.Tunnel.Transport),
			"tls": map[string]any{
				"certFile": g.cert.CertFile,
				"keyFile":  g.cert.KeyFile,
			},
		}
	}

	handlerMap := map[string]any{"type": handlerType}
	if isServer && spec.Tunnel.SecretKey != "" {
		handlerMap["auth"] = map[string]any{
			"username": fmt.Sprintf("rule-%d", spec.RuleID),
			"password": spec.Tunnel.SecretKey,
		}
	}
	if outIP := strings.Trim(strings.TrimSpace(spec.OutboundIP), "[]"); outIP != "" && !isClient {
		handlerMap["metadata"] = map[string]any{"interface": outIP}
	}

	service := map[string]any{
		"name":     fmt.Sprintf("rule-%d-%s", spec.RuleID, spec.Role),
		"addr":     listenAddr,
		"handler":  handlerMap,
		"listener": listenerMap,
	}

	var chains []map[string]any
	if isClient {
		if len(caPaths) != len(spec.Targets) {
			return nil, fmt.Errorf("next-hop tunnel certificate unavailable")
		}
		dialerType := gostTunnelTransport(spec.Tunnel.Transport)
		chainName := fmt.Sprintf("chain-%d-%s", spec.RuleID, spec.Role)
		handlerMap["chain"] = chainName
		service["handler"] = handlerMap
		if !isServer {
			// Ingress forwards user's target via the relay chain; Hop relays whatever target Egress resolves
			service["forwarder"] = map[string]any{
				"nodes": nodes,
			}
		}
		connectorMap := map[string]any{"type": "relay"}
		if spec.Tunnel.SecretKey != "" {
			connectorMap["auth"] = map[string]any{
				"username": fmt.Sprintf("rule-%d", spec.RuleID),
				"password": spec.Tunnel.SecretKey,
			}
		}

		var hopNodes []map[string]any
		for idx, t := range spec.Targets {
			if caPaths[idx] == "" {
				return nil, fmt.Errorf("next-hop tunnel certificate unavailable for target %d", idx)
			}
			dialerMap := map[string]any{
				"type": dialerType,
				"tls": map[string]any{
					"secure":     true,
					"serverName": protocol.TunnelServerName,
					"caFile":     caPaths[idx],
				},
			}
			if outIP := strings.Trim(strings.TrimSpace(spec.OutboundIP), "[]"); outIP != "" {
				dialerMap["metadata"] = map[string]any{"interface": outIP}
			}
			hopNodes = append(hopNodes, map[string]any{
				"name":      fmt.Sprintf("peer-%d", idx),
				"addr":      t.Address,
				"connector": connectorMap,
				"dialer":    dialerMap,
			})
		}

		hopMap := map[string]any{
			"name":  "hop-0",
			"nodes": hopNodes,
		}
		if len(hopNodes) > 1 {
			strat := "round"
			if spec.LoadBalance == "failover" {
				strat = "fifo"
			} else if spec.LoadBalance == "random" {
				strat = "rand"
			}
			hopMap["selector"] = map[string]any{
				"strategy":    strat,
				"maxFails":    2,
				"failTimeout": "15s",
			}
		}

		chains = append(chains, map[string]any{
			"name": chainName,
			"hops": []map[string]any{hopMap},
		})
	} else {
		service["forwarder"] = map[string]any{
			"nodes": nodes,
		}
	}

	root := map[string]any{
		"services": []any{service},
	}
	if len(chains) > 0 {
		root["chains"] = chains
	}
	return json.MarshalIndent(root, "", "  ")
}

func (g *GostEngine) RemoveRule(ruleKey string, ruleID uint64, role protocol.RuleRole) error {
	g.mu.Lock()
	proc, exists := g.procs[ruleKey]
	if exists {
		delete(g.procs, ruleKey)
	}
	g.mu.Unlock()

	if !exists {
		return nil
	}
	sharedPortCounter.UntrackPort(ruleKey)
	proc.cancel()
	if proc.cmd != nil && proc.cmd.Process != nil {
		_ = proc.cmd.Process.Kill()
	}
	_ = os.Remove(proc.configPath)
	cleanupGostFiles(proc.caPaths)
	return nil
}

func (g *GostEngine) CollectDeltas() []protocol.RuleTrafficDelta {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.procs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(g.procs))
	for k := range g.procs {
		keys = append(keys, k)
	}
	portDeltas := sharedPortCounter.HarvestDeltas(keys)

	var list []protocol.RuleTrafficDelta
	for k, proc := range g.procs {
		d := portDeltas[k]
		list = append(list, protocol.RuleTrafficDelta{
			RuleID:      proc.spec.RuleID,
			Role:        proc.spec.Role,
			Engine:      protocol.EngineGost,
			UploadBytes: d[0],
			DownBytes:   d[1],
		})
	}
	return list
}

func (g *GostEngine) ActiveRuleCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.procs)
}

func (g *GostEngine) Close() error {
	g.mu.Lock()
	keys := make([]string, 0, len(g.procs))
	for k := range g.procs {
		keys = append(keys, k)
	}
	g.mu.Unlock()

	for _, k := range keys {
		_ = g.RemoveRule(k, 0, "")
	}
	return nil
}
