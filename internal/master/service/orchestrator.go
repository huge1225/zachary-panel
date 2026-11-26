package service

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/protocol"
	"nexus-panel/pkg/utils"
)

// Orchestrator coordinates rule compilation, dual-end tunnel pairing (Ingress <-> Egress),
// port allocation, and real-time traffic billing.
type Orchestrator struct {
	db       *gorm.DB
	hub      *hub.AgentHub
	notifier *Notifier

	// allocMu serializes quota checks, port allocation and rule persistence so that concurrent requests cannot
	// exceed rule / port quotas or allocate the same port twice (TOCTOU).
	allocMu sync.Mutex
}

// Traffic accounting safety ceilings: bound per-rule delta, per-report aggregate delta, and rate multiplier scaling
// so a misbehaving or compromised Agent can never underflow/overflow int64 counters.
const (
	maxDeltaBytes        int64   = 10 << 30 // 10 GiB per rule per report window
	maxReportWindowBytes int64   = 64 << 30 // 64 GiB aggregate across a single report frame
	maxBilledDeltaBytes  int64   = 1 << 40  // 1 TiB ceiling after multiplier
	maxRateMultiplier    float64 = 1000.0

	// OrderExpireTimeout defines how long an unpaid pending BillingOrder remains payable before auto-closing.
	OrderExpireTimeout = 30 * time.Minute
)

func sanitizeRateMultiplier(m float64) float64 {
	if math.IsNaN(m) || math.IsInf(m, 0) || m <= 0 {
		return 1.0
	}
	if m > maxRateMultiplier {
		return maxRateMultiplier
	}
	return m
}

func safeScaleBytes(baseBytes int64, multiplier float64) int64 {
	if baseBytes <= 0 {
		return 0
	}
	m := sanitizeRateMultiplier(multiplier)
	scaled := math.Round(float64(baseBytes) * m)
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) || scaled <= 0 {
		return 0
	}
	if scaled >= float64(maxBilledDeltaBytes) {
		return maxBilledDeltaBytes
	}
	return int64(scaled)
}

func NewOrchestrator(db *gorm.DB, agentHub *hub.AgentHub) *Orchestrator {
	o := &Orchestrator{
		db:       db,
		hub:      agentHub,
		notifier: NewNotifier(db),
	}
	agentHub.SetCallbacks(o.HandleTrafficReport, func(nodeID uint64) {
		o.SyncNodeRules(nodeID)
		var n model.Node
		if err := o.db.First(&n, nodeID).Error; err == nil {
			o.notifier.NotifyNodeEventAsync(
				"node_online",
				"节点上线通知",
				fmt.Sprintf("节点 #%d「%s」(%s) 已建立连接并同步规则。", n.ID, n.Name, n.ConnectIP),
			)
		}
	})
	agentHub.SetOfflineCallback(func(nodeID uint64) {
		var n model.Node
		if err := o.db.First(&n, nodeID).Error; err == nil {
			o.notifier.NotifyNodeEventAsync(
				"node_offline",
				"节点离线告警",
				fmt.Sprintf("节点 #%d「%s」(%s) 已与主控面板断开连接，请检查服务器网络或 Agent 状态。", n.ID, n.Name, n.ConnectIP),
			)
		}
	})
	agentHub.SetCertChangedCallback(o.OnEgressCertChanged)
	agentHub.SetAckScope(o.NodeOwnsRuleRole)
	return o
}

// Notifier returns the operational alert notifier instance.
func (o *Orchestrator) Notifier() *Notifier {
	return o.notifier
}

// WithAllocLock runs fn while holding the allocation lock. Handlers must perform quota counting, port allocation
// and the DB insert/update of rules inside fn, and dispatch to agents only after it returns.
func (o *Orchestrator) WithAllocLock(fn func() error) error {
	o.allocMu.Lock()
	defer o.allocMu.Unlock()
	return fn()
}

// NodeOwnsRuleRole reports whether nodeID legitimately hosts ruleID in the given role:
//   - relay / ingress: the rule's ingress node
//   - egress: the egress node of the rule's encrypted tunnel line
func (o *Orchestrator) NodeOwnsRuleRole(nodeID, ruleID uint64, role protocol.RuleRole) bool {
	var rule model.ForwardRule
	if err := o.db.Select("id, mode, ingress_node_id, tunnel_line_id").First(&rule, ruleID).Error; err != nil {
		return false
	}
	return o.ruleOwnedBy(&rule, nodeID, role)
}

func (o *Orchestrator) ruleOwnedBy(rule *model.ForwardRule, nodeID uint64, role protocol.RuleRole) bool {
	switch role {
	case protocol.RoleEgress:
		if rule.Mode != "tunnel" || rule.TunnelLineID == 0 {
			return false
		}
		var line model.TunnelLine
		if err := o.db.Select("id, egress_node_id").First(&line, rule.TunnelLineID).Error; err != nil {
			return false
		}
		return line.EgressNodeID == nodeID
	case protocol.RoleIngress, protocol.RoleRelay, "":
		return rule.IngressNodeID == nodeID
	default:
		return false
	}
}

// OnEgressCertChanged re-dispatches every enabled rule on tunnel lines that use nodeID as egress so ingress nodes
// pin the new certificate.
func (o *Orchestrator) OnEgressCertChanged(nodeID uint64) {
	var lineIDs []uint64
	o.db.Model(&model.TunnelLine{}).Where("egress_node_id = ?", nodeID).Pluck("id", &lineIDs)
	if len(lineIDs) == 0 {
		return
	}
	var rules []model.ForwardRule
	o.db.Where("tunnel_line_id IN ? AND enabled = ?", lineIDs, true).Find(&rules)
	for i := range rules {
		o.DispatchRule(&rules[i])
	}
	if len(rules) > 0 {
		log.Printf("[Orchestrator] Egress node #%d rotated its tunnel certificate; re-dispatched %d rules", nodeID, len(rules))
	}
}

// EffectivePortRange returns the port window used for allocations on a node: the node's PortRange, narrowed to the
// tunnel's own PortRange when one is configured (lineRange).
func (o *Orchestrator) EffectivePortRange(node *model.Node, lineRange string) (int, int, error) {
	minP, maxP, err := utils.ParsePortRange(node.PortRange)
	if err != nil {
		minP, maxP = 10000, 50000
	}
	if strings.TrimSpace(lineRange) != "" {
		lmin, lmax, lerr := utils.ParsePortRange(lineRange)
		if lerr != nil {
			return 0, 0, fmt.Errorf("invalid tunnel port range %q", lineRange)
		}
		if lmin > minP {
			minP = lmin
		}
		if lmax < maxP {
			maxP = lmax
		}
		if minP > maxP {
			return 0, 0, fmt.Errorf("tunnel port range %s does not overlap node %s range %s", lineRange, node.Name, node.PortRange)
		}
	}
	return minP, maxP, nil
}

// PortInRange reports whether port lies inside the effective allocation window of the node (and tunnel range).
func (o *Orchestrator) PortInRange(nodeID uint64, port int, lineRange string) bool {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return false
	}
	minP, maxP, err := o.EffectivePortRange(&node, lineRange)
	return err == nil && port >= minP && port <= maxP
}

// OccupiedPorts returns every port held on nodeID: listen ports of rules entering there and relay ports of tunnel
// legs ending there (by relay_node_id, plus rules of tunnels currently egressing there that may not have recorded
// relay_node_id yet). Callers must hold WithAllocLock.
func (o *Orchestrator) OccupiedPorts(nodeID uint64) map[int]bool {
	occupied := make(map[int]bool)
	var ports []int
	o.db.Model(&model.ForwardRule{}).Where("ingress_node_id = ? AND listen_port > 0", nodeID).Pluck("listen_port", &ports)
	for _, p := range ports {
		occupied[p] = true
	}
	ports = ports[:0]
	o.db.Model(&model.ForwardRule{}).Where("relay_node_id = ? AND relay_port > 0", nodeID).Pluck("relay_port", &ports)
	for _, p := range ports {
		occupied[p] = true
	}
	var lineIDs []uint64
	o.db.Model(&model.TunnelLine{}).Where("egress_node_id = ?", nodeID).Pluck("id", &lineIDs)
	if len(lineIDs) > 0 {
		ports = ports[:0]
		o.db.Model(&model.ForwardRule{}).Where("tunnel_line_id IN ? AND relay_port > 0", lineIDs).Pluck("relay_port", &ports)
		for _, p := range ports {
			occupied[p] = true
		}
	}
	return occupied
}

// PickFreePort returns the lowest port in [minP, maxP] that is neither occupied nor rejected by the listen-port
// policy, and marks it occupied so repeated calls with the same map hand out distinct ports (batch allocation).
func PickFreePort(minP, maxP int, occupied map[int]bool) (int, error) {
	for p := minP; p <= maxP; p++ {
		if occupied[p] {
			continue
		}
		if security.ValidateListenPort(p, security.DefaultPolicy) != nil {
			continue
		}
		occupied[p] = true
		return p, nil
	}
	return 0, fmt.Errorf("no free ports available in range %d-%d", minP, maxP)
}

// AllocatePortForNode finds an unused port in the node's PortRange (narrowed to the tunnel's PortRange when the
// optional lineRange is given). Callers must hold WithAllocLock.
func (o *Orchestrator) AllocatePortForNode(nodeID uint64, requestedPort int, lineRange ...string) (int, error) {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return 0, fmt.Errorf("node %d not found", nodeID)
	}
	lr := ""
	if len(lineRange) > 0 {
		lr = lineRange[0]
	}
	minP, maxP, err := o.EffectivePortRange(&node, lr)
	if err != nil {
		return 0, err
	}
	occupied := o.OccupiedPorts(nodeID)

	if requestedPort > 0 {
		if err := security.ValidateListenPort(requestedPort, security.DefaultPolicy); err != nil {
			return 0, err
		}
		if requestedPort < minP || requestedPort > maxP {
			return 0, fmt.Errorf("端口 %d 不在允许范围 %d-%d 内", requestedPort, minP, maxP)
		}
		if occupied[requestedPort] {
			return 0, fmt.Errorf("port %d is already in use on node %s", requestedPort, node.Name)
		}
		return requestedPort, nil
	}
	return PickFreePort(minP, maxP, occupied)
}

// EffectiveEngine returns the engine a rule actually runs on. gost / realm cannot enforce per-rule bandwidth limits
// or per-rule IP ACLs, so rules that carry a speed limit (for non-admins, or explicit rule-level speed limit) or
// an active IP ACL run on the native engine instead.
func EffectiveEngine(rule *model.ForwardRule, owner *model.User) protocol.EngineType {
	eng := rule.Engine
	if eng == "" {
		eng = protocol.EngineNative
	}
	if (rule.AccessMode == "allow" || rule.AccessMode == "deny") && strings.TrimSpace(rule.AccessCIDRs) != "" {
		return protocol.EngineNative
	}
	speedLimit := rule.SpeedMbps
	if speedLimit <= 0 && owner != nil {
		speedLimit = owner.SpeedMbps
	}
	isAdmin := owner != nil && owner.Role == "admin"
	if speedLimit > 0 && !isAdmin && (eng == protocol.EngineGost || eng == protocol.EngineRealm) {
		eng = protocol.EngineNative
	}
	return eng
}

// CompileRuleSpecs transforms a database ForwardRule into 1 (Direct) or 2 (Ingress + Egress) runtime RuleSpecs.
func (o *Orchestrator) CompileRuleSpecs(rule *model.ForwardRule) (ingressSpec *protocol.RuleSpec, egressNodeID uint64, egressSpec *protocol.RuleSpec, err error) {
	var user model.User
	if err := o.db.First(&user, rule.UserID).Error; err != nil {
		return nil, 0, nil, err
	}

	speedLimit := rule.SpeedMbps
	if speedLimit <= 0 {
		speedLimit = user.SpeedMbps
	}

	var targets []protocol.TargetEndpoint
	if err := json.Unmarshal([]byte(rule.TargetsJSON), &targets); err != nil || len(targets) == 0 {
		return nil, 0, nil, fmt.Errorf("invalid targets_json for rule %d", rule.ID)
	}

	eng := EffectiveEngine(rule, &user)

	// Check if this rule uses an encrypted dual-node tunnel (Type == "encrypt") or direct forwarding (Type == "direct")
	var line model.TunnelLine
	hasTunnelLine := false
	if rule.TunnelLineID > 0 {
		if err := o.db.First(&line, rule.TunnelLineID).Error; err != nil {
			return nil, 0, nil, fmt.Errorf("tunnel line %d not found", rule.TunnelLineID)
		}
		if !line.Enabled {
			return nil, 0, nil, fmt.Errorf("tunnel line %d is disabled", rule.TunnelLineID)
		}
		hasTunnelLine = true
	}

	// Case 1: Single-node Direct Forwarding (专线/直连节点直接转发隧道 or standalone direct rule)
	if !hasTunnelLine || line.Type == "direct" || line.EgressNodeID == 0 || rule.Mode == "direct" {
		spec := &protocol.RuleSpec{
			RuleID:         rule.ID,
			UserID:         rule.UserID,
			Name:           rule.Name,
			Role:           protocol.RoleRelay,
			Engine:         eng,
			Protocol:       rule.Protocol,
			ListenHost:     "0.0.0.0",
			ListenPort:     rule.ListenPort,
			LoadBalance:    rule.LoadBalance,
			Targets:        targets,
			SpeedLimitMbps: speedLimit,
			MaxConns:       8192,
			AccessMode:     rule.AccessMode,
			AccessCIDRs:    rule.AccessCIDRs,
			UpdatedAt:      rule.UpdatedAt,
		}
		return spec, 0, nil, nil
	}

	// Case 2: Encrypted Dual-Node Tunnel (国内入口节点 ⇄ 国外出口节点加密对接隧道)
	var egressNode model.Node
	if err := o.db.First(&egressNode, line.EgressNodeID).Error; err != nil {
		return nil, 0, nil, fmt.Errorf("egress node %d not found", line.EgressNodeID)
	}

	// Ensure RelayPort and TunnelSecret are allocated
	if rule.RelayPort <= 0 {
		err := o.WithAllocLock(func() error {
			// Re-read under the lock in case a concurrent dispatch already allocated it.
			var cur model.ForwardRule
			if err := o.db.Select("id, relay_port, relay_node_id").First(&cur, rule.ID).Error; err == nil && cur.RelayPort > 0 {
				rule.RelayPort = cur.RelayPort
				rule.RelayNodeID = cur.RelayNodeID
				return nil
			}
			rp, err := o.AllocatePortForNode(egressNode.ID, 0)
			if err != nil {
				return err
			}
			rule.RelayPort = rp
			rule.RelayNodeID = egressNode.ID
			return o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).
				Updates(map[string]any{"relay_port": rp, "relay_node_id": egressNode.ID}).Error
		})
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to allocate egress port: %w", err)
		}
	}
	if rule.TunnelSecret == "" {
		rule.TunnelSecret = utils.GenerateRandomToken(32)
		o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Update("tunnel_secret", rule.TunnelSecret)
	}

	// Only native and gost implement the authenticated, certificate-pinned encrypted tunnel. Other engines would
	// send the inter-node leg in clear text, so tunnel legs fall back to the native engine.
	if eng != protocol.EngineNative && eng != protocol.EngineGost {
		eng = protocol.EngineNative
	}

	egressConnectHost := egressNode.ServerIP
	if egressConnectHost == "" {
		egressConnectHost = egressNode.InternalHost
	}
	if egressConnectHost == "" {
		egressConnectHost = egressNode.ConnectIP
	}
	if egressConnectHost == "" {
		egressConnectHost = egressNode.PublicHost
	}

	tunnelCfg := &protocol.TunnelConfig{
		Transport: line.Transport,
		SecretKey: rule.TunnelSecret,
		SNI:       egressNode.PublicHost,
		CertPEM:   egressNode.TunnelCertPEM,
	}

	// Egress spec: listens on RelayPort (with tunnel transport) and forwards to user's actual targets
	egSpec := &protocol.RuleSpec{
		RuleID:         rule.ID,
		UserID:         rule.UserID,
		Name:           fmt.Sprintf("%s [Egress]", rule.Name),
		Role:           protocol.RoleEgress,
		Engine:         eng,
		Protocol:       rule.Protocol,
		ListenHost:     "0.0.0.0",
		ListenPort:     rule.RelayPort,
		LoadBalance:    rule.LoadBalance,
		Targets:        targets,
		Tunnel:         tunnelCfg,
		SpeedLimitMbps: speedLimit,
		MaxConns:       8192,
		UpdatedAt:      rule.UpdatedAt,
	}

	// Ingress spec: listens on user's ListenPort and tunnels traffic to EgressNode:RelayPort
	inSpec := &protocol.RuleSpec{
		RuleID:      rule.ID,
		UserID:      rule.UserID,
		Name:        fmt.Sprintf("%s [Ingress]", rule.Name),
		Role:        protocol.RoleIngress,
		Engine:      eng,
		Protocol:    rule.Protocol,
		ListenHost:  "0.0.0.0",
		ListenPort:  rule.ListenPort,
		LoadBalance: "round_robin",
		Targets: []protocol.TargetEndpoint{
			{Address: fmt.Sprintf("%s:%d", egressConnectHost, rule.RelayPort)},
		},
		Tunnel:         tunnelCfg,
		SpeedLimitMbps: speedLimit,
		MaxConns:       8192,
		AccessMode:     rule.AccessMode,
		AccessCIDRs:    rule.AccessCIDRs,
		UpdatedAt:      rule.UpdatedAt,
	}

	return inSpec, egressNode.ID, egSpec, nil
}

// DispatchRule pushes a rule's runtime specs (or removal if paused/disabled) to its Ingress and Egress Agents.
func (o *Orchestrator) DispatchRule(rule *model.ForwardRule) {
	// Defense in depth: never push a rule whose owner is banned / expired / over quota or lost the tunnel
	// permission, whichever code path asked for it.
	if rule.Enabled && !o.ownerMayRun(rule) {
		rule = &model.ForwardRule{ID: rule.ID, UserID: rule.UserID, Mode: rule.Mode, IngressNodeID: rule.IngressNodeID,
			TunnelLineID: rule.TunnelLineID, Engine: rule.Engine, Enabled: false}
	}
	if !rule.Enabled {
		_ = o.hub.SendToNode(rule.IngressNodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
			RuleID: rule.ID,
			Role:   o.ingressRoleFor(rule),
		})
		if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
			var line model.TunnelLine
			if err := o.db.First(&line, rule.TunnelLineID).Error; err == nil {
				_ = o.hub.SendToNode(line.EgressNodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
					RuleID: rule.ID,
					Role:   protocol.RoleEgress,
				})
			}
		}
		return
	}

	inSpec, egressNodeID, egSpec, err := o.CompileRuleSpecs(rule)
	if err != nil {
		log.Printf("[Orchestrator] Failed to compile rule %d: %v", rule.ID, err)
		return
	}

	// Push Egress first so the tunnel endpoint is ready before Ingress dials it
	if egSpec != nil && egressNodeID > 0 {
		_ = o.hub.SendToNode(egressNodeID, protocol.MsgApplyRule, *egSpec)
	}
	if inSpec != nil {
		if err := o.hub.SendToNode(rule.IngressNodeID, protocol.MsgApplyRule, *inSpec); err != nil {
			// Node is currently offline; rule will be synced automatically when node connects
			o.db.Model(rule).Update("status", "syncing")
		}
	}
}

func (o *Orchestrator) tunnelLineEnabled(lineID uint64) bool {
	if lineID == 0 {
		return true
	}
	var line model.TunnelLine
	if err := o.db.Select("id, enabled").First(&line, lineID).Error; err != nil {
		return false
	}
	return line.Enabled
}

// ownerMayRun reports whether the rule's owner and bound tunnel line currently permit deploying this rule.
func (o *Orchestrator) ownerMayRun(rule *model.ForwardRule) bool {
	var u model.User
	if err := o.db.First(&u, rule.UserID).Error; err != nil {
		return false
	}
	if !u.CanForward(time.Now()) || !u.HasTunnelPermission(rule.TunnelLineID) {
		return false
	}
	return o.tunnelLineEnabled(rule.TunnelLineID)
}

// RemoveRuleFromAgents tears down a deleted rule from all involved Agents.
func (o *Orchestrator) RemoveRuleFromAgents(rule *model.ForwardRule) {
	_ = o.hub.SendToNode(rule.IngressNodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
		RuleID: rule.ID,
		Role:   o.ingressRoleFor(rule),
	})
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		var line model.TunnelLine
		if err := o.db.First(&line, rule.TunnelLineID).Error; err == nil {
			_ = o.hub.SendToNode(line.EgressNodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
				RuleID: rule.ID,
				Role:   protocol.RoleEgress,
			})
		}
	}
}

func (o *Orchestrator) ingressRoleFor(rule *model.ForwardRule) protocol.RuleRole {
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		return protocol.RoleIngress
	}
	return protocol.RoleRelay
}

// SyncNodeRules compiles all active rules where nodeID is either the IngressNode or the EgressNode of a TunnelLine,
// and sends a MsgSyncAllRules snapshot to the Agent.
func (o *Orchestrator) SyncNodeRules(nodeID uint64, forceRestart ...bool) {
	force := len(forceRestart) > 0 && forceRestart[0]
	var specs []protocol.RuleSpec

	// 1. Rules where this node is the Ingress / Relay node
	var ingressRules []model.ForwardRule
	o.db.Where("ingress_node_id = ? AND enabled = ?", nodeID, true).Find(&ingressRules)

	// 2. Rules where this node is the Egress node via a TunnelLine
	var lines []model.TunnelLine
	o.db.Where("egress_node_id = ? AND enabled = ?", nodeID, true).Find(&lines)
	var tunnelRules []model.ForwardRule
	if len(lines) > 0 {
		lineIDs := make([]uint64, 0, len(lines))
		for _, l := range lines {
			lineIDs = append(lineIDs, l.ID)
		}
		o.db.Where("mode = 'tunnel' AND tunnel_line_id IN ? AND enabled = ?", lineIDs, true).Find(&tunnelRules)
	}

	// Batch preload bound tunnel lines for ingress rules so disabled lines are never pushed on reconnect/sync.
	inLineSet := make(map[uint64]struct{})
	for i := range ingressRules {
		if ingressRules[i].TunnelLineID > 0 {
			inLineSet[ingressRules[i].TunnelLineID] = struct{}{}
		}
	}
	enabledLines := make(map[uint64]bool, len(inLineSet)+len(lines))
	for _, l := range lines {
		enabledLines[l.ID] = l.Enabled
	}
	if len(inLineSet) > 0 {
		inLineIDs := make([]uint64, 0, len(inLineSet))
		for lid := range inLineSet {
			inLineIDs = append(inLineIDs, lid)
		}
		var fetchedLines []model.TunnelLine
		o.db.Select("id, enabled").Where("id IN ?", inLineIDs).Find(&fetchedLines)
		for _, l := range fetchedLines {
			enabledLines[l.ID] = l.Enabled
		}
	}

	// Batch preload owners for all candidate rules to avoid N+1 user queries during compilation & eligibility checks.
	userIDSet := make(map[uint64]struct{}, len(ingressRules)+len(tunnelRules))
	for i := range ingressRules {
		userIDSet[ingressRules[i].UserID] = struct{}{}
	}
	for i := range tunnelRules {
		userIDSet[tunnelRules[i].UserID] = struct{}{}
	}
	ownerMap := make(map[uint64]*model.User, len(userIDSet))
	canForward := make(map[uint64]bool, len(userIDSet))
	if len(userIDSet) > 0 {
		uids := make([]uint64, 0, len(userIDSet))
		for uid := range userIDSet {
			uids = append(uids, uid)
		}
		var owners []model.User
		o.db.Where("id IN ?", uids).Find(&owners)
		now := time.Now()
		for i := range owners {
			ownerMap[owners[i].ID] = &owners[i]
			canForward[owners[i].ID] = owners[i].CanForward(now)
		}
	}

	for i := range ingressRules {
		r := &ingressRules[i]
		owner := ownerMap[r.UserID]
		if owner == nil || !canForward[r.UserID] || !owner.HasTunnelPermission(r.TunnelLineID) {
			continue
		}
		if r.TunnelLineID > 0 && !enabledLines[r.TunnelLineID] {
			continue
		}
		inSpec, _, _, err := o.CompileRuleSpecs(r)
		if err == nil && inSpec != nil {
			specs = append(specs, *inSpec)
		}
	}

	for i := range tunnelRules {
		r := &tunnelRules[i]
		owner := ownerMap[r.UserID]
		if owner == nil || !canForward[r.UserID] || !owner.HasTunnelPermission(r.TunnelLineID) {
			continue
		}
		_, _, egSpec, err := o.CompileRuleSpecs(r)
		if err == nil && egSpec != nil {
			specs = append(specs, *egSpec)
		}
	}

	_ = o.hub.SendToNode(nodeID, protocol.MsgSyncAllRules, protocol.SyncAllRulesPayload{
		Rules:        specs,
		ForceRestart: force,
	})
	log.Printf("[Orchestrator] Synced %d rule specs to Node #%d (forceRestart=%v)", len(specs), nodeID, force)
}

// HandleTrafficReport processes incremental traffic reports from Agents, applies node/line multipliers,
// updates hourly analytics, and disables rules if the user's quota is exhausted.
func (o *Orchestrator) HandleTrafficReport(nodeID uint64, report protocol.TrafficReportPayload) {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return
	}
	if len(report.Deltas) == 0 {
		return
	}
	if len(report.Deltas) > 10000 {
		log.Printf("[Orchestrator] Dropped oversized traffic report from Node #%d (%d deltas)", nodeID, len(report.Deltas))
		return
	}

	// Pre-collect unique rule IDs so we batch-fetch rules and tunnel lines in O(1) queries instead of N+1 per delta.
	ruleIDSet := make(map[uint64]struct{}, len(report.Deltas))
	for _, d := range report.Deltas {
		if d.RuleID > 0 {
			ruleIDSet[d.RuleID] = struct{}{}
		}
	}
	if len(ruleIDSet) == 0 {
		return
	}
	ruleIDs := make([]uint64, 0, len(ruleIDSet))
	for id := range ruleIDSet {
		ruleIDs = append(ruleIDs, id)
	}
	var fetchedRules []model.ForwardRule
	o.db.Where("id IN ?", ruleIDs).Find(&fetchedRules)
	ruleMap := make(map[uint64]*model.ForwardRule, len(fetchedRules))
	lineIDSet := make(map[uint64]struct{})
	for i := range fetchedRules {
		r := &fetchedRules[i]
		ruleMap[r.ID] = r
		if r.TunnelLineID > 0 {
			lineIDSet[r.TunnelLineID] = struct{}{}
		}
	}
	lineMap := make(map[uint64]*model.TunnelLine, len(lineIDSet))
	if len(lineIDSet) > 0 {
		lineIDs := make([]uint64, 0, len(lineIDSet))
		for lid := range lineIDSet {
			lineIDs = append(lineIDs, lid)
		}
		var fetchedLines []model.TunnelLine
		o.db.Where("id IN ?", lineIDs).Find(&fetchedLines)
		for i := range fetchedLines {
			lineMap[fetchedLines[i].ID] = &fetchedLines[i]
		}
	}

	hourBucket := time.Now().Format("2006-01-02 15:00")
	var nodeWindowBytes int64
	seenRuleRoles := make(map[string]struct{}, len(report.Deltas))
	userBilledTotals := make(map[uint64]int64)

	for _, d := range report.Deltas {
		if d.RuleID == 0 {
			continue
		}
		normRole := d.Role
		if normRole == "" {
			normRole = protocol.RoleRelay
		}
		roleKey := fmt.Sprintf("%d:%s", d.RuleID, normRole)
		if _, dup := seenRuleRoles[roleKey]; dup {
			log.Printf("[Orchestrator] Dropped duplicate traffic delta entry from Node #%d for %s", nodeID, roleKey)
			continue
		}
		seenRuleRoles[roleKey] = struct{}{}

		// Clamp negative or oversized per-window deltas to [0, maxDeltaBytes] so malformed values can never subtract
		// usage or overflow int64, while genuine high-speed bursts are still billed up to the window cap.
		if d.UploadBytes < 0 {
			d.UploadBytes = 0
		} else if d.UploadBytes > maxDeltaBytes {
			log.Printf("[Orchestrator] Clamped oversized upload delta from Node #%d for rule #%d (%d -> %d)", nodeID, d.RuleID, d.UploadBytes, maxDeltaBytes)
			d.UploadBytes = maxDeltaBytes
		}
		if d.DownBytes < 0 {
			d.DownBytes = 0
		} else if d.DownBytes > maxDeltaBytes {
			log.Printf("[Orchestrator] Clamped oversized download delta from Node #%d for rule #%d (%d -> %d)", nodeID, d.RuleID, d.DownBytes, maxDeltaBytes)
			d.DownBytes = maxDeltaBytes
		}
		rawTotal := d.UploadBytes + d.DownBytes
		if rawTotal <= 0 {
			continue
		}

		if nodeWindowBytes+rawTotal > maxReportWindowBytes {
			log.Printf("[Orchestrator] Capped oversized report window from Node #%d at %d bytes", nodeID, nodeWindowBytes)
			break
		}

		rule, ok := ruleMap[d.RuleID]
		if !ok {
			continue
		}
		// Trust boundary: a node may only report traffic for rules it actually hosts in the reported role.
		owned := false
		switch d.Role {
		case protocol.RoleEgress:
			if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
				if line, lOk := lineMap[rule.TunnelLineID]; lOk && line.EgressNodeID == nodeID {
					owned = true
				}
			}
		case protocol.RoleIngress, protocol.RoleRelay, "":
			owned = rule.IngressNodeID == nodeID
		}
		if !owned {
			log.Printf("[Orchestrator] Dropped out-of-scope traffic delta from Node #%d (rule #%d, role %q)", nodeID, d.RuleID, d.Role)
			continue
		}
		nodeWindowBytes += rawTotal

		// Avoid double-billing dual-end tunnel rules for user quota: only bill user on Relay or Ingress role
		if d.Role == protocol.RoleEgress {
			continue
		}

		multiplier := sanitizeRateMultiplier(node.TrafficRate)
		billingMode := "two_way"
		if rule.TunnelLineID > 0 {
			if line, lOk := lineMap[rule.TunnelLineID]; lOk {
				if line.RateMultiplier > 0 {
					multiplier = sanitizeRateMultiplier(line.RateMultiplier)
				}
				if line.BillingMode == "one_way" {
					billingMode = "one_way"
				}
			}
		}

		// one_way (单向计费: 仅统计单方向较大值) vs two_way (双向计费: 上行+下行)
		baseBytes := rawTotal
		if billingMode == "one_way" {
			baseBytes = d.DownBytes
			if d.UploadBytes > baseBytes {
				baseBytes = d.UploadBytes
			}
		}
		billed := safeScaleBytes(baseBytes, multiplier)

		// Update ForwardRule counters
		o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
			"upload_bytes": gorm.Expr("upload_bytes + ?", d.UploadBytes),
			"down_bytes":   gorm.Expr("down_bytes + ?", d.DownBytes),
			"billed_bytes": gorm.Expr("billed_bytes + ?", billed),
		})

		userBilledTotals[rule.UserID] += billed

		// Upsert hourly traffic bucket using composite index idx_stat_user_rule_hour
		res := o.db.Model(&model.TrafficHourlyStat{}).
			Where("user_id = ? AND rule_id = ? AND hour_bucket = ?", rule.UserID, rule.ID, hourBucket).
			Updates(map[string]any{
				"upload_bytes": gorm.Expr("upload_bytes + ?", d.UploadBytes),
				"down_bytes":   gorm.Expr("down_bytes + ?", d.DownBytes),
				"billed_bytes": gorm.Expr("billed_bytes + ?", billed),
			})
		if res.Error == nil && res.RowsAffected == 0 {
			o.db.Create(&model.TrafficHourlyStat{
				UserID:      rule.UserID,
				RuleID:      rule.ID,
				NodeID:      nodeID,
				HourBucket:  hourBucket,
				UploadBytes: d.UploadBytes,
				DownBytes:   d.DownBytes,
				BilledBytes: billed,
			})
		}
	}

	if len(userBilledTotals) > 0 {
		touchedUIDs := make([]uint64, 0, len(userBilledTotals))
		for uid, totalBilled := range userBilledTotals {
			if totalBilled > 0 {
				o.db.Model(&model.User{}).Where("id = ?", uid).Update(
					"used_bytes", gorm.Expr("used_bytes + ?", totalBilled),
				)
			}
			touchedUIDs = append(touchedUIDs, uid)
		}
		var touchedUsers []model.User
		o.db.Where("id IN ?", touchedUIDs).Find(&touchedUsers)
		now := time.Now()
		for i := range touchedUsers {
			if !touchedUsers[i].CanForward(now) {
				o.EnforceUserQuotaCutoff(touchedUsers[i].ID)
			}
		}
	}

	if nodeWindowBytes > 0 {
		o.db.Model(&model.Node{}).Where("id = ?", nodeID).Update(
			"used_bytes", gorm.Expr("used_bytes + ?", nodeWindowBytes),
		)
		var updatedNode model.Node
		if err := o.db.First(&updatedNode, nodeID).Error; err == nil {
			if updatedNode.QuotaBytes > 0 && updatedNode.UsedBytes >= updatedNode.QuotaBytes {
				o.EnforceNodeQuotaCutoff(nodeID)
			}
		}
	}
}

// CloseExpiredOrders automatically closes unpaid pending orders older than OrderExpireTimeout.
func (o *Orchestrator) CloseExpiredOrders(now time.Time) int64 {
	cutoff := now.Add(-OrderExpireTimeout)
	res := o.db.Model(&model.BillingOrder{}).
		Where("status = ? AND created_at < ?", "pending", cutoff).
		Update("status", "cancelled")
	if res.Error != nil {
		return 0
	}
	if res.RowsAffected > 0 {
		log.Printf("[Orchestrator] Auto-closed %d expired unpaid orders (older than %s)", res.RowsAffected, OrderExpireTimeout)
	}
	return res.RowsAffected
}

// EnforceNodeQuotaCutoff pauses all active rules running on a node whose traffic quota has been exhausted.
func (o *Orchestrator) EnforceNodeQuotaCutoff(nodeID uint64) {
	var rules []model.ForwardRule
	o.db.Where("ingress_node_id = ? AND enabled = ?", nodeID, true).Find(&rules)
	for i := range rules {
		r := &rules[i]
		r.Enabled = false
		r.Status = "node_quota_exceeded"
		// Only touch enabled/status: traffic counters are incremented concurrently by traffic reports.
		o.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(map[string]any{"enabled": false, "status": r.Status})
		o.DispatchRule(r)
	}
	if len(rules) > 0 {
		log.Printf("[Orchestrator] Cut off %d rules on Node #%d due to node traffic quota exhaustion", len(rules), nodeID)
		var n model.Node
		if err := o.db.First(&n, nodeID).Error; err == nil {
			o.notifier.NotifyQuotaEventAsync(
				"node_quota_exceeded",
				"节点月流量配额耗尽告警",
				fmt.Sprintf("节点 #%d「%s」已达到月流量上限，已自动暂停该节点上的 %d 条转发规则。", n.ID, n.Name, len(rules)),
			)
		}
	}
}

// ReconcileAllOnlineNodes periodically re-syncs desired rule state to all connected Agents (every 60s).
func (o *Orchestrator) ReconcileAllOnlineNodes() {
	for _, nid := range o.hub.OnlineNodeIDs() {
		o.SyncNodeRules(nid)
	}
}

// EnforceUserQuotaCutoff disables all running rules belonging to a user whose quota or subscription expired.
func (o *Orchestrator) EnforceUserQuotaCutoff(userID uint64) {
	var activeRules []model.ForwardRule
	o.db.Where("user_id = ? AND enabled = ?", userID, true).Find(&activeRules)
	for i := range activeRules {
		r := &activeRules[i]
		r.Enabled = false
		r.Status = "quota_exceeded"
		// Only touch enabled/status: traffic counters are incremented concurrently by traffic reports.
		o.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(map[string]any{"enabled": false, "status": r.Status})
		o.DispatchRule(r)
	}
	if len(activeRules) > 0 {
		log.Printf("[Orchestrator] Cut off %d rules for User #%d due to quota/expiration", len(activeRules), userID)
		var u model.User
		if err := o.db.First(&u, userID).Error; err == nil {
			o.notifier.NotifyQuotaEventAsync(
				"user_quota_exceeded",
				"用户流量耗尽或到期停机通知",
				fmt.Sprintf("用户 #%d (%s) 套餐已到期或流量已用尽，已自动暂停其 %d 条运行中的转发规则。", u.ID, u.Email, len(activeRules)),
			)
		}
	}
}

// PruneOldTrafficStats deletes hourly traffic records older than 30 days so the table remains bounded.
func (o *Orchestrator) PruneOldTrafficStats(now time.Time) {
	cutoff := now.UTC().AddDate(0, 0, -30).Format("2006-01-02 15:00")
	o.db.Where("hour_bucket < ?", cutoff).Delete(&model.TrafficHourlyStat{})
}

// ResetNodeTraffic clears a node's accumulated traffic counter and resumes any `node_quota_exceeded` rules on that node
// whose owners are currently eligible to forward.
func (o *Orchestrator) ResetNodeTraffic(nodeID uint64, now time.Time) int {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return 0
	}
	o.db.Model(&model.Node{}).Where("id = ?", nodeID).Updates(map[string]any{
		"used_bytes":       0,
		"last_reset_month": now.UTC().Format("2006-01"),
	})

	var rules []model.ForwardRule
	o.db.Where("ingress_node_id = ? AND status = ?", nodeID, "node_quota_exceeded").Find(&rules)
	resumed := 0
	for i := range rules {
		var u model.User
		if err := o.db.First(&u, rules[i].UserID).Error; err != nil || !u.CanForward(now) ||
			!u.HasTunnelPermission(rules[i].TunnelLineID) || !o.tunnelLineEnabled(rules[i].TunnelLineID) {
			continue
		}
		if res := o.db.Model(&model.ForwardRule{}).Where("id = ? AND status = ?", rules[i].ID, "node_quota_exceeded").
			Updates(map[string]any{"enabled": true, "status": "running"}); res.Error == nil && res.RowsAffected > 0 {
			o.db.First(&rules[i], rules[i].ID)
			o.DispatchRule(&rules[i])
			resumed++
		}
	}
	o.SyncNodeRules(nodeID)
	return resumed
}

// ResumeUserQuotaRules resumes any `quota_exceeded` rules belonging to the user if the user is eligible to forward.
func (o *Orchestrator) ResumeUserQuotaRules(u *model.User, now time.Time) int {
	if u == nil || !u.CanForward(now) {
		return 0
	}
	var rules []model.ForwardRule
	o.db.Where("user_id = ? AND status = ?", u.ID, "quota_exceeded").Find(&rules)
	resumed := 0
	for i := range rules {
		if !u.HasTunnelPermission(rules[i].TunnelLineID) || !o.tunnelLineEnabled(rules[i].TunnelLineID) || rules[i].ListenPort <= 0 {
			continue
		}
		if res := o.db.Model(&model.ForwardRule{}).Where("id = ? AND status = ?", rules[i].ID, "quota_exceeded").
			Updates(map[string]any{"enabled": true, "status": "running"}); res.Error == nil && res.RowsAffected > 0 {
			o.db.First(&rules[i], rules[i].ID)
			o.DispatchRule(&rules[i])
			resumed++
		}
	}
	return resumed
}

// ProcessPeriodicResets runs the automatic monthly traffic reset for nodes (on ResetDay 1..28)
// and for active long-cycle users (with MonthlyReset == true every 30 days).
func (o *Orchestrator) ProcessPeriodicResets(now time.Time) {
	utcNow := now.UTC()
	currentYM := utcNow.Format("2006-01")
	currentDay := utcNow.Day()

	// 1. Node monthly traffic reset on ResetDay
	var nodes []model.Node
	o.db.Where("reset_day >= 1 AND reset_day <= 28").Find(&nodes)
	for _, n := range nodes {
		if currentDay >= n.ResetDay && n.LastResetMonth != currentYM {
			res := o.db.Model(&model.Node{}).
				Where("id = ? AND last_reset_month <> ?", n.ID, currentYM).
				Updates(map[string]any{"used_bytes": 0, "last_reset_month": currentYM})
			if res.Error == nil && res.RowsAffected > 0 {
				resumed := o.ResetNodeTraffic(n.ID, utcNow)
				log.Printf("[Orchestrator] Auto-reset monthly traffic for Node #%d (%s) on day %d (resumed %d rules)", n.ID, n.Name, n.ResetDay, resumed)
			}
		}
	}

	// 2. User 30-day periodic traffic reset for long-cycle subscriptions (quarterly / annual)
	var users []model.User
	o.db.Where("monthly_reset = ? AND status = ?", true, "active").Find(&users)
	for i := range users {
		u := &users[i]
		if u.Role != "admin" && !u.ExpireAt.IsZero() && utcNow.After(u.ExpireAt) {
			continue
		}
		refTime := u.CreatedAt
		if u.LastResetAt != nil && !u.LastResetAt.IsZero() {
			refTime = *u.LastResetAt
		}
		if refTime.IsZero() || utcNow.Sub(refTime) >= 30*24*time.Hour {
			resetTime := utcNow
			if err := o.db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
				"used_bytes":    0,
				"last_reset_at": &resetTime,
			}).Error; err == nil {
				u.UsedBytes = 0
				u.LastResetAt = &resetTime
				resumed := o.ResumeUserQuotaRules(u, utcNow)
				log.Printf("[Orchestrator] Auto-reset 30-day cycle traffic for User #%d (%s, resumed %d rules)", u.ID, u.Email, resumed)
			}
		}
	}
}

