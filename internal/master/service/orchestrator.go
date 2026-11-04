package service

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
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
	db  *gorm.DB
	hub *hub.AgentHub
}

func NewOrchestrator(db *gorm.DB, agentHub *hub.AgentHub) *Orchestrator {
	o := &Orchestrator{
		db:  db,
		hub: agentHub,
	}
	agentHub.SetCallbacks(o.HandleTrafficReport, o.SyncNodeRules)
	return o
}

// AllocatePortForNode finds an unused port in the node's PortRange.
func (o *Orchestrator) AllocatePortForNode(nodeID uint64, requestedPort int) (int, error) {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return 0, fmt.Errorf("node %d not found", nodeID)
	}

	occupied := make(map[int]bool)

	var ingressPorts []int
	o.db.Model(&model.ForwardRule{}).Where("ingress_node_id = ?", nodeID).Pluck("listen_port", &ingressPorts)
	for _, p := range ingressPorts {
		occupied[p] = true
	}

	// Also check relay ports if this node serves as an Egress node for any TunnelLine
	var lineIDs []uint64
	o.db.Model(&model.TunnelLine{}).Where("egress_node_id = ?", nodeID).Pluck("id", &lineIDs)
	if len(lineIDs) > 0 {
		var relayPorts []int
		o.db.Model(&model.ForwardRule{}).Where("tunnel_line_id IN ?", lineIDs).Pluck("relay_port", &relayPorts)
		for _, p := range relayPorts {
			occupied[p] = true
		}
	}

	if requestedPort > 0 {
		if err := security.ValidateListenPort(requestedPort, security.DefaultPolicy); err != nil {
			return 0, err
		}
		minP, maxP, err := utils.ParsePortRange(node.PortRange)
		if err == nil && (requestedPort < minP || requestedPort > maxP) {
			return 0, fmt.Errorf("port %d is outside node allowed range %s", requestedPort, node.PortRange)
		}
		if occupied[requestedPort] {
			return 0, fmt.Errorf("port %d is already in use on node %s", requestedPort, node.Name)
		}
		return requestedPort, nil
	}

	port, err := utils.AllocateFreePort(node.PortRange, occupied)
	if err != nil {
		return 0, err
	}
	if err := security.ValidateListenPort(port, security.DefaultPolicy); err != nil {
		return 0, err
	}
	return port, nil
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

	eng := rule.Engine
	if eng == "" {
		eng = protocol.EngineNative
	}

	// Check if this rule uses an encrypted dual-node tunnel (Type == "encrypt") or direct forwarding (Type == "direct")
	var line model.TunnelLine
	hasTunnelLine := false
	if rule.TunnelLineID > 0 {
		if err := o.db.First(&line, rule.TunnelLineID).Error; err == nil {
			hasTunnelLine = true
		}
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
		rp, err := o.AllocatePortForNode(egressNode.ID, 0)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to allocate egress port: %w", err)
		}
		rule.RelayPort = rp
		o.db.Model(rule).Update("relay_port", rp)
	}
	if rule.TunnelSecret == "" {
		rule.TunnelSecret = utils.GenerateRandomToken(16)
		o.db.Model(rule).Update("tunnel_secret", rule.TunnelSecret)
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
		UpdatedAt:      rule.UpdatedAt,
	}

	return inSpec, egressNode.ID, egSpec, nil
}

// DispatchRule pushes a rule's runtime specs (or removal if paused/disabled) to its Ingress and Egress Agents.
func (o *Orchestrator) DispatchRule(rule *model.ForwardRule) {
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
	for i := range ingressRules {
		inSpec, _, _, err := o.CompileRuleSpecs(&ingressRules[i])
		if err == nil && inSpec != nil {
			specs = append(specs, *inSpec)
		}
	}

	// 2. Rules where this node is the Egress node via a TunnelLine
	var lines []model.TunnelLine
	o.db.Where("egress_node_id = ? AND enabled = ?", nodeID, true).Find(&lines)
	if len(lines) > 0 {
		var lineIDs []uint64
		for _, l := range lines {
			lineIDs = append(lineIDs, l.ID)
		}
		var tunnelRules []model.ForwardRule
		o.db.Where("mode = 'tunnel' AND tunnel_line_id IN ? AND enabled = ?", lineIDs, true).Find(&tunnelRules)
		for i := range tunnelRules {
			_, _, egSpec, err := o.CompileRuleSpecs(&tunnelRules[i])
			if err == nil && egSpec != nil {
				specs = append(specs, *egSpec)
			}
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

	hourBucket := time.Now().Format("2006-01-02 15:00")
	var nodeWindowBytes int64

	for _, d := range report.Deltas {
		rawTotal := d.UploadBytes + d.DownBytes
		if rawTotal > 0 {
			nodeWindowBytes += rawTotal
		}
		// Avoid double-billing dual-end tunnel rules for user quota: only bill user on Relay or Ingress role
		if d.Role == protocol.RoleEgress {
			continue
		}
		if rawTotal <= 0 {
			continue
		}

		var rule model.ForwardRule
		if err := o.db.First(&rule, d.RuleID).Error; err != nil {
			continue
		}

		multiplier := node.TrafficRate
		if multiplier <= 0 {
			multiplier = 1.0
		}
		billingMode := "two_way"
		if rule.TunnelLineID > 0 {
			var line model.TunnelLine
			if err := o.db.First(&line, rule.TunnelLineID).Error; err == nil {
				if line.RateMultiplier > 0 {
					multiplier = line.RateMultiplier
				}
				if line.BillingMode == "one_way" {
					billingMode = "one_way"
				}
			}
		}

		// flux-panel style billing: one_way (单向计费: 仅统计出站流量) vs two_way (双向计费: 上行+下行)
		baseBytes := rawTotal
		if billingMode == "one_way" {
			baseBytes = d.DownBytes
			if d.UploadBytes > baseBytes {
				baseBytes = d.UploadBytes
			}
		}
		billed := int64(math.Round(float64(baseBytes) * multiplier))

		// Update ForwardRule counters
		o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
			"upload_bytes": gorm.Expr("upload_bytes + ?", d.UploadBytes),
			"down_bytes":   gorm.Expr("down_bytes + ?", d.DownBytes),
			"billed_bytes": gorm.Expr("billed_bytes + ?", billed),
		})

		// Update User UsedBytes
		o.db.Model(&model.User{}).Where("id = ?", rule.UserID).Update(
			"used_bytes", gorm.Expr("used_bytes + ?", billed),
		)

		// Upsert hourly traffic bucket
		var stat model.TrafficHourlyStat
		err := o.db.Where("user_id = ? AND rule_id = ? AND hour_bucket = ?", rule.UserID, rule.ID, hourBucket).First(&stat).Error
		if err != nil {
			o.db.Create(&model.TrafficHourlyStat{
				UserID:      rule.UserID,
				RuleID:      rule.ID,
				NodeID:      nodeID,
				HourBucket:  hourBucket,
				UploadBytes: d.UploadBytes,
				DownBytes:   d.DownBytes,
				BilledBytes: billed,
			})
		} else {
			o.db.Model(&stat).Updates(map[string]any{
				"upload_bytes": gorm.Expr("upload_bytes + ?", d.UploadBytes),
				"down_bytes":   gorm.Expr("down_bytes + ?", d.DownBytes),
				"billed_bytes": gorm.Expr("billed_bytes + ?", billed),
			})
		}

		// Check if user quota is now exhausted
		var user model.User
		if err := o.db.First(&user, rule.UserID).Error; err == nil {
			if user.UsedBytes >= user.QuotaBytes || (!user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt)) {
				o.EnforceUserQuotaCutoff(user.ID)
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

// EnforceNodeQuotaCutoff pauses all active rules running on a node whose traffic quota has been exhausted.
func (o *Orchestrator) EnforceNodeQuotaCutoff(nodeID uint64) {
	var rules []model.ForwardRule
	o.db.Where("ingress_node_id = ? AND enabled = ?", nodeID, true).Find(&rules)
	for i := range rules {
		r := &rules[i]
		r.Enabled = false
		r.Status = "node_quota_exceeded"
		o.db.Save(r)
		o.DispatchRule(r)
	}
	if len(rules) > 0 {
		log.Printf("[Orchestrator] Cut off %d rules on Node #%d due to node traffic quota exhaustion", len(rules), nodeID)
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
		o.db.Save(r)
		o.DispatchRule(r)
	}
	if len(activeRules) > 0 {
		log.Printf("[Orchestrator] Cut off %d rules for User #%d due to quota/expiration", len(activeRules), userID)
	}
}
