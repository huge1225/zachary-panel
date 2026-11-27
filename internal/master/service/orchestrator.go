package service

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"nexus-panel/internal/agent/engine"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/protocol"
	"nexus-panel/pkg/utils"
)

// CompiledNodeSpec pairs a target Agent node ID with the concrete RuleSpec it should run.
type CompiledNodeSpec struct {
	NodeID uint64
	Spec   protocol.RuleSpec
}

// Orchestrator coordinates rule compilation, multi-hop tunnel chaining, multipath egress pooling,
// SNI shared-port allocation, real-time traffic/off-peak billing, per-rule/daily quotas, and DNS failover.
type Orchestrator struct {
	db       *gorm.DB
	hub      *hub.AgentHub
	notifier *Notifier

	// allocMu serializes quota checks, port allocation and rule persistence so that concurrent requests cannot
	// exceed rule / port quotas or allocate the same port twice (TOCTOU).
	allocMu sync.Mutex

	// failoverMu serializes DNS failover health evaluation and provider updates.
	failoverMu        sync.Mutex
	bgWG              sync.WaitGroup
	dnsHTTPClient     *http.Client
	cloudflareBaseURL string
	dnspodBaseURL     string
	dnsTestMode       bool
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

// ParseClockHHMM parses "HH:MM" (00:00..24:00) into minutes since midnight.
func ParseClockHHMM(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("时间格式需为 HH:MM，当前为 %q", raw)
	}
	hh, err1 := strconv.Atoi(parts[0])
	mm, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm > 0) {
		return 0, fmt.Errorf("无效的时间值 %q（范围 00:00 - 24:00）", raw)
	}
	return hh*60 + mm, nil
}

// BillingTimezoneLoc resolves the panel's configured timezone, safely falling back to Asia/Shanghai (+08:00) or UTC.
func BillingTimezoneLoc(cfg *model.SystemConfig) *time.Location {
	tz := "Asia/Shanghai"
	if cfg != nil && strings.TrimSpace(cfg.OffPeakTimezone) != "" {
		tz = strings.TrimSpace(cfg.OffPeakTimezone)
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		return loc
	}
	if tz == "Asia/Shanghai" || tz == "CST" {
		return time.FixedZone("CST", 8*3600)
	}
	return time.UTC
}

// InOffPeakWindow reports whether localTime falls inside [startHHMM, endHHMM), supporting cross-midnight ranges
// such as "23:00" -> "07:00".
func InOffPeakWindow(startHHMM, endHHMM string, localTime time.Time) bool {
	startMin, err1 := ParseClockHHMM(startHHMM)
	endMin, err2 := ParseClockHHMM(endHHMM)
	if err1 != nil || err2 != nil {
		return false
	}
	curMin := localTime.Hour()*60 + localTime.Minute()
	if startMin < endMin {
		return curMin >= startMin && curMin < endMin
	}
	if startMin > endMin {
		return curMin >= startMin || curMin < endMin
	}
	return true
}

// ComputeOffPeakFactor returns the dynamic off-peak traffic multiplier factor at instant `now` (1.0 outside off-peak).
func ComputeOffPeakFactor(cfg *model.SystemConfig, line *model.TunnelLine, now time.Time) float64 {
	if cfg == nil || !cfg.OffPeakEnabled {
		return 1.0
	}
	loc := BillingTimezoneLoc(cfg)
	if !InOffPeakWindow(cfg.OffPeakStart, cfg.OffPeakEnd, now.In(loc)) {
		return 1.0
	}
	if line != nil && line.OffPeakMultiplier > 0 {
		return sanitizeRateMultiplier(line.OffPeakMultiplier)
	}
	if cfg.OffPeakMultiplier > 0 {
		return sanitizeRateMultiplier(cfg.OffPeakMultiplier)
	}
	return 1.0
}

func NewOrchestrator(db *gorm.DB, agentHub *hub.AgentHub) *Orchestrator {
	o := &Orchestrator{
		db:                db,
		hub:               agentHub,
		notifier:          NewNotifier(db),
		dnsHTTPClient:     newSafeDNSHTTPClient(),
		cloudflareBaseURL: "https://api.cloudflare.com/client/v4",
		dnspodBaseURL:     "https://dnsapi.cn",
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
		o.EvaluateDNSFailoverGroupsAsync(time.Now())
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
		o.EvaluateDNSFailoverGroupsAsync(time.Now())
	})
	agentHub.SetCertChangedCallback(o.OnEgressCertChanged)
	agentHub.SetAckScope(o.NodeOwnsRuleRole)
	return o
}

// EvaluateDNSFailoverGroupsAsync triggers non-blocking DNS failover evaluation tracked by bgWG.
func (o *Orchestrator) EvaluateDNSFailoverGroupsAsync(now time.Time) {
	o.bgWG.Add(1)
	go func() {
		defer o.bgWG.Done()
		o.EvaluateDNSFailoverGroups(now)
	}()
}

// WaitBackground blocks until all in-flight asynchronous failover tasks complete.
func (o *Orchestrator) WaitBackground() {
	o.bgWG.Wait()
}

// Notifier returns the operational alert notifier instance.
func (o *Orchestrator) Notifier() *Notifier {
	return o.notifier
}

// BillingDateString returns YYYY-MM-DD in the panel's configured billing timezone.
func (o *Orchestrator) BillingDateString(now time.Time) string {
	var cfg model.SystemConfig
	_ = o.db.First(&cfg, 1).Error
	return now.In(BillingTimezoneLoc(&cfg)).Format("2006-01-02")
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
//   - hop_0..hop_7: the idx-th intermediate hop node of the rule's encrypted tunnel line
//   - egress: an egress pool node of the rule's encrypted tunnel line
func (o *Orchestrator) NodeOwnsRuleRole(nodeID, ruleID uint64, role protocol.RuleRole) bool {
	var rule model.ForwardRule
	if err := o.db.Select("id, mode, ingress_node_id, tunnel_line_id").First(&rule, ruleID).Error; err != nil {
		return false
	}
	return o.ruleOwnedBy(&rule, nodeID, role)
}

func (o *Orchestrator) ruleOwnedBy(rule *model.ForwardRule, nodeID uint64, role protocol.RuleRole) bool {
	switch {
	case role == protocol.RoleEgress:
		if rule.Mode != "tunnel" || rule.TunnelLineID == 0 {
			return false
		}
		var line model.TunnelLine
		if err := o.db.Select("id, type, egress_node_id, egress_node_ids").First(&line, rule.TunnelLineID).Error; err != nil {
			return false
		}
		return line.UsesNodeAsEgress(nodeID)
	case protocol.IsHopRole(role):
		hopIdx, ok := protocol.ParseHopRole(role)
		if !ok || rule.Mode != "tunnel" || rule.TunnelLineID == 0 {
			return false
		}
		var line model.TunnelLine
		if err := o.db.Select("id, type, hop_node_ids").First(&line, rule.TunnelLineID).Error; err != nil {
			return false
		}
		idx, found := line.HopIndexOf(nodeID)
		return found && idx == hopIdx
	case role == protocol.RoleIngress || role == protocol.RoleRelay || role == "":
		return rule.IngressNodeID == nodeID
	default:
		return false
	}
}

// OnEgressCertChanged re-dispatches every enabled rule on tunnel lines that use nodeID as an intermediate hop or egress
// so upstream nodes pin the rotated certificate immediately.
func (o *Orchestrator) OnEgressCertChanged(nodeID uint64) {
	var lines []model.TunnelLine
	o.db.Where("type = ?", "encrypt").Find(&lines)
	var lineIDs []uint64
	for i := range lines {
		if lines[i].UsesNodeInTunnelLeg(nodeID) {
			lineIDs = append(lineIDs, lines[i].ID)
		}
	}
	if len(lineIDs) == 0 {
		return
	}
	var rules []model.ForwardRule
	o.db.Where("tunnel_line_id IN ? AND enabled = ?", lineIDs, true).Find(&rules)
	for i := range rules {
		o.DispatchRule(&rules[i])
	}
	if len(rules) > 0 {
		log.Printf("[Orchestrator] Tunnel node #%d rotated its TLS certificate; re-dispatched %d rules", nodeID, len(rules))
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

// OccupiedTunnelPorts returns internal tunnel ports (relay, hop, and multipath egress ports) held on nodeID.
// Callers must hold WithAllocLock.
func (o *Orchestrator) OccupiedTunnelPorts(nodeID uint64) map[int]bool {
	occupied := make(map[int]bool)
	var ports []int
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
	var allocRows []struct {
		HopPortsJSON    string
		EgressPortsJSON string
	}
	o.db.Model(&model.ForwardRule{}).
		Select("hop_ports_json, egress_ports_json").
		Where("hop_ports_json <> '' OR egress_ports_json <> ''").
		Find(&allocRows)
	for _, row := range allocRows {
		if row.HopPortsJSON != "" {
			var hops []model.NodePortAlloc
			if json.Unmarshal([]byte(row.HopPortsJSON), &hops) == nil {
				for _, a := range hops {
					if a.NodeID == nodeID && a.Port > 0 {
						occupied[a.Port] = true
					}
				}
			}
		}
		if row.EgressPortsJSON != "" {
			var egs []model.NodePortAlloc
			if json.Unmarshal([]byte(row.EgressPortsJSON), &egs) == nil {
				for _, a := range egs {
					if a.NodeID == nodeID && a.Port > 0 {
						occupied[a.Port] = true
					}
				}
			}
		}
	}
	return occupied
}

// OccupiedPorts returns every port held on nodeID: listen ports of rules entering there plus all relay, hop, and
// multipath egress ports ending there. Callers must hold WithAllocLock.
func (o *Orchestrator) OccupiedPorts(nodeID uint64) map[int]bool {
	occupied := o.OccupiedTunnelPorts(nodeID)
	var ports []int
	o.db.Model(&model.ForwardRule{}).Where("ingress_node_id = ? AND listen_port > 0", nodeID).Pluck("listen_port", &ports)
	for _, p := range ports {
		occupied[p] = true
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

// AllocateIngressPortForRule allocates or validates an ingress listen port, supporting non-overlapping shared-port
// TLS SNI / HTTP Host routing when matchDomains is non-empty. Callers must hold WithAllocLock.
func (o *Orchestrator) AllocateIngressPortForRule(nodeID uint64, requestedPort int, matchDomains string, excludeRuleID uint64, lineRange ...string) (int, string, error) {
	var cleanDomains []string
	if strings.TrimSpace(matchDomains) != "" {
		parsed, err := security.ParseAndValidateMatchDomains(matchDomains)
		if err != nil {
			return 0, "", err
		}
		cleanDomains = parsed
	}
	normalizedDomains := strings.Join(cleanDomains, ",")

	if len(cleanDomains) == 0 {
		if requestedPort > 0 && excludeRuleID > 0 {
			var cur model.ForwardRule
			if o.db.Select("id, ingress_node_id, listen_port").First(&cur, excludeRuleID).Error == nil &&
				cur.IngressNodeID == nodeID && cur.ListenPort == requestedPort {
				// Check no OTHER rule shares this port (e.g. switching from shared SNI rule to exclusive port rule)
				var otherCount int64
				o.db.Model(&model.ForwardRule{}).
					Where("ingress_node_id = ? AND listen_port = ? AND id <> ?", nodeID, requestedPort, excludeRuleID).
					Count(&otherCount)
				if otherCount == 0 && !o.OccupiedTunnelPorts(nodeID)[requestedPort] {
					lr := ""
					if len(lineRange) > 0 {
						lr = lineRange[0]
					}
					if !o.PortInRange(nodeID, requestedPort, lr) {
						return 0, "", fmt.Errorf("端口 %d 不在允许范围内", requestedPort)
					}
					return requestedPort, "", nil
				}
			}
		}
		port, err := o.AllocatePortForNode(nodeID, requestedPort, lineRange...)
		return port, "", err
	}

	// Shared-port SNI / HTTP Host mode
	if requestedPort <= 0 {
		port, err := o.AllocatePortForNode(nodeID, 0, lineRange...)
		return port, normalizedDomains, err
	}

	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return 0, "", fmt.Errorf("node %d not found", nodeID)
	}
	lr := ""
	if len(lineRange) > 0 {
		lr = lineRange[0]
	}
	minP, maxP, err := o.EffectivePortRange(&node, lr)
	if err != nil {
		return 0, "", err
	}
	if err := security.ValidateListenPort(requestedPort, security.DefaultPolicy); err != nil {
		return 0, "", err
	}
	if requestedPort < minP || requestedPort > maxP {
		return 0, "", fmt.Errorf("端口 %d 不在允许范围 %d-%d 内", requestedPort, minP, maxP)
	}
	if o.OccupiedTunnelPorts(nodeID)[requestedPort] {
		return 0, "", fmt.Errorf("端口 %d 已被节点内部隧道占用，无法用于共享域名路由", requestedPort)
	}

	var peers []model.ForwardRule
	q := o.db.Select("id, name, match_domains").Where("ingress_node_id = ? AND listen_port = ?", nodeID, requestedPort)
	if excludeRuleID > 0 {
		q = q.Where("id <> ?", excludeRuleID)
	}
	q.Find(&peers)
	for _, peer := range peers {
		if strings.TrimSpace(peer.MatchDomains) == "" {
			return 0, "", fmt.Errorf("端口 %d 已被独占端口规则占用，仅配置了 SNI/Host 域名的 TCP 规则可共享同一端口", requestedPort)
		}
		peerDomains, _ := security.ParseAndValidateMatchDomains(peer.MatchDomains)
		for _, nd := range cleanDomains {
			for _, pd := range peerDomains {
				if engine.DomainsOverlap(nd, pd) {
					return 0, "", fmt.Errorf("共享端口 %d 上的路由域名 %q 与已有域名 %q 存在冲突或通配覆盖", requestedPort, nd, pd)
				}
			}
		}
	}
	return requestedPort, normalizedDomains, nil
}

// EffectiveEngine returns the engine a rule actually runs on (without line context).
func EffectiveEngine(rule *model.ForwardRule, owner *model.User) protocol.EngineType {
	return EffectiveEngineForLine(rule, owner, nil)
}

// EffectiveEngineForLine returns the concrete runtime engine after accounting for IP ACLs, speed limits,
// SNI/Host shared-port routing, Mux/Bonding, multipath egress cert pinning, and PROXY protocol capabilities.
func EffectiveEngineForLine(rule *model.ForwardRule, owner *model.User, line *model.TunnelLine) protocol.EngineType {
	eng := rule.Engine
	if eng == "" {
		eng = protocol.EngineNative
	}
	if strings.TrimSpace(rule.MatchDomains) != "" {
		return protocol.EngineNative
	}
	if (rule.AccessMode == "allow" || rule.AccessMode == "deny") && strings.TrimSpace(rule.AccessCIDRs) != "" {
		return protocol.EngineNative
	}
	proxyProto := rule.EffectiveProxyProto(line)
	if line != nil && line.Type == "encrypt" && rule.Mode == "tunnel" {
		if line.EnableMux || line.EnableBonding || proxyProto > 0 || len(line.EgressMembers()) > 1 {
			return protocol.EngineNative
		}
		if eng != protocol.EngineNative && eng != protocol.EngineGost {
			eng = protocol.EngineNative
		}
	} else if proxyProto > 0 && eng == protocol.EngineNftables {
		eng = protocol.EngineNative
	}
	if rule.LoadBalance == "weighted" || rule.LoadBalance == "least_rtt" ||
		(line != nil && (line.LoadBalance == "weighted" || line.LoadBalance == "least_rtt")) {
		if eng != protocol.EngineNative {
			eng = protocol.EngineNative
		}
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

// CompileRuleGraph compiles a database ForwardRule into an ordered list of node-specific RuleSpecs
// (downstream-to-upstream: Egress pool -> Hop_{K-1}..Hop_0 -> Ingress / Relay).
func (o *Orchestrator) CompileRuleGraph(rule *model.ForwardRule) ([]CompiledNodeSpec, error) {
	var user model.User
	if err := o.db.First(&user, rule.UserID).Error; err != nil {
		return nil, err
	}

	speedLimit := rule.SpeedMbps
	if speedLimit <= 0 {
		speedLimit = user.SpeedMbps
	}

	var targets []protocol.TargetEndpoint
	if err := json.Unmarshal([]byte(rule.TargetsJSON), &targets); err != nil || len(targets) == 0 {
		return nil, fmt.Errorf("invalid targets_json for rule %d", rule.ID)
	}

	var line model.TunnelLine
	hasTunnelLine := false
	if rule.TunnelLineID > 0 {
		if err := o.db.First(&line, rule.TunnelLineID).Error; err != nil {
			return nil, fmt.Errorf("tunnel line %d not found", rule.TunnelLineID)
		}
		if !line.Enabled {
			return nil, fmt.Errorf("tunnel line %d is disabled", rule.TunnelLineID)
		}
		hasTunnelLine = true
	}

	var linePtr *model.TunnelLine
	if hasTunnelLine {
		linePtr = &line
	}
	eng := EffectiveEngineForLine(rule, &user, linePtr)
	proxyProto := rule.EffectiveProxyProto(linePtr)
	egressMembers := line.EgressMembers()

	// Case 1: Single-node Direct Forwarding
	if !hasTunnelLine || line.Type == "direct" || len(egressMembers) == 0 || rule.Mode == "direct" {
		outIP := ""
		var inNode model.Node
		if o.db.Select("id, outbound_ip, allowed_outbound_ips").First(&inNode, rule.IngressNodeID).Error == nil {
			outIP = strings.TrimSpace(inNode.OutboundIP)
			if rOut := strings.TrimSpace(rule.OutboundIP); rOut != "" && inNode.AllowsOutboundIP(rOut, user.ID == 0 || user.Role == "admin") {
				outIP = rOut
			}
		} else if user.ID == 0 || user.Role == "admin" {
			outIP = strings.TrimSpace(rule.OutboundIP)
		}
		spec := protocol.RuleSpec{
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
			OutboundIP:     outIP,
			ProxyProto:     proxyProto,
			MatchDomains:   strings.TrimSpace(rule.MatchDomains),
			UpdatedAt:      rule.UpdatedAt,
		}
		return []CompiledNodeSpec{{NodeID: rule.IngressNodeID, Spec: spec}}, nil
	}

	// Case 2: Encrypted Tunnel (1-hop, Multi-Hop Chaining, and/or Multipath Egress Pool)
	hopIDs := line.HopIDs()
	nodeIDSet := make(map[uint64]struct{}, 1+len(hopIDs)+len(egressMembers))
	nodeIDSet[rule.IngressNodeID] = struct{}{}
	for _, hid := range hopIDs {
		nodeIDSet[hid] = struct{}{}
	}
	for _, em := range egressMembers {
		nodeIDSet[em.NodeID] = struct{}{}
	}
	allNodeIDs := make([]uint64, 0, len(nodeIDSet))
	for nid := range nodeIDSet {
		allNodeIDs = append(allNodeIDs, nid)
	}
	var nodes []model.Node
	o.db.Where("id IN ?", allNodeIDs).Find(&nodes)
	nodeMap := make(map[uint64]*model.Node, len(nodes))
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}
	for _, hid := range hopIDs {
		if nodeMap[hid] == nil {
			return nil, fmt.Errorf("hop node %d not found", hid)
		}
	}
	for _, em := range egressMembers {
		if nodeMap[em.NodeID] == nil {
			return nil, fmt.Errorf("egress node %d not found", em.NodeID)
		}
	}

	// Verify or allocate HopPortsJSON, EgressPortsJSON, RelayPort, and TunnelSecret atomically under WithAllocLock.
	if !allocsMatchNodeIDs(rule.HopPortAllocs(), hopIDs) ||
		!allocsMatchEgressMembers(rule.EgressPortAllocs(), egressMembers) ||
		rule.RelayPort <= 0 || rule.TunnelSecret == "" {
		err := o.WithAllocLock(func() error {
			var cur model.ForwardRule
			if err := o.db.Select("id, relay_port, relay_node_id, hop_ports_json, egress_ports_json, tunnel_secret").
				First(&cur, rule.ID).Error; err == nil {
				rule.RelayPort = cur.RelayPort
				rule.RelayNodeID = cur.RelayNodeID
				rule.HopPortsJSON = cur.HopPortsJSON
				rule.EgressPortsJSON = cur.EgressPortsJSON
				if cur.TunnelSecret != "" {
					rule.TunnelSecret = cur.TunnelSecret
				}
			}

			existingHopMap := make(map[uint64]int)
			for _, a := range rule.HopPortAllocs() {
				if a.NodeID > 0 && a.Port > 0 {
					existingHopMap[a.NodeID] = a.Port
				}
			}
			existingEgMap := make(map[uint64]int)
			for _, a := range rule.EgressPortAllocs() {
				if a.NodeID > 0 && a.Port > 0 {
					existingEgMap[a.NodeID] = a.Port
				}
			}

			occupiedByNode := make(map[uint64]map[int]bool)
			getOccupied := func(nid uint64) map[int]bool {
				if m, ok := occupiedByNode[nid]; ok {
					return m
				}
				m := o.OccupiedPorts(nid)
				occupiedByNode[nid] = m
				return m
			}

			newHopAllocs := make([]model.NodePortAlloc, 0, len(hopIDs))
			for _, hid := range hopIDs {
				if p := existingHopMap[hid]; p > 0 && o.PortInRange(hid, p, "") {
					newHopAllocs = append(newHopAllocs, model.NodePortAlloc{NodeID: hid, Port: p})
					continue
				}
				hNode := nodeMap[hid]
				minP, maxP, rErr := o.EffectivePortRange(hNode, "")
				if rErr != nil {
					return rErr
				}
				p, pErr := PickFreePort(minP, maxP, getOccupied(hid))
				if pErr != nil {
					return fmt.Errorf("failed to allocate hop port on node %d: %w", hid, pErr)
				}
				newHopAllocs = append(newHopAllocs, model.NodePortAlloc{NodeID: hid, Port: p})
			}

			newEgAllocs := make([]model.NodePortAlloc, 0, len(egressMembers))
			for _, em := range egressMembers {
				if p := existingEgMap[em.NodeID]; p > 0 && o.PortInRange(em.NodeID, p, "") {
					newEgAllocs = append(newEgAllocs, model.NodePortAlloc{NodeID: em.NodeID, Port: p})
					continue
				}
				eNode := nodeMap[em.NodeID]
				minP, maxP, rErr := o.EffectivePortRange(eNode, "")
				if rErr != nil {
					return rErr
				}
				p, pErr := PickFreePort(minP, maxP, getOccupied(em.NodeID))
				if pErr != nil {
					return fmt.Errorf("failed to allocate egress port on node %d: %w", em.NodeID, pErr)
				}
				newEgAllocs = append(newEgAllocs, model.NodePortAlloc{NodeID: em.NodeID, Port: p})
			}

			hopBytes := []byte("")
			if len(newHopAllocs) > 0 {
				hopBytes, _ = json.Marshal(newHopAllocs)
			}
			egBytes, _ := json.Marshal(newEgAllocs)
			rule.HopPortsJSON = string(hopBytes)
			rule.EgressPortsJSON = string(egBytes)
			rule.RelayNodeID = newEgAllocs[0].NodeID
			rule.RelayPort = newEgAllocs[0].Port
			if rule.TunnelSecret == "" {
				rule.TunnelSecret = utils.GenerateRandomToken(32)
			}

			return o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
				"hop_ports_json":    rule.HopPortsJSON,
				"egress_ports_json": rule.EgressPortsJSON,
				"relay_node_id":     rule.RelayNodeID,
				"relay_port":        rule.RelayPort,
				"tunnel_secret":     rule.TunnelSecret,
			}).Error
		})
		if err != nil {
			return nil, err
		}
	}

	hopPortMap := make(map[uint64]int, len(hopIDs))
	for _, a := range rule.HopPortAllocs() {
		hopPortMap[a.NodeID] = a.Port
	}
	egPortMap := make(map[uint64]int, len(egressMembers))
	for _, a := range rule.EgressPortAllocs() {
		egPortMap[a.NodeID] = a.Port
	}

	bondLinks := line.BondLinks
	if bondLinks < 2 {
		bondLinks = 4
	} else if bondLinks > 8 {
		bondLinks = 8
	}

	var compiled []CompiledNodeSpec
	nextEndpoints := make([]protocol.TargetEndpoint, 0, len(egressMembers))

	// 1. Downstream Egress specs (exclude any egress node that has exhausted its monthly quota)
	for _, em := range egressMembers {
		egNode := nodeMap[em.NodeID]
		if egNode.QuotaBytes > 0 && egNode.UsedBytes >= egNode.QuotaBytes {
			continue
		}
		egPort := egPortMap[em.NodeID]
		egOutIP := strings.TrimSpace(egNode.OutboundIP)
		if rOut := strings.TrimSpace(rule.OutboundIP); rOut != "" && egNode.AllowsOutboundIP(rOut, user.ID == 0 || user.Role == "admin") {
			egOutIP = rOut
		}
		egTunnel := &protocol.TunnelConfig{
			Transport:     line.Transport,
			SecretKey:     rule.TunnelSecret,
			SNI:           egNode.PublicHost,
			EnableMux:     line.EnableMux,
			EnableBonding: line.EnableBonding,
			BondLinks:     bondLinks,
			ProxyProto:    proxyProto,
			CertPEM:       egNode.TunnelCertPEM,
		}
		egSpec := protocol.RuleSpec{
			RuleID:         rule.ID,
			UserID:         rule.UserID,
			Name:           fmt.Sprintf("%s [Egress]", rule.Name),
			Role:           protocol.RoleEgress,
			Engine:         eng,
			Protocol:       rule.Protocol,
			ListenHost:     "0.0.0.0",
			ListenPort:     egPort,
			LoadBalance:    rule.LoadBalance,
			Targets:        targets,
			Tunnel:         egTunnel,
			SpeedLimitMbps: speedLimit,
			OutboundIP:     egOutIP,
			ProxyProto:     proxyProto,
			MaxConns:       8192,
			UpdatedAt:      rule.UpdatedAt,
		}
		compiled = append(compiled, CompiledNodeSpec{NodeID: egNode.ID, Spec: egSpec})
		egHost := strings.Trim(strings.TrimSpace(egNode.PreferredTunnelHost()), "[]")
		nextEndpoints = append(nextEndpoints, protocol.TargetEndpoint{
			Address: net.JoinHostPort(egHost, strconv.Itoa(egPort)),
			Weight:  em.Weight,
			Backup:  em.Backup,
			CertPEM: egNode.TunnelCertPEM,
			NodeID:  egNode.ID,
		})
	}
	if len(nextEndpoints) == 0 {
		return nil, fmt.Errorf("all egress nodes on line %d exceeded monthly traffic quota", line.ID)
	}

	nextLB := line.LoadBalance
	if nextLB == "" {
		nextLB = "round_robin"
	}

	// 2. Intermediate Hop specs (backwards from Hop_{K-1} down to Hop_0)
	for idx := len(hopIDs) - 1; idx >= 0; idx-- {
		hopNode := nodeMap[hopIDs[idx]]
		hopPort := hopPortMap[hopNode.ID]
		defaultCert := ""
		defaultSNI := ""
		if len(nextEndpoints) > 0 {
			defaultCert = nextEndpoints[0].CertPEM
			if n0 := nodeMap[nextEndpoints[0].NodeID]; n0 != nil {
				defaultSNI = n0.PublicHost
			}
		}
		hopTunnel := &protocol.TunnelConfig{
			Transport:     line.Transport,
			SecretKey:     rule.TunnelSecret,
			SNI:           defaultSNI,
			EnableMux:     line.EnableMux,
			EnableBonding: line.EnableBonding,
			BondLinks:     bondLinks,
			ProxyProto:    proxyProto,
			CertPEM:       defaultCert,
		}
		hopSpec := protocol.RuleSpec{
			RuleID:         rule.ID,
			UserID:         rule.UserID,
			Name:           fmt.Sprintf("%s [Hop-%d]", rule.Name, idx+1),
			Role:           protocol.RoleHop(idx),
			Engine:         eng,
			Protocol:       rule.Protocol,
			ListenHost:     "0.0.0.0",
			ListenPort:     hopPort,
			LoadBalance:    nextLB,
			Targets:        nextEndpoints,
			Tunnel:         hopTunnel,
			SpeedLimitMbps: speedLimit,
			OutboundIP:     strings.TrimSpace(hopNode.OutboundIP),
			ProxyProto:     proxyProto,
			MaxConns:       8192,
			UpdatedAt:      rule.UpdatedAt,
		}
		compiled = append(compiled, CompiledNodeSpec{NodeID: hopNode.ID, Spec: hopSpec})
		hopHost := strings.Trim(strings.TrimSpace(hopNode.PreferredTunnelHost()), "[]")
		nextEndpoints = []protocol.TargetEndpoint{
			{
				Address: net.JoinHostPort(hopHost, strconv.Itoa(hopPort)),
				Weight:  100,
				CertPEM: hopNode.TunnelCertPEM,
				NodeID:  hopNode.ID,
			},
		}
		nextLB = "round_robin"
	}

	// 3. Upstream Ingress spec
	defaultCert := ""
	defaultSNI := ""
	if len(nextEndpoints) > 0 {
		defaultCert = nextEndpoints[0].CertPEM
		if n0 := nodeMap[nextEndpoints[0].NodeID]; n0 != nil {
			defaultSNI = n0.PublicHost
		}
	}
	inOutIP := ""
	if inNode := nodeMap[rule.IngressNodeID]; inNode != nil {
		inOutIP = strings.TrimSpace(inNode.OutboundIP)
	}
	inTunnel := &protocol.TunnelConfig{
		Transport:     line.Transport,
		SecretKey:     rule.TunnelSecret,
		SNI:           defaultSNI,
		EnableMux:     line.EnableMux,
		EnableBonding: line.EnableBonding,
		BondLinks:     bondLinks,
		ProxyProto:    proxyProto,
		CertPEM:       defaultCert,
	}
	inSpec := protocol.RuleSpec{
		RuleID:         rule.ID,
		UserID:         rule.UserID,
		Name:           fmt.Sprintf("%s [Ingress]", rule.Name),
		Role:           protocol.RoleIngress,
		Engine:         eng,
		Protocol:       rule.Protocol,
		ListenHost:     "0.0.0.0",
		ListenPort:     rule.ListenPort,
		LoadBalance:    nextLB,
		Targets:        nextEndpoints,
		Tunnel:         inTunnel,
		SpeedLimitMbps: speedLimit,
		MaxConns:       8192,
		AccessMode:     rule.AccessMode,
		AccessCIDRs:    rule.AccessCIDRs,
		OutboundIP:     inOutIP,
		ProxyProto:     proxyProto,
		MatchDomains:   strings.TrimSpace(rule.MatchDomains),
		UpdatedAt:      rule.UpdatedAt,
	}
	compiled = append(compiled, CompiledNodeSpec{NodeID: rule.IngressNodeID, Spec: inSpec})

	return compiled, nil
}

func allocsMatchNodeIDs(allocs []model.NodePortAlloc, ids []uint64) bool {
	if len(allocs) != len(ids) {
		return false
	}
	for i := range ids {
		if allocs[i].NodeID != ids[i] || allocs[i].Port <= 0 {
			return false
		}
	}
	return true
}

func allocsMatchEgressMembers(allocs []model.NodePortAlloc, members []model.EgressMember) bool {
	if len(allocs) != len(members) {
		return false
	}
	for i := range members {
		if allocs[i].NodeID != members[i].NodeID || allocs[i].Port <= 0 {
			return false
		}
	}
	return true
}

// CompileRuleSpecs preserves backward-compatible access to Ingress + primary Egress RuleSpecs while delegating to CompileRuleGraph.
func (o *Orchestrator) CompileRuleSpecs(rule *model.ForwardRule) (ingressSpec *protocol.RuleSpec, egressNodeID uint64, egressSpec *protocol.RuleSpec, err error) {
	specs, err := o.CompileRuleGraph(rule)
	if err != nil {
		return nil, 0, nil, err
	}
	for i := range specs {
		switch specs[i].Spec.Role {
		case protocol.RoleRelay, protocol.RoleIngress:
			cp := specs[i].Spec
			ingressSpec = &cp
		case protocol.RoleEgress:
			if egressSpec == nil {
				cp := specs[i].Spec
				egressSpec = &cp
				egressNodeID = specs[i].NodeID
			}
		}
	}
	return ingressSpec, egressNodeID, egressSpec, nil
}

// DispatchRule pushes a rule's runtime specs (or removal if paused/disabled) to its Ingress, Hop, and Egress Agents.
func (o *Orchestrator) DispatchRule(rule *model.ForwardRule) {
	now := time.Now()
	todayStr := o.BillingDateString(now)
	if rule.Enabled && (!o.ownerMayRun(rule) || !rule.WithinRuleQuotas(todayStr)) {
		cp := *rule
		cp.Enabled = false
		rule = &cp
	}
	if !rule.Enabled {
		o.RemoveRuleFromAgents(rule)
		return
	}

	compiled, err := o.CompileRuleGraph(rule)
	if err != nil {
		log.Printf("[Orchestrator] Failed to compile rule %d: %v", rule.ID, err)
		return
	}

	// CompiledNodeSpecs are ordered downstream-to-upstream (Egress -> Hops -> Ingress) so upstream dials succeed immediately.
	for i := range compiled {
		err := o.hub.SendToNode(compiled[i].NodeID, protocol.MsgApplyRule, compiled[i].Spec)
		if err != nil && compiled[i].NodeID == rule.IngressNodeID {
			o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Update("status", "syncing")
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

// RuleNodesWithinQuota reports whether the rule's Ingress node, intermediate Hop nodes, and at least one Egress pool
// member are within their configured monthly QuotaBytes.
func (o *Orchestrator) RuleNodesWithinQuota(rule *model.ForwardRule) bool {
	if rule == nil || rule.IngressNodeID == 0 {
		return false
	}
	var line model.TunnelLine
	hasTunnel := false
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		if err := o.db.First(&line, rule.TunnelLineID).Error; err != nil {
			return false
		}
		if line.Type == "encrypt" && len(line.EgressMembers()) > 0 {
			hasTunnel = true
		}
	}

	idSet := map[uint64]struct{}{rule.IngressNodeID: {}}
	if hasTunnel {
		for _, hid := range line.HopIDs() {
			idSet[hid] = struct{}{}
		}
		for _, em := range line.EgressMembers() {
			idSet[em.NodeID] = struct{}{}
		}
	}
	ids := make([]uint64, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	var nodes []model.Node
	o.db.Select("id, used_bytes, quota_bytes").Where("id IN ?", ids).Find(&nodes)
	underQuota := make(map[uint64]bool, len(nodes))
	for _, n := range nodes {
		underQuota[n.ID] = n.QuotaBytes <= 0 || n.UsedBytes < n.QuotaBytes
	}
	if !underQuota[rule.IngressNodeID] {
		return false
	}
	if hasTunnel {
		for _, hid := range line.HopIDs() {
			if !underQuota[hid] {
				return false
			}
		}
		hasHealthyEgress := false
		for _, em := range line.EgressMembers() {
			if underQuota[em.NodeID] {
				hasHealthyEgress = true
				break
			}
		}
		if !hasHealthyEgress {
			return false
		}
	}
	return true
}

// ownerMayRun reports whether the rule's owner, bound tunnel line, and participating nodes currently permit deploying this rule.
func (o *Orchestrator) ownerMayRun(rule *model.ForwardRule) bool {
	var u model.User
	if err := o.db.First(&u, rule.UserID).Error; err != nil {
		return false
	}
	if !u.CanForward(time.Now()) || !u.HasTunnelPermission(rule.TunnelLineID) {
		return false
	}
	if !o.tunnelLineEnabled(rule.TunnelLineID) {
		return false
	}
	return o.RuleNodesWithinQuota(rule)
}

// RemoveRuleFromAgents tears down a paused or deleted rule from all involved Ingress, Hop, and Egress Agents.
func (o *Orchestrator) RemoveRuleFromAgents(rule *model.ForwardRule) {
	_ = o.hub.SendToNode(rule.IngressNodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
		RuleID: rule.ID,
		Role:   o.ingressRoleFor(rule),
	})
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		hopSent := make(map[string]struct{})
		egSent := make(map[uint64]struct{})

		var line model.TunnelLine
		if err := o.db.First(&line, rule.TunnelLineID).Error; err == nil {
			for idx, hid := range line.HopIDs() {
				role := protocol.RoleHop(idx)
				key := fmt.Sprintf("%d:%s", hid, role)
				hopSent[key] = struct{}{}
				_ = o.hub.SendToNode(hid, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
					RuleID: rule.ID,
					Role:   role,
				})
			}
			for _, em := range line.EgressMembers() {
				egSent[em.NodeID] = struct{}{}
				_ = o.hub.SendToNode(em.NodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
					RuleID: rule.ID,
					Role:   protocol.RoleEgress,
				})
			}
		}
		for idx, a := range rule.HopPortAllocs() {
			role := protocol.RoleHop(idx)
			key := fmt.Sprintf("%d:%s", a.NodeID, role)
			if _, ok := hopSent[key]; !ok && a.NodeID > 0 {
				_ = o.hub.SendToNode(a.NodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
					RuleID: rule.ID,
					Role:   role,
				})
			}
		}
		for _, a := range rule.EgressPortAllocs() {
			if _, ok := egSent[a.NodeID]; !ok && a.NodeID > 0 {
				egSent[a.NodeID] = struct{}{}
				_ = o.hub.SendToNode(a.NodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
					RuleID: rule.ID,
					Role:   protocol.RoleEgress,
				})
			}
		}
	}
}

func (o *Orchestrator) ingressRoleFor(rule *model.ForwardRule) protocol.RuleRole {
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		return protocol.RoleIngress
	}
	return protocol.RoleRelay
}

// SyncNodeRules compiles all active rules where nodeID acts as Ingress/Relay, intermediate Hop, or Egress,
// and sends a MsgSyncAllRules snapshot to the Agent.
func (o *Orchestrator) SyncNodeRules(nodeID uint64, forceRestart ...bool) {
	force := len(forceRestart) > 0 && forceRestart[0]
	var specs []protocol.RuleSpec

	// 1. Rules where this node is the Ingress / Relay node
	var ingressRules []model.ForwardRule
	o.db.Where("ingress_node_id = ? AND enabled = ?", nodeID, true).Find(&ingressRules)

	// 2. Rules where this node is an intermediate Hop or Egress node via an enabled TunnelLine
	var allEncryptLines []model.TunnelLine
	o.db.Where("type = ? AND enabled = ?", "encrypt", true).Find(&allEncryptLines)
	var legLineIDs []uint64
	for i := range allEncryptLines {
		if allEncryptLines[i].UsesNodeInTunnelLeg(nodeID) {
			legLineIDs = append(legLineIDs, allEncryptLines[i].ID)
		}
	}
	var tunnelRules []model.ForwardRule
	if len(legLineIDs) > 0 {
		o.db.Where("mode = 'tunnel' AND tunnel_line_id IN ? AND enabled = ?", legLineIDs, true).Find(&tunnelRules)
	}

	// Merge unique candidate rules preserving deterministic order
	ruleByID := make(map[uint64]*model.ForwardRule, len(ingressRules)+len(tunnelRules))
	orderedRules := make([]*model.ForwardRule, 0, len(ingressRules)+len(tunnelRules))
	for i := range ingressRules {
		r := &ingressRules[i]
		ruleByID[r.ID] = r
		orderedRules = append(orderedRules, r)
	}
	for i := range tunnelRules {
		r := &tunnelRules[i]
		if _, exists := ruleByID[r.ID]; !exists {
			ruleByID[r.ID] = r
			orderedRules = append(orderedRules, r)
		}
	}

	inLineSet := make(map[uint64]struct{})
	userIDSet := make(map[uint64]struct{}, len(orderedRules))
	for _, r := range orderedRules {
		userIDSet[r.UserID] = struct{}{}
		if r.TunnelLineID > 0 {
			inLineSet[r.TunnelLineID] = struct{}{}
		}
	}
	enabledLines := make(map[uint64]bool, len(inLineSet))
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

	now := time.Now()
	todayStr := o.BillingDateString(now)
	ownerMap := make(map[uint64]*model.User, len(userIDSet))
	canForward := make(map[uint64]bool, len(userIDSet))
	if len(userIDSet) > 0 {
		uids := make([]uint64, 0, len(userIDSet))
		for uid := range userIDSet {
			uids = append(uids, uid)
		}
		var owners []model.User
		o.db.Where("id IN ?", uids).Find(&owners)
		for i := range owners {
			ownerMap[owners[i].ID] = &owners[i]
			canForward[owners[i].ID] = owners[i].CanForward(now)
		}
	}

	for _, r := range orderedRules {
		owner := ownerMap[r.UserID]
		if owner == nil || !canForward[r.UserID] || !owner.HasTunnelPermission(r.TunnelLineID) {
			continue
		}
		if r.TunnelLineID > 0 && !enabledLines[r.TunnelLineID] {
			continue
		}
		if !r.WithinRuleQuotas(todayStr) || !o.RuleNodesWithinQuota(r) {
			continue
		}
		compiled, err := o.CompileRuleGraph(r)
		if err != nil {
			continue
		}
		for _, ns := range compiled {
			if ns.NodeID == nodeID {
				specs = append(specs, ns.Spec)
			}
		}
	}

	_ = o.hub.SendToNode(nodeID, protocol.MsgSyncAllRules, protocol.SyncAllRulesPayload{
		Rules:        specs,
		ForceRestart: force,
	})
	log.Printf("[Orchestrator] Synced %d rule specs to Node #%d (forceRestart=%v)", len(specs), nodeID, force)
}

// HandleTrafficReport processes incremental traffic reports from Agents, applies node/line/off-peak multipliers,
// updates hourly analytics, and enforces user, node, per-rule total, and per-rule daily traffic quotas.
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

	var sysCfg model.SystemConfig
	_ = o.db.First(&sysCfg, 1).Error
	now := time.Now()
	if report.Timestamp > 0 {
		ts := time.Unix(report.Timestamp, 0)
		// Only accept agent report timestamps within 2 minutes of server clock; otherwise use server clock
		// so a skewed or malicious Agent cannot spoof off-peak billing hours!
		if diff := now.Sub(ts); diff >= -2*time.Minute && diff <= 2*time.Minute {
			now = ts
		}
	}
	todayStr := now.In(BillingTimezoneLoc(&sysCfg)).Format("2006-01-02")
	hourBucket := time.Now().Format("2006-01-02 15:00")

	var nodeWindowBytes int64
	seenRuleRoles := make(map[string]struct{}, len(report.Deltas))
	userBilledTotals := make(map[uint64]int64)
	touchedQuotaRuleIDs := make(map[uint64]struct{})

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
		line := lineMap[rule.TunnelLineID]

		// Trust boundary: a node may only report traffic for rules it actually hosts in the reported role.
		owned := false
		switch {
		case d.Role == protocol.RoleEgress:
			if rule.Mode == "tunnel" && line != nil && line.UsesNodeAsEgress(nodeID) {
				owned = true
			}
		case protocol.IsHopRole(d.Role):
			if hopIdx, hOk := protocol.ParseHopRole(d.Role); hOk && rule.Mode == "tunnel" && line != nil {
				if idx, found := line.HopIndexOf(nodeID); found && idx == hopIdx {
					owned = true
				}
			}
		case d.Role == protocol.RoleIngress || d.Role == protocol.RoleRelay || d.Role == "":
			owned = rule.IngressNodeID == nodeID
		}
		if !owned {
			log.Printf("[Orchestrator] Dropped out-of-scope traffic delta from Node #%d (rule #%d, role %q)", nodeID, d.RuleID, d.Role)
			continue
		}
		nodeWindowBytes += rawTotal

		// Avoid double-billing multi-hop / multi-egress tunnel rules for user & rule quota:
		// count physical bandwidth on every hop/egress node above, but bill user/rule ONCE on Ingress/Relay!
		if d.Role == protocol.RoleEgress || protocol.IsHopRole(d.Role) {
			continue
		}

		multiplier := sanitizeRateMultiplier(node.TrafficRate)
		billingMode := "two_way"
		if line != nil {
			if line.RateMultiplier > 0 {
				multiplier = sanitizeRateMultiplier(line.RateMultiplier)
			}
			if line.BillingMode == "one_way" {
				billingMode = "one_way"
			}
		}
		offPeakFactor := ComputeOffPeakFactor(&sysCfg, line, now)
		multiplier = sanitizeRateMultiplier(multiplier * offPeakFactor)

		baseBytes := rawTotal
		if billingMode == "one_way" {
			baseBytes = d.DownBytes
			if d.UploadBytes > baseBytes {
				baseBytes = d.UploadBytes
			}
		}
		billed := safeScaleBytes(baseBytes, multiplier)

		ruleUpdates := map[string]any{
			"upload_bytes": gorm.Expr("upload_bytes + ?", d.UploadBytes),
			"down_bytes":   gorm.Expr("down_bytes + ?", d.DownBytes),
			"billed_bytes": gorm.Expr("billed_bytes + ?", billed),
		}
		if rule.DailyResetDate != todayStr {
			ruleUpdates["daily_used_bytes"] = billed
			ruleUpdates["daily_reset_date"] = todayStr
			rule.DailyResetDate = todayStr
			rule.DailyUsedBytes = billed
		} else {
			ruleUpdates["daily_used_bytes"] = gorm.Expr("daily_used_bytes + ?", billed)
		}
		o.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(ruleUpdates)
		if rule.RuleQuotaBytes > 0 || rule.DailyQuotaBytes > 0 {
			touchedQuotaRuleIDs[rule.ID] = struct{}{}
		}

		userBilledTotals[rule.UserID] += billed

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

	if len(touchedQuotaRuleIDs) > 0 {
		qIDs := make([]uint64, 0, len(touchedQuotaRuleIDs))
		for rid := range touchedQuotaRuleIDs {
			qIDs = append(qIDs, rid)
		}
		var updatedRules []model.ForwardRule
		o.db.Where("id IN ? AND enabled = ?", qIDs, true).Find(&updatedRules)
		for i := range updatedRules {
			r := &updatedRules[i]
			if r.RuleQuotaBytes > 0 && r.BilledBytes >= r.RuleQuotaBytes {
				o.EnforceRuleQuotaCutoff(r, "rule_quota_exceeded")
			} else if r.DailyQuotaBytes > 0 && r.DailyResetDate == todayStr && r.DailyUsedBytes >= r.DailyQuotaBytes {
				o.EnforceRuleQuotaCutoff(r, "daily_quota_exceeded")
			}
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
		checkNow := time.Now()
		for i := range touchedUsers {
			if !touchedUsers[i].CanForward(checkNow) {
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

// EnforceRuleQuotaCutoff pauses an individual rule that reached its total RuleQuotaBytes or daily DailyQuotaBytes cap.
func (o *Orchestrator) EnforceRuleQuotaCutoff(r *model.ForwardRule, statusReason string) {
	if r == nil {
		return
	}
	res := o.db.Model(&model.ForwardRule{}).
		Where("id = ? AND enabled = ?", r.ID, true).
		Updates(map[string]any{"enabled": false, "status": statusReason})
	if res.Error == nil && res.RowsAffected > 0 {
		r.Enabled = false
		r.Status = statusReason
		o.DispatchRule(r)
		log.Printf("[Orchestrator] Paused rule #%d (%s) due to %s", r.ID, r.Name, statusReason)
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

// rulesTouchingNode queries rules with a given enabled/status state where nodeID is Ingress or a Hop/Egress tunnel leg.
func (o *Orchestrator) rulesTouchingNode(nodeID uint64, onlyEnabled *bool, onlyStatus string) []model.ForwardRule {
	var allLines []model.TunnelLine
	o.db.Where("type = ?", "encrypt").Find(&allLines)
	var legLineIDs []uint64
	for i := range allLines {
		if allLines[i].UsesNodeInTunnelLeg(nodeID) {
			legLineIDs = append(legLineIDs, allLines[i].ID)
		}
	}
	q := o.db.Model(&model.ForwardRule{})
	if len(legLineIDs) > 0 {
		q = q.Where("(ingress_node_id = ? OR (mode = 'tunnel' AND tunnel_line_id IN ?))", nodeID, legLineIDs)
	} else {
		q = q.Where("ingress_node_id = ?", nodeID)
	}
	if onlyEnabled != nil {
		q = q.Where("enabled = ?", *onlyEnabled)
	}
	if onlyStatus != "" {
		q = q.Where("status = ?", onlyStatus)
	}
	var rules []model.ForwardRule
	q.Find(&rules)
	return rules
}

// EnforceNodeQuotaCutoff pauses all active rules whose required path nodes exhausted monthly quota,
// and drains an over-quota Egress member from multipath pools when sibling Egress nodes remain within quota.
func (o *Orchestrator) EnforceNodeQuotaCutoff(nodeID uint64) {
	enabledTrue := true
	rules := o.rulesTouchingNode(nodeID, &enabledTrue, "")
	cutoffCount := 0
	for i := range rules {
		r := &rules[i]
		if !o.RuleNodesWithinQuota(r) {
			r.Enabled = false
			r.Status = "node_quota_exceeded"
			o.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(map[string]any{"enabled": false, "status": r.Status})
			o.DispatchRule(r)
			cutoffCount++
		} else {
			// Multipath pool still has at least one healthy under-quota Egress: remove rule from this exhausted Egress
			// and re-dispatch upstream so traffic shifts away from nodeID immediately.
			_ = o.hub.SendToNode(nodeID, protocol.MsgRemoveRule, protocol.RemoveRulePayload{
				RuleID: r.ID,
				Role:   protocol.RoleEgress,
			})
			o.DispatchRule(r)
		}
	}
	if cutoffCount > 0 {
		log.Printf("[Orchestrator] Cut off %d rules involving Node #%d due to node traffic quota exhaustion", cutoffCount, nodeID)
		var n model.Node
		if err := o.db.First(&n, nodeID).Error; err == nil {
			o.notifier.NotifyQuotaEventAsync(
				"node_quota_exceeded",
				"节点月流量配额耗尽告警",
				fmt.Sprintf("节点 #%d「%s」已达到月流量上限，已自动暂停涉及该节点的 %d 条转发规则。", n.ID, n.Name, cutoffCount),
			)
		}
	}
}

// ResumeNodeQuotaRules resumes any `node_quota_exceeded` rules touching nodeID whose path nodes, owner, line, and port are now valid.
// When `rejoinMultipath` is omitted or true, it also triggers a non-disruptive SyncNodeRules (`forceRestart=false`) on multipath
// Egress lines using nodeID so live connections on unchanged rules are never restarted or dropped.
func (o *Orchestrator) ResumeNodeQuotaRules(nodeID uint64, now time.Time, rejoinMultipath ...bool) int {
	todayStr := o.BillingDateString(now)
	rules := o.rulesTouchingNode(nodeID, nil, "node_quota_exceeded")
	resumed := 0
	for i := range rules {
		r := &rules[i]
		if !r.WithinRuleQuotas(todayStr) || !o.RuleNodesWithinQuota(r) {
			continue
		}
		var lineRange string
		if r.TunnelLineID > 0 {
			var ln model.TunnelLine
			if o.db.Select("id, port_range, enabled").First(&ln, r.TunnelLineID).Error != nil || !ln.Enabled {
				continue
			}
			lineRange = ln.PortRange
		}
		var u model.User
		if err := o.db.First(&u, r.UserID).Error; err != nil || !u.CanForward(now) || !u.HasTunnelPermission(r.TunnelLineID) {
			continue
		}
		if r.ListenPort <= 0 || !o.PortInRange(r.IngressNodeID, r.ListenPort, lineRange) {
			o.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(map[string]any{
				"enabled":    false,
				"status":     "error",
				"last_error": "规则端口不在当前允许的端口范围内，请编辑规则重新分配端口后再启用",
			})
			continue
		}
		if res := o.db.Model(&model.ForwardRule{}).Where("id = ? AND status = ?", r.ID, "node_quota_exceeded").
			Updates(map[string]any{"enabled": true, "status": "running"}); res.Error == nil && res.RowsAffected > 0 {
			o.db.First(r, r.ID)
			o.DispatchRule(r)
			resumed++
		}
	}

	shouldRejoin := len(rejoinMultipath) == 0 || rejoinMultipath[0]
	if shouldRejoin {
		var mpLines []model.TunnelLine
		o.db.Where("type = ? AND enabled = ?", "encrypt", true).Find(&mpLines)
		upstreamNodes := make(map[uint64]struct{})
		isMultipathMember := false
		for i := range mpLines {
			if len(mpLines[i].EgressMembers()) > 1 && mpLines[i].UsesNodeAsEgress(nodeID) {
				isMultipathMember = true
				hops := mpLines[i].HopIDs()
				if len(hops) > 0 {
					upstreamNodes[hops[len(hops)-1]] = struct{}{}
				} else if mpLines[i].IngressNodeID > 0 {
					upstreamNodes[mpLines[i].IngressNodeID] = struct{}{}
				}
			}
		}
		if isMultipathMember {
			o.SyncNodeRules(nodeID, false)
			for upID := range upstreamNodes {
				o.SyncNodeRules(upID, false)
			}
		}
	}
	return resumed
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

// ResetNodeTraffic clears a node's accumulated traffic counter and resumes any `node_quota_exceeded` rules touching that node
// whose owners and path nodes are currently eligible to forward.
func (o *Orchestrator) ResetNodeTraffic(nodeID uint64, now time.Time) int {
	var node model.Node
	if err := o.db.First(&node, nodeID).Error; err != nil {
		return 0
	}
	wasOverQuota := node.QuotaBytes > 0 && node.UsedBytes >= node.QuotaBytes
	o.db.Model(&model.Node{}).Where("id = ?", nodeID).Updates(map[string]any{
		"used_bytes":       0,
		"last_reset_month": now.UTC().Format("2006-01"),
	})

	resumed := o.ResumeNodeQuotaRules(nodeID, now, wasOverQuota)
	if wasOverQuota || resumed > 0 {
		o.SyncNodeRules(nodeID, false)
	}
	return resumed
}

// ResumeUserQuotaRules resumes any `quota_exceeded` rules belonging to the user if the user is eligible to forward.
func (o *Orchestrator) ResumeUserQuotaRules(u *model.User, now time.Time) int {
	if u == nil || !u.CanForward(now) {
		return 0
	}
	todayStr := o.BillingDateString(now)
	var rules []model.ForwardRule
	o.db.Where("user_id = ? AND status = ?", u.ID, "quota_exceeded").Find(&rules)
	resumed := 0
	for i := range rules {
		if !u.HasTunnelPermission(rules[i].TunnelLineID) || !o.tunnelLineEnabled(rules[i].TunnelLineID) ||
			rules[i].ListenPort <= 0 || !rules[i].WithinRuleQuotas(todayStr) || !o.RuleNodesWithinQuota(&rules[i]) {
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

// ProcessPeriodicResets runs:
//  1. Daily per-rule traffic rollover & auto-resume for `daily_quota_exceeded` rules
//  2. Monthly traffic reset for nodes (on ResetDay 1..28)
//  3. 30-day periodic traffic reset for long-cycle users (MonthlyReset == true)
func (o *Orchestrator) ProcessPeriodicResets(now time.Time) {
	todayStr := o.BillingDateString(now)

	// 0. Daily per-rule traffic rollover & resume
	o.db.Model(&model.ForwardRule{}).
		Where("daily_reset_date <> '' AND daily_reset_date <> ? AND status <> ?", todayStr, "daily_quota_exceeded").
		Updates(map[string]any{"daily_used_bytes": 0, "daily_reset_date": todayStr})

	var dailyPaused []model.ForwardRule
	o.db.Where("status = ? AND daily_reset_date <> ?", "daily_quota_exceeded", todayStr).Find(&dailyPaused)
	for i := range dailyPaused {
		r := &dailyPaused[i]
		o.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(map[string]any{
			"daily_used_bytes": 0,
			"daily_reset_date": todayStr,
		})
		r.DailyUsedBytes = 0
		r.DailyResetDate = todayStr
		if r.ListenPort <= 0 || !r.WithinRuleQuotas(todayStr) || !o.RuleNodesWithinQuota(r) {
			continue
		}
		var u model.User
		if err := o.db.First(&u, r.UserID).Error; err != nil || !u.CanForward(now) ||
			!u.HasTunnelPermission(r.TunnelLineID) || !o.tunnelLineEnabled(r.TunnelLineID) {
			continue
		}
		if res := o.db.Model(&model.ForwardRule{}).Where("id = ? AND status = ?", r.ID, "daily_quota_exceeded").
			Updates(map[string]any{"enabled": true, "status": "running"}); res.Error == nil && res.RowsAffected > 0 {
			o.db.First(r, r.ID)
			o.DispatchRule(r)
			log.Printf("[Orchestrator] Auto-resumed daily_quota_exceeded rule #%d (%s) on new day %s", r.ID, r.Name, todayStr)
		}
	}

	utcNow := now.UTC()
	currentYM := utcNow.Format("2006-01")
	currentDay := utcNow.Day()

	// 1. Node monthly traffic reset on ResetDay
	var nodes []model.Node
	o.db.Where("reset_day >= 1 AND reset_day <= 28").Find(&nodes)
	for _, n := range nodes {
		if currentDay >= n.ResetDay && n.LastResetMonth != currentYM {
			wasOver := n.QuotaBytes > 0 && n.UsedBytes >= n.QuotaBytes
			res := o.db.Model(&model.Node{}).
				Where("id = ? AND last_reset_month <> ?", n.ID, currentYM).
				Updates(map[string]any{"used_bytes": 0, "last_reset_month": currentYM})
			if res.Error == nil && res.RowsAffected > 0 {
				resumed := o.ResumeNodeQuotaRules(n.ID, utcNow, wasOver)
				if wasOver || resumed > 0 {
					o.SyncNodeRules(n.ID, false)
				}
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


