package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
)

type dnsFailoverReq struct {
	Name                string  `json:"name"`
	Domain              string  `json:"domain"`
	RecordType          string  `json:"record_type"`
	TTL                 *int    `json:"ttl"`
	Proxied             *bool   `json:"proxied"`
	PrimaryNodeID       uint64  `json:"primary_node_id"`
	BackupNodeIDs       string  `json:"backup_node_ids"`
	Provider            string  `json:"provider"`
	ZoneID              *string `json:"zone_id"`
	RecordID            *string `json:"record_id"`
	SubDomain           *string `json:"sub_domain"`
	APIToken            *string `json:"api_token"`
	WebhookURL          *string `json:"webhook_url"`
	OfflineThresholdSec *int    `json:"offline_threshold_sec"`
	CooldownSec         *int    `json:"cooldown_sec"`
	AutoFailback        *bool   `json:"auto_failback"`
	Enabled             *bool   `json:"enabled"`
}

func maskFailoverGroup(g *model.IngressFailoverGroup) {
	if g == nil {
		return
	}
	g.HasAPIToken = strings.TrimSpace(g.APIToken) != ""
}

func isSafeDNSPodSubDomain(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '*') {
			return false
		}
	}
	return true
}

func (s *Server) validateAndNormalizeFailoverGroup(g *model.IngressFailoverGroup) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" || utf8.RuneCountInString(g.Name) > 64 {
		return fmt.Errorf("容灾组名称不能为空且不超过 64 个字符")
	}

	g.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(g.Domain), "."))
	parsedDomains, dErr := security.ParseAndValidateMatchDomains(g.Domain)
	if dErr != nil || len(parsedDomains) != 1 || strings.HasPrefix(parsedDomains[0], "*.") {
		return fmt.Errorf("解析域名格式无效（需为具体域名，如 entry.example.com）")
	}
	g.Domain = parsedDomains[0]

	g.RecordType = strings.ToUpper(strings.TrimSpace(g.RecordType))
	if g.RecordType == "" {
		g.RecordType = "A"
	}
	if g.RecordType != "A" && g.RecordType != "AAAA" {
		return fmt.Errorf("解析记录类型仅支持 A 或 AAAA")
	}

	if g.TTL <= 0 {
		g.TTL = 60
	}
	if g.TTL < 1 || g.TTL > 86400 {
		return fmt.Errorf("DNS TTL 需在 1 - 86400 秒之间")
	}

	if g.PrimaryNodeID == 0 {
		return fmt.Errorf("请选择主入口节点")
	}
	backupIDs, bErr := model.ParseHopNodeIDs(g.BackupNodeIDs)
	if bErr != nil {
		return fmt.Errorf("备用入口节点列表无效: %v", bErr)
	}
	if len(backupIDs) == 0 {
		return fmt.Errorf("请至少选择一个备用入口节点")
	}
	for _, bid := range backupIDs {
		if bid == g.PrimaryNodeID {
			return fmt.Errorf("主入口节点 #%d 不能同时出现在备用节点列表中", bid)
		}
	}
	bStrs := make([]string, 0, len(backupIDs))
	allIDs := []uint64{g.PrimaryNodeID}
	for _, bid := range backupIDs {
		bStrs = append(bStrs, strconv.FormatUint(bid, 10))
		allIDs = append(allIDs, bid)
	}
	g.BackupNodeIDs = strings.Join(bStrs, ",")

	var nodes []model.Node
	s.db.Where("id IN ?", allIDs).Find(&nodes)
	nodeMap := make(map[uint64]*model.Node, len(nodes))
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}
	for _, nid := range allIDs {
		n := nodeMap[nid]
		if n == nil {
			return fmt.Errorf("引用的入口节点 #%d 不存在", nid)
		}
		if _, ipErr := service.ResolveNodeRecordIP(n, g.RecordType); ipErr != nil {
			return ipErr
		}
	}

	g.Provider = strings.ToLower(strings.TrimSpace(g.Provider))
	switch g.Provider {
	case "cloudflare":
		g.ZoneID = strings.TrimSpace(g.ZoneID)
		g.RecordID = strings.TrimSpace(g.RecordID)
		if g.ZoneID == "" || len(g.ZoneID) > 64 || !service.IsSafeProviderIdentifier(g.ZoneID) {
			return fmt.Errorf("Cloudflare 模式必须填写有效的 Zone ID")
		}
		if g.RecordID != "" && !service.IsSafeProviderIdentifier(g.RecordID) {
			return fmt.Errorf("Cloudflare Record ID 格式无效")
		}
		if strings.TrimSpace(g.APIToken) == "" {
			return fmt.Errorf("Cloudflare 模式必须填写 API Token")
		}
	case "dnspod":
		g.ZoneID = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(g.ZoneID), "."))
		g.RecordID = strings.TrimSpace(g.RecordID)
		g.SubDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(g.SubDomain), "."))
		if g.ZoneID != "" {
			parsedZone, zErr := security.ParseAndValidateMatchDomains(g.ZoneID)
			validDomain := zErr == nil && len(parsedZone) == 1 && !strings.HasPrefix(parsedZone[0], "*.")
			if validDomain {
				g.ZoneID = parsedZone[0]
			} else if !service.IsSafeProviderIdentifier(g.ZoneID) {
				return fmt.Errorf("DNSPod 主域名或 Domain ID 格式无效")
			}
		}
		if g.SubDomain != "" && g.SubDomain != "@" && g.SubDomain != "*" {
			if len(g.SubDomain) > 128 || !isSafeDNSPodSubDomain(g.SubDomain) {
				return fmt.Errorf("DNSPod 主机记录格式无效")
			}
		}
		if g.RecordID != "" && !service.IsSafeProviderIdentifier(g.RecordID) {
			return fmt.Errorf("DNSPod Record ID 格式无效")
		}
		if strings.TrimSpace(g.APIToken) == "" || !strings.Contains(g.APIToken, ",") {
			return fmt.Errorf("DNSPod 模式必须填写 'ID,Token' 格式的 API 密钥")
		}
	case "webhook":
		g.WebhookURL = strings.TrimSpace(g.WebhookURL)
		if err := service.ValidateWebhookURL(g.WebhookURL); err != nil {
			return err
		}
	default:
		return fmt.Errorf("不支持的 DNS 服务商 %q（仅支持 cloudflare / dnspod / webhook）", g.Provider)
	}

	if g.OfflineThresholdSec < 0 || g.OfflineThresholdSec > 3600 {
		return fmt.Errorf("离线判定秒数需在 0 - 3600 秒之间")
	}
	if g.CooldownSec < 0 || g.CooldownSec > 86400 {
		return fmt.Errorf("防抖冷却秒数需在 0 - 86400 秒之间")
	}
	return nil
}

func (s *Server) handleAdminListDNSFailover(c *gin.Context) {
	var groups []model.IngressFailoverGroup
	s.db.Order("id desc").Find(&groups)
	for i := range groups {
		maskFailoverGroup(&groups[i])
	}
	c.JSON(http.StatusOK, groups)
}

func (s *Server) handleAdminCreateDNSFailover(c *gin.Context) {
	var req dnsFailoverReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 DNS 容灾参数"})
		return
	}
	group := model.IngressFailoverGroup{
		Name:                req.Name,
		Domain:              req.Domain,
		RecordType:          req.RecordType,
		TTL:                 60,
		PrimaryNodeID:       req.PrimaryNodeID,
		BackupNodeIDs:       req.BackupNodeIDs,
		Provider:            req.Provider,
		OfflineThresholdSec: 30,
		CooldownSec:         120,
		AutoFailback:        true,
		Enabled:             true,
	}
	if req.TTL != nil {
		group.TTL = *req.TTL
	}
	if req.Proxied != nil {
		group.Proxied = *req.Proxied
	}
	if req.ZoneID != nil {
		group.ZoneID = *req.ZoneID
	}
	if req.RecordID != nil {
		group.RecordID = *req.RecordID
	}
	if req.SubDomain != nil {
		group.SubDomain = *req.SubDomain
	}
	if req.APIToken != nil {
		group.APIToken = strings.TrimSpace(*req.APIToken)
	}
	if req.WebhookURL != nil {
		group.WebhookURL = *req.WebhookURL
	}
	if req.OfflineThresholdSec != nil {
		group.OfflineThresholdSec = *req.OfflineThresholdSec
	}
	if req.CooldownSec != nil {
		group.CooldownSec = *req.CooldownSec
	}
	if req.AutoFailback != nil {
		group.AutoFailback = *req.AutoFailback
	}
	if req.Enabled != nil {
		group.Enabled = *req.Enabled
	}

	if err := s.validateAndNormalizeFailoverGroup(&group); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建 DNS 容灾组失败"})
		return
	}
	// Persist explicit false booleans if set
	s.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(map[string]any{
		"proxied":       group.Proxied,
		"auto_failback": group.AutoFailback,
		"enabled":       group.Enabled,
	})
	s.recordAudit(c, "admin.create_dns_failover", group.Domain,
		fmt.Sprintf("创建多入口 DNS 容灾组 #%d「%s」(%s, 主节点 #%d)", group.ID, group.Name, group.Provider, group.PrimaryNodeID))
	maskFailoverGroup(&group)
	c.JSON(http.StatusCreated, group)
}

func (s *Server) handleAdminUpdateDNSFailover(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var group model.IngressFailoverGroup
	if err := s.db.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS 容灾组不存在"})
		return
	}
	oldDomain := group.Domain
	oldRecordType := group.RecordType
	oldZoneID := group.ZoneID
	oldSubDomain := group.SubDomain
	oldProvider := group.Provider
	oldRecordID := group.RecordID

	var req dnsFailoverReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 DNS 容灾参数"})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		group.Name = req.Name
	}
	if strings.TrimSpace(req.Domain) != "" {
		group.Domain = req.Domain
	}
	if strings.TrimSpace(req.RecordType) != "" {
		group.RecordType = req.RecordType
	}
	if req.TTL != nil {
		group.TTL = *req.TTL
	}
	if req.Proxied != nil {
		group.Proxied = *req.Proxied
	}
	if req.PrimaryNodeID > 0 {
		group.PrimaryNodeID = req.PrimaryNodeID
	}
	if strings.TrimSpace(req.BackupNodeIDs) != "" {
		group.BackupNodeIDs = req.BackupNodeIDs
	}
	if strings.TrimSpace(req.Provider) != "" {
		group.Provider = req.Provider
	}
	if req.ZoneID != nil {
		group.ZoneID = *req.ZoneID
	}
	if req.RecordID != nil {
		group.RecordID = *req.RecordID
	}
	if req.SubDomain != nil {
		group.SubDomain = *req.SubDomain
	}
	if req.APIToken != nil {
		tok := strings.TrimSpace(*req.APIToken)
		if tok != "" && tok != maskedSecretPlaceholder {
			group.APIToken = tok
		}
	}
	if req.WebhookURL != nil {
		group.WebhookURL = *req.WebhookURL
	}
	if req.OfflineThresholdSec != nil {
		group.OfflineThresholdSec = *req.OfflineThresholdSec
	}
	if req.CooldownSec != nil {
		group.CooldownSec = *req.CooldownSec
	}
	if req.AutoFailback != nil {
		group.AutoFailback = *req.AutoFailback
	}
	if req.Enabled != nil {
		group.Enabled = *req.Enabled
	}

	if err := s.validateAndNormalizeFailoverGroup(&group); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	recordIdentityChanged := group.Domain != oldDomain ||
		group.RecordType != oldRecordType ||
		group.ZoneID != oldZoneID ||
		group.SubDomain != oldSubDomain ||
		group.Provider != oldProvider
	if recordIdentityChanged && group.RecordID == oldRecordID {
		group.RecordID = ""
	}
	omitCols := []string{"last_switch_at", "last_check_at", "last_error", "switch_count"}
	if recordIdentityChanged {
		group.ActiveNodeID = 0
		group.ActiveIP = ""
	} else {
		omitCols = append(omitCols, "active_node_id", "active_ip")
	}
	if err := s.db.Omit(omitCols...).Save(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新 DNS 容灾组失败"})
		return
	}
	s.recordAudit(c, "admin.update_dns_failover", group.Domain,
		fmt.Sprintf("更新多入口 DNS 容灾组 #%d「%s」", group.ID, group.Name))
	_ = s.db.First(&group, group.ID).Error
	maskFailoverGroup(&group)
	c.JSON(http.StatusOK, group)
}

func (s *Server) handleAdminDeleteDNSFailover(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var group model.IngressFailoverGroup
	if err := s.db.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS 容灾组不存在"})
		return
	}
	s.db.Delete(&model.IngressFailoverGroup{}, id)
	s.recordAudit(c, "admin.delete_dns_failover", group.Domain, fmt.Sprintf("删除 DNS 容灾组 #%d「%s」", group.ID, group.Name))
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminReconcileDNSFailover(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var req struct {
		TargetNodeID uint64 `json:"target_node_id"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	updated, switched, err := s.orch.EvaluateSingleFailoverGroup(id, time.Now(), true, req.TargetNodeID)
	if err != nil {
		if updated == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		maskFailoverGroup(updated)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "group": updated})
		return
	}
	maskFailoverGroup(updated)
	msg := "已完成巡检，当前 DNS 解析状态正常无需切换"
	if switched {
		msg = fmt.Sprintf("已执行 DNS 切换：%s -> %s (节点 #%d)", updated.Domain, updated.ActiveIP, updated.ActiveNodeID)
		s.recordAudit(c, "admin.reconcile_dns_failover", updated.Domain, msg)
	}
	c.JSON(http.StatusOK, gin.H{
		"message":  msg,
		"switched": switched,
		"group":    updated,
	})
}
