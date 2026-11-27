package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
)

func newSafeDNSHTTPClient() *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return security.SafeDialTCP(ctx, addr, 6*time.Second, security.DefaultPolicy.AllowPrivateTargets)
		},
		TLSHandshakeTimeout:   6 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SetDNSProviderOverrideForTest overrides the HTTP client and provider base URLs in unit/integration tests.
func (o *Orchestrator) SetDNSProviderOverrideForTest(client *http.Client, cfBaseURL, dpBaseURL string) {
	o.failoverMu.Lock()
	defer o.failoverMu.Unlock()
	o.dnsTestMode = true
	if client != nil {
		o.dnsHTTPClient = client
	}
	if cfBaseURL != "" {
		o.cloudflareBaseURL = strings.TrimRight(cfBaseURL, "/")
	}
	if dpBaseURL != "" {
		o.dnspodBaseURL = strings.TrimRight(dpBaseURL, "/")
	}
}

// IsSafeProviderIdentifier checks that a Cloudflare/DNSPod ZoneID or RecordID contains only safe URL/form identifier characters.
func IsSafeProviderIdentifier(s string) bool {
	return isSafeProviderIdentifier(s)
}

func isSafeProviderIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ResolveNodeRecordIP extracts a valid IPv4 ("A") or IPv6 ("AAAA") public/routable address from a Node's ConnectIP/PublicHost/ServerIP.
func ResolveNodeRecordIP(node *model.Node, recordType string) (string, error) {
	if node == nil {
		return "", fmt.Errorf("节点不存在")
	}
	wantV6 := strings.EqualFold(strings.TrimSpace(recordType), "AAAA")
	for _, raw := range []string{node.ConnectIP, node.PublicHost, node.ServerIP} {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() {
			continue
		}
		if wantV6 && addr.Is6() {
			return addr.String(), nil
		}
		if !wantV6 && addr.Is4() {
			return addr.String(), nil
		}
	}
	rType := "A"
	if wantV6 {
		rType = "AAAA"
	}
	return "", fmt.Errorf("节点 #%d (%s) 未配置有效的 %s 记录 IP（请在节点连接 IP 或服务器 IP 填写对应 IPv4/IPv6 地址）", node.ID, node.Name, rType)
}

func (o *Orchestrator) isFailoverNodeHealthy(node *model.Node, thresholdSec int, now time.Time) bool {
	if node == nil {
		return false
	}
	if node.Status == "maintenance" {
		return false
	}
	if node.Status == "online" {
		if node.LastSeenAt != nil && !node.LastSeenAt.IsZero() {
			maxStale := 90 * time.Second
			if thresholdSec > 90 {
				maxStale = time.Duration(thresholdSec) * time.Second
			}
			if now.Sub(*node.LastSeenAt) > maxStale {
				// Double-check live hub session before declaring stale
				online := false
				if o.hub != nil {
					for _, id := range o.hub.OnlineNodeIDs() {
						if id == node.ID {
							online = true
							break
						}
					}
				}
				if !online {
					return false
				}
			}
		}
		return true
	}

	// Node status is offline
	if thresholdSec <= 0 {
		return false
	}
	if node.LastSeenAt == nil || node.LastSeenAt.IsZero() {
		return false
	}
	return now.Sub(*node.LastSeenAt) < time.Duration(thresholdSec)*time.Second
}

// EvaluateDNSFailoverGroups inspects all enabled IngressFailoverGroups and executes automatic DNS failover or failback.
func (o *Orchestrator) EvaluateDNSFailoverGroups(now time.Time) {
	var groups []model.IngressFailoverGroup
	if err := o.db.Where("enabled = ?", true).Find(&groups).Error; err != nil || len(groups) == 0 {
		return
	}
	for i := range groups {
		_, _, _ = o.EvaluateSingleFailoverGroup(groups[i].ID, now, false, 0)
	}
}

// EvaluateSingleFailoverGroup evaluates one IngressFailoverGroup and switches DNS if needed (or when manualTargetNodeID > 0).
func (o *Orchestrator) EvaluateSingleFailoverGroup(groupID uint64, now time.Time, force bool, manualTargetNodeID uint64) (*model.IngressFailoverGroup, bool, error) {
	o.failoverMu.Lock()
	defer o.failoverMu.Unlock()

	var group model.IngressFailoverGroup
	if err := o.db.First(&group, groupID).Error; err != nil {
		return nil, false, fmt.Errorf("DNS 容灾组不存在")
	}

	backupIDs, err := group.ParseBackupNodeIDs()
	if err != nil {
		return &group, false, err
	}

	nodeIDs := make([]uint64, 0, 1+len(backupIDs)+1)
	nodeIDs = append(nodeIDs, group.PrimaryNodeID)
	nodeIDs = append(nodeIDs, backupIDs...)
	if group.ActiveNodeID > 0 {
		nodeIDs = append(nodeIDs, group.ActiveNodeID)
	}
	var nodes []model.Node
	o.db.Where("id IN ?", nodeIDs).Find(&nodes)
	onlineSet := make(map[uint64]struct{})
	if o.hub != nil {
		for _, id := range o.hub.OnlineNodeIDs() {
			onlineSet[id] = struct{}{}
		}
	}
	nodeMap := make(map[uint64]*model.Node, len(nodes))
	for i := range nodes {
		n := nodes[i]
		if _, live := onlineSet[n.ID]; live && n.Status != "maintenance" {
			n.Status = "online"
		}
		nodeMap[n.ID] = &n
	}

	threshold := group.OfflineThresholdSec
	if force || manualTargetNodeID > 0 {
		threshold = 0
	}

	var desiredNodeID uint64
	var desiredIP string

	if manualTargetNodeID > 0 {
		allowed := manualTargetNodeID == group.PrimaryNodeID
		for _, bid := range backupIDs {
			if bid == manualTargetNodeID {
				allowed = true
				break
			}
		}
		if !allowed {
			return &group, false, fmt.Errorf("目标节点 #%d 不在该容灾组的主备列表中", manualTargetNodeID)
		}
		ip, ipErr := ResolveNodeRecordIP(nodeMap[manualTargetNodeID], group.RecordType)
		if ipErr != nil {
			return &group, false, ipErr
		}
		desiredNodeID = manualTargetNodeID
		desiredIP = ip
	} else {
		pickHealthyCandidate := func(ids []uint64) (uint64, string) {
			for _, id := range ids {
				n := nodeMap[id]
				if !o.isFailoverNodeHealthy(n, threshold, now) {
					continue
				}
				if ip, ipErr := ResolveNodeRecordIP(n, group.RecordType); ipErr == nil {
					return id, ip
				}
			}
			return 0, ""
		}

		primaryNode := nodeMap[group.PrimaryNodeID]
		primaryHealthy := o.isFailoverNodeHealthy(primaryNode, threshold, now)
		primaryIP, primaryIPErr := ResolveNodeRecordIP(primaryNode, group.RecordType)
		if primaryIPErr != nil {
			primaryHealthy = false
		}

		curNode := nodeMap[group.ActiveNodeID]
		curHealthy := group.ActiveNodeID > 0 && o.isFailoverNodeHealthy(curNode, threshold, now)
		curIP := ""
		if curHealthy {
			if ip, ipErr := ResolveNodeRecordIP(curNode, group.RecordType); ipErr == nil {
				curIP = ip
			} else {
				curHealthy = false
			}
		}

		switch {
		case group.ActiveNodeID == 0:
			if primaryHealthy {
				desiredNodeID, desiredIP = group.PrimaryNodeID, primaryIP
			} else {
				desiredNodeID, desiredIP = pickHealthyCandidate(backupIDs)
			}
		case group.ActiveNodeID == group.PrimaryNodeID:
			if primaryHealthy {
				desiredNodeID, desiredIP = group.PrimaryNodeID, primaryIP
			} else {
				desiredNodeID, desiredIP = pickHealthyCandidate(backupIDs)
			}
		default:
			if group.AutoFailback && primaryHealthy {
				desiredNodeID, desiredIP = group.PrimaryNodeID, primaryIP
			} else if curHealthy {
				desiredNodeID, desiredIP = group.ActiveNodeID, curIP
			} else if primaryHealthy {
				desiredNodeID, desiredIP = group.PrimaryNodeID, primaryIP
			} else {
				desiredNodeID, desiredIP = pickHealthyCandidate(backupIDs)
			}
		}

		if desiredNodeID == 0 || desiredIP == "" {
			errMsg := "主备入口节点当前均离线或无可用解析 IP，保留现有 DNS 记录"
			o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(map[string]any{
				"last_check_at": &now,
				"last_error":    errMsg,
			})
			group.LastCheckAt = &now
			group.LastError = errMsg
			return &group, false, fmt.Errorf("%s", errMsg)
		}
	}

	// No change needed during automatic polling if already pointing at desiredNodeID + desiredIP
	if !force && manualTargetNodeID == 0 && group.ActiveNodeID == desiredNodeID && group.ActiveIP == desiredIP {
		o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(map[string]any{
			"last_check_at": &now,
			"last_error":    "",
		})
		group.LastCheckAt = &now
		group.LastError = ""
		return &group, false, nil
	}

	// Enforce anti-flap cooldown on automatic switches
	if !force && manualTargetNodeID == 0 && group.LastSwitchAt != nil && group.CooldownSec > 0 {
		if now.Sub(*group.LastSwitchAt) < time.Duration(group.CooldownSec)*time.Second {
			o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Update("last_check_at", &now)
			group.LastCheckAt = &now
			return &group, false, nil
		}
	}

	oldNodeID := group.ActiveNodeID
	oldIP := group.ActiveIP

	if err := o.applyDNSProviderUpdate(&group, oldNodeID, desiredNodeID, oldIP, desiredIP, now); err != nil {
		errStr := truncateString(err.Error(), 250)
		o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(map[string]any{
			"last_check_at": &now,
			"last_error":    errStr,
		})
		group.LastCheckAt = &now
		group.LastError = errStr
		return &group, false, err
	}

	changed := oldNodeID != desiredNodeID || oldIP != desiredIP
	if !changed && manualTargetNodeID == 0 {
		o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(map[string]any{
			"record_id":     group.RecordID,
			"last_check_at": &now,
			"last_error":    "",
		})
		group.LastCheckAt = &now
		group.LastError = ""
		return &group, false, nil
	}

	updates := map[string]any{
		"active_node_id": desiredNodeID,
		"active_ip":      desiredIP,
		"record_id":      group.RecordID,
		"last_switch_at": &now,
		"last_check_at":  &now,
		"last_error":     "",
		"switch_count":   group.SwitchCount + 1,
	}
	o.db.Model(&model.IngressFailoverGroup{}).Where("id = ?", group.ID).Updates(updates)
	group.ActiveNodeID = desiredNodeID
	group.ActiveIP = desiredIP
	group.LastSwitchAt = &now
	group.LastCheckAt = &now
	group.LastError = ""
	group.SwitchCount++

	newNodeName := fmt.Sprintf("#%d", desiredNodeID)
	if n := nodeMap[desiredNodeID]; n != nil {
		newNodeName = fmt.Sprintf("#%d「%s」", n.ID, n.Name)
	}
	actionLabel := "DNS 故障自动切换"
	if desiredNodeID == group.PrimaryNodeID && oldNodeID != 0 && oldNodeID != group.PrimaryNodeID {
		actionLabel = "DNS 主入口恢复回切"
	} else if manualTargetNodeID > 0 {
		actionLabel = "DNS 手动切换"
	}

	detail := fmt.Sprintf("%s: %s (%s) %s -> %s (节点 %s)", actionLabel, group.Domain, group.RecordType, emptyDash(oldIP), desiredIP, newNodeName)
	o.db.Create(&model.AuditLog{
		UserID:    0,
		UserEmail: "system@failover",
		Action:    "dns_failover_switch",
		Target:    group.Domain,
		Detail:    truncateString(detail, 500),
		ClientIP:  "127.0.0.1",
	})
	log.Printf("[DNSFailover] %s", detail)
	o.notifier.NotifyNodeEventAsync("dns_failover_switch", actionLabel, detail)

	return &group, true, nil
}

func emptyDash(s string) string {
	if s == "" {
		return "未初始化"
	}
	return s
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && (s[cut]&0xc0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func (o *Orchestrator) applyDNSProviderUpdate(group *model.IngressFailoverGroup, oldNodeID, newNodeID uint64, oldIP, newIP string, now time.Time) error {
	provider := strings.ToLower(strings.TrimSpace(group.Provider))
	switch provider {
	case "cloudflare":
		return o.updateCloudflareRecord(group, newIP)
	case "dnspod":
		return o.updateDNSPodRecord(group, newIP)
	case "webhook":
		return o.updateWebhookDNSRecord(group, oldNodeID, newNodeID, oldIP, newIP, now)
	default:
		return fmt.Errorf("不支持的 DNS 服务商类型 %q", group.Provider)
	}
}

func (o *Orchestrator) updateCloudflareRecord(group *model.IngressFailoverGroup, newIP string) error {
	zoneID := strings.TrimSpace(group.ZoneID)
	token := strings.TrimSpace(group.APIToken)
	if !isSafeProviderIdentifier(zoneID) {
		return fmt.Errorf("Cloudflare Zone ID 格式无效")
	}
	if token == "" {
		return fmt.Errorf("Cloudflare API Token 不能为空")
	}
	recordType := strings.ToUpper(strings.TrimSpace(group.RecordType))
	if recordType != "AAAA" {
		recordType = "A"
	}
	ttl := group.TTL
	if ttl <= 0 {
		ttl = 60
	}

	recordID := strings.TrimSpace(group.RecordID)
	if recordID == "" {
		// Auto-discover existing DNS record ID in Cloudflare Zone
		q := url.Values{}
		q.Set("type", recordType)
		q.Set("name", strings.TrimSpace(group.Domain))
		listURL := fmt.Sprintf("%s/zones/%s/dns_records?%s", o.cloudflareBaseURL, url.PathEscape(zoneID), q.Encode())
		req, err := http.NewRequest(http.MethodGet, listURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := o.dnsHTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("查询 Cloudflare DNS 记录失败: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		var listRes struct {
			Success bool `json:"success"`
			Result  []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.Unmarshal(raw, &listRes) != nil || !listRes.Success || len(listRes.Result) == 0 {
			return fmt.Errorf("未能在 Cloudflare Zone 中找到 %s (%s) 记录，请先创建对应解析记录或填写 Record ID", group.Domain, recordType)
		}
		recordID = strings.TrimSpace(listRes.Result[0].ID)
		group.RecordID = recordID
	}
	if !isSafeProviderIdentifier(recordID) {
		return fmt.Errorf("Cloudflare Record ID 格式无效")
	}

	putBody, _ := json.Marshal(map[string]any{
		"type":    recordType,
		"name":    strings.TrimSpace(group.Domain),
		"content": newIP,
		"ttl":     ttl,
		"proxied": group.Proxied,
	})
	putURL := fmt.Sprintf("%s/zones/%s/dns_records/%s", o.cloudflareBaseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	req, err := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(putBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.dnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("请求 Cloudflare API 失败: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	var cfRes struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(raw, &cfRes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !cfRes.Success {
		errMsg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(cfRes.Errors) > 0 && cfRes.Errors[0].Message != "" {
			errMsg = cfRes.Errors[0].Message
		}
		return fmt.Errorf("Cloudflare 更新 DNS 失败: %s", errMsg)
	}
	return nil
}

func splitDNSPodZoneAndSub(fullDomain, explicitZone, explicitSub string) (zone, sub string) {
	full := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fullDomain)), ".")
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(explicitZone)), ".")
	sub = strings.TrimSpace(explicitSub)

	if zone == "" {
		labels := strings.Split(full, ".")
		if len(labels) >= 2 {
			zone = strings.Join(labels[len(labels)-2:], ".")
		} else {
			zone = full
		}
	}
	if sub == "" {
		if full == zone {
			sub = "@"
		} else if strings.HasSuffix(full, "."+zone) {
			sub = strings.TrimSuffix(full, "."+zone)
		} else {
			sub = "@"
		}
	}
	return zone, sub
}

func (o *Orchestrator) updateDNSPodRecord(group *model.IngressFailoverGroup, newIP string) error {
	token := strings.TrimSpace(group.APIToken)
	if token == "" || !strings.Contains(token, ",") {
		return fmt.Errorf("DNSPod API Token 需为 'ID,Token' 组合格式")
	}
	recordType := strings.ToUpper(strings.TrimSpace(group.RecordType))
	if recordType != "AAAA" {
		recordType = "A"
	}
	ttl := group.TTL
	if ttl < 60 {
		ttl = 60
	}
	zone, sub := splitDNSPodZoneAndSub(group.Domain, group.ZoneID, group.SubDomain)
	recordID := strings.TrimSpace(group.RecordID)

	if recordID == "" {
		form := url.Values{}
		form.Set("login_token", token)
		form.Set("format", "json")
		form.Set("domain", zone)
		form.Set("sub_domain", sub)
		form.Set("record_type", recordType)
		req, err := http.NewRequest(http.MethodPost, o.dnspodBaseURL+"/Record.List", strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "ZacharyPanel-DNSFailover/1.0")
		resp, err := o.dnsHTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("查询 DNSPod 记录失败: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		var listRes struct {
			Status struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"status"`
			Records []struct {
				ID string `json:"id"`
			} `json:"records"`
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.Unmarshal(raw, &listRes) != nil || listRes.Status.Code != "1" || len(listRes.Records) == 0 {
			return fmt.Errorf("未能在 DNSPod 中找到 %s.%s (%s) 记录，请先创建记录或填写 Record ID", sub, zone, recordType)
		}
		recordID = strings.TrimSpace(listRes.Records[0].ID)
		if !isSafeProviderIdentifier(recordID) {
			return fmt.Errorf("DNSPod 返回的记录 ID 格式异常")
		}
		group.RecordID = recordID
	}

	form := url.Values{}
	form.Set("login_token", token)
	form.Set("format", "json")
	form.Set("domain", zone)
	form.Set("record_id", recordID)
	form.Set("sub_domain", sub)
	form.Set("record_type", recordType)
	form.Set("record_line", "默认")
	form.Set("value", newIP)
	form.Set("ttl", fmt.Sprintf("%d", ttl))

	req, err := http.NewRequest(http.MethodPost, o.dnspodBaseURL+"/Record.Modify", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "ZacharyPanel-DNSFailover/1.0")
	resp, err := o.dnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("请求 DNSPod API 失败: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()

	var dpRes struct {
		Status struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	}
	_ = json.Unmarshal(raw, &dpRes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || dpRes.Status.Code != "1" {
		msg := dpRes.Status.Message
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("DNSPod 更新 DNS 失败: %s", msg)
	}
	return nil
}

func (o *Orchestrator) updateWebhookDNSRecord(group *model.IngressFailoverGroup, oldNodeID, newNodeID uint64, oldIP, newIP string, now time.Time) error {
	webhookURL := strings.TrimSpace(group.WebhookURL)
	if o.dnsTestMode {
		u, err := url.Parse(webhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("Webhook 地址无效")
		}
	} else if err := ValidateWebhookURL(webhookURL); err != nil {
		return err
	}
	recordType := strings.ToUpper(strings.TrimSpace(group.RecordType))
	if recordType != "AAAA" {
		recordType = "A"
	}
	ttl := group.TTL
	if ttl <= 0 {
		ttl = 60
	}
	body, err := json.Marshal(map[string]any{
		"event":       "dns_failover_switch",
		"group_id":    group.ID,
		"group_name":  group.Name,
		"domain":      strings.TrimSpace(group.Domain),
		"record_type": recordType,
		"ttl":         ttl,
		"old_node_id": oldNodeID,
		"new_node_id": newNodeID,
		"old_ip":      oldIP,
		"new_ip":      newIP,
		"timestamp":   now.Unix(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "ZacharyPanel-DNSFailover/1.0")
	if secret := strings.TrimSpace(group.APIToken); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Zachary-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := o.dnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("调用自定义 DNS Webhook 失败: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("自定义 DNS Webhook 返回 HTTP %d", resp.StatusCode)
	}
	return nil
}
