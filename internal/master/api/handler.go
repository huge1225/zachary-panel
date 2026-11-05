package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
	"nexus-panel/pkg/utils"
)

type Server struct {
	db        *gorm.DB
	hub       *hub.AgentHub
	orch      *service.Orchestrator
	staticDir string // directory containing install-agent.sh and releases/ (agent binaries)
	publicURL string // externally reachable panel base URL, e.g. https://panel.example.com

	hashMu    sync.Mutex
	hashCache map[string]cachedHash
}

type cachedHash struct {
	modTime time.Time
	size    int64
	sum     string
}

// SetStaticDir configures where agent install assets are served from.
func (s *Server) SetStaticDir(dir string) { s.staticDir = dir }

// SetPublicURL configures the externally reachable base URL used in generated install commands.
func (s *Server) SetPublicURL(u string) { s.publicURL = strings.TrimRight(strings.TrimSpace(u), "/") }

func NewServer(db *gorm.DB, agentHub *hub.AgentHub, orch *service.Orchestrator) *Server {
	return &Server{
		db:   db,
		hub:  agentHub,
		orch: orch,
	}
}

func (s *Server) SetupRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Only trust X-Forwarded-For / X-Real-IP from explicitly configured reverse proxies; otherwise clients could
	// spoof their IP and bypass per-IP rate limits.
	var trusted []string
	for _, p := range strings.Split(os.Getenv("NEXUS_TRUSTED_PROXIES"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			trusted = append(trusted, p)
		}
	}
	if err := r.SetTrustedProxies(trusted); err != nil {
		log.Printf("[API] Invalid NEXUS_TRUSTED_PROXIES (%v); trusting no proxies", err)
		_ = r.SetTrustedProxies(nil)
	}

	// The SPA is served same-origin; cross-origin access is only enabled for explicitly listed origins.
	if origins := strings.TrimSpace(os.Getenv("NEXUS_CORS_ORIGINS")); origins != "" {
		var list []string
		for _, o := range strings.Split(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				list = append(list, o)
			}
		}
		r.Use(cors.New(cors.Config{
			AllowOrigins:     list,
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: false,
			MaxAge:           12 * time.Hour,
		}))
	}

	r.Use(func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		c.Next()
	})

	v1 := r.Group("/api/v1")
	{
		// Agent WebSocket communication endpoint
		v1.GET("/agent/ws", s.hub.HandleAgentWS)

		// Public endpoints
		v1.GET("/site-config", s.handleGetSiteConfig)
		v1.POST("/auth/login", s.handleLogin)
		v1.POST("/auth/register", s.handleRegister)

		// Authenticated user endpoints
		auth := v1.Group("")
		auth.Use(s.AuthMiddleware())
		{
			auth.GET("/user/profile", s.handleProfile)
			auth.POST("/user/password", userRateLimit(), s.handleChangePassword)
			auth.GET("/dashboard", s.handleDashboard)
			auth.GET("/telemetry", s.handleTelemetry)

			// Nodes & Tunnel Lines available for user rule creation
			auth.GET("/nodes", s.handleListNodes)
			auth.GET("/lines", s.handleListLines)

			// Forwarding Rules CRUD & Batch & Probe
			auth.GET("/rules", s.handleListRules)
			auth.POST("/rules", ruleMutationLimit(), s.handleCreateRule)
			auth.POST("/rules/batch", ruleMutationLimit(), s.handleBatchCreateRules)
			auth.PUT("/rules/:id", ruleMutationLimit(), s.handleUpdateRule)
			auth.POST("/rules/:id/toggle", ruleMutationLimit(), s.handleToggleRule)
			auth.POST("/rules/:id/probe", userRateLimit(), s.handleProbeRule)
			auth.DELETE("/rules/:id", ruleMutationLimit(), s.handleDeleteRule)

			// Roles, Plans & Redeem Codes
			auth.GET("/roles", s.handleListRoleGroups)
			auth.GET("/plans", s.handleListPlans)
			auth.POST("/plans/:id/purchase", userRateLimit(), s.handlePurchasePlan)
			auth.POST("/redeem", userRateLimit(), s.handleRedeemCode)

			// Admin-only management endpoints
			admin := auth.Group("/admin")
			admin.Use(AdminMiddleware())
			{
				admin.GET("/settings", s.handleAdminGetSettings)
				admin.PUT("/settings", s.handleAdminUpdateSettings)

				admin.POST("/roles", s.handleAdminCreateRoleGroup)
				admin.PUT("/roles/:id", s.handleAdminUpdateRoleGroup)
				admin.DELETE("/roles/:id", s.handleAdminDeleteRoleGroup)

				admin.POST("/nodes", s.handleAdminCreateNode)
				admin.PUT("/nodes/:id", s.handleAdminUpdateNode)
				admin.DELETE("/nodes/:id", s.handleAdminDeleteNode)
				admin.GET("/nodes/:id/install-cmd", s.handleAdminNodeInstallCmd)
				admin.POST("/nodes/:id/resync", s.handleAdminResyncNode)

				admin.POST("/lines", s.handleAdminCreateLine)
				admin.PUT("/lines/:id", s.handleAdminUpdateLine)
				admin.DELETE("/lines/:id", s.handleAdminDeleteLine)

				admin.POST("/plans", s.handleAdminCreatePlan)
				admin.PUT("/plans/:id", s.handleAdminUpdatePlan)
				admin.DELETE("/plans/:id", s.handleAdminDeletePlan)

				admin.GET("/users", s.handleAdminListUsers)
				admin.POST("/users", s.handleAdminCreateUser)
				admin.PUT("/users/:id", s.handleAdminUpdateUser)
				admin.DELETE("/users/:id", s.handleAdminDeleteUser)
				admin.POST("/users/:id/reset-traffic", s.handleAdminResetUserTraffic)
				admin.POST("/redeem/generate", s.handleAdminGenerateRedeem)
			}
		}
	}

	return r
}

func (s *Server) currentUserID(c *gin.Context) uint64 {
	v, _ := c.Get("user_id")
	id, _ := v.(uint64)
	return id
}

func (s *Server) isAdmin(c *gin.Context) bool {
	role, _ := c.Get("user_role")
	return role == "admin"
}

func (s *Server) handleProfile(c *gin.Context) {
	var user model.User
	if err := s.db.First(&user, s.currentUserID(c)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (s *Server) handleDashboard(c *gin.Context) {
	uid := s.currentUserID(c)
	var user model.User
	s.db.First(&user, uid)

	var ruleCount, runningRules int64
	s.db.Model(&model.ForwardRule{}).Where("user_id = ?", uid).Count(&ruleCount)
	s.db.Model(&model.ForwardRule{}).Where("user_id = ? AND enabled = ?", uid, true).Count(&runningRules)

	var nodes []model.Node
	s.db.Find(&nodes)
	onlineNodes := 0
	for i := range nodes {
		s.hub.EnrichNodeMetrics(&nodes[i])
		if nodes[i].Status == "online" {
			onlineNodes++
		}
	}

	var hourly []model.TrafficHourlyStat
	s.db.Where("user_id = ?", uid).Order("hour_bucket asc").Limit(24).Find(&hourly)

	c.JSON(http.StatusOK, gin.H{
		"user":          user,
		"total_rules":   ruleCount,
		"running_rules": runningRules,
		"total_nodes":   len(nodes),
		"online_nodes":  onlineNodes,
		"hourly_stats":  hourly,
		"engines": []map[string]string{
			{"id": "native", "name": "Native (内置/自研协议底座)", "desc": "纯 Go 零依赖转发与自研加密隧道扩展接口"},
			{"id": "gost", "name": "GOST v3 (多跳加密隧道)", "desc": "支持 TLS / WS / WSS / QUIC / KCP 多跳链路"},
			{"id": "realm", "name": "Realm (极速轻量直转)", "desc": "Rust 编写的高性能低内存 TCP/UDP 转发引擎"},
			{"id": "nftables", "name": "nftables (Linux 内核零拷贝)", "desc": "Linux 内核态 DNAT/SNAT 转发，极致吞吐零 CPU 开销"},
		},
	})
}

func (s *Server) getSystemConfig() model.SystemConfig {
	var cfg model.SystemConfig
	if err := s.db.First(&cfg, 1).Error; err != nil {
		cfg = model.SystemConfig{
			ID:               1,
			SiteName:         "Zachary Panel",
			SiteLogo:         "ZP",
			Announcement:     "",
			AllowRegister:    false,
			DefaultQuotaGB:   10,
			DefaultMaxRules:  5,
			DefaultSpeedMbps: 50,
			DefaultTunnels:   "1",
		}
		s.db.Create(&cfg)
	}
	return cfg
}

func (s *Server) handleGetSiteConfig(c *gin.Context) {
	cfg := s.getSystemConfig()
	c.JSON(http.StatusOK, gin.H{
		"site_name":      cfg.SiteName,
		"site_logo":      cfg.SiteLogo,
		"announcement":   cfg.Announcement,
		"allow_register": cfg.AllowRegister,
	})
}

func (s *Server) handleAdminGetSettings(c *gin.Context) {
	cfg := s.getSystemConfig()
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) handleAdminUpdateSettings(c *gin.Context) {
	cfg := s.getSystemConfig()
	var req struct {
		SiteName           *string `json:"site_name"`
		SiteLogo           *string `json:"site_logo"`
		Announcement       *string `json:"announcement"`
		AllowRegister      *bool   `json:"allow_register"`
		DefaultRoleGroupID *uint64 `json:"default_role_group_id"`
		DefaultPlanID      *uint64 `json:"default_plan_id"`
		DefaultQuotaGB     *int64  `json:"default_quota_gb"`
		DefaultMaxRules    *int    `json:"default_max_rules"`
		DefaultSpeedMbps   *int    `json:"default_speed_mbps"`
		DefaultTunnels     *string `json:"default_tunnels"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SiteName != nil && strings.TrimSpace(*req.SiteName) != "" {
		cfg.SiteName = strings.TrimSpace(*req.SiteName)
	}
	if req.SiteLogo != nil && strings.TrimSpace(*req.SiteLogo) != "" {
		cfg.SiteLogo = strings.TrimSpace(*req.SiteLogo)
	}
	if req.Announcement != nil {
		cfg.Announcement = strings.TrimSpace(*req.Announcement)
	}
	if req.AllowRegister != nil {
		cfg.AllowRegister = *req.AllowRegister
	}
	if req.DefaultRoleGroupID != nil && *req.DefaultRoleGroupID > 0 {
		cfg.DefaultRoleGroupID = *req.DefaultRoleGroupID
		var rg model.RoleGroup
		if err := s.db.First(&rg, cfg.DefaultRoleGroupID).Error; err == nil {
			cfg.DefaultTunnels = rg.AllowedTunnels
		}
	}
	if req.DefaultPlanID != nil {
		cfg.DefaultPlanID = *req.DefaultPlanID
	}
	if req.DefaultQuotaGB != nil && *req.DefaultQuotaGB > 0 {
		cfg.DefaultQuotaGB = *req.DefaultQuotaGB
	}
	if req.DefaultMaxRules != nil && *req.DefaultMaxRules > 0 {
		cfg.DefaultMaxRules = *req.DefaultMaxRules
	}
	if req.DefaultSpeedMbps != nil && *req.DefaultSpeedMbps > 0 {
		cfg.DefaultSpeedMbps = *req.DefaultSpeedMbps
	}
	if req.DefaultTunnels != nil && req.DefaultRoleGroupID == nil {
		cfg.DefaultTunnels = strings.TrimSpace(*req.DefaultTunnels)
	}
	s.db.Save(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) handleListNodes(c *gin.Context) {
	if s.isAdmin(c) {
		var nodes []model.Node
		s.db.Order("id asc").Find(&nodes)
		for i := range nodes {
			s.hub.EnrichNodeMetrics(&nodes[i])
		}
		c.JSON(http.StatusOK, nodes)
		return
	}

	// 普通用户无权维护或查看底层节点服务器探针，仅返回其已授权隧道关联的入口连接地址用于前端展示连接地址
	var user model.User
	s.db.First(&user, s.currentUserID(c))

	var allLines []model.TunnelLine
	s.db.Where("enabled = ?", true).Find(&allLines)
	allowedIngressIDs := make(map[uint64]bool)
	for _, l := range allLines {
		if user.HasTunnelPermission(l.ID) {
			allowedIngressIDs[l.IngressNodeID] = true
		}
	}

	var allNodes []model.Node
	s.db.Order("id asc").Find(&allNodes)
	sanitized := make([]model.Node, 0)
	for _, n := range allNodes {
		if allowedIngressIDs[n.ID] {
			sanitized = append(sanitized, model.Node{
				ID:         n.ID,
				Name:       n.Name,
				ConnectIP:  n.ConnectIP,
				PublicHost: n.PublicHost,
				Status:     n.Status,
			})
		}
	}
	c.JSON(http.StatusOK, sanitized)
}

// handleTelemetry is a lightweight, zero-heavy-join endpoint designed for 3-second real-time frontend refresh.
// It returns only hot runtime probe metrics (from in-memory AgentHub) and incremental traffic counters.
func (s *Server) handleTelemetry(c *gin.Context) {
	uid := s.currentUserID(c)
	var user struct {
		ID             uint64 `json:"id"`
		RoleGroupID    uint64 `json:"role_group_id"`
		PlanID         uint64 `json:"plan_id"`
		QuotaBytes     int64  `json:"quota_bytes"`
		UsedBytes      int64  `json:"used_bytes"`
		Status         string `json:"status"`
		AllowedTunnels string `json:"allowed_tunnels"`
	}
	s.db.Model(&model.User{}).Select("id, role_group_id, plan_id, quota_bytes, used_bytes, status, allowed_tunnels").Where("id = ?", uid).Scan(&user)

	nodes := make([]model.Node, 0)
	if s.isAdmin(c) {
		s.db.Select("id, status, quota_bytes, used_bytes").Order("id asc").Find(&nodes)
		for i := range nodes {
			s.hub.EnrichNodeMetrics(&nodes[i])
		}
	}

	type ruleDelta struct {
		ID          uint64 `json:"id"`
		UploadBytes int64  `json:"upload_bytes"`
		DownBytes   int64  `json:"down_bytes"`
		BilledBytes int64  `json:"billed_bytes"`
		Enabled     bool   `json:"enabled"`
		Status      string `json:"status"`
	}
	var rules []ruleDelta
	q := s.db.Model(&model.ForwardRule{}).Select("id, upload_bytes, down_bytes, billed_bytes, enabled, status")
	if !s.isAdmin(c) {
		q = q.Where("user_id = ?", uid)
	}
	q.Scan(&rules)

	c.JSON(http.StatusOK, gin.H{
		"timestamp": time.Now().Unix(),
		"user":      user,
		"nodes":     nodes,
		"rules":     rules,
	})
}

func (s *Server) handleListLines(c *gin.Context) {
	var lines []model.TunnelLine
	s.db.Order("id asc").Find(&lines)
	if s.isAdmin(c) {
		c.JSON(http.StatusOK, lines)
		return
	}

	var user model.User
	if err := s.db.First(&user, s.currentUserID(c)).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	authorized := make([]model.TunnelLine, 0)
	for _, l := range lines {
		if l.Enabled && user.HasTunnelPermission(l.ID) {
			authorized = append(authorized, l)
		}
	}
	c.JSON(http.StatusOK, authorized)
}

func (s *Server) handleListRules(c *gin.Context) {
	uid := s.currentUserID(c)
	var rules []model.ForwardRule
	query := s.db.Order("id desc")
	if !s.isAdmin(c) || c.Query("all") != "1" {
		query = query.Where("user_id = ?", uid)
	}
	query.Find(&rules)
	c.JSON(http.StatusOK, rules)
}

type ruleCreateUpdateReq struct {
	Name          string                    `json:"name" binding:"required"`
	Mode          string                    `json:"mode"`            // "direct" | "tunnel"
	IngressNodeID uint64                    `json:"ingress_node_id"` // Mode=="direct" 时必选
	TunnelLineID  uint64                    `json:"tunnel_line_id"`  // Mode=="tunnel" 时必选
	Engine        protocol.EngineType       `json:"engine"`          // "native" | "gost" | "realm" | "nftables"
	Protocol      string                    `json:"protocol"`        // "tcp" | "udp" | "both"
	ListenPort    int                       `json:"listen_port"`     // 0 表示自动从节点端口池分配
	LoadBalance   string                    `json:"load_balance"`    // "round_robin" | "failover"
	Targets       []protocol.TargetEndpoint `json:"targets" binding:"required"`
	SpeedMbps     int                       `json:"speed_mbps"`
}

// validateRuleInput enforces whitelists and size limits on user-supplied rule fields.
func validateRuleInput(name, proto, lb string, targets []protocol.TargetEndpoint) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 || len(name) > 128 {
		return fmt.Errorf("规则名称不能为空且不超过 64 个字符")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("规则名称包含非法字符")
		}
	}
	switch proto {
	case "", "tcp", "udp", "both":
	default:
		return fmt.Errorf("不支持的协议类型 %q", proto)
	}
	switch lb {
	case "", "round_robin", "failover", "random":
	default:
		return fmt.Errorf("不支持的负载均衡策略 %q", lb)
	}
	if len(targets) == 0 || len(targets) > 32 {
		return fmt.Errorf("目标地址数量需在 1-32 个之间")
	}
	for _, t := range targets {
		if len(t.Address) > 255 {
			return fmt.Errorf("目标地址过长")
		}
		if t.Weight < 0 || t.Weight > 1000 {
			return fmt.Errorf("目标权重需在 0-1000 之间")
		}
		// 内网目标默认拦截；仅当面板显式设置 NEXUS_ALLOW_PRIVATE_TARGETS=true（且节点也开启 -allow-private-targets）时放行
		if err := security.ValidateTargetAddress(t.Address, os.Getenv("NEXUS_ALLOW_PRIVATE_TARGETS") == "true"); err != nil {
			return fmt.Errorf("目标地址安全策略拦截 (%s): %v", t.Address, err)
		}
	}
	return nil
}

// checkNodeAddressTargets rejects targets that point back at one of the panel's own nodes (e.g. a cloud public IP
// that is 1:1 NATed and therefore not visible on the node's interfaces). Such targets hairpin into the node and reach
// services that are only firewalled for outside traffic. Disabled together with the private-target opt-in.
func (s *Server) checkNodeAddressTargets(targets []protocol.TargetEndpoint) error {
	if os.Getenv("NEXUS_ALLOW_PRIVATE_TARGETS") == "true" {
		return nil
	}
	var nodes []model.Node
	s.db.Select("server_ip", "connect_ip", "public_host", "internal_host").Find(&nodes)
	nodeAddrs := map[string]bool{}
	for _, n := range nodes {
		for _, h := range []string{n.ServerIP, n.ConnectIP, n.PublicHost, n.InternalHost} {
			h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]"))
			if h == "" {
				continue
			}
			nodeAddrs[h] = true
			if ip := net.ParseIP(h); ip != nil {
				nodeAddrs[ip.String()] = true
			}
		}
	}
	if len(nodeAddrs) == 0 {
		return nil
	}
	for _, t := range targets {
		host, _, err := net.SplitHostPort(t.Address)
		if err != nil {
			continue // format errors are reported by validateRuleInput
		}
		host = strings.ToLower(host)
		ips := []net.IP{}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		} else {
			if nodeAddrs[host] {
				return fmt.Errorf("目标地址不能指向面板节点自身 (%s)", t.Address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			ips, _ = net.DefaultResolver.LookupIP(ctx, "ip", host)
			cancel()
		}
		for _, ip := range ips {
			if nodeAddrs[ip.String()] {
				return fmt.Errorf("目标地址不能指向面板节点自身 (%s)", t.Address)
			}
		}
	}
	return nil
}

func (s *Server) handleCreateRule(c *gin.Context) {
	uid := s.currentUserID(c)
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	if user.UsedBytes >= user.QuotaBytes {
		c.JSON(http.StatusForbidden, gin.H{"error": "流量配额已用尽，请先升级套餐或兑换流量"})
		return
	}
	if user.Role != "admin" && !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "套餐已到期，请续费后再创建规则"})
		return
	}

	var req ruleCreateUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则参数"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := validateRuleInput(req.Name, req.Protocol, req.LoadBalance, req.Targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.checkNodeAddressTargets(req.Targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 普通用户严禁绕过隧道直接指定节点，且必须具备所选隧道的使用权限
	if !s.isAdmin(c) {
		if req.TunnelLineID == 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "必须选择已授权的隧道创建转发"})
			return
		}
		if !user.HasTunnelPermission(req.TunnelLineID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该隧道，请联系管理员分配权限"})
			return
		}
	}

	if req.Mode == "" {
		req.Mode = "direct"
	}
	if req.Mode != "direct" && req.Mode != "tunnel" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的转发模式"})
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.LoadBalance == "" {
		req.LoadBalance = "round_robin"
	}
	if req.Engine == "" {
		req.Engine = protocol.EngineNative
	}
	if !validEngine(req.Engine) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的转发引擎"})
		return
	}

	ingressNodeID := req.IngressNodeID
	ruleMode := req.Mode
	ruleEngine := req.Engine
	var line model.TunnelLine
	if req.TunnelLineID > 0 {
		if err := s.db.First(&line, req.TunnelLineID).Error; err != nil || (!line.Enabled && !s.isAdmin(c)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
			return
		}
		ingressNodeID = line.IngressNodeID
		if line.Type == "encrypt" && line.EgressNodeID > 0 {
			ruleMode = "tunnel"
		} else {
			ruleMode = "direct"
		}
		// 转发方式在隧道创建时已固化，直接继承所属隧道的转发方式
		if line.Engine != "" {
			ruleEngine = line.Engine
		}
	} else if ruleMode == "tunnel" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "隧道模式必须选择隧道"})
		return
	}

	targetsBytes, _ := json.Marshal(req.Targets)
	speedLimit := req.SpeedMbps
	if !s.isAdmin(c) && (speedLimit <= 0 || speedLimit > user.SpeedMbps) {
		speedLimit = user.SpeedMbps
	}
	if speedLimit < 0 {
		speedLimit = 0
	}
	rule := model.ForwardRule{
		UserID:        uid,
		Name:          req.Name,
		Mode:          ruleMode,
		IngressNodeID: ingressNodeID,
		TunnelLineID:  req.TunnelLineID,
		Engine:        ruleEngine,
		Protocol:      req.Protocol,
		LoadBalance:   req.LoadBalance,
		TargetsJSON:   string(targetsBytes),
		SpeedMbps:     speedLimit,
		Enabled:       true,
		Status:        "running",
	}

	// Quota checks, port allocation and insert are serialized to prevent concurrent requests from exceeding
	// quotas or allocating the same port twice.
	status, err := 0, error(nil)
	_ = s.orch.WithAllocLock(func() error {
		var currentCount int64
		s.db.Model(&model.ForwardRule{}).Where("user_id = ?", uid).Count(&currentCount)
		if int(currentCount) >= user.MaxRules {
			status, err = http.StatusForbidden, fmt.Errorf("规则数量已达套餐上限 (%d 条)", user.MaxRules)
			return err
		}
		if req.TunnelLineID > 0 && line.MaxPortCount > 0 {
			var lineRuleCount int64
			s.db.Model(&model.ForwardRule{}).Where("tunnel_line_id = ?", line.ID).Count(&lineRuleCount)
			if int(lineRuleCount) >= line.MaxPortCount {
				status, err = http.StatusForbidden, fmt.Errorf("该隧道转发规则数已达上限 (%d 条)", line.MaxPortCount)
				return err
			}
		}
		allocPort, aerr := s.orch.AllocatePortForNode(ingressNodeID, req.ListenPort)
		if aerr != nil {
			status, err = http.StatusBadRequest, aerr
			return err
		}
		rule.ListenPort = allocPort
		if cerr := s.db.Create(&rule).Error; cerr != nil {
			log.Printf("[API] create rule failed: %v", cerr)
			status, err = http.StatusInternalServerError, fmt.Errorf("创建规则失败，请稍后再试")
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	s.orch.DispatchRule(&rule)
	c.JSON(http.StatusCreated, rule)
}

func validEngine(e protocol.EngineType) bool {
	switch e {
	case protocol.EngineNative, protocol.EngineGost, protocol.EngineRealm, protocol.EngineNftables:
		return true
	}
	return false
}

func (s *Server) handleBatchCreateRules(c *gin.Context) {
	uid := s.currentUserID(c)
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}
	if user.UsedBytes >= user.QuotaBytes {
		c.JSON(http.StatusForbidden, gin.H{"error": "流量配额已用尽，无法批量创建规则"})
		return
	}
	if user.Role != "admin" && !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "套餐已到期，请续费后再创建规则"})
		return
	}

	var req struct {
		TunnelLineID uint64                `json:"tunnel_line_id" binding:"required"`
		Protocol     string                `json:"protocol"`
		Items        []ruleCreateUpdateReq `json:"items" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的批量规则参数"})
		return
	}
	if len(req.Items) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "单次批量导入最多支持 50 条规则"})
		return
	}
	switch req.Protocol {
	case "", "tcp", "udp", "both":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的协议类型"})
		return
	}

	if !s.isAdmin(c) && !user.HasTunnelPermission(req.TunnelLineID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该隧道，请联系管理员分配权限"})
		return
	}

	var line model.TunnelLine
	if err := s.db.First(&line, req.TunnelLineID).Error; err != nil || (!line.Enabled && !s.isAdmin(c)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
		return
	}

	for i := range req.Items {
		req.Items[i].Name = strings.TrimSpace(req.Items[i].Name)
		item := req.Items[i]
		if err := validateRuleInput(item.Name, item.Protocol, item.LoadBalance, item.Targets); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, err)})
			return
		}
		if err := s.checkNodeAddressTargets(item.Targets); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, err)})
			return
		}
	}

	ruleMode := "direct"
	if line.Type == "encrypt" && line.EgressNodeID > 0 {
		ruleMode = "tunnel"
	}
	proto := req.Protocol
	if proto == "" {
		proto = "tcp"
	}

	var created []model.ForwardRule
	status, err := 0, error(nil)
	_ = s.orch.WithAllocLock(func() error {
		var currentUserRules int64
		s.db.Model(&model.ForwardRule{}).Where("user_id = ?", uid).Count(&currentUserRules)
		if int(currentUserRules)+len(req.Items) > user.MaxRules {
			status, err = http.StatusForbidden, fmt.Errorf("超出套餐规则数上限 (%d/%d)", int(currentUserRules)+len(req.Items), user.MaxRules)
			return err
		}
		if line.MaxPortCount > 0 {
			var lineRuleCount int64
			s.db.Model(&model.ForwardRule{}).Where("tunnel_line_id = ?", line.ID).Count(&lineRuleCount)
			if int(lineRuleCount)+len(req.Items) > line.MaxPortCount {
				status, err = http.StatusForbidden, fmt.Errorf("超出该隧道端口上限 (%d/%d)", int(lineRuleCount)+len(req.Items), line.MaxPortCount)
				return err
			}
		}
		for _, item := range req.Items {
			allocPort, aerr := s.orch.AllocatePortForNode(line.IngressNodeID, item.ListenPort)
			if aerr != nil {
				status, err = http.StatusBadRequest, fmt.Errorf("规则「%s」端口分配失败: %v", item.Name, aerr)
				return err
			}
			itemProto := item.Protocol
			if itemProto == "" {
				itemProto = proto
			}
			lb := item.LoadBalance
			if lb == "" {
				lb = "round_robin"
			}
			speedLimit := item.SpeedMbps
			if !s.isAdmin(c) && (speedLimit <= 0 || speedLimit > user.SpeedMbps) {
				speedLimit = user.SpeedMbps
			}
			if speedLimit < 0 {
				speedLimit = 0
			}
			targetsBytes, _ := json.Marshal(item.Targets)
			rule := model.ForwardRule{
				UserID:        uid,
				Name:          item.Name,
				Mode:          ruleMode,
				IngressNodeID: line.IngressNodeID,
				TunnelLineID:  line.ID,
				Engine:        line.Engine,
				Protocol:      itemProto,
				ListenPort:    allocPort,
				LoadBalance:   lb,
				TargetsJSON:   string(targetsBytes),
				SpeedMbps:     speedLimit,
				Enabled:       true,
				Status:        "running",
			}
			if cerr := s.db.Create(&rule).Error; cerr != nil {
				log.Printf("[API] batch create rule failed: %v", cerr)
				continue
			}
			created = append(created, rule)
		}
		return nil
	})
	for i := range created {
		s.orch.DispatchRule(&created[i])
	}
	if err != nil {
		msg := err.Error()
		if len(created) > 0 {
			msg = fmt.Sprintf("%s（已成功创建 %d 条）", msg, len(created))
		}
		c.JSON(status, gin.H{"error": msg})
		return
	}
	c.JSON(http.StatusCreated, created)
}

func (s *Server) handleUpdateRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	if rule.UserID != s.currentUserID(c) && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权修改此规则"})
		return
	}

	var req ruleCreateUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的规则参数"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := validateRuleInput(req.Name, req.Protocol, req.LoadBalance, req.Targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.checkNodeAddressTargets(req.Targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var owner model.User
	s.db.First(&owner, rule.UserID)

	targetTunnelID := rule.TunnelLineID
	if req.TunnelLineID > 0 {
		targetTunnelID = req.TunnelLineID
	}
	if !s.isAdmin(c) && !owner.HasTunnelPermission(targetTunnelID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该隧道，请联系管理员分配权限"})
		return
	}

	oldRule := rule
	targetsBytes, _ := json.Marshal(req.Targets)
	rule.Name = req.Name

	needRemoveOld := false
	var newLine model.TunnelLine
	switchLine := req.TunnelLineID > 0 && req.TunnelLineID != rule.TunnelLineID
	if switchLine {
		if err := s.db.First(&newLine, req.TunnelLineID).Error; err != nil || (!newLine.Enabled && !s.isAdmin(c)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
			return
		}
		needRemoveOld = true
		rule.TunnelLineID = newLine.ID
		rule.IngressNodeID = newLine.IngressNodeID
		rule.Engine = newLine.Engine
		rule.RelayPort = 0
		if newLine.Type == "encrypt" && newLine.EgressNodeID > 0 {
			rule.Mode = "tunnel"
		} else {
			rule.Mode = "direct"
		}
	}

	if req.Protocol != "" {
		rule.Protocol = req.Protocol
	}
	if req.LoadBalance != "" {
		rule.LoadBalance = req.LoadBalance
	}
	rule.TargetsJSON = string(targetsBytes)
	if s.isAdmin(c) {
		if req.SpeedMbps >= 0 {
			rule.SpeedMbps = req.SpeedMbps
		}
	} else {
		if req.SpeedMbps <= 0 || req.SpeedMbps > owner.SpeedMbps {
			rule.SpeedMbps = owner.SpeedMbps
		} else {
			rule.SpeedMbps = req.SpeedMbps
		}
	}

	status, err := 0, error(nil)
	_ = s.orch.WithAllocLock(func() error {
		if switchLine && newLine.MaxPortCount > 0 {
			var lineRuleCount int64
			s.db.Model(&model.ForwardRule{}).Where("tunnel_line_id = ?", newLine.ID).Count(&lineRuleCount)
			if int(lineRuleCount) >= newLine.MaxPortCount {
				status, err = http.StatusForbidden, fmt.Errorf("目标隧道转发规则数已达上限 (%d 条)", newLine.MaxPortCount)
				return err
			}
		}
		if rule.IngressNodeID != oldRule.IngressNodeID {
			// 切换到了不同入口节点的隧道，需在新节点上校验或重新分配端口
			desiredPort := req.ListenPort
			if desiredPort == oldRule.ListenPort {
				desiredPort = 0
			}
			allocPort, aerr := s.orch.AllocatePortForNode(rule.IngressNodeID, desiredPort)
			if aerr != nil {
				status, err = http.StatusBadRequest, aerr
				return err
			}
			rule.ListenPort = allocPort
		} else if req.ListenPort > 0 && req.ListenPort != rule.ListenPort {
			allocPort, aerr := s.orch.AllocatePortForNode(rule.IngressNodeID, req.ListenPort)
			if aerr != nil {
				status, err = http.StatusBadRequest, aerr
				return err
			}
			rule.ListenPort = allocPort
		}
		if serr := s.db.Omit(ruleCounterCols...).Save(&rule).Error; serr != nil {
			log.Printf("[API] update rule failed: %v", serr)
			status, err = http.StatusInternalServerError, fmt.Errorf("保存规则失败，请稍后再试")
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if needRemoveOld {
		s.orch.RemoveRuleFromAgents(&oldRule)
	}
	s.orch.DispatchRule(&rule)
	c.JSON(http.StatusOK, rule)
}

func (s *Server) handleToggleRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	if rule.UserID != s.currentUserID(c) && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权操作此规则"})
		return
	}

	if !rule.Enabled {
		var user model.User
		if err := s.db.First(&user, rule.UserID).Error; err == nil {
			if !s.isAdmin(c) && !user.HasTunnelPermission(rule.TunnelLineID) {
				c.JSON(http.StatusForbidden, gin.H{"error": "该隧道权限未授权或已收回，无法启用转发"})
				return
			}
			if user.UsedBytes >= user.QuotaBytes || (!user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt)) {
				c.JSON(http.StatusForbidden, gin.H{"error": "账户流量已用尽或套餐已到期，无法启用规则"})
				return
			}
		}
	}

	rule.Enabled = !rule.Enabled
	if rule.Enabled {
		rule.Status = "running"
	} else {
		rule.Status = "paused"
	}
	s.db.Omit(ruleCounterCols...).Save(&rule)
	s.orch.DispatchRule(&rule)
	c.JSON(http.StatusOK, rule)
}

func (s *Server) handleProbeRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	if rule.UserID != s.currentUserID(c) && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权探测他人规则"})
		return
	}

	var targets []protocol.TargetEndpoint
	_ = json.Unmarshal([]byte(rule.TargetsJSON), &targets)
	var addrs []string
	for _, t := range targets {
		addrs = append(addrs, t.Address)
	}

	// 双端加密对接隧道：支持端到端分段测速（入口->出口隧道延迟 tunnel_ms + 出口->目标落地延迟 latencies）
	tunnelMs := 0
	probeNodeID := rule.IngressNodeID
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		var line model.TunnelLine
		if err := s.db.First(&line, rule.TunnelLineID).Error; err == nil && line.EgressNodeID > 0 {
			probeNodeID = line.EgressNodeID
			var egressNode model.Node
			if err := s.db.First(&egressNode, line.EgressNodeID).Error; err == nil && rule.RelayPort > 0 {
				egressHost := egressNode.ServerIP
				if egressHost == "" {
					egressHost = egressNode.ConnectIP
				}
				hopAddr := fmt.Sprintf("%s:%d", egressHost, rule.RelayPort)
				if hopMap, hErr := s.hub.RequestProbe(rule.IngressNodeID, rule.ID, []string{hopAddr}); hErr == nil {
					if ms, ok := hopMap[hopAddr]; ok && ms > 0 {
						tunnelMs = ms
					}
				}
			}
		}
	}

	latencies, err := s.hub.RequestProbe(probeNodeID, rule.ID, addrs)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("节点探测未响应 (%v)", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tunnel_ms": tunnelMs,
		"latencies": latencies,
	})
}

func (s *Server) handleDeleteRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	if rule.UserID != s.currentUserID(c) && !s.isAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权删除此规则"})
		return
	}

	s.orch.RemoveRuleFromAgents(&rule)
	s.db.Delete(&rule)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleListRoleGroups(c *gin.Context) {
	var roles []model.RoleGroup
	s.db.Order("id asc").Find(&roles)
	c.JSON(http.StatusOK, roles)
}

func (s *Server) handleListPlans(c *gin.Context) {
	var plans []model.Plan
	if s.isAdmin(c) {
		s.db.Order("id asc").Find(&plans)
	} else {
		s.db.Where("active = ?", true).Order("price_cents asc").Find(&plans)
	}
	c.JSON(http.StatusOK, plans)
}

func (s *Server) handlePurchasePlan(c *gin.Context) {
	planID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var plan model.Plan
	if err := s.db.First(&plan, planID).Error; err != nil || !plan.Active {
		c.JSON(http.StatusNotFound, gin.H{"error": "套餐不存在或已下架"})
		return
	}

	allowedTunnels := strings.TrimSpace(plan.AllowedTunnels)
	if plan.RoleGroupID > 0 {
		var rg model.RoleGroup
		if err := s.db.First(&rg, plan.RoleGroupID).Error; err == nil {
			allowedTunnels = strings.TrimSpace(rg.AllowedTunnels)
		}
	}

	uid := s.currentUserID(c)
	var updatedUser model.User
	err := s.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{
			"balance_cents": gorm.Expr("balance_cents - ?", plan.PriceCents),
			"plan_id":       plan.ID,
			"quota_bytes":   plan.QuotaBytes,
			"max_rules":     plan.MaxRules,
			"speed_mbps":    plan.SpeedMbps,
			"expire_at":     time.Now().AddDate(0, 0, plan.DurationDays),
		}
		// 付费套餐购买时重置已用流量；免费套餐 (price=0) 可被反复"购买"，绝不能借此清零用量
		if plan.PriceCents > 0 {
			updates["used_bytes"] = 0
		}
		if plan.RoleGroupID > 0 {
			updates["role_group_id"] = plan.RoleGroupID
		}
		if allowedTunnels != "" {
			updates["allowed_tunnels"] = allowedTunnels
		}
		// Atomic balance deduction to prevent concurrent double-spending
		res := tx.Model(&model.User{}).
			Where("id = ? AND balance_cents >= ?", uid, plan.PriceCents).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("insufficient_balance")
		}
		return tx.First(&updatedUser, uid).Error
	})
	if err != nil {
		if err.Error() == "insufficient_balance" {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "账户余额不足，请先充值或使用兑换码"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "购买失败，请重试"})
		return
	}

	s.enforceUserTunnelPermissions(&updatedUser)
	c.JSON(http.StatusOK, gin.H{"message": "套餐购买并激活成功，已自动同步对应角色与隧道权限", "user": updatedUser})
}

func (s *Server) handleRedeemCode(c *gin.Context) {
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入兑换码"})
		return
	}

	uid := s.currentUserID(c)
	codeStr := strings.TrimSpace(req.Code)
	var updatedUser model.User

	err := s.db.Transaction(func(tx *gorm.DB) error {
		var rc model.RedeemCode
		if err := tx.Where("code = ?", codeStr).First(&rc).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		now := time.Now()
		// Atomic CAS update (`used_by = 0`) to prevent concurrent replay of the same redeem code
		claimRes := tx.Model(&model.RedeemCode{}).
			Where("id = ? AND used_by = 0", rc.ID).
			Updates(map[string]any{
				"used_by": uid,
				"used_at": &now,
			})
		if claimRes.Error != nil {
			return claimRes.Error
		}
		if claimRes.RowsAffected == 0 {
			return fmt.Errorf("already_used")
		}

		var user model.User
		if err := tx.First(&user, uid).Error; err != nil {
			return err
		}
		if rc.PlanID > 0 {
			var plan model.Plan
			if err := tx.First(&plan, rc.PlanID).Error; err == nil {
				user.PlanID = plan.ID
				if plan.RoleGroupID > 0 {
					user.RoleGroupID = plan.RoleGroupID
					var rg model.RoleGroup
					if err := tx.First(&rg, plan.RoleGroupID).Error; err == nil && user.Role != "admin" {
						user.AllowedTunnels = rg.AllowedTunnels
					}
				} else if plan.AllowedTunnels != "" && user.Role != "admin" {
					user.AllowedTunnels = plan.AllowedTunnels
				}
				if plan.MaxRules > user.MaxRules {
					user.MaxRules = plan.MaxRules
				}
				if plan.SpeedMbps > user.SpeedMbps {
					user.SpeedMbps = plan.SpeedMbps
				}
			}
		}
		if user.ExpireAt.Before(now) {
			user.ExpireAt = now.AddDate(0, 0, rc.Duration)
		} else {
			user.ExpireAt = user.ExpireAt.AddDate(0, 0, rc.Duration)
		}
		// Only write the columns changed by the code; balance / used_bytes may be modified concurrently by purchases
		// and traffic reports and must never be overwritten with a stale snapshot.
		if err := tx.Model(&model.User{}).Where("id = ?", uid).Updates(map[string]any{
			"plan_id":         user.PlanID,
			"role_group_id":   user.RoleGroupID,
			"allowed_tunnels": user.AllowedTunnels,
			"max_rules":       user.MaxRules,
			"speed_mbps":      user.SpeedMbps,
			"expire_at":       user.ExpireAt,
			"quota_bytes":     gorm.Expr("quota_bytes + ?", rc.QuotaBytes),
		}).Error; err != nil {
			return err
		}
		return tx.First(&updatedUser, uid).Error
	})
	if err != nil {
		switch err.Error() {
		case "not_found":
			c.JSON(http.StatusNotFound, gin.H{"error": "兑换码无效或不存在"})
		case "already_used":
			c.JSON(http.StatusConflict, gin.H{"error": "该兑换码已被使用"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "核销失败，请重试"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "兑换成功", "user": updatedUser})
}

// --- Admin Handlers ---

func (s *Server) handleAdminCreateNode(c *gin.Context) {
	var node model.Node
	if err := c.ShouldBindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if node.ConnectIP == "" && node.PublicHost != "" {
		node.ConnectIP = node.PublicHost
	}
	if node.ConnectIP == "" && node.ServerIP != "" {
		node.ConnectIP = node.ServerIP
	}
	if node.ServerIP == "" && node.ConnectIP != "" {
		node.ServerIP = node.ConnectIP
	}
	node.PublicHost = node.ConnectIP
	if len(node.SecretToken) < 32 {
		// Node tokens are HMAC keys for the control channel: always use a strong random value unless the admin
		// supplied a sufficiently long one.
		node.SecretToken = utils.GenerateRandomToken(32)
	}
	if node.PortRange == "" {
		node.PortRange = "10000-50000"
	}
	if node.TrafficRate <= 0 {
		node.TrafficRate = 1.0
	}
	if node.QuotaBytes <= 0 {
		node.QuotaBytes = 10 * 1024 * 1024 * 1024 * 1024 // 默认 10TB
	}
	if node.DefaultEngine == "" {
		node.DefaultEngine = protocol.EngineNative
	}
	node.Status = "offline"
	node.ID = 0
	node.UsedBytes = 0
	if err := s.db.Create(&node).Error; err != nil {
		log.Printf("[API] create node failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建节点失败，请检查参数"})
		return
	}
	c.JSON(http.StatusCreated, node)
}

// ruleCounterCols are incremented concurrently by agent traffic reports (gorm.Expr); full-row saves of a rule must
// never write back a stale snapshot of them.
var ruleCounterCols = []string{"upload_bytes", "down_bytes", "billed_bytes"}

func (s *Server) handleAdminUpdateNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	var req struct {
		Name          string              `json:"name"`
		Role          string              `json:"role"`
		ConnectIP     string              `json:"connect_ip"`
		ServerIP      string              `json:"server_ip"`
		PublicHost    string              `json:"public_host"`
		InternalHost  string              `json:"internal_host"`
		PortRange     string              `json:"port_range"`
		TrafficRate   float64             `json:"traffic_rate"`
		QuotaBytes    *int64              `json:"quota_bytes"`
		UsedBytes     *int64              `json:"used_bytes"`
		DefaultEngine protocol.EngineType `json:"default_engine"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	oldServerIP := node.ServerIP
	if req.Name != "" {
		node.Name = req.Name
	}
	if req.Role != "" {
		node.Role = req.Role
	}
	if req.ConnectIP != "" {
		node.ConnectIP = req.ConnectIP
		node.PublicHost = req.ConnectIP
	} else if req.PublicHost != "" {
		node.ConnectIP = req.PublicHost
		node.PublicHost = req.PublicHost
	}
	if req.ServerIP != "" {
		node.ServerIP = req.ServerIP
	} else if node.ServerIP == "" {
		node.ServerIP = node.ConnectIP
	}
	if req.InternalHost != "" {
		node.InternalHost = req.InternalHost
	}
	if req.PortRange != "" {
		node.PortRange = req.PortRange
	}
	if req.TrafficRate > 0 {
		node.TrafficRate = req.TrafficRate
	}
	if req.QuotaBytes != nil && *req.QuotaBytes >= 0 {
		node.QuotaBytes = *req.QuotaBytes
	}
	if req.DefaultEngine != "" {
		node.DefaultEngine = req.DefaultEngine
	}
	// Never write back fields owned by the agent / traffic accounting from a stale snapshot.
	s.db.Omit("used_bytes", "tunnel_cert_pem", "status", "supported_engines", "last_seen_at").Save(&node)
	if req.UsedBytes != nil && *req.UsedBytes >= 0 {
		node.UsedBytes = *req.UsedBytes
		s.db.Model(&model.Node{}).Where("id = ?", node.ID).Update("used_bytes", node.UsedBytes)
	} else {
		var fresh model.Node
		if s.db.Select("used_bytes").First(&fresh, node.ID).Error == nil {
			node.UsedBytes = fresh.UsedBytes
		}
	}

	if node.QuotaBytes > 0 && node.UsedBytes >= node.QuotaBytes {
		s.orch.EnforceNodeQuotaCutoff(node.ID)
	} else {
		var pausedRules []model.ForwardRule
		s.db.Where("ingress_node_id = ? AND status = ?", node.ID, "node_quota_exceeded").Find(&pausedRules)
		now := time.Now()
		for i := range pausedRules {
			var owner model.User
			if s.db.First(&owner, pausedRules[i].UserID).Error != nil || !owner.CanForward(now) ||
				!owner.HasTunnelPermission(pausedRules[i].TunnelLineID) {
				continue
			}
			pausedRules[i].Enabled = true
			pausedRules[i].Status = "running"
			s.db.Omit(ruleCounterCols...).Save(&pausedRules[i])
			s.orch.DispatchRule(&pausedRules[i])
		}
	}

	// 若该节点作为加密隧道出口且 ServerIP 变更，通知关联入口节点更新隧道连接目标地址
	if node.ServerIP != oldServerIP {
		var egressLines []model.TunnelLine
		s.db.Where("egress_node_id = ?", node.ID).Find(&egressLines)
		for _, l := range egressLines {
			var rules []model.ForwardRule
			s.db.Where("tunnel_line_id = ? AND enabled = ?", l.ID, true).Find(&rules)
			for i := range rules {
				s.orch.DispatchRule(&rules[i])
			}
		}
	}
	c.JSON(http.StatusOK, node)
}

func (s *Server) handleAdminDeleteNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var lineCount int64
	s.db.Model(&model.TunnelLine{}).Where("ingress_node_id = ? OR egress_node_id = ?", id, id).Count(&lineCount)
	if lineCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该节点仍被隧道引用，请先删除或修改关联隧道"})
		return
	}
	s.db.Delete(&model.Node{}, id)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// validateLine checks enum fields and node references of a tunnel line.
func validateLine(line *model.TunnelLine) error {
	line.Name = strings.TrimSpace(line.Name)
	if line.Name == "" || utf8.RuneCountInString(line.Name) > 64 {
		return fmt.Errorf("隧道名称不能为空且不超过 64 个字符")
	}
	if line.Type != "direct" && line.Type != "encrypt" {
		return fmt.Errorf("无效的隧道类型")
	}
	if line.IngressNodeID == 0 {
		return fmt.Errorf("请选择入口节点")
	}
	if line.Type == "encrypt" {
		if line.EgressNodeID == 0 {
			return fmt.Errorf("加密隧道必须选择出口节点")
		}
		switch line.Transport {
		case "tls", "ws", "wss", "quic", "custom":
		default:
			return fmt.Errorf("加密隧道不支持传输方式 %q", line.Transport)
		}
	}
	if !validEngine(line.Engine) {
		return fmt.Errorf("不支持的转发引擎")
	}
	if line.BillingMode != "one_way" && line.BillingMode != "two_way" {
		return fmt.Errorf("无效的计费模式")
	}
	if line.RateMultiplier < 0 || line.MaxPortCount < 0 {
		return fmt.Errorf("倍率与端口上限不能为负数")
	}
	return nil
}

// agentBinarySHA256 returns the hex SHA-256 of the agent release binary for arch (cached by mtime/size).
func (s *Server) agentBinarySHA256(arch string) string {
	if s.staticDir == "" {
		return ""
	}
	path := filepath.Join(s.staticDir, "releases", "nexus-agent-linux-"+arch)
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	if s.hashCache == nil {
		s.hashCache = make(map[string]cachedHash)
	}
	if ch, ok := s.hashCache[path]; ok && ch.modTime.Equal(fi.ModTime()) && ch.size == fi.Size() {
		return ch.sum
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.hashCache[path] = cachedHash{modTime: fi.ModTime(), size: fi.Size(), sum: sum}
	return sum
}

// panelBaseURL returns the externally reachable base URL (configured NEXUS_PUBLIC_URL preferred).
func (s *Server) panelBaseURL(c *gin.Context) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host
}

// shellQuote single-quotes a value for safe inclusion in a POSIX shell command line.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func (s *Server) handleAdminNodeInstallCmd(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	base := s.panelBaseURL(c)
	insecure := strings.HasPrefix(base, "http://")
	masterWS := "wss://" + strings.TrimPrefix(base, "https://") + "/api/v1/agent/ws"
	if insecure {
		masterWS = "ws://" + strings.TrimPrefix(base, "http://") + "/api/v1/agent/ws"
	}
	scriptURL := base + "/deploy/install-agent.sh"

	args := []string{
		"--panel", shellQuote(base),
		"--master", shellQuote(masterWS),
		"--id", strconv.FormatUint(node.ID, 10),
		"--token", shellQuote(node.SecretToken),
	}
	missing := []string{}
	for _, arch := range []string{"amd64", "arm64"} {
		if sum := s.agentBinarySHA256(arch); sum != "" {
			args = append(args, "--sha256-"+arch, sum)
		} else {
			missing = append(missing, arch)
		}
	}
	if insecure {
		args = append(args, "--allow-insecure-ws")
	}
	systemdInstall := fmt.Sprintf("curl -fsSL %s | sudo bash -s -- %s", shellQuote(scriptURL), strings.Join(args, " "))
	systemdUninstall := fmt.Sprintf("curl -fsSL %s | sudo bash -s -- --uninstall", shellQuote(scriptURL))

	dockerEnv := fmt.Sprintf("-e NEXUS_MASTER_URL=%s -e NEXUS_NODE_ID=%d -e NEXUS_NODE_TOKEN=%s", shellQuote(masterWS), node.ID, shellQuote(node.SecretToken))
	if insecure {
		dockerEnv += " -e NEXUS_ALLOW_INSECURE_WS=true"
	}
	dockerInstall := fmt.Sprintf("docker run -d --name nexus-agent-%d --restart always --net=host --cap-add=NET_ADMIN -v nexus-agent-%d:/var/lib/nexus-agent -e NEXUS_STATE_DIR=/var/lib/nexus-agent %s zachary-panel-agent:latest",
		node.ID, node.ID, dockerEnv)
	dockerUninstall := fmt.Sprintf("docker stop nexus-agent-%d && docker rm -v nexus-agent-%d", node.ID, node.ID)

	var warnings []string
	if insecure {
		warnings = append(warnings, "面板当前通过 HTTP 访问：安装脚本与控制通道均未加密，可能被中间人篡改。生产环境请配置 HTTPS 并设置 NEXUS_PUBLIC_URL=https://…")
	}
	warnings = append(warnings, "Docker 方式需先在节点上用仓库内 deploy/Dockerfile.agent 构建本地镜像：docker build -f deploy/Dockerfile.agent -t zachary-panel-agent:latest .")
	if len(missing) > 0 {
		warnings = append(warnings, fmt.Sprintf("未在 %s/releases 找到以下架构的 Agent 二进制，对应架构无法安装: %s", s.staticDir, strings.Join(missing, ", ")))
	}

	c.JSON(http.StatusOK, gin.H{
		"node_id":           node.ID,
		"install_cmd":       systemdInstall,
		"systemd_install":   systemdInstall,
		"systemd_uninstall": systemdUninstall,
		"docker_install":    dockerInstall,
		"docker_uninstall":  dockerUninstall,
		"warnings":          warnings,
		"sync_policy":       "探针与流量同步: 3秒/次 · 规则下发: 0延迟实时推送 · 全量状态对账: 60秒/次 · 重启自愈: 本地快照+主控重连自动重启全部规则",
	})
}

func (s *Server) handleAdminResyncNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	s.orch.SyncNodeRules(node.ID, true)
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已向节点「%s」下发全量规则重同步/重启指令", node.Name)})
}

func (s *Server) handleAdminCreateLine(c *gin.Context) {
	var line model.TunnelLine
	if err := c.ShouldBindJSON(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if line.Type == "" {
		if line.EgressNodeID > 0 {
			line.Type = "encrypt"
		} else {
			line.Type = "direct"
		}
	}
	if line.BillingMode == "" {
		line.BillingMode = "two_way"
	}
	if line.Engine == "" {
		line.Engine = protocol.EngineNative
	}
	if line.Transport == "" {
		line.Transport = "tls"
	}
	if err := validateLine(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	line.ID = 0
	line.Enabled = true
	if err := s.db.Create(&line).Error; err != nil {
		log.Printf("[API] create tunnel failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建隧道失败，请检查参数"})
		return
	}
	c.JSON(http.StatusCreated, line)
}

func (s *Server) handleAdminUpdateLine(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var line model.TunnelLine
	if err := s.db.First(&line, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		return
	}
	var req model.TunnelLine
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	oldIngressID := line.IngressNodeID
	oldEgressID := line.EgressNodeID
	oldType := line.Type

	line.Name = req.Name
	line.Type = req.Type
	line.IngressNodeID = req.IngressNodeID
	if line.Type == "encrypt" {
		line.EgressNodeID = req.EgressNodeID
		line.Transport = req.Transport
	} else {
		line.EgressNodeID = 0
		line.Transport = "raw"
	}
	line.Engine = req.Engine
	line.BillingMode = req.BillingMode
	line.RateMultiplier = req.RateMultiplier
	line.MaxPortCount = req.MaxPortCount
	if line.Engine == "" {
		line.Engine = protocol.EngineNative
	}
	if line.BillingMode == "" {
		line.BillingMode = "two_way"
	}
	if err := validateLine(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.db.Save(&line)

	topologyChanged := oldIngressID != line.IngressNodeID || oldEgressID != line.EgressNodeID || oldType != line.Type

	// 隧道固化转发方式或拓扑变更后，先清理旧节点上的残留实例，再同步更新该隧道下所有转发规则并重新下发
	var rules []model.ForwardRule
	s.db.Where("tunnel_line_id = ?", line.ID).Find(&rules)
	for i := range rules {
		oldRule := rules[i]
		if topologyChanged {
			s.orch.RemoveRuleFromAgents(&oldRule)
		}
		rules[i].Engine = line.Engine
		_ = s.orch.WithAllocLock(func() error {
			if oldIngressID != line.IngressNodeID {
				rules[i].IngressNodeID = line.IngressNodeID
				// Persist the node change first so the rule's old port on the old node is not counted twice.
				rules[i].ListenPort = 0
				s.db.Model(&model.ForwardRule{}).Where("id = ?", rules[i].ID).Updates(map[string]any{"ingress_node_id": line.IngressNodeID, "listen_port": 0})
				if p, err := s.orch.AllocatePortForNode(line.IngressNodeID, oldRule.ListenPort); err == nil {
					rules[i].ListenPort = p
				} else if p2, err2 := s.orch.AllocatePortForNode(line.IngressNodeID, 0); err2 == nil {
					rules[i].ListenPort = p2
				} else {
					rules[i].Enabled = false
					rules[i].Status = "error"
					rules[i].LastError = "新入口节点无可用端口"
				}
			}
			if oldEgressID != line.EgressNodeID {
				rules[i].RelayPort = 0
			}
			if line.Type == "encrypt" && line.EgressNodeID > 0 {
				rules[i].Mode = "tunnel"
			} else {
				rules[i].Mode = "direct"
			}
			return s.db.Omit(ruleCounterCols...).Save(&rules[i]).Error
		})
		s.orch.DispatchRule(&rules[i])
	}
	c.JSON(http.StatusOK, line)
}

func (s *Server) handleAdminDeleteLine(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var ruleCount int64
	s.db.Model(&model.ForwardRule{}).Where("tunnel_line_id = ?", id).Count(&ruleCount)
	if ruleCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该隧道下仍有转发规则，请先删除或迁移规则"})
		return
	}
	s.db.Delete(&model.TunnelLine{}, id)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// enforceUserTunnelPermissions pauses and unloads any active forwarding rules of the user
// that are on tunnels not permitted by the user's current role/tunnel permissions.
func (s *Server) enforceUserTunnelPermissions(u *model.User) {
	if u.Role == "admin" {
		return
	}
	var userRules []model.ForwardRule
	s.db.Where("user_id = ? AND enabled = ?", u.ID, true).Find(&userRules)
	for i := range userRules {
		if !u.HasTunnelPermission(userRules[i].TunnelLineID) {
			userRules[i].Enabled = false
			userRules[i].Status = "paused"
			s.db.Omit(ruleCounterCols...).Save(&userRules[i])
			s.orch.RemoveRuleFromAgents(&userRules[i])
		}
	}
}

func (s *Server) handleAdminCreateRoleGroup(c *gin.Context) {
	var req model.RoleGroup
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效的角色名称"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.AllowedTunnels = strings.TrimSpace(req.AllowedTunnels)
	req.ID = 0
	if err := s.db.Create(&req).Error; err != nil {
		log.Printf("[API] create role failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建角色失败，请检查参数"})
		return
	}
	c.JSON(http.StatusCreated, req)
}

func (s *Server) handleAdminUpdateRoleGroup(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rg model.RoleGroup
	if err := s.db.First(&rg, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "角色不存在"})
		return
	}
	var req struct {
		Name           string  `json:"name"`
		Description    *string `json:"description"`
		AllowedTunnels *string `json:"allowed_tunnels"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		rg.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != nil {
		rg.Description = strings.TrimSpace(*req.Description)
	}
	if req.AllowedTunnels != nil {
		rg.AllowedTunnels = strings.TrimSpace(*req.AllowedTunnels)
	}
	s.db.Save(&rg)

	// 级联同步：更新所有绑定该角色的套餐与用户的可用隧道，并自动暂停/卸载无权限隧道上的存量转发规则
	s.db.Model(&model.Plan{}).Where("role_group_id = ?", rg.ID).Update("allowed_tunnels", rg.AllowedTunnels)

	var users []model.User
	s.db.Where("role_group_id = ? AND role != ?", rg.ID, "admin").Find(&users)
	for i := range users {
		users[i].AllowedTunnels = rg.AllowedTunnels
		s.db.Model(&model.User{}).Where("id = ?", users[i].ID).Update("allowed_tunnels", rg.AllowedTunnels)
		s.enforceUserTunnelPermissions(&users[i])
	}

	c.JSON(http.StatusOK, rg)
}

func (s *Server) handleAdminDeleteRoleGroup(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var planCount int64
	s.db.Model(&model.Plan{}).Where("role_group_id = ?", id).Count(&planCount)
	if planCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该角色仍被套餐绑定，请先修改或删除关联套餐"})
		return
	}
	var userCount int64
	s.db.Model(&model.User{}).Where("role_group_id = ?", id).Count(&userCount)
	if userCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该角色下仍有存量用户，请先迁移用户的所属角色"})
		return
	}
	s.db.Delete(&model.RoleGroup{}, id)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminCreatePlan(c *gin.Context) {
	var plan model.Plan
	if err := c.ShouldBindJSON(&plan); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if plan.RoleGroupID > 0 {
		var rg model.RoleGroup
		if err := s.db.First(&rg, plan.RoleGroupID).Error; err == nil {
			plan.AllowedTunnels = rg.AllowedTunnels
		}
	}
	plan.ID = 0
	plan.Active = true
	if strings.TrimSpace(plan.Name) == "" || plan.PriceCents < 0 || plan.QuotaBytes < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的套餐参数"})
		return
	}
	if err := s.db.Create(&plan).Error; err != nil {
		log.Printf("[API] create plan failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建套餐失败，请检查参数"})
		return
	}
	c.JSON(http.StatusCreated, plan)
}

func (s *Server) handleAdminUpdatePlan(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var plan model.Plan
	if err := s.db.First(&plan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "套餐不存在"})
		return
	}
	var req model.Plan
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		plan.Name = strings.TrimSpace(req.Name)
	}
	plan.Description = strings.TrimSpace(req.Description)
	if req.RoleGroupID > 0 {
		plan.RoleGroupID = req.RoleGroupID
		var rg model.RoleGroup
		if err := s.db.First(&rg, req.RoleGroupID).Error; err == nil {
			plan.AllowedTunnels = rg.AllowedTunnels
		}
	} else if req.AllowedTunnels != "" {
		plan.AllowedTunnels = strings.TrimSpace(req.AllowedTunnels)
	}
	if req.PriceCents >= 0 {
		plan.PriceCents = req.PriceCents
	}
	if req.DurationDays > 0 {
		plan.DurationDays = req.DurationDays
	}
	if req.QuotaBytes > 0 {
		plan.QuotaBytes = req.QuotaBytes
	}
	if req.MaxRules > 0 {
		plan.MaxRules = req.MaxRules
	}
	if req.SpeedMbps > 0 {
		plan.SpeedMbps = req.SpeedMbps
	}
	plan.Active = req.Active
	s.db.Save(&plan)
	c.JSON(http.StatusOK, plan)
}

func (s *Server) handleAdminDeletePlan(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	s.db.Delete(&model.Plan{}, id)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminListUsers(c *gin.Context) {
	var users []model.User
	s.db.Order("id asc").Find(&users)
	c.JSON(http.StatusOK, users)
}

func (s *Server) handleAdminCreateUser(c *gin.Context) {
	var req struct {
		Email          string `json:"email" binding:"required"`
		Password       string `json:"password" binding:"required"`
		Role           string `json:"role"`
		RoleGroupID    uint64 `json:"role_group_id"`
		PlanID         uint64 `json:"plan_id"`
		AllowedTunnels string `json:"allowed_tunnels"`
		QuotaBytes     int64  `json:"quota_bytes"`
		MaxRules       int    `json:"max_rules"`
		SpeedMbps      int    `json:"speed_mbps"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	email := normalizeEmail(req.Email)
	if !validEmail(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效的邮箱地址"})
		return
	}
	if !validPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码长度需为 8-72 位"})
		return
	}
	var count int64
	s.db.Model(&model.User{}).Where("LOWER(email) = ?", email).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该邮箱已存在"})
		return
	}
	role := req.Role
	if role != "admin" {
		role = "user"
	}

	roleGroupID := req.RoleGroupID
	quota := req.QuotaBytes
	maxRules := req.MaxRules
	speed := req.SpeedMbps
	allowedTunnels := strings.TrimSpace(req.AllowedTunnels)

	// 若指定了套餐，优先继承套餐的角色与配额默认值
	if req.PlanID > 0 {
		var plan model.Plan
		if err := s.db.First(&plan, req.PlanID).Error; err == nil {
			if roleGroupID == 0 && plan.RoleGroupID > 0 {
				roleGroupID = plan.RoleGroupID
			}
			if quota <= 0 {
				quota = plan.QuotaBytes
			}
			if maxRules <= 0 {
				maxRules = plan.MaxRules
			}
			if speed <= 0 {
				speed = plan.SpeedMbps
			}
		}
	}
	if roleGroupID == 0 {
		roleGroupID = 1
	}
	if role == "admin" {
		allowedTunnels = "*"
	} else if allowedTunnels == "" {
		var rg model.RoleGroup
		if err := s.db.First(&rg, roleGroupID).Error; err == nil {
			allowedTunnels = rg.AllowedTunnels
		}
	}
	if quota <= 0 {
		quota = 100 * 1024 * 1024 * 1024
	}
	if maxRules <= 0 {
		maxRules = 20
	}
	if speed <= 0 {
		speed = 100
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}
	u := model.User{
		Email:          email,
		PasswordHash:   string(hash),
		Role:           role,
		Status:         "active",
		RoleGroupID:    roleGroupID,
		PlanID:         req.PlanID,
		AllowedTunnels: allowedTunnels,
		QuotaBytes:     quota,
		MaxRules:       maxRules,
		SpeedMbps:      speed,
		ExpireAt:       time.Now().AddDate(1, 0, 0),
	}
	if err := s.db.Create(&u).Error; err != nil {
		log.Printf("[API] admin create user failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败，请检查参数"})
		return
	}
	c.JSON(http.StatusCreated, u)
}

func (s *Server) handleAdminDeleteUser(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == s.currentUserID(c) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除当前登录的管理员账号"})
		return
	}
	var rules []model.ForwardRule
	s.db.Where("user_id = ?", id).Find(&rules)
	for i := range rules {
		s.orch.RemoveRuleFromAgents(&rules[i])
	}
	s.db.Where("user_id = ?", id).Delete(&model.ForwardRule{})
	s.db.Delete(&model.User{}, id)
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminUpdateUser(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	var req struct {
		Role           string  `json:"role"`
		Status         string  `json:"status"`
		Password       string  `json:"password"`
		RoleGroupID    *uint64 `json:"role_group_id"`
		PlanID         *uint64 `json:"plan_id"`
		AllowedTunnels *string `json:"allowed_tunnels"`
		QuotaBytes     int64   `json:"quota_bytes"`
		UsedBytes      *int64  `json:"used_bytes"`
		MaxRules       int     `json:"max_rules"`
		SpeedMbps      int     `json:"speed_mbps"`
		BalanceCents   *int64  `json:"balance_cents"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role != "" && req.Role != "admin" && req.Role != "user" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户角色"})
		return
	}
	if req.Status != "" && req.Status != "active" && req.Status != "banned" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户状态"})
		return
	}
	if id == s.currentUserID(c) && ((req.Role != "" && req.Role != "admin") || req.Status == "banned") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能降级或封禁当前登录的管理员账号"})
		return
	}
	revokeTokens := false
	if req.Role != "" && req.Role != u.Role {
		u.Role = req.Role
		revokeTokens = true
	}
	if req.Status != "" && req.Status != u.Status {
		u.Status = req.Status
		revokeTokens = revokeTokens || req.Status == "banned"
	}
	if req.Password != "" {
		if !validPassword(req.Password) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "密码长度需为 8-72 位"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "密码更新失败"})
			return
		}
		u.PasswordHash = string(hash)
		revokeTokens = true
	}
	if req.PlanID != nil {
		u.PlanID = *req.PlanID
	}
	if req.RoleGroupID != nil && *req.RoleGroupID > 0 {
		u.RoleGroupID = *req.RoleGroupID
		var rg model.RoleGroup
		if err := s.db.First(&rg, u.RoleGroupID).Error; err == nil && u.Role != "admin" {
			u.AllowedTunnels = rg.AllowedTunnels
		}
	}
	if req.AllowedTunnels != nil {
		u.AllowedTunnels = strings.TrimSpace(*req.AllowedTunnels)
	}
	if u.Role == "admin" {
		u.AllowedTunnels = "*"
	}
	if req.QuotaBytes > 0 {
		u.QuotaBytes = req.QuotaBytes
	}
	if req.MaxRules > 0 {
		u.MaxRules = req.MaxRules
	}
	if req.SpeedMbps > 0 {
		u.SpeedMbps = req.SpeedMbps
	}
	// used_bytes / balance_cents / token_version / quota_bytes / expire_at / password_hash change concurrently
	// (traffic reports, purchases, redeems, password changes): save the profile without them and only write them
	// explicitly when the admin actually set them.
	s.db.Omit("used_bytes", "balance_cents", "token_version", "quota_bytes", "expire_at", "password_hash").Save(&u)
	explicit := map[string]any{}
	if req.Password != "" {
		explicit["password_hash"] = u.PasswordHash
	}
	if req.QuotaBytes > 0 {
		explicit["quota_bytes"] = req.QuotaBytes
	}
	if revokeTokens {
		explicit["token_version"] = gorm.Expr("token_version + 1")
	}
	if req.UsedBytes != nil && *req.UsedBytes >= 0 {
		explicit["used_bytes"] = *req.UsedBytes
	}
	if req.BalanceCents != nil && *req.BalanceCents >= 0 {
		explicit["balance_cents"] = *req.BalanceCents
	}
	if len(explicit) > 0 {
		s.db.Model(&model.User{}).Where("id = ?", u.ID).Updates(explicit)
	}
	_ = s.db.First(&u, u.ID).Error

	// 若通过修改角色或隧道权限收回了某条隧道的权限，自动暂停该用户在无权限隧道下的规则并从节点卸载
	s.enforceUserTunnelPermissions(&u)

	if !u.CanForward(time.Now()) {
		s.orch.EnforceUserQuotaCutoff(u.ID)
	} else {
		var rules []model.ForwardRule
		s.db.Where("user_id = ? AND status = ?", u.ID, "quota_exceeded").Find(&rules)
		for i := range rules {
			if u.HasTunnelPermission(rules[i].TunnelLineID) {
				rules[i].Enabled = true
				rules[i].Status = "running"
				s.db.Omit(ruleCounterCols...).Save(&rules[i])
				s.orch.DispatchRule(&rules[i])
			}
		}
	}
	c.JSON(http.StatusOK, u)
}

func (s *Server) handleAdminResetUserTraffic(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	u.UsedBytes = 0
	s.db.Model(&model.User{}).Where("id = ?", u.ID).Update("used_bytes", 0)

	// 自动恢复该用户因流量超额暂停的转发规则（封禁 / 已过期账号以及无隧道权限的规则不恢复）
	if !u.CanForward(time.Now()) {
		c.JSON(http.StatusOK, u)
		return
	}
	var rules []model.ForwardRule
	s.db.Where("user_id = ? AND status = ?", u.ID, "quota_exceeded").Find(&rules)
	for i := range rules {
		if !u.HasTunnelPermission(rules[i].TunnelLineID) {
			continue
		}
		rules[i].Enabled = true
		rules[i].Status = "running"
		s.db.Omit(ruleCounterCols...).Save(&rules[i])
		s.orch.DispatchRule(&rules[i])
	}
	c.JSON(http.StatusOK, u)
}

func (s *Server) handleAdminGenerateRedeem(c *gin.Context) {
	var req struct {
		Count    int   `json:"count"`
		QuotaGB  int64 `json:"quota_gb"`
		Duration int   `json:"duration_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Count <= 0 || req.Count > 50 {
		req.Count = 5
	}
	if req.QuotaGB <= 0 {
		req.QuotaGB = 100
	}
	if req.Duration <= 0 {
		req.Duration = 30
	}

	var codes []model.RedeemCode
	for i := 0; i < req.Count; i++ {
		rc := model.RedeemCode{
			Code:       "NX-" + strings.ToUpper(utils.GenerateRandomToken(6)),
			QuotaBytes: req.QuotaGB * 1024 * 1024 * 1024,
			Duration:   req.Duration,
		}
		s.db.Create(&rc)
		codes = append(codes, rc)
	}
	c.JSON(http.StatusCreated, codes)
}
