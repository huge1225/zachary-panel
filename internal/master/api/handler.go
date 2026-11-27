package api

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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

const (
	// MaxRequestBodyBytes bounds all incoming HTTP request bodies (1 MiB) to prevent memory exhaustion DoS.
	MaxRequestBodyBytes     int64 = 1 << 20
	maskedSecretPlaceholder       = "********"
)

type maxBytesBodyReader struct {
	rc       io.ReadCloser
	exceeded *bool
}

func (m *maxBytesBodyReader) Read(p []byte) (int, error) {
	n, err := m.rc.Read(p)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			*m.exceeded = true
		}
	}
	return n, err
}

func (m *maxBytesBodyReader) Close() error {
	return m.rc.Close()
}

type maxBytesResponseWriter struct {
	gin.ResponseWriter
	exceeded *bool
	code     int
}

func (w *maxBytesResponseWriter) WriteHeader(code int) {
	if *w.exceeded && code < http.StatusInternalServerError {
		code = http.StatusRequestEntityTooLarge
	}
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *maxBytesResponseWriter) WriteHeaderNow() {
	if *w.exceeded && (w.code < http.StatusInternalServerError && w.ResponseWriter.Status() < http.StatusInternalServerError) {
		w.ResponseWriter.WriteHeader(http.StatusRequestEntityTooLarge)
	}
	w.ResponseWriter.WriteHeaderNow()
}

func (w *maxBytesResponseWriter) Write(data []byte) (int, error) {
	if *w.exceeded && (w.code < http.StatusInternalServerError && w.ResponseWriter.Status() < http.StatusInternalServerError) {
		w.ResponseWriter.WriteHeader(http.StatusRequestEntityTooLarge)
	}
	return w.ResponseWriter.Write(data)
}

// payNotifyMu serializes webhook order settlement across orders in-process alongside idx_orders_gateway_trade_no.
var payNotifyMu sync.Mutex

// bindOptionalJSON binds an optional JSON body into dst: empty/EOF bodies succeed as no-ops, bodies exceeding
// MaxRequestBodyBytes abort with 413, and malformed JSON bodies abort with 400 instead of silently executing defaults.
func bindOptionalJSON(c *gin.Context, dst any) bool {
	if c.Request == nil || c.Request.Body == nil || c.Request.Body == http.NoBody {
		return true
	}
	err := c.ShouldBindJSON(dst)
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体超过大小限制 (最大 1MB)"})
		return false
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数 JSON 格式错误"})
	return false
}

// buildSafeLike caps search keywords to 128 UTF-8 bytes and escapes '!', '%', and '_' for portable SQL LIKE ... ESCAPE '!'.
func buildSafeLike(raw string) string {
	trimmed := truncateUTF8(strings.TrimSpace(raw), 128)
	var b strings.Builder
	b.Grow(len(trimmed) + 6)
	b.WriteByte('%')
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch == '!' || ch == '%' || ch == '_' {
			b.WriteByte('!')
		}
		b.WriteByte(ch)
	}
	b.WriteByte('%')
	return b.String()
}

type Server struct {
	db                *gorm.DB
	hub               *hub.AgentHub
	orch              *service.Orchestrator
	staticDir         string // directory containing install-agent.sh and releases/ (agent binaries)
	publicURL         string // externally reachable panel base URL, e.g. https://panel.example.com
	hasTrustedProxies bool

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
		s.hasTrustedProxies = false
	} else {
		s.hasTrustedProxies = len(trusted) > 0
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
			AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-API-Key"},
			ExposeHeaders:    []string{"Content-Length", "Subscription-Userinfo", "Profile-Update-Interval", "X-Renewed-Token", "X-Total-Count", "X-Page", "X-Page-Size"},
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
		if c.Request.TLS != nil || (s.hasTrustedProxies && strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		// Enforce global request body limit across all routes (covers both Content-Length and chunked transfers).
		if c.Request.ContentLength > MaxRequestBodyBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体超过大小限制 (最大 1MB)"})
			return
		}
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			exceeded := false
			c.Writer = &maxBytesResponseWriter{ResponseWriter: c.Writer, exceeded: &exceeded}
			c.Request.Body = &maxBytesBodyReader{
				rc:       http.MaxBytesReader(c.Writer, c.Request.Body, MaxRequestBodyBytes),
				exceeded: &exceeded,
			}
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
		v1.GET("/sub/:token", subRateLimit(), s.handleGetSubscription)
		v1.GET("/pay/epay/notify", s.handleEpayNotify)
		v1.POST("/pay/epay/notify", s.handleEpayNotify)
		v1.GET("/payment/epay/notify", s.handleEpayNotify)
		v1.POST("/payment/epay/notify", s.handleEpayNotify)
		v1.POST("/pay/usdt/notify", s.handleUSDTNotify)
		v1.POST("/payment/usdt/notify", s.handleUSDTNotify)

		// Authenticated user endpoints
		auth := v1.Group("")
		auth.Use(s.AuthMiddleware())
		{
			auth.GET("/user/profile", s.handleProfile)
			auth.POST("/user/password", userRateLimit(), s.handleChangePassword)
			auth.POST("/user/totp/setup", userRateLimit(), s.handleSetupTOTP)
			auth.POST("/user/totp/enable", userRateLimit(), s.handleEnableTOTP)
			auth.POST("/user/totp/disable", userRateLimit(), s.handleDisableTOTP)
			auth.POST("/user/reset-sub-token", userRateLimit(), s.handleUserResetSubToken)
			auth.POST("/user/reset-subscription", userRateLimit(), s.handleUserResetSubscription)
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
			auth.POST("/rules/batch-delete", ruleMutationLimit(), s.handleBatchDeleteRules)

			// Roles, Plans, Coupons, Orders & Redeem Codes
			auth.GET("/roles", s.handleListRoleGroups)
			auth.GET("/plans", s.handleListPlans)
			auth.POST("/plans/:id/purchase", userRateLimit(), s.handlePurchasePlan)
			auth.POST("/coupons/preview", userRateLimit(), s.handlePreviewCoupon)
			auth.POST("/redeem", userRateLimit(), s.handleRedeemCode)
			auth.GET("/orders", s.handleListOrders)
			auth.POST("/orders/recharge", userRateLimit(), s.handleCreateRechargeOrder)

			// Affiliate / Referral System
			auth.GET("/affiliate/overview", s.handleAffiliateOverview)
			auth.POST("/affiliate/transfer", userRateLimit(), s.handleAffiliateTransfer)
			auth.POST("/affiliate/withdraw", userRateLimit(), s.handleAffiliateWithdraw)

			// Customer Support Tickets
			auth.GET("/tickets", s.handleListTickets)
			auth.POST("/tickets", userRateLimit(), s.handleCreateTicket)
			auth.GET("/tickets/:id", s.handleGetTicketDetail)
			auth.POST("/tickets/:id/reply", userRateLimit(), s.handleReplyTicket)
			auth.POST("/tickets/:id/close", userRateLimit(), s.handleCloseTicket)

			// Admin-only management endpoints
			admin := auth.Group("/admin")
			admin.Use(AdminMiddleware())
			{
				admin.GET("/settings", s.handleAdminGetSettings)
				admin.PUT("/settings", s.handleAdminUpdateSettings)
				admin.POST("/settings/test-notify", s.handleAdminTestNotify)
				admin.POST("/settings/api-key", s.handleAdminGenerateAPIKey)
				admin.DELETE("/settings/api-key", s.handleAdminRevokeAPIKey)

				admin.POST("/roles", s.handleAdminCreateRoleGroup)
				admin.PUT("/roles/:id", s.handleAdminUpdateRoleGroup)
				admin.DELETE("/roles/:id", s.handleAdminDeleteRoleGroup)

				admin.POST("/nodes", s.handleAdminCreateNode)
				admin.PUT("/nodes/:id", s.handleAdminUpdateNode)
				admin.DELETE("/nodes/:id", s.handleAdminDeleteNode)
				admin.GET("/nodes/:id/install-cmd", s.handleAdminNodeInstallCmd)
				admin.POST("/nodes/:id/resync", s.handleAdminResyncNode)
				admin.POST("/nodes/:id/reset-traffic", s.handleAdminResetNodeTraffic)
				admin.POST("/nodes/:id/upgrade", s.handleAdminUpgradeNode)
				admin.POST("/nodes/batch-upgrade", s.handleAdminBatchUpgradeNodes)

				admin.POST("/lines", s.handleAdminCreateLine)
				admin.PUT("/lines/:id", s.handleAdminUpdateLine)
				admin.DELETE("/lines/:id", s.handleAdminDeleteLine)

				admin.GET("/dns-failover", s.handleAdminListDNSFailover)
				admin.POST("/dns-failover", s.handleAdminCreateDNSFailover)
				admin.PUT("/dns-failover/:id", s.handleAdminUpdateDNSFailover)
				admin.DELETE("/dns-failover/:id", s.handleAdminDeleteDNSFailover)
				admin.POST("/dns-failover/:id/reconcile", s.handleAdminReconcileDNSFailover)

				admin.POST("/plans", s.handleAdminCreatePlan)
				admin.PUT("/plans/:id", s.handleAdminUpdatePlan)
				admin.DELETE("/plans/:id", s.handleAdminDeletePlan)

				admin.GET("/coupons", s.handleAdminListCoupons)
				admin.POST("/coupons", s.handleAdminCreateCoupon)
				admin.PUT("/coupons/:id", s.handleAdminUpdateCoupon)
				admin.DELETE("/coupons/:id", s.handleAdminDeleteCoupon)

				admin.GET("/affiliate/withdrawals", s.handleAdminListWithdrawals)
				admin.POST("/affiliate/withdrawals/:id/review", s.handleAdminReviewWithdrawal)

				admin.GET("/tickets", s.handleAdminListTickets)
				admin.POST("/tickets/:id/status", s.handleAdminUpdateTicketStatus)

				admin.GET("/users", s.handleAdminListUsers)
				admin.POST("/users", s.handleAdminCreateUser)
				admin.PUT("/users/:id", s.handleAdminUpdateUser)
				admin.DELETE("/users/:id", s.handleAdminDeleteUser)
				admin.POST("/users/:id/reset-traffic", s.handleAdminResetUserTraffic)
				admin.POST("/users/:id/reset-subscription", s.handleAdminResetUserSubscription)
				admin.POST("/users/:id/reset-password", s.handleAdminResetUserPassword)
				admin.POST("/users/:id/reset-sub-token", s.handleAdminResetUserSubToken)
				admin.GET("/redeem", s.handleAdminListRedeemCodes)
				admin.POST("/redeem/generate", s.handleAdminGenerateRedeem)
				admin.DELETE("/redeem/:id", s.handleAdminDeleteRedeemCode)
				admin.POST("/redeem/batch-delete", s.handleAdminBatchDeleteRedeemCodes)
				admin.POST("/orders/:id/confirm", s.handleAdminConfirmOrder)
				admin.GET("/audit-logs", s.handleAdminListAuditLogs)
				admin.GET("/backup/sqlite", s.handleAdminBackupSQLite)
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

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	end := 0
	for i := range s {
		if i > maxBytes {
			break
		}
		end = i
	}
	return s[:end]
}

func (s *Server) recordAuditForUser(c *gin.Context, uid uint64, email, action, target, detail string) {
	target = truncateUTF8(target, 191)
	detail = truncateUTF8(detail, 512)
	clientIP := ""
	if c != nil {
		clientIP = c.ClientIP()
	}
	_ = s.db.Create(&model.AuditLog{
		UserID:    uid,
		UserEmail: email,
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  clientIP,
	}).Error
}

func (s *Server) recordAudit(c *gin.Context, action, target, detail string) {
	uid := s.currentUserID(c)
	email := ""
	if uid > 0 {
		var u model.User
		if s.db.Select("id, email").First(&u, uid).Error == nil {
			email = u.Email
		}
	}
	s.recordAuditForUser(c, uid, email, action, target, detail)
}

func (s *Server) handleProfile(c *gin.Context) {
	var user model.User
	if err := s.db.First(&user, s.currentUserID(c)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

type hourlyBucketPoint struct {
	HourBucket  string `json:"hour_bucket"`
	UploadBytes int64  `json:"upload_bytes"`
	DownBytes   int64  `json:"down_bytes"`
	BilledBytes int64  `json:"billed_bytes"`
}

func build24HourSeries(now time.Time, rows []model.TrafficHourlyStat) []hourlyBucketPoint {
	cur := now.Truncate(time.Hour)
	start := cur.Add(-23 * time.Hour)
	byBucket := make(map[string]*hourlyBucketPoint, 24)
	series := make([]hourlyBucketPoint, 0, 24)
	for i := 0; i < 24; i++ {
		b := start.Add(time.Duration(i) * time.Hour).Format("2006-01-02 15:00")
		pt := hourlyBucketPoint{HourBucket: b}
		series = append(series, pt)
		byBucket[b] = &series[len(series)-1]
	}
	for _, r := range rows {
		if pt, ok := byBucket[r.HourBucket]; ok {
			pt.UploadBytes += r.UploadBytes
			pt.DownBytes += r.DownBytes
			pt.BilledBytes += r.BilledBytes
		}
	}
	return series
}

func (s *Server) handleDashboard(c *gin.Context) {
	uid := s.currentUserID(c)
	var user model.User
	s.db.First(&user, uid)

	var ruleCount, runningRules int64
	s.db.Model(&model.ForwardRule{}).Where("user_id = ?", uid).Count(&ruleCount)
	s.db.Model(&model.ForwardRule{}).Where("user_id = ? AND enabled = ?", uid, true).Count(&runningRules)

	var nodes []model.Node
	s.db.Select("id, status").Find(&nodes)
	onlineNodes := 0
	for i := range nodes {
		s.hub.EnrichNodeMetrics(&nodes[i])
		if nodes[i].Status == "online" {
			onlineNodes++
		}
	}

	now := time.Now()
	startBucket := now.Truncate(time.Hour).Add(-23 * time.Hour).Format("2006-01-02 15:00")

	var userRows []model.TrafficHourlyStat
	s.db.Model(&model.TrafficHourlyStat{}).
		Select("hour_bucket, COALESCE(SUM(upload_bytes), 0) AS upload_bytes, COALESCE(SUM(down_bytes), 0) AS down_bytes, COALESCE(SUM(billed_bytes), 0) AS billed_bytes").
		Where("user_id = ? AND hour_bucket >= ?", uid, startBucket).
		Group("hour_bucket").
		Scan(&userRows)
	hourlySeries := build24HourSeries(now, userRows)

	resp := gin.H{
		"user":          user,
		"total_rules":   ruleCount,
		"running_rules": runningRules,
		"total_nodes":   len(nodes),
		"online_nodes":  onlineNodes,
		"hourly_stats":  hourlySeries,
		"engines": []map[string]string{
			{"id": "native", "name": "Native (内置/自研协议底座)", "desc": "纯 Go 零依赖转发与自研加密隧道扩展接口"},
			{"id": "gost", "name": "GOST v3 (多跳加密隧道)", "desc": "支持 TLS / WS / WSS / QUIC / KCP 多跳链路"},
			{"id": "realm", "name": "Realm (极速轻量直转)", "desc": "Rust 编写的高性能低内存 TCP/UDP 转发引擎"},
			{"id": "nftables", "name": "nftables (Linux 内核零拷贝)", "desc": "Linux 内核态 DNAT/SNAT 转发，极致吞吐零 CPU 开销"},
		},
	}

	if s.isAdmin(c) {
		var globalRows []model.TrafficHourlyStat
		s.db.Model(&model.TrafficHourlyStat{}).
			Select("hour_bucket, COALESCE(SUM(upload_bytes), 0) AS upload_bytes, COALESCE(SUM(down_bytes), 0) AS down_bytes, COALESCE(SUM(billed_bytes), 0) AS billed_bytes").
			Where("hour_bucket >= ?", startBucket).
			Group("hour_bucket").
			Scan(&globalRows)
		resp["global_hourly_stats"] = build24HourSeries(now, globalRows)

		type topUserItem struct {
			ID         uint64 `json:"id"`
			Email      string `json:"email"`
			UsedBytes  int64  `json:"used_bytes"`
			QuotaBytes int64  `json:"quota_bytes"`
			PlanID     uint64 `json:"plan_id"`
		}
		var topUsers []topUserItem
		s.db.Model(&model.User{}).
			Select("id, email, used_bytes, quota_bytes, plan_id").
			Order("used_bytes desc").
			Limit(5).
			Scan(&topUsers)
		resp["top_users"] = topUsers

		type topNodeItem struct {
			ID         uint64 `json:"id"`
			Name       string `json:"name"`
			UsedBytes  int64  `json:"used_bytes"`
			QuotaBytes int64  `json:"quota_bytes"`
			Status     string `json:"status"`
		}
		var topNodes []topNodeItem
		s.db.Model(&model.Node{}).
			Select("id, name, used_bytes, quota_bytes, status").
			Order("used_bytes desc").
			Limit(5).
			Scan(&topNodes)
		resp["top_nodes"] = topNodes
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) getSystemConfig() model.SystemConfig {
	var cfg model.SystemConfig
	if err := s.db.First(&cfg, 1).Error; err != nil {
		cfg = model.SystemConfig{
			ID:                        1,
			SiteName:                  "Zachary Panel",
			SiteLogo:                  "ZP",
			Announcement:              "",
			AllowRegister:             false,
			DefaultQuotaGB:            10,
			DefaultMaxRules:           5,
			DefaultSpeedMbps:          50,
			DefaultTunnels:            "1",
			NotifyOnNodeEvents:        true,
			NotifyOnQuotaEvents:       true,
			NotifyOnTicketEvents:      true,
			AffiliateEnabled:          true,
			AffiliateCommissionRate:   10,
			AffiliateMinWithdrawCents: 1000,
		}
		s.db.Create(&cfg)
	}
	return cfg
}

func maskSystemConfig(cfg model.SystemConfig) model.SystemConfig {
	if strings.TrimSpace(cfg.EpayKey) != "" {
		cfg.EpayKey = maskedSecretPlaceholder
	}
	if strings.TrimSpace(cfg.USDTWebhookSecret) != "" {
		cfg.USDTWebhookSecret = maskedSecretPlaceholder
	}
	if strings.TrimSpace(cfg.NotifyTelegramBotToken) != "" {
		cfg.NotifyTelegramBotToken = maskedSecretPlaceholder
	}
	return cfg
}

func validateExternalGatewayURL(raw string) (string, error) {
	uStr := strings.TrimSpace(raw)
	if uStr == "" {
		return "", nil
	}
	parsed, err := url.Parse(uStr)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("易支付接口地址需为有效的 http:// 或 https:// 地址")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("易支付接口地址不能包含账号凭据、查询参数或锚点")
	}
	return strings.TrimRight(uStr, "/"), nil
}

func (s *Server) handleGetSiteConfig(c *gin.Context) {
	cfg := s.getSystemConfig()
	epayEnabled := cfg.PaymentEnabled &&
		strings.TrimSpace(cfg.EpayURL) != "" &&
		strings.TrimSpace(cfg.EpayPID) != "" &&
		strings.TrimSpace(cfg.EpayKey) != ""
	usdtEnabled := cfg.PaymentEnabled && strings.TrimSpace(cfg.USDTAddress) != ""
	c.JSON(http.StatusOK, gin.H{
		"site_name":                    cfg.SiteName,
		"site_logo":                    cfg.SiteLogo,
		"announcement":                 cfg.Announcement,
		"allow_register":               cfg.AllowRegister,
		"payment_enabled":              cfg.PaymentEnabled,
		"epay_enabled":                 epayEnabled,
		"usdt_enabled":                 usdtEnabled,
		"usdt_address":                 cfg.USDTAddress,
		"recharge_notice":              cfg.RechargeNotice,
		"affiliate_enabled":            cfg.AffiliateEnabled,
		"affiliate_commission_rate":    sanitizeAffiliateRate(cfg.AffiliateCommissionRate),
		"affiliate_min_withdraw_cents": cfg.AffiliateMinWithdrawCents,
		"offpeak_enabled":              cfg.OffPeakEnabled,
		"offpeak_start":                cfg.OffPeakStart,
		"offpeak_end":                  cfg.OffPeakEnd,
		"offpeak_multiplier":           cfg.OffPeakMultiplier,
		"offpeak_timezone":             cfg.OffPeakTimezone,
	})
}

func (s *Server) handleAdminGetSettings(c *gin.Context) {
	cfg := s.getSystemConfig()
	c.JSON(http.StatusOK, maskSystemConfig(cfg))
}

func (s *Server) handleAdminUpdateSettings(c *gin.Context) {
	cfg := s.getSystemConfig()
	var req struct {
		SiteName                  *string  `json:"site_name"`
		SiteLogo                  *string  `json:"site_logo"`
		Announcement              *string  `json:"announcement"`
		AllowRegister             *bool    `json:"allow_register"`
		DefaultRoleGroupID        *uint64  `json:"default_role_group_id"`
		DefaultPlanID             *uint64  `json:"default_plan_id"`
		DefaultQuotaGB            *int64   `json:"default_quota_gb"`
		DefaultMaxRules           *int     `json:"default_max_rules"`
		DefaultSpeedMbps          *int     `json:"default_speed_mbps"`
		DefaultTunnels            *string  `json:"default_tunnels"`
		PaymentEnabled            *bool    `json:"payment_enabled"`
		EpayURL                   *string  `json:"epay_url"`
		EpayPID                   *string  `json:"epay_pid"`
		EpayKey                   *string  `json:"epay_key"`
		USDTAddress               *string  `json:"usdt_address"`
		USDTWebhookSecret         *string  `json:"usdt_webhook_secret"`
		RechargeNotice            *string  `json:"recharge_notice"`
		NotifyTelegramBotToken    *string  `json:"notify_telegram_bot_token"`
		NotifyTelegramChatID      *string  `json:"notify_telegram_chat_id"`
		NotifyWebhookURL          *string  `json:"notify_webhook_url"`
		NotifyOnNodeEvents        *bool    `json:"notify_on_node_events"`
		NotifyOnQuotaEvents       *bool    `json:"notify_on_quota_events"`
		NotifyOnTicketEvents      *bool    `json:"notify_on_ticket_events"`
		AffiliateEnabled          *bool    `json:"affiliate_enabled"`
		AffiliateCommissionRate   *float64 `json:"affiliate_commission_rate"`
		AffiliateMinWithdrawCents *int64   `json:"affiliate_min_withdraw_cents"`
		OffPeakEnabled            *bool    `json:"offpeak_enabled"`
		OffPeakStart              *string  `json:"offpeak_start"`
		OffPeakEnd                *string  `json:"offpeak_end"`
		OffPeakMultiplier         *float64 `json:"offpeak_multiplier"`
		OffPeakTimezone           *string  `json:"offpeak_timezone"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SiteName != nil && strings.TrimSpace(*req.SiteName) != "" {
		cfg.SiteName = truncateUTF8(strings.TrimSpace(*req.SiteName), 64)
	}
	if req.SiteLogo != nil && strings.TrimSpace(*req.SiteLogo) != "" {
		cfg.SiteLogo = truncateUTF8(strings.TrimSpace(*req.SiteLogo), 16)
	}
	if req.Announcement != nil {
		cfg.Announcement = truncateUTF8(strings.TrimSpace(*req.Announcement), 2048)
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
	if req.DefaultQuotaGB != nil && *req.DefaultQuotaGB > 0 && *req.DefaultQuotaGB <= 1048576 {
		cfg.DefaultQuotaGB = *req.DefaultQuotaGB
	}
	if req.DefaultMaxRules != nil && *req.DefaultMaxRules > 0 && *req.DefaultMaxRules <= 10000 {
		cfg.DefaultMaxRules = *req.DefaultMaxRules
	}
	if req.DefaultSpeedMbps != nil && *req.DefaultSpeedMbps > 0 && *req.DefaultSpeedMbps <= 100000 {
		cfg.DefaultSpeedMbps = *req.DefaultSpeedMbps
	}
	if req.DefaultTunnels != nil && req.DefaultRoleGroupID == nil {
		cfg.DefaultTunnels = strings.TrimSpace(*req.DefaultTunnels)
	}
	if req.PaymentEnabled != nil {
		cfg.PaymentEnabled = *req.PaymentEnabled
	}
	if req.EpayURL != nil {
		cleanURL, err := validateExternalGatewayURL(*req.EpayURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		cfg.EpayURL = cleanURL
	}
	if req.EpayPID != nil {
		cfg.EpayPID = truncateUTF8(strings.TrimSpace(*req.EpayPID), 64)
	}
	if req.EpayKey != nil {
		if v := strings.TrimSpace(*req.EpayKey); v != maskedSecretPlaceholder {
			cfg.EpayKey = truncateUTF8(v, 128)
		}
	}
	if req.USDTAddress != nil {
		cfg.USDTAddress = truncateUTF8(strings.TrimSpace(*req.USDTAddress), 128)
	}
	if req.USDTWebhookSecret != nil {
		if v := strings.TrimSpace(*req.USDTWebhookSecret); v != maskedSecretPlaceholder {
			cfg.USDTWebhookSecret = truncateUTF8(v, 128)
		}
	}
	if req.RechargeNotice != nil {
		cfg.RechargeNotice = truncateUTF8(strings.TrimSpace(*req.RechargeNotice), 512)
	}
	if req.NotifyTelegramBotToken != nil {
		if v := strings.TrimSpace(*req.NotifyTelegramBotToken); v != maskedSecretPlaceholder {
			cfg.NotifyTelegramBotToken = truncateUTF8(v, 128)
		}
	}
	if req.NotifyTelegramChatID != nil {
		cfg.NotifyTelegramChatID = truncateUTF8(strings.TrimSpace(*req.NotifyTelegramChatID), 64)
	}
	if req.NotifyWebhookURL != nil {
		wurl := strings.TrimSpace(*req.NotifyWebhookURL)
		if wurl != "" {
			if err := service.ValidateWebhookURL(wurl); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}
		cfg.NotifyWebhookURL = wurl
	}
	if req.NotifyOnNodeEvents != nil {
		cfg.NotifyOnNodeEvents = *req.NotifyOnNodeEvents
	}
	if req.NotifyOnQuotaEvents != nil {
		cfg.NotifyOnQuotaEvents = *req.NotifyOnQuotaEvents
	}
	if req.NotifyOnTicketEvents != nil {
		cfg.NotifyOnTicketEvents = *req.NotifyOnTicketEvents
	}
	if req.AffiliateEnabled != nil {
		cfg.AffiliateEnabled = *req.AffiliateEnabled
	}
	if req.AffiliateCommissionRate != nil {
		if math.IsNaN(*req.AffiliateCommissionRate) || math.IsInf(*req.AffiliateCommissionRate, 0) || *req.AffiliateCommissionRate < 0 || *req.AffiliateCommissionRate > 50 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "返利佣金比例需在 0% - 50% 之间"})
			return
		}
		cfg.AffiliateCommissionRate = sanitizeAffiliateRate(*req.AffiliateCommissionRate)
	}
	if req.AffiliateMinWithdrawCents != nil {
		if *req.AffiliateMinWithdrawCents < 100 || *req.AffiliateMinWithdrawCents > maxWithdrawAmountCent {
			c.JSON(http.StatusBadRequest, gin.H{"error": "最低提现门槛需在 ¥1.00 - ¥1,000,000.00 之间"})
			return
		}
		cfg.AffiliateMinWithdrawCents = *req.AffiliateMinWithdrawCents
	}
	if req.OffPeakEnabled != nil {
		cfg.OffPeakEnabled = *req.OffPeakEnabled
	}
	if req.OffPeakStart != nil {
		v := strings.TrimSpace(*req.OffPeakStart)
		if v != "" {
			if _, err := service.ParseClockHHMM(v); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "闲时开始" + err.Error()})
				return
			}
			cfg.OffPeakStart = v
		}
	}
	if req.OffPeakEnd != nil {
		v := strings.TrimSpace(*req.OffPeakEnd)
		if v != "" {
			if _, err := service.ParseClockHHMM(v); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "闲时结束" + err.Error()})
				return
			}
			cfg.OffPeakEnd = v
		}
	}
	if req.OffPeakMultiplier != nil {
		if math.IsNaN(*req.OffPeakMultiplier) || math.IsInf(*req.OffPeakMultiplier, 0) || *req.OffPeakMultiplier < 0.01 || *req.OffPeakMultiplier > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "闲时流量倍率需在 0.01 - 100 之间"})
			return
		}
		cfg.OffPeakMultiplier = *req.OffPeakMultiplier
	}
	if req.OffPeakTimezone != nil {
		tz := strings.TrimSpace(*req.OffPeakTimezone)
		if tz == "" {
			tz = "Asia/Shanghai"
		}
		if tz != "Asia/Shanghai" && tz != "UTC" && tz != "CST" {
			if _, err := time.LoadLocation(tz); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("无效的时区标识 %q（示例: Asia/Shanghai 或 UTC）", tz)})
				return
			}
		}
		cfg.OffPeakTimezone = truncateUTF8(tz, 64)
	}
	s.db.Save(&cfg)
	s.recordAudit(c, "admin.update_settings", cfg.SiteName, "更新系统设置、闲时倍率、推广返利、支付网关或告警配置")
	c.JSON(http.StatusOK, maskSystemConfig(cfg))
}

func (s *Server) handleAdminTestNotify(c *gin.Context) {
	if s.orch == nil || s.orch.Notifier() == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "告警通知服务未初始化"})
		return
	}
	if err := s.orch.Notifier().SendAlert(
		"test_alert",
		"告警通道连通性测试",
		"这是一条来自控制面板的测试通知，说明您的 Webhook / Telegram 告警通道已配置成功。",
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "发送测试通知失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "测试通知已成功发送"})
}

func (s *Server) handleListNodes(c *gin.Context) {
	if s.isAdmin(c) {
		var nodes []model.Node
		s.db.Order("id asc").Find(&nodes)
		for i := range nodes {
			s.hub.EnrichNodeMetrics(&nodes[i])
			nodes[i].SecretToken = ""
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
		ID                     uint64    `json:"id"`
		RoleGroupID            uint64    `json:"role_group_id"`
		PlanID                 uint64    `json:"plan_id"`
		BalanceCents           int64     `json:"balance_cents"`
		CommissionBalanceCents int64     `json:"commission_balance_cents"`
		QuotaBytes             int64     `json:"quota_bytes"`
		UsedBytes              int64     `json:"used_bytes"`
		MaxRules               int       `json:"max_rules"`
		SpeedMbps              int       `json:"speed_mbps"`
		ExpireAt               time.Time `json:"expire_at"`
		Status                 string    `json:"status"`
		AllowedTunnels         string    `json:"allowed_tunnels"`
	}
	s.db.Model(&model.User{}).Select("id, role_group_id, plan_id, balance_cents, commission_balance_cents, quota_bytes, used_bytes, max_rules, speed_mbps, expire_at, status, allowed_tunnels").Where("id = ?", uid).Scan(&user)

	nodes := make([]model.Node, 0)
	if s.isAdmin(c) {
		s.db.Select("id, status, quota_bytes, used_bytes, agent_version").Order("id asc").Find(&nodes)
		for i := range nodes {
			s.hub.EnrichNodeMetrics(&nodes[i])
		}
	}

	type ruleDelta struct {
		ID              uint64 `json:"id"`
		UploadBytes     int64  `json:"upload_bytes"`
		DownBytes       int64  `json:"down_bytes"`
		BilledBytes     int64  `json:"billed_bytes"`
		DailyUsedBytes  int64  `json:"daily_used_bytes"`
		DailyResetDate  string `json:"daily_reset_date"`
		RuleQuotaBytes  int64  `json:"rule_quota_bytes"`
		DailyQuotaBytes int64  `json:"daily_quota_bytes"`
		Enabled         bool   `json:"enabled"`
		Status          string `json:"status"`
	}
	var rules []ruleDelta
	q := s.db.Model(&model.ForwardRule{}).Select("id, upload_bytes, down_bytes, billed_bytes, daily_used_bytes, daily_reset_date, rule_quota_bytes, daily_quota_bytes, enabled, status")
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

func collectNodeAllowedIPList(n model.Node) []string {
	var ips []string
	seen := make(map[string]struct{})
	for _, raw := range append([]string{n.OutboundIP}, strings.Split(n.AllowedOutboundIPs, ",")...) {
		v := strings.TrimSpace(raw)
		if v != "" {
			if _, dup := seen[v]; !dup {
				seen[v] = struct{}{}
				ips = append(ips, v)
			}
		}
	}
	return ips
}

func (s *Server) populateLineAllowedOutboundIPs(lines []model.TunnelLine) {
	if len(lines) == 0 {
		return
	}
	var nodes []model.Node
	s.db.Select("id, outbound_ip, allowed_outbound_ips").Find(&nodes)
	nodeMap := make(map[uint64]model.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}
	for i := range lines {
		if lines[i].Type == "encrypt" {
			ems := lines[i].EgressMembers()
			if len(ems) > 0 {
				var common []string
				for idx, em := range ems {
					n, ok := nodeMap[em.NodeID]
					if !ok {
						common = nil
						break
					}
					if idx == 0 {
						common = collectNodeAllowedIPList(n)
					} else {
						filtered := common[:0]
						for _, ip := range common {
							if n.AllowsOutboundIP(ip, false) {
								filtered = append(filtered, ip)
							}
						}
						common = filtered
					}
				}
				lines[i].AllowedOutboundIPs = strings.Join(common, ",")
				continue
			}
		}
		if n, ok := nodeMap[lines[i].IngressNodeID]; ok {
			lines[i].AllowedOutboundIPs = strings.Join(collectNodeAllowedIPList(n), ",")
		}
	}
}

func sanitizeRuleForClient(r *model.ForwardRule, isAdmin bool) {
	if r == nil || isAdmin {
		return
	}
	r.HopPortsJSON = ""
	r.EgressPortsJSON = ""
	r.RelayPort = 0
	r.RelayNodeID = 0
}

func sanitizeRulesForClient(rules []model.ForwardRule, isAdmin bool) {
	if isAdmin {
		return
	}
	for i := range rules {
		sanitizeRuleForClient(&rules[i], false)
	}
}

func (s *Server) handleListLines(c *gin.Context) {
	var lines []model.TunnelLine
	s.db.Order("id asc").Find(&lines)
	s.populateLineAllowedOutboundIPs(lines)
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
			// Mask internal hop/egress topology node IDs from non-admin tenants
			l.HopNodeIDs = ""
			l.EgressNodeIDs = ""
			l.EgressNodeID = 0
			authorized = append(authorized, l)
		}
	}
	c.JSON(http.StatusOK, authorized)
}

// parseListPagination extracts bounded page & page_size query parameters.
// When paged=1 is passed, respondListPayload wraps the result in {items, total, page, page_size};
// otherwise it returns the bare array while always setting X-Total-Count / X-Page / X-Page-Size headers.
func parseListPagination(c *gin.Context, defaultSize, maxSize int) (page, pageSize int, pagedEnvelope bool) {
	page = 1
	if pStr := strings.TrimSpace(c.Query("page")); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 {
			page = p
		}
	}
	pageSize = defaultSize
	if psStr := strings.TrimSpace(c.Query("page_size")); psStr != "" {
		if ps, err := strconv.Atoi(psStr); err == nil && ps > 0 {
			pageSize = ps
		}
	}
	if pageSize > maxSize {
		pageSize = maxSize
	}
	if page > 100000 {
		page = 100000
	}
	pagedEnvelope = c.Query("paged") == "1"
	return page, pageSize, pagedEnvelope
}

func respondListPayload(c *gin.Context, items any, total int64, page, pageSize int, pagedEnvelope bool) {
	c.Header("X-Total-Count", strconv.FormatInt(total, 10))
	c.Header("X-Page", strconv.Itoa(page))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	if pagedEnvelope {
		c.JSON(http.StatusOK, gin.H{
			"items":     items,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
		return
	}
	c.JSON(http.StatusOK, items)
}

func (s *Server) handleListRules(c *gin.Context) {
	uid := s.currentUserID(c)
	isAdmin := s.isAdmin(c)
	var rules []model.ForwardRule
	query := s.db.Model(&model.ForwardRule{})
	if !isAdmin || c.Query("all") != "1" {
		query = query.Where("user_id = ?", uid)
	} else if uidParam := strings.TrimSpace(c.Query("user_id")); uidParam != "" {
		if filterUID, err := strconv.ParseUint(uidParam, 10, 64); err == nil && filterUID > 0 {
			query = query.Where("user_id = ?", filterUID)
		}
	}
	if tidParam := strings.TrimSpace(c.Query("tunnel_line_id")); tidParam != "" {
		if tid, err := strconv.ParseUint(tidParam, 10, 64); err == nil && tid > 0 {
			query = query.Where("tunnel_line_id = ?", tid)
		}
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if proto := strings.TrimSpace(c.Query("protocol")); proto != "" {
		query = query.Where("protocol = ?", proto)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		if portNum, err := strconv.Atoi(q); err == nil && portNum > 0 {
			query = query.Where(`(name LIKE ? ESCAPE '!' OR targets_json LIKE ? ESCAPE '!' OR match_domains LIKE ? ESCAPE '!' OR listen_port = ?)`, like, like, like, portNum)
		} else {
			query = query.Where(`(name LIKE ? ESCAPE '!' OR targets_json LIKE ? ESCAPE '!' OR match_domains LIKE ? ESCAPE '!')`, like, like, like)
		}
	}
	var total int64
	query.Count(&total)

	page, pageSize, pagedEnvelope := parseListPagination(c, 500, 1000)
	query.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rules)
	s.fillEffectiveEngines(rules)
	sanitizeRulesForClient(rules, isAdmin)
	respondListPayload(c, rules, total, page, pageSize, pagedEnvelope)
}

// fillEffectiveEngines sets the read-only EffectiveEngine field so the UI shows the engine actually running.
// Batch-fetches rule owners and tunnel lines in O(1) queries to eliminate N+1 round-trips.
func (s *Server) fillEffectiveEngines(rules []model.ForwardRule) {
	if len(rules) == 0 {
		return
	}
	uidSet := make(map[uint64]struct{}, len(rules))
	lineSet := make(map[uint64]struct{}, len(rules))
	for i := range rules {
		if rules[i].UserID > 0 {
			uidSet[rules[i].UserID] = struct{}{}
		}
		if rules[i].TunnelLineID > 0 {
			lineSet[rules[i].TunnelLineID] = struct{}{}
		}
	}
	users := make(map[uint64]*model.User, len(uidSet))
	if len(uidSet) > 0 {
		uids := make([]uint64, 0, len(uidSet))
		for id := range uidSet {
			uids = append(uids, id)
		}
		var fetched []model.User
		s.db.Select("id, role, speed_mbps").Where("id IN ?", uids).Find(&fetched)
		for i := range fetched {
			users[fetched[i].ID] = &fetched[i]
		}
	}
	lines := make(map[uint64]*model.TunnelLine, len(lineSet))
	if len(lineSet) > 0 {
		lids := make([]uint64, 0, len(lineSet))
		for id := range lineSet {
			lids = append(lids, id)
		}
		var fetchedLines []model.TunnelLine
		s.db.Where("id IN ?", lids).Find(&fetchedLines)
		for i := range fetchedLines {
			lines[fetchedLines[i].ID] = &fetchedLines[i]
		}
	}
	for i := range rules {
		rules[i].EffectiveEngine = service.EffectiveEngineForLine(&rules[i], users[rules[i].UserID], lines[rules[i].TunnelLineID])
	}
}

type ruleCreateUpdateReq struct {
	Name            string                    `json:"name" binding:"required"`
	Mode            string                    `json:"mode"`            // "direct" | "tunnel"
	IngressNodeID   uint64                    `json:"ingress_node_id"` // Mode=="direct" 时必选
	TunnelLineID    uint64                    `json:"tunnel_line_id"`  // Mode=="tunnel" 时必选
	Engine          protocol.EngineType       `json:"engine"`          // "native" | "gost" | "realm" | "nftables"
	Protocol        string                    `json:"protocol"`        // "tcp" | "udp" | "both"
	ListenPort      int                       `json:"listen_port"`     // 0 表示自动从节点端口池分配
	PortRange       string                    `json:"port_range"`      // 批量导入时支持端口段如 "20201-20205"
	LoadBalance     string                    `json:"load_balance"`    // "round_robin" | "weighted" | "least_rtt" | "failover" | "random"
	Targets         []protocol.TargetEndpoint `json:"targets" binding:"required"`
	SpeedMbps       int                       `json:"speed_mbps"`
	AccessMode      string                    `json:"access_mode"`       // "off" | "allow" | "deny"
	AccessCIDRs     string                    `json:"access_cidrs"`      // 逗号分隔的 IP 或 CIDR
	ProxyProtocol   *int                      `json:"proxy_protocol"`    // 0=继承隧道/关闭, 1=v1, 2=v2, -1=强制关闭
	MatchDomains    *string                   `json:"match_domains"`     // SNI / HTTP Host 共享端口域名
	OutboundIP      *string                   `json:"outbound_ip"`       // 指定出站源 IP
	RuleQuotaBytes  *int64                    `json:"rule_quota_bytes"`  // 单规则累计流量上限 (0=不限)
	DailyQuotaBytes *int64                    `json:"daily_quota_bytes"` // 单规则每日流量上限 (0=不限)
}

func validateRuleAccessACL(mode, cidrs string) (string, string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "off"
	}
	if mode != "off" && mode != "allow" && mode != "deny" {
		return "", "", fmt.Errorf("无效的访问控制模式 %q（仅支持 off / allow / deny）", mode)
	}
	var normalized []string
	for _, token := range strings.FieldsFunc(cidrs, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "/") {
			_, ipNet, err := net.ParseCIDR(token)
			if err != nil || ipNet == nil {
				return "", "", fmt.Errorf("无效的 CIDR 网段 %q", token)
			}
			normalized = append(normalized, ipNet.String())
		} else {
			ip := net.ParseIP(token)
			if ip == nil {
				return "", "", fmt.Errorf("无效的 IP 地址 %q", token)
			}
			normalized = append(normalized, ip.String())
		}
	}
	if len(normalized) > 64 {
		return "", "", fmt.Errorf("单条规则最多支持配置 64 个 IP/CIDR 条目")
	}
	if (mode == "allow" || mode == "deny") && len(normalized) == 0 {
		return "", "", fmt.Errorf("启用 IP 白名单或黑名单时，请至少填写一个有效 IP 或 CIDR 网段")
	}
	return mode, strings.Join(normalized, ","), nil
}

func expandBatchRuleItems(items []ruleCreateUpdateReq) ([]ruleCreateUpdateReq, error) {
	var expanded []ruleCreateUpdateReq
	for _, item := range items {
		pr := strings.TrimSpace(item.PortRange)
		if pr == "" {
			expanded = append(expanded, item)
			continue
		}
		if item.MatchDomains != nil && strings.TrimSpace(*item.MatchDomains) != "" {
			return nil, fmt.Errorf("规则「%s」配置了共享端口域名路由，不支持同时展开端口段", item.Name)
		}
		startP, endP, err := utils.ParsePortRange(pr)
		if err != nil || startP <= 0 || endP < startP {
			return nil, fmt.Errorf("规则「%s」端口段格式无效 (%s)", item.Name, pr)
		}
		span := endP - startP + 1
		if span > 50 {
			return nil, fmt.Errorf("规则「%s」单次展开端口段不能超过 50 个端口", item.Name)
		}
		for offset := 0; offset < span; offset++ {
			port := startP + offset
			cloned := item
			cloned.PortRange = ""
			cloned.ListenPort = port
			if span > 1 {
				cloned.Name = fmt.Sprintf("%s-%d", strings.TrimSpace(item.Name), port)
			}
			mappedTargets := make([]protocol.TargetEndpoint, 0, len(item.Targets))
			for _, t := range item.Targets {
				addr := strings.TrimSpace(t.Address)
				host, portPart, splitErr := net.SplitHostPort(addr)
				if splitErr == nil && strings.Contains(portPart, "-") {
					tStart, tEnd, tErr := utils.ParsePortRange(portPart)
					if tErr != nil || (tEnd-tStart+1) != span {
						return nil, fmt.Errorf("规则「%s」目标端口段 %s 必须与监听端口段 %s 长度一致 (%d 个端口)", item.Name, addr, pr, span)
					}
					addr = net.JoinHostPort(host, strconv.Itoa(tStart+offset))
				}
				mappedTargets = append(mappedTargets, protocol.TargetEndpoint{
					Address: addr,
					Weight:  t.Weight,
					Backup:  t.Backup,
				})
			}
			cloned.Targets = mappedTargets
			expanded = append(expanded, cloned)
		}
	}
	if len(expanded) > 50 {
		return nil, fmt.Errorf("批量规则展开后总条数 (%d) 超过单次上限 50 条", len(expanded))
	}
	return expanded, nil
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
	case "", "round_robin", "weighted", "least_rtt", "failover", "random":
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
		if t.Weight < 0 || t.Weight > 10000 {
			return fmt.Errorf("目标权重需在 0-10000 之间")
		}
		// 内网目标默认拦截；仅当面板显式设置 NEXUS_ALLOW_PRIVATE_TARGETS=true（且节点也开启 -allow-private-targets）时放行
		if err := security.ValidateTargetAddress(t.Address, os.Getenv("NEXUS_ALLOW_PRIVATE_TARGETS") == "true"); err != nil {
			return fmt.Errorf("目标地址安全策略拦截 (%s): %v", t.Address, err)
		}
	}
	return nil
}

const maxRuleQuotaCeiling int64 = 1 << 50 // 1 PiB ceiling

// validateRuleNextGenOptions validates ProxyProtocol, MatchDomains, OutboundIP RBAC, and Rule/Daily Quotas.
func (s *Server) validateRuleNextGenOptions(proto string, proxyProto int, rawDomains, rawOutIP string, ruleQuota, dailyQuota int64, ingressNodeID uint64, line *model.TunnelLine, isAdmin bool) (cleanDomains string, cleanOutIP string, status int, err error) {
	if proxyProto < -1 || proxyProto > 2 {
		return "", "", http.StatusBadRequest, fmt.Errorf("无效的 PROXY Protocol 版本（仅支持 -1=强制关闭, 0=默认, 1=v1, 2=v2）")
	}
	effPP := proxyProto
	if effPP == 0 && line != nil {
		effPP = line.ProxyProtocol
	}
	if effPP > 0 && proto == "udp" {
		return "", "", http.StatusBadRequest, fmt.Errorf("纯 UDP 规则不支持开启 PROXY Protocol，请改用 TCP 或关闭 PROXY Protocol")
	}

	if strings.TrimSpace(rawDomains) != "" {
		if proto != "tcp" {
			return "", "", http.StatusBadRequest, fmt.Errorf("SNI / HTTP Host 共享端口域名路由仅支持 TCP 协议")
		}
		parsed, dErr := security.ParseAndValidateMatchDomains(rawDomains)
		if dErr != nil {
			return "", "", http.StatusBadRequest, fmt.Errorf("路由域名配置无效: %v", dErr)
		}
		cleanDomains = strings.Join(parsed, ",")
	}

	if strings.TrimSpace(rawOutIP) != "" {
		parsedIP, oErr := security.ValidateOutboundIP(rawOutIP, os.Getenv("NEXUS_ALLOW_PRIVATE_TARGETS") == "true")
		if oErr != nil || parsedIP == nil {
			return "", "", http.StatusBadRequest, fmt.Errorf("出站源 IP 无效: %v", oErr)
		}
		cleanOutIP = parsedIP.String()
		if line != nil && line.Type == "encrypt" && len(line.EgressMembers()) > 0 {
			for _, em := range line.EgressMembers() {
				var egNode model.Node
				if s.db.First(&egNode, em.NodeID).Error != nil || !egNode.AllowsOutboundIP(cleanOutIP, isAdmin) {
					return "", "", http.StatusForbidden, fmt.Errorf("无权在出口节点选用出站源 IP %s，仅可选择节点已授权的出站 IP", cleanOutIP)
				}
			}
		} else if ingressNodeID > 0 {
			var inNode model.Node
			if s.db.First(&inNode, ingressNodeID).Error != nil || !inNode.AllowsOutboundIP(cleanOutIP, isAdmin) {
				return "", "", http.StatusForbidden, fmt.Errorf("无权在入口节点选用出站源 IP %s，仅可选择节点已授权的出站 IP", cleanOutIP)
			}
		}
	}

	if ruleQuota < 0 || ruleQuota > maxRuleQuotaCeiling {
		return "", "", http.StatusBadRequest, fmt.Errorf("单规则累计流量上限数值超出有效范围")
	}
	if dailyQuota < 0 || dailyQuota > maxRuleQuotaCeiling {
		return "", "", http.StatusBadRequest, fmt.Errorf("单规则每日流量上限数值超出有效范围")
	}
	return cleanDomains, cleanOutIP, 0, nil
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

	isAdmin := s.isAdmin(c)
	// 普通用户严禁绕过隧道直接指定节点，且必须具备所选隧道的使用权限
	if !isAdmin {
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
	var linePtr *model.TunnelLine
	if req.TunnelLineID > 0 {
		if err := s.db.First(&line, req.TunnelLineID).Error; err != nil || (!line.Enabled && !isAdmin) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
			return
		}
		linePtr = &line
		ingressNodeID = line.IngressNodeID
		if line.Type == "encrypt" && len(line.EgressMembers()) > 0 {
			ruleMode = "tunnel"
		} else {
			ruleMode = "direct"
		}
		if line.Engine != "" {
			ruleEngine = line.Engine
		}
	} else if ruleMode == "tunnel" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "隧道模式必须选择隧道"})
		return
	}

	proxyProto := 0
	if req.ProxyProtocol != nil {
		proxyProto = *req.ProxyProtocol
	}
	rawDomains := ""
	if req.MatchDomains != nil {
		rawDomains = *req.MatchDomains
	}
	rawOutIP := ""
	if req.OutboundIP != nil {
		rawOutIP = *req.OutboundIP
	}
	ruleQuota := int64(0)
	if req.RuleQuotaBytes != nil {
		ruleQuota = *req.RuleQuotaBytes
	}
	dailyQuota := int64(0)
	if req.DailyQuotaBytes != nil {
		dailyQuota = *req.DailyQuotaBytes
	}

	cleanDomains, cleanOutIP, optStatus, optErr := s.validateRuleNextGenOptions(
		req.Protocol, proxyProto, rawDomains, rawOutIP, ruleQuota, dailyQuota, ingressNodeID, linePtr, isAdmin,
	)
	if optErr != nil {
		c.JSON(optStatus, gin.H{"error": optErr.Error()})
		return
	}

	// Sanitize client-supplied TargetEndpoint fields so users cannot inject CertPEM/NodeID on backend targets
	sanitizedTargets := make([]protocol.TargetEndpoint, 0, len(req.Targets))
	for _, t := range req.Targets {
		sanitizedTargets = append(sanitizedTargets, protocol.TargetEndpoint{
			Address: strings.TrimSpace(t.Address),
			Weight:  t.Weight,
			Backup:  t.Backup,
		})
	}
	targetsBytes, _ := json.Marshal(sanitizedTargets)
	aclMode, aclCIDRs, aclErr := validateRuleAccessACL(req.AccessMode, req.AccessCIDRs)
	if aclErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": aclErr.Error()})
		return
	}
	speedLimit := clampRuleSpeedMbps(req.SpeedMbps, user.SpeedMbps, isAdmin)
	rule := model.ForwardRule{
		UserID:          uid,
		Name:            req.Name,
		Mode:            ruleMode,
		IngressNodeID:   ingressNodeID,
		TunnelLineID:    req.TunnelLineID,
		Engine:          ruleEngine,
		Protocol:        req.Protocol,
		LoadBalance:     req.LoadBalance,
		TargetsJSON:     string(targetsBytes),
		SpeedMbps:       speedLimit,
		AccessMode:      aclMode,
		AccessCIDRs:     aclCIDRs,
		ProxyProtocol:   proxyProto,
		MatchDomains:    cleanDomains,
		OutboundIP:      cleanOutIP,
		RuleQuotaBytes:  ruleQuota,
		DailyQuotaBytes: dailyQuota,
		Enabled:         true,
		Status:          "running",
	}

	if !s.orch.RuleNodesWithinQuota(&rule) {
		c.JSON(http.StatusForbidden, gin.H{"error": "所选隧道或节点月流量配额已耗尽，暂时无法创建转发规则"})
		return
	}

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
		allocPort, normDomains, aerr := s.orch.AllocateIngressPortForRule(ingressNodeID, req.ListenPort, cleanDomains, 0, line.PortRange)
		if aerr != nil {
			status, err = http.StatusBadRequest, aerr
			return err
		}
		rule.ListenPort = allocPort
		rule.MatchDomains = normDomains
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
	rule.EffectiveEngine = service.EffectiveEngineForLine(&rule, &user, linePtr)
	sanitizeRuleForClient(&rule, isAdmin)
	c.JSON(http.StatusCreated, rule)
}

func clampRuleSpeedMbps(requested, ownerMax int, isAdmin bool) int {
	if isAdmin {
		if requested < 0 {
			return 0
		}
		if requested > 100000 {
			return 100000
		}
		return requested
	}
	if requested <= 0 || requested > ownerMax {
		requested = ownerMax
	}
	if requested < 0 {
		return 0
	}
	if requested > 100000 {
		return 100000
	}
	return requested
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
	expandedItems, expErr := expandBatchRuleItems(req.Items)
	if expErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": expErr.Error()})
		return
	}
	req.Items = expandedItems

	switch req.Protocol {
	case "", "tcp", "udp", "both":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的协议类型"})
		return
	}

	isAdmin := s.isAdmin(c)
	if !isAdmin && !user.HasTunnelPermission(req.TunnelLineID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该隧道，请联系管理员分配权限"})
		return
	}

	var line model.TunnelLine
	if err := s.db.First(&line, req.TunnelLineID).Error; err != nil || (!line.Enabled && !isAdmin) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
		return
	}

	proto := req.Protocol
	if proto == "" {
		proto = "tcp"
	}

	for i := range req.Items {
		req.Items[i].Name = strings.TrimSpace(req.Items[i].Name)
		itemProto := req.Items[i].Protocol
		if itemProto == "" {
			itemProto = proto
		}
		req.Items[i].Protocol = itemProto
		item := req.Items[i]
		if err := validateRuleInput(item.Name, item.Protocol, item.LoadBalance, item.Targets); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, err)})
			return
		}
		if err := s.checkNodeAddressTargets(item.Targets); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, err)})
			return
		}
		aclMode, aclCIDRs, aclErr := validateRuleAccessACL(item.AccessMode, item.AccessCIDRs)
		if aclErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, aclErr)})
			return
		}
		req.Items[i].AccessMode = aclMode
		req.Items[i].AccessCIDRs = aclCIDRs

		pp := 0
		if item.ProxyProtocol != nil {
			pp = *item.ProxyProtocol
		}
		md := ""
		if item.MatchDomains != nil {
			md = *item.MatchDomains
		}
		oip := ""
		if item.OutboundIP != nil {
			oip = *item.OutboundIP
		}
		rq := int64(0)
		if item.RuleQuotaBytes != nil {
			rq = *item.RuleQuotaBytes
		}
		dq := int64(0)
		if item.DailyQuotaBytes != nil {
			dq = *item.DailyQuotaBytes
		}
		cleanMD, cleanOIP, optSt, optErr := s.validateRuleNextGenOptions(itemProto, pp, md, oip, rq, dq, line.IngressNodeID, &line, isAdmin)
		if optErr != nil {
			c.JSON(optSt, gin.H{"error": fmt.Sprintf("规则「%s」: %v", item.Name, optErr)})
			return
		}
		req.Items[i].MatchDomains = &cleanMD
		req.Items[i].OutboundIP = &cleanOIP
	}

	ruleMode := "direct"
	if line.Type == "encrypt" && len(line.EgressMembers()) > 0 {
		ruleMode = "tunnel"
	}

	probeRule := model.ForwardRule{
		Mode:          ruleMode,
		IngressNodeID: line.IngressNodeID,
		TunnelLineID:  line.ID,
	}
	if !s.orch.RuleNodesWithinQuota(&probeRule) {
		c.JSON(http.StatusForbidden, gin.H{"error": "所选隧道或节点月流量配额已耗尽，暂时无法批量创建规则"})
		return
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
			md := ""
			if item.MatchDomains != nil {
				md = *item.MatchDomains
			}
			allocPort, normMD, aerr := s.orch.AllocateIngressPortForRule(line.IngressNodeID, item.ListenPort, md, 0, line.PortRange)
			if aerr != nil {
				status, err = http.StatusBadRequest, fmt.Errorf("规则「%s」端口分配失败: %v", item.Name, aerr)
				return err
			}
			lb := item.LoadBalance
			if lb == "" {
				lb = "round_robin"
			}
			pp := 0
			if item.ProxyProtocol != nil {
				pp = *item.ProxyProtocol
			}
			oip := ""
			if item.OutboundIP != nil {
				oip = *item.OutboundIP
			}
			rq := int64(0)
			if item.RuleQuotaBytes != nil {
				rq = *item.RuleQuotaBytes
			}
			dq := int64(0)
			if item.DailyQuotaBytes != nil {
				dq = *item.DailyQuotaBytes
			}
			speedLimit := clampRuleSpeedMbps(item.SpeedMbps, user.SpeedMbps, isAdmin)
			sanitizedTargets := make([]protocol.TargetEndpoint, 0, len(item.Targets))
			for _, t := range item.Targets {
				sanitizedTargets = append(sanitizedTargets, protocol.TargetEndpoint{
					Address: strings.TrimSpace(t.Address),
					Weight:  t.Weight,
					Backup:  t.Backup,
				})
			}
			targetsBytes, _ := json.Marshal(sanitizedTargets)
			rule := model.ForwardRule{
				UserID:          uid,
				Name:            item.Name,
				Mode:            ruleMode,
				IngressNodeID:   line.IngressNodeID,
				TunnelLineID:    line.ID,
				Engine:          line.Engine,
				Protocol:        item.Protocol,
				ListenPort:      allocPort,
				LoadBalance:     lb,
				TargetsJSON:     string(targetsBytes),
				SpeedMbps:       speedLimit,
				AccessMode:      item.AccessMode,
				AccessCIDRs:     item.AccessCIDRs,
				ProxyProtocol:   pp,
				MatchDomains:    normMD,
				OutboundIP:      oip,
				RuleQuotaBytes:  rq,
				DailyQuotaBytes: dq,
				Enabled:         true,
				Status:          "running",
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
	s.fillEffectiveEngines(created)
	sanitizeRulesForClient(created, isAdmin)
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
	isAdmin := s.isAdmin(c)
	if rule.UserID != s.currentUserID(c) && !isAdmin {
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
	if req.AccessMode != "" || req.AccessCIDRs != "" {
		aclMode, aclCIDRs, aclErr := validateRuleAccessACL(req.AccessMode, req.AccessCIDRs)
		if aclErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": aclErr.Error()})
			return
		}
		rule.AccessMode = aclMode
		rule.AccessCIDRs = aclCIDRs
	}

	var owner model.User
	s.db.First(&owner, rule.UserID)

	targetTunnelID := rule.TunnelLineID
	if req.TunnelLineID > 0 {
		targetTunnelID = req.TunnelLineID
	}
	if !isAdmin && !owner.HasTunnelPermission(targetTunnelID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权使用该隧道，请联系管理员分配权限"})
		return
	}

	oldRule := rule
	sanitizedTargets := make([]protocol.TargetEndpoint, 0, len(req.Targets))
	for _, t := range req.Targets {
		sanitizedTargets = append(sanitizedTargets, protocol.TargetEndpoint{
			Address: strings.TrimSpace(t.Address),
			Weight:  t.Weight,
			Backup:  t.Backup,
		})
	}
	targetsBytes, _ := json.Marshal(sanitizedTargets)
	rule.Name = req.Name

	needRemoveOld := false
	var newLine model.TunnelLine
	var activeLinePtr *model.TunnelLine
	switchLine := req.TunnelLineID > 0 && req.TunnelLineID != rule.TunnelLineID
	if switchLine {
		if err := s.db.First(&newLine, req.TunnelLineID).Error; err != nil || (!newLine.Enabled && !isAdmin) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "所选隧道不存在或已禁用"})
			return
		}
		activeLinePtr = &newLine
		needRemoveOld = true
		rule.TunnelLineID = newLine.ID
		rule.IngressNodeID = newLine.IngressNodeID
		rule.Engine = newLine.Engine
		rule.RelayPort = 0
		rule.RelayNodeID = 0
		rule.HopPortsJSON = ""
		rule.EgressPortsJSON = ""
		if newLine.Type == "encrypt" && len(newLine.EgressMembers()) > 0 {
			rule.Mode = "tunnel"
		} else {
			rule.Mode = "direct"
		}
	} else if rule.TunnelLineID > 0 {
		var existingLine model.TunnelLine
		if s.db.First(&existingLine, rule.TunnelLineID).Error == nil {
			activeLinePtr = &existingLine
		}
	}

	if req.Protocol != "" {
		rule.Protocol = req.Protocol
	}
	if req.LoadBalance != "" {
		rule.LoadBalance = req.LoadBalance
	}
	if req.ProxyProtocol != nil {
		rule.ProxyProtocol = *req.ProxyProtocol
	}
	if req.MatchDomains != nil {
		rule.MatchDomains = *req.MatchDomains
	}
	if req.OutboundIP != nil {
		rule.OutboundIP = *req.OutboundIP
	}
	if req.RuleQuotaBytes != nil {
		rule.RuleQuotaBytes = *req.RuleQuotaBytes
	}
	if req.DailyQuotaBytes != nil {
		rule.DailyQuotaBytes = *req.DailyQuotaBytes
	}

	cleanDomains, cleanOutIP, optSt, optErr := s.validateRuleNextGenOptions(
		rule.Protocol, rule.ProxyProtocol, rule.MatchDomains, rule.OutboundIP, rule.RuleQuotaBytes, rule.DailyQuotaBytes,
		rule.IngressNodeID, activeLinePtr, isAdmin,
	)
	if optErr != nil {
		c.JSON(optSt, gin.H{"error": optErr.Error()})
		return
	}
	rule.MatchDomains = cleanDomains
	rule.OutboundIP = cleanOutIP

	rule.TargetsJSON = string(targetsBytes)
	if isAdmin {
		if req.SpeedMbps >= 0 {
			rule.SpeedMbps = clampRuleSpeedMbps(req.SpeedMbps, owner.SpeedMbps, true)
		}
	} else {
		rule.SpeedMbps = clampRuleSpeedMbps(req.SpeedMbps, owner.SpeedMbps, false)
	}

	status, err := 0, error(nil)
	_ = s.orch.WithAllocLock(func() error {
		var cur model.ForwardRule
		if e := s.db.First(&cur, ruleID).Error; e != nil {
			status, err = http.StatusNotFound, fmt.Errorf("规则不存在")
			return err
		}
		reqPort := req.ListenPort
		if reqPort == oldRule.ListenPort {
			reqPort = cur.ListenPort
		}
		oldRule = cur
		rule.Enabled, rule.Status, rule.LastError = cur.Enabled, cur.Status, cur.LastError
		rule.TunnelSecret = cur.TunnelSecret
		rule.ListenPort = cur.ListenPort
		if !switchLine {
			rule.TunnelLineID, rule.IngressNodeID, rule.Mode, rule.Engine = cur.TunnelLineID, cur.IngressNodeID, cur.Mode, cur.Engine
			rule.RelayPort, rule.RelayNodeID = cur.RelayPort, cur.RelayNodeID
			rule.HopPortsJSON, rule.EgressPortsJSON = cur.HopPortsJSON, cur.EgressPortsJSON
		}
		if req.ProxyProtocol == nil {
			rule.ProxyProtocol = cur.ProxyProtocol
		}
		if req.MatchDomains == nil {
			rule.MatchDomains = cur.MatchDomains
		}
		if req.OutboundIP == nil {
			rule.OutboundIP = cur.OutboundIP
		}
		if req.RuleQuotaBytes == nil {
			rule.RuleQuotaBytes = cur.RuleQuotaBytes
		}
		if req.DailyQuotaBytes == nil {
			rule.DailyQuotaBytes = cur.DailyQuotaBytes
		}
		if req.Protocol == "" {
			rule.Protocol = cur.Protocol
		}

		var lockLinePtr *model.TunnelLine
		lineRange := ""
		if switchLine {
			lockLinePtr = &newLine
			lineRange = newLine.PortRange
		} else if rule.TunnelLineID > 0 {
			var curLine model.TunnelLine
			if s.db.First(&curLine, rule.TunnelLineID).Error == nil {
				lockLinePtr = &curLine
				lineRange = curLine.PortRange
			}
		}

		// Re-validate merged options inside WithAllocLock to prevent concurrent TOCTOU smuggling across lines/protocols
		lockedDomains, lockedOutIP, lSt, lErr := s.validateRuleNextGenOptions(
			rule.Protocol, rule.ProxyProtocol, rule.MatchDomains, rule.OutboundIP, rule.RuleQuotaBytes, rule.DailyQuotaBytes,
			rule.IngressNodeID, lockLinePtr, isAdmin,
		)
		if lErr != nil {
			status, err = lSt, lErr
			return err
		}
		rule.MatchDomains = lockedDomains
		rule.OutboundIP = lockedOutIP

		if switchLine && newLine.MaxPortCount > 0 {
			var lineRuleCount int64
			s.db.Model(&model.ForwardRule{}).Where("tunnel_line_id = ?", newLine.ID).Count(&lineRuleCount)
			if int(lineRuleCount) >= newLine.MaxPortCount {
				status, err = http.StatusForbidden, fmt.Errorf("目标隧道转发规则数已达上限 (%d 条)", newLine.MaxPortCount)
				return err
			}
		}

		movedOutOfRange := rule.IngressNodeID == oldRule.IngressNodeID &&
			(rule.ListenPort <= 0 || !s.orch.PortInRange(rule.IngressNodeID, rule.ListenPort, lineRange))
		domainsChanged := rule.MatchDomains != oldRule.MatchDomains

		if rule.IngressNodeID != oldRule.IngressNodeID || movedOutOfRange {
			desiredPort := reqPort
			if desiredPort == oldRule.ListenPort {
				desiredPort = 0
			}
			if movedOutOfRange {
				s.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Update("listen_port", 0)
			}
			allocPort, normDomains, aerr := s.orch.AllocateIngressPortForRule(rule.IngressNodeID, desiredPort, rule.MatchDomains, rule.ID, lineRange)
			if aerr != nil {
				if movedOutOfRange {
					s.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Update("listen_port", oldRule.ListenPort)
				}
				status, err = http.StatusBadRequest, aerr
				return err
			}
			rule.ListenPort = allocPort
			rule.MatchDomains = normDomains
		} else if (reqPort > 0 && reqPort != rule.ListenPort) || domainsChanged {
			targetPort := reqPort
			if targetPort <= 0 {
				targetPort = rule.ListenPort
			}
			allocPort, normDomains, aerr := s.orch.AllocateIngressPortForRule(rule.IngressNodeID, targetPort, rule.MatchDomains, rule.ID, lineRange)
			if aerr != nil {
				status, err = http.StatusBadRequest, aerr
				return err
			}
			rule.ListenPort = allocPort
			rule.MatchDomains = normDomains
		}

		// Auto-resume if rule was paused due to rule_quota_exceeded or daily_quota_exceeded and user just raised the limit
		now := time.Now()
		todayStr := s.orch.BillingDateString(now)
		curCopy := cur
		curCopy.RuleQuotaBytes = rule.RuleQuotaBytes
		curCopy.DailyQuotaBytes = rule.DailyQuotaBytes
		nodesOK := s.orch.RuleNodesWithinQuota(&rule)
		if (rule.Status == "rule_quota_exceeded" || rule.Status == "daily_quota_exceeded") &&
			curCopy.WithinRuleQuotas(todayStr) &&
			owner.CanForward(now) &&
			(isAdmin || owner.HasTunnelPermission(rule.TunnelLineID)) &&
			s.tunnelLineEnabled(rule.TunnelLineID) &&
			s.ruleHasValidPort(&rule) &&
			nodesOK {
			rule.Enabled = true
			rule.Status = "running"
		} else if rule.Enabled && !curCopy.WithinRuleQuotas(todayStr) {
			rule.Enabled = false
			if rule.RuleQuotaBytes > 0 && cur.BilledBytes >= rule.RuleQuotaBytes {
				rule.Status = "rule_quota_exceeded"
			} else {
				rule.Status = "daily_quota_exceeded"
			}
		} else if rule.Enabled && !nodesOK {
			rule.Enabled = false
			rule.Status = "node_quota_exceeded"
		}

		if serr := s.db.Omit(ruleCounterCols...).Save(&rule).Error; serr != nil {
			log.Printf("[API] update rule failed: %v", serr)
			s.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
				"listen_port": oldRule.ListenPort, "ingress_node_id": oldRule.IngressNodeID, "match_domains": oldRule.MatchDomains,
			})
			status, err = http.StatusInternalServerError, fmt.Errorf("保存规则失败，请稍后再试")
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if needRemoveOld || oldRule.MatchDomains != rule.MatchDomains || oldRule.ListenPort != rule.ListenPort {
		s.orch.RemoveRuleFromAgents(&oldRule)
	}
	s.orch.DispatchRule(&rule)
	rule.EffectiveEngine = service.EffectiveEngineForLine(&rule, &owner, activeLinePtr)
	sanitizeRuleForClient(&rule, isAdmin)
	c.JSON(http.StatusOK, rule)
}

func (s *Server) handleToggleRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	isAdmin := s.isAdmin(c)
	if rule.UserID != s.currentUserID(c) && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权操作此规则"})
		return
	}

	if !rule.Enabled {
		if rule.TunnelLineID > 0 {
			var line model.TunnelLine
			if err := s.db.First(&line, rule.TunnelLineID).Error; err != nil || !line.Enabled {
				c.JSON(http.StatusForbidden, gin.H{"error": "所属隧道不存在或已停用，无法启用转发"})
				return
			}
		}
		now := time.Now()
		if !rule.WithinRuleQuotas(s.orch.BillingDateString(now)) {
			c.JSON(http.StatusForbidden, gin.H{"error": "该规则已达单规则总流量或今日流量上限，请调高规则配额或等待次日自动恢复"})
			return
		}
		if !s.orch.RuleNodesWithinQuota(&rule) {
			c.JSON(http.StatusForbidden, gin.H{"error": "所属节点月流量配额已耗尽，无法启用转发规则"})
			return
		}
		var user model.User
		if err := s.db.First(&user, rule.UserID).Error; err == nil {
			if !isAdmin && !user.HasTunnelPermission(rule.TunnelLineID) {
				c.JSON(http.StatusForbidden, gin.H{"error": "该隧道权限未授权或已收回，无法启用转发"})
				return
			}
			if !user.CanForward(now) {
				c.JSON(http.StatusForbidden, gin.H{"error": "账户状态异常、流量已用尽或套餐已到期，无法启用规则"})
				return
			}
		}
	}

	enable := !rule.Enabled
	status := "paused"
	if enable {
		status = "running"
	}
	errBadPort := fmt.Errorf("规则端口不在当前允许的端口范围内，请编辑规则重新分配端口后再启用")
	errNodeQuota := fmt.Errorf("所属节点月流量配额已耗尽，无法启用转发规则")
	terr := s.orch.WithAllocLock(func() error {
		if err := s.db.First(&rule, rule.ID).Error; err != nil {
			return err
		}
		if enable && !s.ruleHasValidPort(&rule) {
			return errBadPort
		}
		if enable && !s.orch.RuleNodesWithinQuota(&rule) {
			return errNodeQuota
		}
		return s.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).
			Updates(map[string]any{"enabled": enable, "status": status}).Error
	})
	if terr == errBadPort {
		c.JSON(http.StatusBadRequest, gin.H{"error": terr.Error()})
		return
	}
	if terr == errNodeQuota {
		c.JSON(http.StatusForbidden, gin.H{"error": terr.Error()})
		return
	}
	if terr != nil {
		log.Printf("[API] toggle rule %d failed: %v", rule.ID, terr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "操作失败，请稍后再试"})
		return
	}
	rule.Enabled = enable
	rule.Status = status
	s.orch.DispatchRule(&rule)
	sanitizeRuleForClient(&rule, isAdmin)
	c.JSON(http.StatusOK, rule)
}

func (s *Server) handleProbeRule(c *gin.Context) {
	ruleID, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var rule model.ForwardRule
	if err := s.db.First(&rule, ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "规则不存在"})
		return
	}
	isAdmin := s.isAdmin(c)
	if rule.UserID != s.currentUserID(c) && !isAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权探测他人规则"})
		return
	}

	var targets []protocol.TargetEndpoint
	_ = json.Unmarshal([]byte(rule.TargetsJSON), &targets)
	var addrs []string
	for _, t := range targets {
		addrs = append(addrs, t.Address)
	}

	type probeLeg struct {
		Leg        string `json:"leg"`
		FromNodeID uint64 `json:"from_node_id,omitempty"`
		FromName   string `json:"from_name"`
		ToNodeID   uint64 `json:"to_node_id,omitempty"`
		ToName     string `json:"to_name"`
		LatencyMs  int    `json:"latency_ms"`
		Backup     bool   `json:"backup,omitempty"`
	}
	var legs []probeLeg

	// 链式/多出口加密对接隧道：支持逐跳分段测速（入口 -> 跳点1 -> ... -> 出口池 -> 落地目标）
	tunnelMs := 0
	probeNodeID := rule.IngressNodeID
	if rule.Mode == "tunnel" && rule.TunnelLineID > 0 {
		var line model.TunnelLine
		if err := s.db.First(&line, rule.TunnelLineID).Error; err == nil && len(line.EgressMembers()) > 0 {
			// Ensure HopPorts & EgressPorts exist
			if rule.RelayPort <= 0 {
				_, _ = s.orch.CompileRuleGraph(&rule)
			}
			hopIDs := line.HopIDs()
			egMembers := line.EgressMembers()
			probeNodeID = egMembers[0].NodeID

			nodeIDs := []uint64{rule.IngressNodeID}
			nodeIDs = append(nodeIDs, hopIDs...)
			for _, em := range egMembers {
				nodeIDs = append(nodeIDs, em.NodeID)
			}
			var nodes []model.Node
			s.db.Where("id IN ?", nodeIDs).Find(&nodes)
			nMap := make(map[uint64]model.Node, len(nodes))
			for _, n := range nodes {
				nMap[n.ID] = n
			}
			hopPortMap := make(map[uint64]int)
			for _, a := range rule.HopPortAllocs() {
				hopPortMap[a.NodeID] = a.Port
			}
			egPortMap := make(map[uint64]int)
			for _, a := range rule.EgressPortAllocs() {
				egPortMap[a.NodeID] = a.Port
			}

			displayNodeName := func(nid uint64, fallback string) string {
				if !isAdmin {
					return fallback
				}
				if n, ok := nMap[nid]; ok && n.Name != "" {
					return n.Name
				}
				return fallback
			}

			curFromID := rule.IngressNodeID
			curFromLabel := displayNodeName(curFromID, "入口节点")
			for idx, hid := range hopIDs {
				hp := hopPortMap[hid]
				hNode, ok := nMap[hid]
				toLabel := displayNodeName(hid, fmt.Sprintf("中继跳点 #%d", idx+1))
				ms := -1
				if ok && hp > 0 {
					hHost := strings.Trim(strings.TrimSpace(hNode.PreferredTunnelHost()), "[]")
					addr := net.JoinHostPort(hHost, strconv.Itoa(hp))
					if resMap, pErr := s.hub.RequestProbe(curFromID, rule.ID, []string{addr}); pErr == nil {
						if v, vOk := resMap[addr]; vOk {
							ms = v
						}
					}
				}
				if ms > 0 {
					tunnelMs += ms
				}
				legs = append(legs, probeLeg{
					Leg:       fmt.Sprintf("hop_%d", idx+1),
					FromName:  curFromLabel,
					ToName:    toLabel,
					LatencyMs: ms,
				})
				if isAdmin {
					legs[len(legs)-1].FromNodeID = curFromID
					legs[len(legs)-1].ToNodeID = hid
				}
				curFromID = hid
				curFromLabel = toLabel
			}

			// Probe final tunnel leg from last hop (or ingress) to each egress member
			egAddrs := make([]string, 0, len(egMembers))
			addrByEgID := make(map[uint64]string, len(egMembers))
			for _, em := range egMembers {
				ep := egPortMap[em.NodeID]
				if ep <= 0 && em.NodeID == line.EgressNodeID {
					ep = rule.RelayPort
				}
				if eNode, ok := nMap[em.NodeID]; ok && ep > 0 {
					eHost := strings.Trim(strings.TrimSpace(eNode.PreferredTunnelHost()), "[]")
					addr := net.JoinHostPort(eHost, strconv.Itoa(ep))
					egAddrs = append(egAddrs, addr)
					addrByEgID[em.NodeID] = addr
				}
			}
			var egLatMap map[string]int
			if len(egAddrs) > 0 {
				egLatMap, _ = s.hub.RequestProbe(curFromID, rule.ID, egAddrs)
			}
			for i, em := range egMembers {
				ms := -1
				if addr := addrByEgID[em.NodeID]; addr != "" && egLatMap != nil {
					if v, vOk := egLatMap[addr]; vOk {
						ms = v
					}
				}
				if i == 0 && ms > 0 {
					tunnelMs += ms
				}
				toLabel := displayNodeName(em.NodeID, fmt.Sprintf("出口节点 #%d", i+1))
				legs = append(legs, probeLeg{
					Leg:       fmt.Sprintf("egress_%d", i+1),
					FromName:  curFromLabel,
					ToName:    toLabel,
					LatencyMs: ms,
					Backup:    em.Backup,
				})
				if isAdmin {
					legs[len(legs)-1].FromNodeID = curFromID
					legs[len(legs)-1].ToNodeID = em.NodeID
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
		"legs":      legs,
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

func (s *Server) handleBatchDeleteRules(c *gin.Context) {
	var req struct {
		IDs []uint64 `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要删除的规则"})
		return
	}
	seen := make(map[uint64]bool, len(req.IDs))
	ids := make([]uint64, 0, len(req.IDs))
	for _, id := range req.IDs {
		if id > 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要删除的规则"})
		return
	}
	if len(ids) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "单次批量删除最多支持 200 条规则"})
		return
	}

	var rules []model.ForwardRule
	s.db.Where("id IN ?", ids).Find(&rules)
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到要删除的规则"})
		return
	}
	uid := s.currentUserID(c)
	admin := s.isAdmin(c)
	for i := range rules {
		if rules[i].UserID != uid && !admin {
			c.JSON(http.StatusForbidden, gin.H{"error": "无权删除他人规则"})
			return
		}
	}

	deletedIDs := make([]uint64, 0, len(rules))
	for i := range rules {
		s.orch.RemoveRuleFromAgents(&rules[i])
		deletedIDs = append(deletedIDs, rules[i].ID)
	}
	s.db.Where("id IN ?", deletedIDs).Delete(&model.ForwardRule{})
	c.JSON(http.StatusOK, gin.H{"deleted": len(deletedIDs), "ids": deletedIDs})
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

	couponCode, statusCode, bodyErr := readOptionalCouponCode(c)
	if bodyErr != nil {
		c.JSON(statusCode, gin.H{"error": bodyErr.Error()})
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
	isAdminUser := s.isAdmin(c)
	durationDays := plan.DurationDays
	if durationDays <= 0 {
		durationDays = 30
	}
	cfg := s.getSystemConfig()
	var updatedUser model.User
	var discountApplied int64
	var payableApplied int64
	now := time.Now()

	if couponCode != "" {
		couponClaimMu.Lock()
		defer couponClaimMu.Unlock()
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.Select("id, email").First(&u, uid).Error; err != nil {
			return err
		}
		orderNo := newOrderNo()
		payable := plan.PriceCents
		var discount int64
		var appliedCode string
		if couponCode != "" {
			quote, cerr := claimCouponInTx(tx, uid, u.Email, couponCode, "plan_purchase", orderNo, &plan, now)
			if cerr != nil {
				return cerr
			}
			payable = quote.PayableCents
			discount = quote.DiscountCents
			appliedCode = quote.Coupon.Code
		}

		updates := map[string]any{
			"balance_cents": gorm.Expr("balance_cents - ?", payable),
			"plan_id":       plan.ID,
			"quota_bytes":   plan.QuotaBytes,
			"max_rules":     plan.MaxRules,
			"speed_mbps":    plan.SpeedMbps,
			"monthly_reset": plan.MonthlyReset,
			"last_reset_at": &now,
			"expire_at":     now.AddDate(0, 0, durationDays),
		}
		// 付费套餐购买时重置已用流量；免费套餐 (price=0) 可被反复"购买"，绝不能借此清零用量
		if plan.PriceCents > 0 {
			updates["used_bytes"] = 0
		}
		if plan.RoleGroupID > 0 {
			updates["role_group_id"] = plan.RoleGroupID
		}
		if allowedTunnels != "" && !isAdminUser {
			updates["allowed_tunnels"] = allowedTunnels
		}
		// Atomic balance deduction to prevent concurrent double-spending
		res := tx.Model(&model.User{}).
			Where("id = ? AND balance_cents >= ?", uid, payable).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("insufficient_balance")
		}
		if err := tx.First(&updatedUser, uid).Error; err != nil {
			return err
		}
		planLabel := plan.Name
		if appliedCode != "" && discount > 0 {
			planLabel = fmt.Sprintf("%s [优惠券 %s -¥%.2f]", plan.Name, appliedCode, float64(discount)/100.0)
		}
		order := model.BillingOrder{
			OrderNo:       orderNo,
			UserID:        uid,
			UserEmail:     updatedUser.Email,
			Type:          "plan_purchase",
			PlanID:        plan.ID,
			PlanName:      truncateUTF8(planLabel, 128),
			OriginalCents: plan.PriceCents,
			DiscountCents: discount,
			CouponCode:    appliedCode,
			AmountCents:   payable,
			Status:        "paid",
			Gateway:       "balance",
			PaidAt:        &now,
		}
		if err := tx.Create(&order).Error; err != nil {
			return err
		}
		discountApplied = discount
		payableApplied = payable
		return settleAffiliateOnSpendTx(tx, cfg, &order, payable)
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "coupon_invalid:") {
			c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "coupon_invalid:")})
			return
		}
		if err.Error() == "insufficient_balance" {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "账户余额不足，请先充值或使用兑换码"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "购买失败，请重试"})
		return
	}

	s.enforceUserTunnelPermissions(&updatedUser)
	s.resumeUserQuotaExceededRules(&updatedUser)
	msg := "套餐购买并激活成功，已自动同步对应角色与隧道权限"
	if discountApplied > 0 {
		msg = fmt.Sprintf("套餐购买成功（优惠券已抵扣 ¥%.2f，实付 ¥%.2f）", float64(discountApplied)/100.0, float64(payableApplied)/100.0)
	}
	c.JSON(http.StatusOK, gin.H{
		"message":        msg,
		"user":           updatedUser,
		"discount_cents": discountApplied,
		"payable_cents":  payableApplied,
	})
}

// handleUserResetSubscription lets a user pay their bound plan's price to reset used traffic to 0 and refresh the
// subscription cycle early when they run out of monthly traffic.
func (s *Server) handleUserResetSubscription(c *gin.Context) {
	couponCode, statusCode, bodyErr := readOptionalCouponCode(c)
	if bodyErr != nil {
		c.JSON(statusCode, gin.H{"error": bodyErr.Error()})
		return
	}

	uid := s.currentUserID(c)
	var u model.User
	if err := s.db.First(&u, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if u.PlanID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前账号未绑定套餐，请先在套餐管理中选购套餐"})
		return
	}
	var plan model.Plan
	if err := s.db.First(&plan, u.PlanID).Error; err != nil || !plan.Active {
		c.JSON(http.StatusNotFound, gin.H{"error": "当前绑定的套餐不存在或已下架，请选购其他可用套餐"})
		return
	}
	if plan.PriceCents <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "免费套餐不支持自助重置流量周期，请联系管理员或升级付费套餐"})
		return
	}

	allowedTunnels := strings.TrimSpace(plan.AllowedTunnels)
	if plan.RoleGroupID > 0 {
		var rg model.RoleGroup
		if err := s.db.First(&rg, plan.RoleGroupID).Error; err == nil {
			allowedTunnels = strings.TrimSpace(rg.AllowedTunnels)
		}
	}
	durationDays := plan.DurationDays
	if durationDays <= 0 {
		durationDays = 30
	}
	cfg := s.getSystemConfig()

	var updatedUser model.User
	var discountApplied int64
	var payableApplied int64
	now := time.Now()

	if couponCode != "" {
		couponClaimMu.Lock()
		defer couponClaimMu.Unlock()
	}

	err := s.db.Transaction(func(tx *gorm.DB) error {
		orderNo := newOrderNo()
		payable := plan.PriceCents
		var discount int64
		var appliedCode string
		if couponCode != "" {
			quote, cerr := claimCouponInTx(tx, uid, u.Email, couponCode, "plan_reset", orderNo, &plan, now)
			if cerr != nil {
				return cerr
			}
			payable = quote.PayableCents
			discount = quote.DiscountCents
			appliedCode = quote.Coupon.Code
		}

		updates := map[string]any{
			"balance_cents": gorm.Expr("balance_cents - ?", payable),
			"used_bytes":    0,
			"quota_bytes":   plan.QuotaBytes,
			"max_rules":     plan.MaxRules,
			"speed_mbps":    plan.SpeedMbps,
			"monthly_reset": plan.MonthlyReset,
			"last_reset_at": &now,
			"expire_at":     now.AddDate(0, 0, durationDays),
		}
		if plan.RoleGroupID > 0 {
			updates["role_group_id"] = plan.RoleGroupID
		}
		if allowedTunnels != "" && u.Role != "admin" {
			updates["allowed_tunnels"] = allowedTunnels
		}
		res := tx.Model(&model.User{}).
			Where("id = ? AND balance_cents >= ?", uid, payable).
			Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("insufficient_balance")
		}
		if err := tx.First(&updatedUser, uid).Error; err != nil {
			return err
		}
		planLabel := plan.Name + " (重置流量周期)"
		if appliedCode != "" && discount > 0 {
			planLabel = fmt.Sprintf("%s (重置周期 · 优惠券 %s -¥%.2f)", plan.Name, appliedCode, float64(discount)/100.0)
		}
		order := model.BillingOrder{
			OrderNo:       orderNo,
			UserID:        uid,
			UserEmail:     updatedUser.Email,
			Type:          "plan_reset",
			PlanID:        plan.ID,
			PlanName:      truncateUTF8(planLabel, 128),
			OriginalCents: plan.PriceCents,
			DiscountCents: discount,
			CouponCode:    appliedCode,
			AmountCents:   payable,
			Status:        "paid",
			Gateway:       "balance",
			PaidAt:        &now,
		}
		if err := tx.Create(&order).Error; err != nil {
			return err
		}
		discountApplied = discount
		payableApplied = payable
		return settleAffiliateOnSpendTx(tx, cfg, &order, payable)
	})
	if err != nil {
		if strings.HasPrefix(err.Error(), "coupon_invalid:") {
			c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "coupon_invalid:")})
			return
		}
		if err.Error() == "insufficient_balance" {
			c.JSON(http.StatusPaymentRequired, gin.H{"error": "账户余额不足，无法重置当前套餐周期，请先充值或使用兑换码"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重置订阅周期失败，请稍后重试"})
		return
	}

	s.enforceUserTunnelPermissions(&updatedUser)
	s.resumeUserQuotaExceededRules(&updatedUser)
	msg := "订阅周期与当月流量已重置，因超额暂停的转发规则已自动恢复"
	if discountApplied > 0 {
		msg = fmt.Sprintf("订阅周期与流量已重置（优惠券抵扣 ¥%.2f，实付 ¥%.2f）", float64(discountApplied)/100.0, float64(payableApplied)/100.0)
	}
	c.JSON(http.StatusOK, gin.H{
		"message":        msg,
		"user":           updatedUser,
		"discount_cents": discountApplied,
		"payable_cents":  payableApplied,
	})
}

// handleUserResetSubToken rotates the current user's subscription token so any leaked subscription URL is revoked.
func (s *Server) handleUserResetSubToken(c *gin.Context) {
	uid := s.currentUserID(c)
	newToken := utils.GenerateRandomToken(16)
	if err := s.db.Model(&model.User{}).Where("id = ?", uid).Update("sub_token", newToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重置订阅链接失败，请稍后重试"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":   "订阅链接已重置，旧订阅链接已立即失效",
		"sub_token": newToken,
	})
}

func isValidHexToken(tok string) bool {
	if len(tok) < 16 || len(tok) > 64 || len(tok)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(tok)
	return err == nil
}

// handleGetSubscription serves the user's subscription info and active forwarding endpoints via their SubToken.
// Supports standard `Subscription-Userinfo` header, Base64 text (default), plain text (`?raw=1`), and JSON (`?format=json`).
func (s *Server) handleGetSubscription(c *gin.Context) {
	token := strings.TrimSpace(c.Param("token"))
	if !isValidHexToken(token) {
		c.JSON(http.StatusNotFound, gin.H{"error": "订阅链接无效或已失效"})
		return
	}
	var u model.User
	if err := s.db.Where("sub_token = ?", token).First(&u).Error; err != nil || u.SubToken == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "订阅链接无效或已失效"})
		return
	}
	if u.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
		return
	}

	var expUnix int64
	if !u.ExpireAt.IsZero() {
		expUnix = u.ExpireAt.Unix()
	}
	c.Header("Subscription-Userinfo", fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", u.UsedBytes, u.QuotaBytes, expUnix))
	c.Header("Profile-Update-Interval", "6")
	c.Header("Cache-Control", "no-store")

	canForward := u.CanForward(time.Now())
	var rules []model.ForwardRule
	if canForward {
		s.db.Where("user_id = ? AND enabled = ?", u.ID, true).Order("id asc").Find(&rules)
	}

	var nodes []model.Node
	s.db.Select("id, name, connect_ip, public_host, server_ip").Find(&nodes)
	nodeHost := make(map[uint64]string, len(nodes))
	for _, n := range nodes {
		host := strings.TrimSpace(n.ConnectIP)
		if host == "" {
			host = strings.TrimSpace(n.PublicHost)
		}
		if host == "" {
			host = strings.TrimSpace(n.ServerIP)
		}
		nodeHost[n.ID] = host
	}

	type subRuleItem struct {
		ID           uint64 `json:"id"`
		Name         string `json:"name"`
		Protocol     string `json:"protocol"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		Entry        string `json:"entry"`
		Mode         string `json:"mode"`
		Status       string `json:"status"`
		MatchDomains string `json:"match_domains,omitempty"`
	}
	todayStr := s.orch.BillingDateString(time.Now())
	items := make([]subRuleItem, 0, len(rules))
	var lines []string
	for _, r := range rules {
		if !u.HasTunnelPermission(r.TunnelLineID) && r.TunnelLineID > 0 {
			continue
		}
		if !r.WithinRuleQuotas(todayStr) {
			continue
		}
		host := nodeHost[r.IngressNodeID]
		if host == "" {
			host = "127.0.0.1"
		}
		if strings.TrimSpace(r.MatchDomains) != "" {
			for _, part := range strings.Split(r.MatchDomains, ",") {
				d := strings.TrimSpace(part)
				if d != "" && !strings.HasPrefix(d, "*.") {
					host = d
					break
				}
			}
		}
		entry := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(r.ListenPort))
		items = append(items, subRuleItem{
			ID:           r.ID,
			Name:         r.Name,
			Protocol:     r.Protocol,
			Host:         host,
			Port:         r.ListenPort,
			Entry:        entry,
			Mode:         r.Mode,
			Status:       r.Status,
			MatchDomains: r.MatchDomains,
		})
		lines = append(lines, fmt.Sprintf("%s://%s#%s", r.Protocol, entry, url.PathEscape(r.Name)))
	}

	if strings.EqualFold(c.Query("format"), "json") {
		cfg := s.getSystemConfig()
		c.JSON(http.StatusOK, gin.H{
			"site_name":   cfg.SiteName,
			"email":       maskEmail(u.Email),
			"status":      u.Status,
			"used_bytes":  u.UsedBytes,
			"quota_bytes": u.QuotaBytes,
			"expire_at":   u.ExpireAt,
			"can_forward": canForward,
			"rules":       items,
		})
		return
	}

	plain := strings.Join(lines, "\n")
	if c.Query("raw") == "1" {
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(plain))
		return
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(encoded))
}

func maskEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.IndexByte(email, '@')
	if at <= 0 || at >= len(email)-1 {
		return "***"
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 1 {
		return local + "***" + domain
	}
	return local[:1] + "***" + domain
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

		updates := map[string]any{}
		quotaAdd := rc.QuotaBytes
		durationAdd := rc.Duration

		if rc.PlanID > 0 {
			var plan model.Plan
			if err := tx.First(&plan, rc.PlanID).Error; err == nil {
				user.PlanID = plan.ID
				updates["plan_id"] = plan.ID
				updates["monthly_reset"] = plan.MonthlyReset
				updates["last_reset_at"] = &now
				if plan.RoleGroupID > 0 {
					user.RoleGroupID = plan.RoleGroupID
					updates["role_group_id"] = plan.RoleGroupID
					var rg model.RoleGroup
					if err := tx.First(&rg, plan.RoleGroupID).Error; err == nil && user.Role != "admin" {
						user.AllowedTunnels = rg.AllowedTunnels
						updates["allowed_tunnels"] = rg.AllowedTunnels
					}
				} else if plan.AllowedTunnels != "" && user.Role != "admin" {
					user.AllowedTunnels = plan.AllowedTunnels
					updates["allowed_tunnels"] = plan.AllowedTunnels
				}
				if plan.MaxRules > user.MaxRules {
					user.MaxRules = plan.MaxRules
					updates["max_rules"] = plan.MaxRules
				}
				if plan.SpeedMbps > user.SpeedMbps {
					user.SpeedMbps = plan.SpeedMbps
					updates["speed_mbps"] = plan.SpeedMbps
				}
				if quotaAdd <= 0 && plan.QuotaBytes > 0 {
					quotaAdd = plan.QuotaBytes
				}
				if durationAdd <= 0 && plan.DurationDays > 0 {
					durationAdd = plan.DurationDays
				}
			}
		}

		if durationAdd > 0 {
			if user.ExpireAt.IsZero() || user.ExpireAt.Before(now) {
				user.ExpireAt = now.AddDate(0, 0, durationAdd)
			} else {
				user.ExpireAt = user.ExpireAt.AddDate(0, 0, durationAdd)
			}
			updates["expire_at"] = user.ExpireAt
		}
		if quotaAdd > 0 {
			updates["quota_bytes"] = gorm.Expr("quota_bytes + ?", quotaAdd)
		}
		if rc.BalanceCents > 0 {
			updates["balance_cents"] = gorm.Expr("balance_cents + ?", rc.BalanceCents)
		}

		if len(updates) > 0 {
			// Only write the columns changed by the code; balance / used_bytes may be modified concurrently by purchases
			// and traffic reports and must never be overwritten with a stale snapshot.
			if err := tx.Model(&model.User{}).Where("id = ?", uid).Updates(updates).Error; err != nil {
				return err
			}
		}
		if err := tx.First(&updatedUser, uid).Error; err != nil {
			return err
		}
		planLabel := "卡密兑换 (" + rc.Code + ")"
		if rc.PlanID > 0 {
			var plan model.Plan
			if tx.First(&plan, rc.PlanID).Error == nil {
				planLabel = plan.Name + " [卡密激活]"
			}
		}
		order := model.BillingOrder{
			OrderNo:     newOrderNo(),
			UserID:      uid,
			UserEmail:   updatedUser.Email,
			Type:        "redeem",
			PlanID:      rc.PlanID,
			PlanName:    planLabel,
			AmountCents: rc.BalanceCents,
			Status:      "paid",
			Gateway:     "redeem",
			TradeNo:     rc.Code,
			PaidAt:      &now,
		}
		return tx.Create(&order).Error
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

	s.enforceUserTunnelPermissions(&updatedUser)
	s.resumeUserQuotaExceededRules(&updatedUser)
	c.JSON(http.StatusOK, gin.H{"message": "兑换成功", "user": updatedUser})
}

func newOrderNo() string {
	return fmt.Sprintf("ZP%s%s", time.Now().UTC().Format("20060102150405"), strings.ToUpper(utils.GenerateRandomToken(4)))
}

// computeEpaySign computes the standard Rainbow EPay MD5 signature over non-empty sorted query/form parameters.
func computeEpaySign(params map[string]string, secretKey string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || k == "sign_type" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	b.WriteString(strings.TrimSpace(secretKey))
	sum := md5.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// ComputeUSDTWebhookSign computes the HMAC-SHA256 hex digest over "<timestamp>.<rawBody>" using secret.
func ComputeUSDTWebhookSign(timestamp int64, rawBody []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(secret)))
	_, _ = fmt.Fprintf(mac, "%d.", timestamp)
	_, _ = mac.Write(rawBody)
	return hex.EncodeToString(mac.Sum(nil))
}

func isValidTradeRef(ref string) bool {
	if len(ref) == 0 || len(ref) > 128 {
		return false
	}
	for _, r := range ref {
		if r <= 0x20 || r >= 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) handleListOrders(c *gin.Context) {
	if s.orch != nil {
		s.orch.CloseExpiredOrders(time.Now())
	}
	isAdmin := s.isAdmin(c)
	uid := s.currentUserID(c)

	query := s.db.Model(&model.BillingOrder{})
	if !(isAdmin && c.Query("all") == "1") {
		query = query.Where("user_id = ?", uid)
	}
	if st := strings.TrimSpace(c.Query("status")); st != "" {
		query = query.Where("status = ?", st)
	}
	if tp := strings.TrimSpace(c.Query("type")); tp != "" {
		query = query.Where("type = ?", tp)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		query = query.Where(`(order_no LIKE ? ESCAPE '!' OR user_email LIKE ? ESCAPE '!' OR plan_name LIKE ? ESCAPE '!' OR trade_no LIKE ? ESCAPE '!')`, like, like, like, like)
	}
	var total int64
	query.Count(&total)

	defaultLimit := 100
	if isAdmin && c.Query("all") == "1" {
		defaultLimit = 200
	}
	page, pageSize, pagedEnvelope := parseListPagination(c, defaultLimit, 500)
	var orders []model.BillingOrder
	query.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&orders)
	respondListPayload(c, orders, total, page, pageSize, pagedEnvelope)
}

func (s *Server) handleCreateRechargeOrder(c *gin.Context) {
	var req struct {
		AmountCents int64  `json:"amount_cents" binding:"required"`
		Gateway     string `json:"gateway"`  // "epay" | "usdt" | "manual"
		PayType     string `json:"pay_type"` // "alipay" | "wxpay" | "qqpay" | "usdt"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效的充值金额"})
		return
	}
	if req.AmountCents < 100 || req.AmountCents > 10000000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "单笔充值金额需在 ¥1.00 - ¥100,000.00 之间"})
		return
	}

	uid := s.currentUserID(c)
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	cfg := s.getSystemConfig()
	epayReady := cfg.PaymentEnabled &&
		strings.TrimSpace(cfg.EpayURL) != "" &&
		strings.TrimSpace(cfg.EpayPID) != "" &&
		strings.TrimSpace(cfg.EpayKey) != ""

	gateway := strings.ToLower(strings.TrimSpace(req.Gateway))
	switch gateway {
	case "epay", "usdt", "manual":
	default:
		if epayReady {
			gateway = "epay"
		} else if strings.TrimSpace(cfg.USDTAddress) != "" {
			gateway = "usdt"
		} else {
			gateway = "manual"
		}
	}

	payType := strings.ToLower(strings.TrimSpace(req.PayType))
	switch payType {
	case "alipay", "wxpay", "qqpay", "usdt":
	default:
		payType = "alipay"
	}

	orderNo := newOrderNo()
	payURL := ""
	if gateway == "epay" && epayReady {
		base := s.panelBaseURL(c)
		moneyStr := fmt.Sprintf("%.2f", float64(req.AmountCents)/100.0)
		params := map[string]string{
			"pid":          strings.TrimSpace(cfg.EpayPID),
			"type":         payType,
			"out_trade_no": orderNo,
			"notify_url":   base + "/api/v1/pay/epay/notify",
			"return_url":   base + "/",
			"name":         fmt.Sprintf("%s 余额充值", cfg.SiteName),
			"money":        moneyStr,
		}
		sign := computeEpaySign(params, cfg.EpayKey)
		vals := url.Values{}
		for k, v := range params {
			vals.Set(k, v)
		}
		vals.Set("sign", sign)
		vals.Set("sign_type", "MD5")
		payURL = strings.TrimRight(strings.TrimSpace(cfg.EpayURL), "/") + "/submit.php?" + vals.Encode()
	}

	order := model.BillingOrder{
		OrderNo:     orderNo,
		UserID:      user.ID,
		UserEmail:   user.Email,
		Type:        "recharge",
		PlanName:    "账户余额在线充值",
		AmountCents: req.AmountCents,
		Status:      "pending",
		Gateway:     gateway,
		PayURL:      payURL,
	}
	if err := s.db.Create(&order).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建充值订单失败"})
		return
	}
	c.JSON(http.StatusCreated, order)
}

func (s *Server) handleEpayNotify(c *gin.Context) {
	clientIP := c.ClientIP()
	if payNotifyGuard.isBlocked(clientIP) {
		c.String(http.StatusTooManyRequests, "fail")
		return
	}

	if err := c.Request.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.String(http.StatusRequestEntityTooLarge, "fail")
			return
		}
		c.String(http.StatusBadRequest, "fail")
		return
	}
	params := make(map[string]string)
	for k, vals := range c.Request.URL.Query() {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}
	for k, vals := range c.Request.PostForm {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}

	cfg := s.getSystemConfig()
	if !cfg.PaymentEnabled || strings.TrimSpace(cfg.EpayKey) == "" {
		c.String(http.StatusBadRequest, "fail")
		return
	}

	givenSign := strings.ToLower(strings.TrimSpace(params["sign"]))
	expectedSign := computeEpaySign(params, cfg.EpayKey)
	if len(givenSign) == 0 || subtle.ConstantTimeCompare([]byte(givenSign), []byte(expectedSign)) != 1 {
		if payNotifyGuard.recordFailure(clientIP) {
			c.String(http.StatusTooManyRequests, "fail")
			return
		}
		c.String(http.StatusForbidden, "fail")
		return
	}
	payNotifyGuard.recordSuccess(clientIP)

	if strings.TrimSpace(cfg.EpayPID) != "" && strings.TrimSpace(params["pid"]) != strings.TrimSpace(cfg.EpayPID) {
		c.String(http.StatusBadRequest, "fail")
		return
	}

	if params["trade_status"] != "TRADE_SUCCESS" {
		c.String(http.StatusOK, "ignore")
		return
	}

	outTradeNo := strings.TrimSpace(params["out_trade_no"])
	tradeNo := strings.TrimSpace(params["trade_no"])
	if outTradeNo == "" || !isValidTradeRef(tradeNo) {
		c.String(http.StatusBadRequest, "fail")
		return
	}

	now := time.Now()
	var creditedOrder *model.BillingOrder
	var expiredOrderID uint64

	payNotifyMu.Lock()
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var order model.BillingOrder
		if err := tx.Where("order_no = ? AND type = ?", outTradeNo, "recharge").First(&order).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		if order.Gateway != "epay" {
			return fmt.Errorf("gateway_mismatch")
		}
		if order.Status == "paid" {
			if order.TradeNo != "" && order.TradeNo != tradeNo {
				return fmt.Errorf("trade_no_conflict")
			}
			return nil
		}
		if order.Status != "pending" {
			return fmt.Errorf("order_closed")
		}
		if !order.CreatedAt.IsZero() && now.Sub(order.CreatedAt) > service.OrderExpireTimeout {
			expiredOrderID = order.ID
			return fmt.Errorf("order_expired")
		}
		var dupCount int64
		tx.Model(&model.BillingOrder{}).
			Where("gateway = ? AND trade_no = ? AND status = ? AND id <> ?", "epay", tradeNo, "paid", order.ID).
			Count(&dupCount)
		if dupCount > 0 {
			return fmt.Errorf("duplicate_trade_no")
		}
		moneyStr := strings.TrimSpace(params["money"])
		moneyFloat, perr := strconv.ParseFloat(moneyStr, 64)
		if moneyStr == "" || perr != nil || math.IsNaN(moneyFloat) || math.IsInf(moneyFloat, 0) || int64(math.Round(moneyFloat*100)) != order.AmountCents {
			return fmt.Errorf("amount_mismatch")
		}
		res := tx.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", order.ID, "pending").
			Updates(map[string]any{
				"status":   "paid",
				"trade_no": tradeNo,
				"paid_at":  &now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", order.UserID).
			Update("balance_cents", gorm.Expr("balance_cents + ?", order.AmountCents)).Error; err != nil {
			return err
		}
		if err := settleAffiliateOnRechargeTx(tx, cfg, &order); err != nil {
			return err
		}
		orderCopy := order
		creditedOrder = &orderCopy
		return nil
	})
	payNotifyMu.Unlock()
	if expiredOrderID > 0 {
		s.db.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", expiredOrderID, "pending").
			Update("status", "cancelled")
	}
	if err != nil {
		c.String(http.StatusBadRequest, "fail")
		return
	}
	if creditedOrder != nil {
		s.recordAuditForUser(c, creditedOrder.UserID, creditedOrder.UserEmail, "payment.epay_notify", creditedOrder.OrderNo,
			fmt.Sprintf("易支付回调入账 %.2f 元 (流水号: %s)", float64(creditedOrder.AmountCents)/100.0, tradeNo))
	}
	c.String(http.StatusOK, "success")
}

// handleUSDTNotify processes HMAC-SHA256 authenticated USDT payment gateway webhooks.
// Expected headers:
//   - X-USDT-Timestamp (or X-Webhook-Timestamp): Unix seconds within ±300s
//   - X-USDT-Signature (or X-Webhook-Signature): hex HMAC-SHA256(usdt_webhook_secret, "<timestamp>.<raw_body>")
func (s *Server) handleUSDTNotify(c *gin.Context) {
	clientIP := c.ClientIP()
	if payNotifyGuard.isBlocked(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "回调鉴权失败过于频繁，请稍后再试"})
		return
	}

	cfg := s.getSystemConfig()
	secret := strings.TrimSpace(cfg.USDTWebhookSecret)
	if !cfg.PaymentEnabled || secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "USDT 自动回调未启用或未配置签名密钥"})
		return
	}

	if c.Request.Body == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "空的回调请求体"})
		return
	}
	rawBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体超过大小限制"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "读取回调请求体失败"})
		return
	}
	if len(rawBody) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "空的回调请求体"})
		return
	}

	var payload struct {
		OrderNo     string  `json:"order_no"`
		OutTradeNo  string  `json:"out_trade_no"`
		TradeNo     string  `json:"trade_no"`
		TxHash      string  `json:"tx_hash"`
		AmountCents int64   `json:"amount_cents"`
		Amount      float64 `json:"amount"`
		Status      string  `json:"status"`
		Timestamp   int64   `json:"timestamp"`
	}
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 JSON 回调数据"})
		return
	}

	tsHeader := strings.TrimSpace(c.GetHeader("X-USDT-Timestamp"))
	if tsHeader == "" {
		tsHeader = strings.TrimSpace(c.GetHeader("X-Webhook-Timestamp"))
	}
	var ts int64
	if tsHeader != "" {
		parsedTS, perr := strconv.ParseInt(tsHeader, 10, 64)
		if perr != nil {
			if payNotifyGuard.recordFailure(clientIP) {
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
				return
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "无效的回调时间戳"})
			return
		}
		ts = parsedTS
	} else {
		ts = payload.Timestamp
	}

	now := time.Now()
	diff := now.Unix() - ts
	if ts <= 0 || diff < -300 || diff > 300 {
		if payNotifyGuard.recordFailure(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "回调时间戳已过期或偏差过大 (±300s)"})
		return
	}

	sigHeader := strings.TrimSpace(c.GetHeader("X-USDT-Signature"))
	if sigHeader == "" {
		sigHeader = strings.TrimSpace(c.GetHeader("X-Webhook-Signature"))
	}
	sigHeader = strings.TrimPrefix(strings.ToLower(sigHeader), "sha256=")
	expectedSig := ComputeUSDTWebhookSign(ts, rawBody, secret)
	if len(sigHeader) != 64 || subtle.ConstantTimeCompare([]byte(sigHeader), []byte(expectedSig)) != 1 {
		if payNotifyGuard.recordFailure(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "USDT Webhook 签名校验失败"})
		return
	}
	payNotifyGuard.recordSuccess(clientIP)

	st := strings.ToLower(strings.TrimSpace(payload.Status))
	if st != "" && st != "paid" && st != "success" && st != "confirmed" && st != "completed" && st != "trade_success" {
		c.JSON(http.StatusOK, gin.H{"status": "ignored"})
		return
	}

	orderNo := strings.TrimSpace(payload.OrderNo)
	if orderNo == "" {
		orderNo = strings.TrimSpace(payload.OutTradeNo)
	}
	txHash := strings.TrimSpace(payload.TxHash)
	if txHash == "" {
		txHash = strings.TrimSpace(payload.TradeNo)
	}
	if orderNo == "" || !isValidTradeRef(txHash) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少订单号或有效的链上交易哈希 (tx_hash)"})
		return
	}

	paidCents := payload.AmountCents
	if paidCents <= 0 && payload.Amount > 0 && !math.IsNaN(payload.Amount) && !math.IsInf(payload.Amount, 0) {
		paidCents = int64(math.Round(payload.Amount * 100))
	}
	if paidCents <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的回调入账金额"})
		return
	}

	var creditedOrder *model.BillingOrder
	var idempotentHit bool
	var expiredOrderID uint64

	payNotifyMu.Lock()
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		var order model.BillingOrder
		if err := tx.Where("order_no = ? AND type = ?", orderNo, "recharge").First(&order).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		if order.Gateway != "usdt" {
			return fmt.Errorf("gateway_mismatch")
		}
		if order.Status == "paid" {
			if order.TradeNo != "" && order.TradeNo != txHash {
				return fmt.Errorf("tx_hash_conflict")
			}
			idempotentHit = true
			return nil
		}
		if order.Status != "pending" {
			return fmt.Errorf("order_closed")
		}
		if !order.CreatedAt.IsZero() && now.Sub(order.CreatedAt) > service.OrderExpireTimeout {
			expiredOrderID = order.ID
			return fmt.Errorf("order_expired")
		}
		if paidCents != order.AmountCents {
			return fmt.Errorf("amount_mismatch")
		}

		var dupCount int64
		tx.Model(&model.BillingOrder{}).
			Where("gateway = ? AND trade_no = ? AND status = ? AND id <> ?", "usdt", txHash, "paid", order.ID).
			Count(&dupCount)
		if dupCount > 0 {
			return fmt.Errorf("duplicate_tx_hash")
		}

		res := tx.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", order.ID, "pending").
			Updates(map[string]any{
				"status":   "paid",
				"trade_no": txHash,
				"paid_at":  &now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			idempotentHit = true
			return nil
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", order.UserID).
			Update("balance_cents", gorm.Expr("balance_cents + ?", order.AmountCents)).Error; err != nil {
			return err
		}
		if err := settleAffiliateOnRechargeTx(tx, cfg, &order); err != nil {
			return err
		}
		orderCopy := order
		creditedOrder = &orderCopy
		return nil
	})
	payNotifyMu.Unlock()
	if expiredOrderID > 0 {
		s.db.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", expiredOrderID, "pending").
			Update("status", "cancelled")
	}
	if txErr != nil {
		switch txErr.Error() {
		case "not_found":
			c.JSON(http.StatusNotFound, gin.H{"error": "充值订单不存在"})
		case "duplicate_tx_hash", "tx_hash_conflict":
			c.JSON(http.StatusConflict, gin.H{"error": "链上交易哈希已被使用或与原记录冲突"})
		case "order_expired", "order_closed":
			c.JSON(http.StatusBadRequest, gin.H{"error": "订单已超时关闭或状态不可入账"})
		case "amount_mismatch":
			c.JSON(http.StatusBadRequest, gin.H{"error": "回调金额与订单金额不一致"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "USDT 回调入账失败"})
		}
		return
	}
	if creditedOrder != nil {
		s.recordAuditForUser(c, creditedOrder.UserID, creditedOrder.UserEmail, "payment.usdt_notify", creditedOrder.OrderNo,
			fmt.Sprintf("USDT Webhook 验签入账 %.2f 元 (TxHash: %s)", float64(creditedOrder.AmountCents)/100.0, txHash))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "idempotent": idempotentHit})
}

func (s *Server) handleAdminConfirmOrder(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid order id"})
		return
	}
	now := time.Now()
	var confirmedOrder model.BillingOrder
	var expiredOrderID uint64
	payNotifyMu.Lock()
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		var order model.BillingOrder
		if err := tx.First(&order, id).Error; err != nil {
			return fmt.Errorf("not_found")
		}
		if order.Type != "recharge" {
			return fmt.Errorf("invalid_type")
		}
		if order.Status == "paid" {
			return fmt.Errorf("already_paid")
		}
		if order.Status != "pending" {
			return fmt.Errorf("order_closed")
		}
		if !order.CreatedAt.IsZero() && now.Sub(order.CreatedAt) > service.OrderExpireTimeout {
			expiredOrderID = order.ID
			return fmt.Errorf("order_expired")
		}
		res := tx.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", order.ID, "pending").
			Updates(map[string]any{
				"status":   "paid",
				"trade_no": fmt.Sprintf("ADMIN-MANUAL-%d-%s", s.currentUserID(c), order.OrderNo),
				"paid_at":  &now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("already_paid")
		}
		if err := tx.Model(&model.User{}).
			Where("id = ?", order.UserID).
			Update("balance_cents", gorm.Expr("balance_cents + ?", order.AmountCents)).Error; err != nil {
			return err
		}
		if err := tx.First(&confirmedOrder, order.ID).Error; err != nil {
			return err
		}
		return settleAffiliateOnRechargeTx(tx, s.getSystemConfig(), &confirmedOrder)
	})
	if expiredOrderID > 0 {
		s.db.Model(&model.BillingOrder{}).
			Where("id = ? AND status = ?", expiredOrderID, "pending").
			Update("status", "cancelled")
	}
	payNotifyMu.Unlock()
	if txErr != nil {
		switch txErr.Error() {
		case "not_found":
			c.JSON(http.StatusNotFound, gin.H{"error": "订单不存在"})
		case "already_paid":
			c.JSON(http.StatusConflict, gin.H{"error": "该订单已入账，请勿重复确认"})
		case "order_expired", "order_closed":
			c.JSON(http.StatusBadRequest, gin.H{"error": "该订单已超时关闭，无法继续入账"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "确认订单入账失败"})
		}
		return
	}
	s.recordAudit(c, "admin.confirm_order", confirmedOrder.OrderNo,
		fmt.Sprintf("人工确认充值订单入账 %.2f 元 (用户: %s)", float64(confirmedOrder.AmountCents)/100.0, confirmedOrder.UserEmail))
	c.JSON(http.StatusOK, gin.H{"message": "订单已确认入账，用户余额已自动增加", "order": confirmedOrder})
}

// --- Admin Handlers ---

func normalizeNodeOutboundIPs(defaultIP, allowedRaw string) (string, string, error) {
	allowPriv := os.Getenv("NEXUS_ALLOW_PRIVATE_TARGETS") == "true"
	cleanDefault := strings.TrimSpace(defaultIP)
	if cleanDefault != "" {
		parsed, err := security.ValidateOutboundIP(cleanDefault, allowPriv)
		if err != nil || parsed == nil {
			return "", "", fmt.Errorf("默认出站源 IP 无效: %v", err)
		}
		cleanDefault = parsed.String()
	}
	var allowed []string
	seen := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(allowedRaw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		v := strings.TrimSpace(token)
		if v == "" {
			continue
		}
		parsed, err := security.ValidateOutboundIP(v, allowPriv)
		if err != nil || parsed == nil {
			return "", "", fmt.Errorf("授权出站 IP %q 无效: %v", v, err)
		}
		canon := parsed.String()
		if _, dup := seen[canon]; !dup {
			seen[canon] = struct{}{}
			allowed = append(allowed, canon)
		}
	}
	if len(allowed) > 32 {
		return "", "", fmt.Errorf("单节点最多配置 32 个授权出站源 IP")
	}
	return cleanDefault, strings.Join(allowed, ","), nil
}

func (s *Server) handleAdminCreateNode(c *gin.Context) {
	var node model.Node
	if err := c.ShouldBindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	node.Name = strings.TrimSpace(node.Name)
	if node.Name == "" || utf8.RuneCountInString(node.Name) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "节点名称不能为空且不超过 64 个字符"})
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
	outIP, allowedIPs, oErr := normalizeNodeOutboundIPs(node.OutboundIP, node.AllowedOutboundIPs)
	if oErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oErr.Error()})
		return
	}
	node.OutboundIP = outIP
	node.AllowedOutboundIPs = allowedIPs
	if len(node.SecretToken) < 32 {
		node.SecretToken = utils.GenerateRandomToken(32)
	}
	if node.PortRange == "" {
		node.PortRange = "10000-50000"
	} else {
		nmin, nmax, perr := utils.ParsePortRange(node.PortRange)
		if perr != nil || nmin < security.DefaultPolicy.MinListenPort {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("端口范围格式应为 起始-结束，且起始端口不小于 %d", security.DefaultPolicy.MinListenPort)})
			return
		}
		node.PortRange = fmt.Sprintf("%d-%d", nmin, nmax)
	}
	if math.IsNaN(node.TrafficRate) || math.IsInf(node.TrafficRate, 0) || node.TrafficRate > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "节点流量倍率需在 0.01 - 1000 之间"})
		return
	}
	if node.TrafficRate <= 0 {
		node.TrafficRate = 1.0
	}
	if node.QuotaBytes <= 0 {
		node.QuotaBytes = 10 * 1024 * 1024 * 1024 * 1024 // 默认 10TB
	}
	if node.ResetDay < 0 || node.ResetDay > 28 {
		node.ResetDay = 0
	}
	if node.DefaultEngine == "" {
		node.DefaultEngine = protocol.EngineNative
	}
	if !validEngine(node.DefaultEngine) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的默认转发引擎"})
		return
	}
	node.Status = "offline"
	node.ID = 0
	node.UsedBytes = 0
	if err := s.db.Create(&node).Error; err != nil {
		log.Printf("[API] create node failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建节点失败，请检查参数"})
		return
	}
	s.recordAudit(c, "admin.create_node", node.Name, fmt.Sprintf("创建节点 #%d (%s)", node.ID, node.ConnectIP))
	c.JSON(http.StatusCreated, node)
}

// ruleCounterCols are incremented concurrently by agent traffic reports (gorm.Expr); full-row saves of a rule must
// never write back a stale snapshot of them.
var ruleCounterCols = []string{"upload_bytes", "down_bytes", "billed_bytes", "daily_used_bytes", "daily_reset_date"}

func (s *Server) handleAdminUpdateNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	var req struct {
		Name               string              `json:"name"`
		Role               string              `json:"role"`
		ConnectIP          string              `json:"connect_ip"`
		ServerIP           string              `json:"server_ip"`
		PublicHost         string              `json:"public_host"`
		InternalHost       *string             `json:"internal_host"`
		OutboundIP         *string             `json:"outbound_ip"`
		AllowedOutboundIPs *string             `json:"allowed_outbound_ips"`
		Status             *string             `json:"status"`
		PortRange          string              `json:"port_range"`
		TrafficRate        float64             `json:"traffic_rate"`
		QuotaBytes         *int64              `json:"quota_bytes"`
		UsedBytes          *int64              `json:"used_bytes"`
		ResetDay           *int                `json:"reset_day"`
		DefaultEngine      protocol.EngineType `json:"default_engine"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	oldTunnelHost := node.PreferredTunnelHost()
	oldOutboundIP := node.OutboundIP
	oldAllowedOutboundIPs := node.AllowedOutboundIPs
	oldPortRange := node.PortRange
	oldStatus := node.Status
	wasOverQuota := node.QuotaBytes > 0 && node.UsedBytes >= node.QuotaBytes
	portRangeChanged := false
	if strings.TrimSpace(req.Name) != "" {
		if utf8.RuneCountInString(strings.TrimSpace(req.Name)) > 64 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "节点名称不能超过 64 个字符"})
			return
		}
		node.Name = strings.TrimSpace(req.Name)
	}
	if req.Role != "" {
		node.Role = req.Role
	}
	if req.ConnectIP != "" {
		node.ConnectIP = strings.TrimSpace(req.ConnectIP)
		node.PublicHost = node.ConnectIP
	} else if req.PublicHost != "" {
		node.ConnectIP = strings.TrimSpace(req.PublicHost)
		node.PublicHost = node.ConnectIP
	}
	if req.ServerIP != "" {
		node.ServerIP = strings.TrimSpace(req.ServerIP)
	} else if node.ServerIP == "" {
		node.ServerIP = node.ConnectIP
	}
	if req.InternalHost != nil {
		node.InternalHost = strings.TrimSpace(*req.InternalHost)
	}
	newOutIP := node.OutboundIP
	if req.OutboundIP != nil {
		newOutIP = *req.OutboundIP
	}
	newAllowedIPs := node.AllowedOutboundIPs
	if req.AllowedOutboundIPs != nil {
		newAllowedIPs = *req.AllowedOutboundIPs
	}
	cleanOutIP, cleanAllowedIPs, oErr := normalizeNodeOutboundIPs(newOutIP, newAllowedIPs)
	if oErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oErr.Error()})
		return
	}
	node.OutboundIP = cleanOutIP
	node.AllowedOutboundIPs = cleanAllowedIPs

	statusExplicit := false
	if req.Status != nil {
		st := strings.ToLower(strings.TrimSpace(*req.Status))
		switch st {
		case "maintenance":
			node.Status = "maintenance"
			statusExplicit = true
		case "online", "offline":
			node.Status = "offline"
			if s.hub != nil {
				for _, oid := range s.hub.OnlineNodeIDs() {
					if oid == node.ID {
						node.Status = "online"
						break
					}
				}
			}
			statusExplicit = true
		}
	}

	if req.PortRange != "" && req.PortRange != node.PortRange {
		nmin, nmax, perr := utils.ParsePortRange(req.PortRange)
		if perr != nil || nmin < security.DefaultPolicy.MinListenPort {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("端口范围格式应为 起始-结束，且起始端口不小于 %d", security.DefaultPolicy.MinListenPort)})
			return
		}
		var ranged []model.TunnelLine
		s.db.Where("ingress_node_id = ? AND port_range <> ''", node.ID).Find(&ranged)
		for _, l := range ranged {
			lmin, lmax, lerr := utils.ParsePortRange(l.PortRange)
			if lerr == nil && (lmin < nmin || lmax > nmax) {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("隧道「%s」的端口范围 %s 不在新的节点端口范围内，请先调整该隧道", l.Name, l.PortRange)})
				return
			}
		}
		node.PortRange = fmt.Sprintf("%d-%d", nmin, nmax)
		portRangeChanged = node.PortRange != oldPortRange
	}
	if math.IsNaN(req.TrafficRate) || math.IsInf(req.TrafficRate, 0) || req.TrafficRate < 0 || req.TrafficRate > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "节点流量倍率需在 0.01 - 1000 之间"})
		return
	}
	if req.TrafficRate > 0 {
		node.TrafficRate = req.TrafficRate
	}
	if req.QuotaBytes != nil && *req.QuotaBytes >= 0 {
		node.QuotaBytes = *req.QuotaBytes
	}
	if req.ResetDay != nil {
		if *req.ResetDay >= 0 && *req.ResetDay <= 28 {
			node.ResetDay = *req.ResetDay
		}
	}
	if req.DefaultEngine != "" {
		if !validEngine(req.DefaultEngine) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的默认转发引擎"})
			return
		}
		node.DefaultEngine = req.DefaultEngine
	}
	omitCols := []string{"used_bytes", "tunnel_cert_pem", "supported_engines", "last_seen_at"}
	if !statusExplicit {
		omitCols = append(omitCols, "status")
	}
	if err := s.db.Omit(omitCols...).Save(&node).Error; err != nil {
		log.Printf("[API] update node %d failed: %v", node.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存节点失败，请稍后再试"})
		return
	}
	if statusExplicit && node.Status != oldStatus {
		s.orch.EvaluateDNSFailoverGroupsAsync(time.Now())
	}
	if portRangeChanged {
		s.reallocNodeRulesOutOfRange(node.ID)
	}
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
		s.orch.ResumeNodeQuotaRules(node.ID, time.Now(), wasOverQuota)
	}

	// Re-dispatch rules if tunnel host, default outbound IP, or allowed outbound IP whitelist changed
	if node.PreferredTunnelHost() != oldTunnelHost || node.OutboundIP != oldOutboundIP || node.AllowedOutboundIPs != oldAllowedOutboundIPs {
		var allLines []model.TunnelLine
		s.db.Find(&allLines)
		var affectedLineIDs []uint64
		for i := range allLines {
			if allLines[i].IngressNodeID == node.ID || allLines[i].UsesNodeInTunnelLeg(node.ID) {
				affectedLineIDs = append(affectedLineIDs, allLines[i].ID)
			}
		}
		var rules []model.ForwardRule
		if len(affectedLineIDs) > 0 {
			s.db.Where("(ingress_node_id = ? OR tunnel_line_id IN ?) AND enabled = ?", node.ID, affectedLineIDs, true).Find(&rules)
		} else {
			s.db.Where("ingress_node_id = ? AND enabled = ?", node.ID, true).Find(&rules)
		}
		for i := range rules {
			s.orch.DispatchRule(&rules[i])
		}
	}
	s.recordAudit(c, "admin.update_node", node.Name, fmt.Sprintf("更新节点 #%d 配置", node.ID))
	node.SecretToken = ""
	c.JSON(http.StatusOK, node)
}

func (s *Server) handleAdminResetNodeTraffic(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
		return
	}
	resumed := s.orch.ResetNodeTraffic(node.ID, time.Now())
	_ = s.db.First(&node, node.ID).Error
	node.SecretToken = ""
	s.recordAudit(c, "admin.reset_node_traffic", node.Name, fmt.Sprintf("重置节点 #%d 流量并恢复 %d 条规则", node.ID, resumed))
	c.JSON(http.StatusOK, gin.H{"node": node, "resumed_rules": resumed})
}

func (s *Server) handleAdminDeleteNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var allLines []model.TunnelLine
	s.db.Find(&allLines)
	for i := range allLines {
		if allLines[i].IngressNodeID == id || allLines[i].EgressNodeID == id || allLines[i].UsesNodeInTunnelLeg(id) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("该节点仍被隧道「%s」引用，请先删除或修改关联隧道", allLines[i].Name)})
			return
		}
	}
	var foGroups []model.IngressFailoverGroup
	s.db.Find(&foGroups)
	for i := range foGroups {
		if foGroups[i].PrimaryNodeID == id {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("该节点仍被 DNS 容灾组「%s」设为主入口，请先调整容灾组", foGroups[i].Name)})
			return
		}
		bIDs, _ := foGroups[i].ParseBackupNodeIDs()
		for _, bid := range bIDs {
			if bid == id {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("该节点仍被 DNS 容灾组「%s」设为备用入口，请先调整容灾组", foGroups[i].Name)})
				return
			}
		}
	}
	s.db.Delete(&model.Node{}, id)
	s.recordAudit(c, "admin.delete_node", strconv.FormatUint(id, 10), fmt.Sprintf("删除节点 #%d", id))
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) reallocIfOutOfRange(rule *model.ForwardRule, lineRange string) (bool, error) {
	if rule.ListenPort <= 0 || s.orch.PortInRange(rule.IngressNodeID, rule.ListenPort, lineRange) {
		return false, nil
	}
	p, err := s.orch.AllocatePortForNode(rule.IngressNodeID, 0, lineRange)
	if err != nil {
		return false, err
	}
	res := s.db.Model(&model.ForwardRule{}).Where("id = ? AND listen_port = ?", rule.ID, rule.ListenPort).Update("listen_port", p)
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		return false, fmt.Errorf("rule %d changed concurrently", rule.ID)
	}
	rule.ListenPort = p
	return true, nil
}

func (s *Server) ruleHasValidPort(rule *model.ForwardRule) bool {
	lineRange := ""
	if rule.TunnelLineID > 0 {
		var l model.TunnelLine
		if s.db.Select("id", "port_range").First(&l, rule.TunnelLineID).Error == nil {
			lineRange = l.PortRange
		}
	}
	return rule.ListenPort > 0 && s.orch.PortInRange(rule.IngressNodeID, rule.ListenPort, lineRange)
}

func (s *Server) resumeBlockedByPort(rule *model.ForwardRule) bool {
	if s.ruleHasValidPort(rule) {
		return false
	}
	s.db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
		"enabled": false, "status": "error", "last_error": "规则端口不在当前允许的端口范围内，请编辑规则重新分配端口后再启用",
	})
	return true
}

func (s *Server) markRuleNoPort(ruleID uint64, wasEnabled bool, msg string) {
	updates := map[string]any{"last_error": msg}
	if wasEnabled {
		updates["enabled"] = false
		updates["status"] = "error"
	}
	s.db.Model(&model.ForwardRule{}).Where("id = ?", ruleID).Updates(updates)
}

func (s *Server) reallocNodeRulesOutOfRange(nodeID uint64) {
	var moved, failed []uint64
	_ = s.orch.WithAllocLock(func() error {
		var node model.Node
		if s.db.First(&node, nodeID).Error != nil {
			return nil
		}
		occupied := s.orch.OccupiedPorts(nodeID)
		type window struct {
			min, max int
			ok       bool
		}
		windows := map[uint64]window{}
		windowFor := func(lineID uint64) window {
			if w, ok := windows[lineID]; ok {
				return w
			}
			lr := ""
			if lineID > 0 {
				var l model.TunnelLine
				if s.db.Select("id", "port_range").First(&l, lineID).Error == nil {
					lr = l.PortRange
				}
			}
			mn, mx, err := s.orch.EffectivePortRange(&node, lr)
			w := window{mn, mx, err == nil}
			windows[lineID] = w
			return w
		}
		fail := func(id uint64, enabled bool, msg string, err error) {
			log.Printf("[API] node %d: rule %d out of range and re-allocation failed: %v", nodeID, id, err)
			s.markRuleNoPort(id, enabled, msg)
			failed = append(failed, id)
		}

		// 1. Listen ports (keeping shared MatchDomains groups together when on the same line)
		type sharedPortKey struct {
			lineID  uint64
			oldPort int
		}
		sharedMoved := make(map[sharedPortKey]int)
		var rules []model.ForwardRule
		s.db.Select("id", "enabled", "tunnel_line_id", "listen_port", "match_domains").
			Where("ingress_node_id = ? AND listen_port > 0", nodeID).Find(&rules)
		for _, r := range rules {
			w := windowFor(r.TunnelLineID)
			if w.ok && r.ListenPort >= w.min && r.ListenPort <= w.max {
				continue
			}
			if !w.ok {
				fail(r.ID, r.Enabled, "端口范围调整后无可用端口，请重新编辑该规则", fmt.Errorf("invalid port range"))
				continue
			}
			var p int
			var err error
			sk := sharedPortKey{lineID: r.TunnelLineID, oldPort: r.ListenPort}
			if strings.TrimSpace(r.MatchDomains) != "" {
				if mapped, ok := sharedMoved[sk]; ok {
					p = mapped
				}
			}
			if p == 0 {
				p, err = service.PickFreePort(w.min, w.max, occupied)
				if err == nil && strings.TrimSpace(r.MatchDomains) != "" {
					sharedMoved[sk] = p
				}
			}
			if err == nil {
				res := s.db.Model(&model.ForwardRule{}).Where("id = ? AND listen_port = ?", r.ID, r.ListenPort).Update("listen_port", p)
				if err = res.Error; err == nil && res.RowsAffected == 0 {
					err = fmt.Errorf("rule changed concurrently")
				}
			}
			if err != nil {
				fail(r.ID, r.Enabled, "端口范围调整后无可用端口，请重新编辑该规则", err)
				continue
			}
			log.Printf("[API] node %d: rule %d listen port %d -> %d after port range change", nodeID, r.ID, r.ListenPort, p)
			moved = append(moved, r.ID)
		}

		// 2. Primary Relay ports & Hop/Egress JSON port allocations on nodeID
		nw := windowFor(0)
		var tunnelRules []model.ForwardRule
		s.db.Select("id", "enabled", "relay_port", "relay_node_id", "hop_ports_json", "egress_ports_json").
			Where("(relay_node_id = ? AND relay_port > 0) OR hop_ports_json <> '' OR egress_ports_json <> ''", nodeID).
			Find(&tunnelRules)
		for _, r := range tunnelRules {
			updates := make(map[string]any)
			changed := false
			allocErr := error(nil)

			hops := r.HopPortAllocs()
			hopsMod := false
			for i := range hops {
				if hops[i].NodeID != nodeID || hops[i].Port <= 0 {
					continue
				}
				if nw.ok && hops[i].Port >= nw.min && hops[i].Port <= nw.max {
					continue
				}
				if !nw.ok {
					allocErr = fmt.Errorf("invalid port range")
					break
				}
				np, pErr := service.PickFreePort(nw.min, nw.max, occupied)
				if pErr != nil {
					allocErr = pErr
					break
				}
				hops[i].Port = np
				hopsMod = true
			}
			if allocErr == nil && hopsMod {
				hb, _ := json.Marshal(hops)
				updates["hop_ports_json"] = string(hb)
				changed = true
			}

			egs := r.EgressPortAllocs()
			egsMod := false
			newRelayPort := r.RelayPort
			for i := range egs {
				if allocErr != nil {
					break
				}
				if egs[i].NodeID != nodeID || egs[i].Port <= 0 {
					continue
				}
				if nw.ok && egs[i].Port >= nw.min && egs[i].Port <= nw.max {
					continue
				}
				if !nw.ok {
					allocErr = fmt.Errorf("invalid port range")
					break
				}
				np, pErr := service.PickFreePort(nw.min, nw.max, occupied)
				if pErr != nil {
					allocErr = pErr
					break
				}
				egs[i].Port = np
				if i == 0 && r.RelayNodeID == nodeID {
					newRelayPort = np
				}
				egsMod = true
			}
			if allocErr == nil && egsMod {
				eb, _ := json.Marshal(egs)
				updates["egress_ports_json"] = string(eb)
				if r.RelayNodeID == nodeID && newRelayPort != r.RelayPort {
					updates["relay_port"] = newRelayPort
				}
				changed = true
			} else if allocErr == nil && r.RelayNodeID == nodeID && r.RelayPort > 0 && !(nw.ok && r.RelayPort >= nw.min && r.RelayPort <= nw.max) {
				if !nw.ok {
					allocErr = fmt.Errorf("invalid port range")
				} else if np, pErr := service.PickFreePort(nw.min, nw.max, occupied); pErr != nil {
					allocErr = pErr
				} else {
					updates["relay_port"] = np
					changed = true
				}
			}

			if allocErr != nil {
				clearMap := map[string]any{"hop_ports_json": "", "egress_ports_json": ""}
				if r.RelayNodeID == nodeID {
					clearMap["relay_port"] = 0
					clearMap["relay_node_id"] = 0
				}
				s.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(clearMap)
				fail(r.ID, r.Enabled, "隧道节点端口范围调整后无可用中继端口，请调整范围后重新编辑该规则", allocErr)
				continue
			}
			if changed {
				if err := s.db.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Updates(updates).Error; err == nil {
					moved = append(moved, r.ID)
				}
			}
		}
		return nil
	})
	seen := map[uint64]bool{}
	for _, id := range append(moved, failed...) {
		if seen[id] {
			continue
		}
		seen[id] = true
		var fresh model.ForwardRule
		if s.db.First(&fresh, id).Error == nil {
			s.orch.DispatchRule(&fresh)
		}
	}
}

// validateLinePortRange normalizes the tunnel's optional port range and checks it lies inside the ingress node's range.
func (s *Server) validateLinePortRange(line *model.TunnelLine) error {
	line.PortRange = strings.ReplaceAll(strings.TrimSpace(line.PortRange), " ", "")
	if line.PortRange == "" {
		return nil
	}
	minP, maxP, err := utils.ParsePortRange(line.PortRange)
	if err != nil || minP < security.DefaultPolicy.MinListenPort {
		return fmt.Errorf("隧道端口范围格式应为 起始-结束（如 20000-20999），且起始端口不小于 %d", security.DefaultPolicy.MinListenPort)
	}
	line.PortRange = fmt.Sprintf("%d-%d", minP, maxP)
	var node model.Node
	if err := s.db.First(&node, line.IngressNodeID).Error; err != nil {
		return fmt.Errorf("入口节点不存在")
	}
	nmin, nmax, nerr := utils.ParsePortRange(node.PortRange)
	if nerr != nil {
		nmin, nmax = 10000, 50000
	}
	if minP < nmin || maxP > nmax {
		return fmt.Errorf("隧道端口范围 %s 必须位于入口节点「%s」的端口范围 %d-%d 之内", line.PortRange, node.Name, nmin, nmax)
	}
	return nil
}

// validateAndNormalizeLine validates enum fields, multi-hop chains, multipath egress pools, mux/bonding options,
// and ensures all referenced nodes exist and form a strictly loop-free DAG.
func (s *Server) validateAndNormalizeLine(line *model.TunnelLine) error {
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
	var inNode model.Node
	if err := s.db.Select("id").First(&inNode, line.IngressNodeID).Error; err != nil {
		return fmt.Errorf("所选入口节点 #%d 不存在", line.IngressNodeID)
	}

	if line.LoadBalance == "" {
		line.LoadBalance = "round_robin"
	}
	switch line.LoadBalance {
	case "round_robin", "weighted", "least_rtt", "failover", "random":
	default:
		return fmt.Errorf("不支持的多出口调度策略 %q", line.LoadBalance)
	}

	if line.ProxyProtocol < 0 || line.ProxyProtocol > 2 {
		return fmt.Errorf("默认 PROXY Protocol 版本仅支持 0 (关闭)、1 (v1)、2 (v2)")
	}
	if math.IsNaN(line.OffPeakMultiplier) || math.IsInf(line.OffPeakMultiplier, 0) || line.OffPeakMultiplier < 0 || line.OffPeakMultiplier > 1000 {
		return fmt.Errorf("隧道专属闲时倍率需在 0 - 1000 之间")
	}

	if line.Type == "direct" {
		line.HopNodeIDs = ""
		line.EgressNodeID = 0
		line.EgressNodeIDs = ""
		line.EnableMux = false
		line.EnableBonding = false
		line.BondLinks = 4
		line.Transport = "raw"
	} else {
		// Encrypt tunnel: parse & normalize HopNodeIDs and EgressNodeIDs
		hops, hErr := model.ParseHopNodeIDs(line.HopNodeIDs)
		if hErr != nil {
			return hErr
		}
		hopStrs := make([]string, 0, len(hops))
		for _, hid := range hops {
			hopStrs = append(hopStrs, strconv.FormatUint(hid, 10))
		}
		line.HopNodeIDs = strings.Join(hopStrs, ",")

		var egMembers []model.EgressMember
		if strings.TrimSpace(line.EgressNodeIDs) != "" {
			parsedEg, eErr := model.ParseEgressNodeIDs(line.EgressNodeIDs)
			if eErr != nil {
				return eErr
			}
			egMembers = parsedEg
		} else if line.EgressNodeID > 0 {
			egMembers = []model.EgressMember{{NodeID: line.EgressNodeID, Weight: 100}}
		}
		if len(egMembers) == 0 {
			return fmt.Errorf("加密隧道必须至少选择一个出口节点")
		}
		line.EgressNodeID = egMembers[0].NodeID
		if len(egMembers) > 1 || egMembers[0].Weight != 100 || egMembers[0].Backup {
			line.EgressNodeIDs = model.FormatEgressMembers(egMembers)
		} else {
			line.EgressNodeIDs = ""
		}

		// Loop & duplicate guard across Ingress -> Hops -> EgressPool
		usedNodes := map[uint64]string{line.IngressNodeID: "入口节点"}
		checkNodeIDs := make([]uint64, 0, len(hops)+len(egMembers))
		for idx, hid := range hops {
			if roleName, dup := usedNodes[hid]; dup {
				return fmt.Errorf("链式转发检测到环路或重复节点：节点 #%d 已作为%s，不能同时作为中间跳点 #%d", hid, roleName, idx+1)
			}
			usedNodes[hid] = fmt.Sprintf("中间跳点 #%d", idx+1)
			checkNodeIDs = append(checkNodeIDs, hid)
		}
		for _, em := range egMembers {
			if roleName, dup := usedNodes[em.NodeID]; dup {
				return fmt.Errorf("拓扑冲突：节点 #%d 已作为%s，不能同时作为出口节点", em.NodeID, roleName)
			}
			usedNodes[em.NodeID] = "出口节点"
			checkNodeIDs = append(checkNodeIDs, em.NodeID)
		}
		var existingNodes []model.Node
		s.db.Select("id").Where("id IN ?", checkNodeIDs).Find(&existingNodes)
		existSet := make(map[uint64]bool, len(existingNodes))
		for _, n := range existingNodes {
			existSet[n.ID] = true
		}
		for _, nid := range checkNodeIDs {
			if !existSet[nid] {
				return fmt.Errorf("隧道拓扑引用的节点 #%d 不存在", nid)
			}
		}

		if line.EnableMux && line.EnableBonding {
			return fmt.Errorf("多路复用连接池 (Mux) 与单流多通道条带化聚合 (Bonding) 请二选一开启")
		}
		if line.BondLinks <= 0 {
			line.BondLinks = 4
		}
		if line.BondLinks < 2 || line.BondLinks > 8 {
			return fmt.Errorf("单流带宽聚合通道数需在 2 - 8 之间")
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
	if math.IsNaN(line.RateMultiplier) || math.IsInf(line.RateMultiplier, 0) || line.RateMultiplier < 0 || line.RateMultiplier > 1000 {
		return fmt.Errorf("隧道计费倍率需在 0 - 1000 之间")
	}
	if line.MaxPortCount < 0 || line.MaxPortCount > 65535 {
		return fmt.Errorf("端口上限需在 0 - 65535 之间")
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

// sanitizeRequestHost strictly validates an HTTP Host header value against injection characters.
func sanitizeRequestHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 255 {
		return "127.0.0.1:8080"
	}
	for _, r := range raw {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == ':' || r == '[' || r == ']') {
			return "127.0.0.1:8080"
		}
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		if h == "" {
			return "127.0.0.1:8080"
		}
		if portNum, perr := strconv.Atoi(p); perr != nil || portNum < 1 || portNum > 65535 {
			return "127.0.0.1:8080"
		}
		return raw
	}
	if strings.Contains(raw, ":") && !(strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")) {
		return "127.0.0.1:8080"
	}
	return raw
}

// panelBaseURL returns the externally reachable base URL (configured NEXUS_PUBLIC_URL preferred).
func (s *Server) panelBaseURL(c *gin.Context) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := "http"
	if c.Request.TLS != nil || (s.hasTrustedProxies && strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")) {
		scheme = "https"
	}
	return scheme + "://" + sanitizeRequestHost(c.Request.Host)
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
	s.recordAudit(c, "admin.resync_node", node.Name, fmt.Sprintf("向节点 #%d 下发全量规则重同步指令", node.ID))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已向节点「%s」下发全量规则重同步/重启指令", node.Name)})
}

func (s *Server) buildUpgradeAgentPayload(c *gin.Context, targetVer string) protocol.UpgradeAgentPayload {
	targetVer = strings.TrimSpace(targetVer)
	if targetVer == "" {
		targetVer = "1.2.0-sec"
	}
	if len(targetVer) > 32 {
		targetVer = targetVer[:32]
	}
	shaByArch := make(map[string]string, 2)
	for _, arch := range []string{"amd64", "arm64"} {
		if sum := s.agentBinarySHA256(arch); sum != "" {
			shaByArch[arch] = sum
		}
	}
	return protocol.UpgradeAgentPayload{
		TargetVersion: targetVer,
		BaseURL:       s.panelBaseURL(c),
		SHA256ByArch:  shaByArch,
	}
}

func (s *Server) handleAdminUpgradeNode(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var node model.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	var req struct {
		TargetVersion string `json:"target_version"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	payload := s.buildUpgradeAgentPayload(c, req.TargetVersion)
	if err := s.hub.SendToNode(node.ID, protocol.MsgUpgradeAgent, payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("节点「%s」当前离线，无法下发远程升级指令", node.Name)})
		return
	}
	s.recordAudit(c, "admin.upgrade_node", node.Name, fmt.Sprintf("下发远程升级指令 (%s)", payload.TargetVersion))
	c.JSON(http.StatusOK, gin.H{
		"message":        fmt.Sprintf("已向节点「%s」下发签名远程升级指令 (%s)", node.Name, payload.TargetVersion),
		"node_id":        node.ID,
		"target_version": payload.TargetVersion,
	})
}

func (s *Server) handleAdminBatchUpgradeNodes(c *gin.Context) {
	var req struct {
		IDs           []uint64 `json:"ids"`
		TargetVersion string   `json:"target_version"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	payload := s.buildUpgradeAgentPayload(c, req.TargetVersion)

	targetIDs := req.IDs
	if len(targetIDs) == 0 {
		targetIDs = s.hub.OnlineNodeIDs()
	}
	upgraded := make([]uint64, 0, len(targetIDs))
	for _, nid := range targetIDs {
		if err := s.hub.SendToNode(nid, protocol.MsgUpgradeAgent, payload); err == nil {
			upgraded = append(upgraded, nid)
		}
	}
	s.recordAudit(c, "admin.batch_upgrade_nodes", payload.TargetVersion, fmt.Sprintf("向 %d 个在线节点下发批量升级指令", len(upgraded)))
	c.JSON(http.StatusOK, gin.H{
		"message":        fmt.Sprintf("已向 %d 个在线节点下发签名远程升级指令 (%s)", len(upgraded), payload.TargetVersion),
		"upgraded_nodes": upgraded,
		"target_version": payload.TargetVersion,
	})
}

func (s *Server) handleAdminCreateLine(c *gin.Context) {
	var line model.TunnelLine
	if err := c.ShouldBindJSON(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if line.Type == "" {
		if line.EgressNodeID > 0 || strings.TrimSpace(line.EgressNodeIDs) != "" {
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
	if err := s.validateAndNormalizeLine(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.validateLinePortRange(&line); err != nil {
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
	lines := []model.TunnelLine{line}
	s.populateLineAllowedOutboundIPs(lines)
	c.JSON(http.StatusCreated, lines[0])
}

func (s *Server) handleAdminUpdateLine(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var line model.TunnelLine
	if err := s.db.First(&line, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tunnel not found"})
		return
	}
	var req struct {
		Name              string              `json:"name"`
		Type              string              `json:"type"`
		Description       *string             `json:"description"`
		IngressNodeID     uint64              `json:"ingress_node_id"`
		HopNodeIDs        *string             `json:"hop_node_ids"`
		EgressNodeID      uint64              `json:"egress_node_id"`
		EgressNodeIDs     *string             `json:"egress_node_ids"`
		LoadBalance       *string             `json:"load_balance"`
		EnableMux         *bool               `json:"enable_mux"`
		EnableBonding     *bool               `json:"enable_bonding"`
		BondLinks         *int                `json:"bond_links"`
		ProxyProtocol     *int                `json:"proxy_protocol"`
		OffPeakMultiplier *float64            `json:"offpeak_multiplier"`
		Transport         string              `json:"transport"`
		Engine            protocol.EngineType `json:"engine"`
		BillingMode       string              `json:"billing_mode"`
		RateMultiplier    float64             `json:"rate_multiplier"`
		MaxPortCount      int                 `json:"max_port_count"`
		PortRange         string              `json:"port_range"`
		Enabled           *bool               `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	oldLine := line
	oldIngressID := line.IngressNodeID
	oldEgressID := line.EgressNodeID
	oldHops := line.HopNodeIDs
	oldEgressPool := line.EgressNodeIDs
	oldType := line.Type
	oldPortRange := line.PortRange
	oldEnabled := line.Enabled

	line.Name = req.Name
	line.Type = req.Type
	if req.Description != nil {
		line.Description = sanitizeSingleLine(*req.Description, 255)
	}
	if req.Enabled != nil {
		line.Enabled = *req.Enabled
	}
	line.IngressNodeID = req.IngressNodeID
	if req.LoadBalance != nil {
		line.LoadBalance = *req.LoadBalance
	}
	if req.EnableMux != nil {
		line.EnableMux = *req.EnableMux
	}
	if req.EnableBonding != nil {
		line.EnableBonding = *req.EnableBonding
	}
	if req.BondLinks != nil {
		line.BondLinks = *req.BondLinks
	}
	if req.ProxyProtocol != nil {
		line.ProxyProtocol = *req.ProxyProtocol
	}
	if req.OffPeakMultiplier != nil {
		line.OffPeakMultiplier = *req.OffPeakMultiplier
	}
	if line.Type == "encrypt" {
		line.EgressNodeID = req.EgressNodeID
		if req.HopNodeIDs != nil {
			line.HopNodeIDs = *req.HopNodeIDs
		}
		if req.EgressNodeIDs != nil {
			line.EgressNodeIDs = *req.EgressNodeIDs
		} else if req.EgressNodeID > 0 && req.EgressNodeID != oldEgressID && oldEgressPool == "" {
			line.EgressNodeIDs = ""
		}
		line.Transport = req.Transport
	} else {
		line.HopNodeIDs = ""
		line.EgressNodeID = 0
		line.EgressNodeIDs = ""
		line.Transport = "raw"
	}
	line.Engine = req.Engine
	line.BillingMode = req.BillingMode
	line.RateMultiplier = req.RateMultiplier
	line.MaxPortCount = req.MaxPortCount
	line.PortRange = req.PortRange
	if line.Engine == "" {
		line.Engine = protocol.EngineNative
	}
	if line.BillingMode == "" {
		line.BillingMode = "two_way"
	}
	if err := s.validateAndNormalizeLine(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.validateLinePortRange(&line); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hopsOrEgressChanged := oldEgressID != line.EgressNodeID || oldHops != line.HopNodeIDs || oldEgressPool != line.EgressNodeIDs
	topologyChanged := oldIngressID != line.IngressNodeID || hopsOrEgressChanged || oldType != line.Type ||
		oldLine.EnableMux != line.EnableMux || oldLine.EnableBonding != line.EnableBonding ||
		oldLine.ProxyProtocol != line.ProxyProtocol || (oldEnabled && !line.Enabled)

	// Tear down old rule instances on old topology BEFORE overwriting line in DB so RemoveRuleFromAgents sees oldLine's nodes!
	var preRules []model.ForwardRule
	if topologyChanged || !line.Enabled {
		s.db.Where("tunnel_line_id = ?", line.ID).Find(&preRules)
		for i := range preRules {
			s.orch.RemoveRuleFromAgents(&preRules[i])
		}
	}

	s.db.Save(&line)

	ruleGone := fmt.Errorf("rule deleted concurrently")
	sharedMoved := make(map[int]int) // oldListenPort -> newly allocated shared port for MatchDomains groups
	var rules []model.ForwardRule
	s.db.Where("tunnel_line_id = ?", line.ID).Find(&rules)
	for i := range rules {
		oldRule := rules[i]
		saveErr := s.orch.WithAllocLock(func() error {
			if err := s.db.First(&rules[i], oldRule.ID).Error; err != nil {
				return ruleGone
			}
			rules[i].Engine = line.Engine
			hasDomains := strings.TrimSpace(rules[i].MatchDomains) != ""
			if oldIngressID != line.IngressNodeID {
				rules[i].IngressNodeID = line.IngressNodeID
				rules[i].ListenPort = 0
				s.db.Model(&model.ForwardRule{}).Where("id = ?", rules[i].ID).Updates(map[string]any{"ingress_node_id": line.IngressNodeID, "listen_port": 0})
				preferredPort := oldRule.ListenPort
				if hasDomains && oldRule.ListenPort > 0 {
					if mapped, ok := sharedMoved[oldRule.ListenPort]; ok {
						preferredPort = mapped
					}
				}
				if p, normMD, err := s.orch.AllocateIngressPortForRule(line.IngressNodeID, preferredPort, rules[i].MatchDomains, rules[i].ID, line.PortRange); err == nil {
					rules[i].ListenPort = p
					rules[i].MatchDomains = normMD
					if hasDomains && oldRule.ListenPort > 0 {
						if _, ok := sharedMoved[oldRule.ListenPort]; !ok {
							sharedMoved[oldRule.ListenPort] = p
						}
					}
				} else if p2, normMD2, err2 := s.orch.AllocateIngressPortForRule(line.IngressNodeID, 0, rules[i].MatchDomains, rules[i].ID, line.PortRange); err2 == nil {
					rules[i].ListenPort = p2
					rules[i].MatchDomains = normMD2
					if hasDomains && oldRule.ListenPort > 0 {
						sharedMoved[oldRule.ListenPort] = p2
					}
				} else {
					rules[i].Enabled = false
					rules[i].Status = "error"
					rules[i].LastError = "新入口节点无可用端口"
				}
			} else if rules[i].ListenPort > 0 && !s.orch.PortInRange(rules[i].IngressNodeID, rules[i].ListenPort, line.PortRange) {
				prevPort := rules[i].ListenPort
				desiredPort := 0
				if hasDomains {
					if mapped, ok := sharedMoved[prevPort]; ok {
						desiredPort = mapped
					}
				}
				s.db.Model(&model.ForwardRule{}).Where("id = ?", rules[i].ID).Update("listen_port", 0)
				if p, normMD, rerr := s.orch.AllocateIngressPortForRule(rules[i].IngressNodeID, desiredPort, rules[i].MatchDomains, rules[i].ID, line.PortRange); rerr == nil {
					rules[i].ListenPort = p
					rules[i].MatchDomains = normMD
					if hasDomains {
						sharedMoved[prevPort] = p
					}
				} else {
					s.db.Model(&model.ForwardRule{}).Where("id = ?", rules[i].ID).Update("listen_port", prevPort)
					rules[i].ListenPort = prevPort
					if rules[i].Enabled {
						rules[i].Enabled = false
						rules[i].Status = "error"
					}
					rules[i].LastError = "隧道端口范围内无可用端口，请调整范围后重新编辑该规则"
				}
			}
			if hopsOrEgressChanged || line.Type != "encrypt" {
				rules[i].RelayPort = 0
				rules[i].RelayNodeID = 0
				rules[i].HopPortsJSON = ""
				rules[i].EgressPortsJSON = ""
			}
			if line.Type == "encrypt" && len(line.EgressMembers()) > 0 {
				rules[i].Mode = "tunnel"
			} else {
				rules[i].Mode = "direct"
			}
			return s.db.Omit(ruleCounterCols...).Save(&rules[i]).Error
		})
		if saveErr == ruleGone {
			continue
		}
		if saveErr != nil {
			log.Printf("[API] tunnel %d: failed to migrate rule %d: %v", line.ID, rules[i].ID, saveErr)
			s.db.Model(&model.ForwardRule{}).Where("id = ?", rules[i].ID).Updates(map[string]any{
				"enabled": false, "status": "error", "last_error": "隧道变更后规则迁移失败，请重新编辑该规则",
			})
			rules[i].Enabled = false
			s.orch.RemoveRuleFromAgents(&oldRule)
			continue
		}
		s.orch.DispatchRule(&rules[i])
	}
	if line.PortRange != oldPortRange {
		s.reallocNodeRulesOutOfRange(line.IngressNodeID)
	}
	lines := []model.TunnelLine{line}
	s.populateLineAllowedOutboundIPs(lines)
	c.JSON(http.StatusOK, lines[0])
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
			s.db.Model(&model.ForwardRule{}).Where("id = ?", userRules[i].ID).Updates(map[string]any{"enabled": false, "status": "paused"})
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
	plan.Name = strings.TrimSpace(plan.Name)
	plan.Description = strings.TrimSpace(plan.Description)
	if plan.Name == "" || utf8.RuneCountInString(plan.Name) > 64 || plan.PriceCents < 0 || plan.QuotaBytes < 0 ||
		plan.SpeedMbps < 0 || plan.SpeedMbps > 100000 || plan.MaxRules < 0 || plan.MaxRules > 100000 || plan.DurationDays < 0 || plan.DurationDays > 36500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的套餐参数"})
		return
	}
	if err := s.db.Create(&plan).Error; err != nil {
		log.Printf("[API] create plan failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建套餐失败，请检查参数"})
		return
	}
	s.recordAudit(c, "admin.create_plan", plan.Name, fmt.Sprintf("创建套餐 #%d (¥%.2f)", plan.ID, float64(plan.PriceCents)/100.0))
	c.JSON(http.StatusCreated, plan)
}

func (s *Server) handleAdminUpdatePlan(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var plan model.Plan
	if err := s.db.First(&plan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "套餐不存在"})
		return
	}
	var req struct {
		Name           string  `json:"name"`
		Description    *string `json:"description"`
		RoleGroupID    uint64  `json:"role_group_id"`
		AllowedTunnels string  `json:"allowed_tunnels"`
		PriceCents     *int64  `json:"price_cents"`
		DurationDays   int     `json:"duration_days"`
		QuotaBytes     int64   `json:"quota_bytes"`
		MaxRules       int     `json:"max_rules"`
		SpeedMbps      int     `json:"speed_mbps"`
		MonthlyReset   *bool   `json:"monthly_reset"`
		Active         *bool   `json:"active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		if utf8.RuneCountInString(strings.TrimSpace(req.Name)) > 64 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "套餐名称不能超过 64 个字符"})
			return
		}
		plan.Name = strings.TrimSpace(req.Name)
	}
	if req.Description != nil {
		plan.Description = strings.TrimSpace(*req.Description)
	}
	if req.RoleGroupID > 0 {
		plan.RoleGroupID = req.RoleGroupID
		var rg model.RoleGroup
		if err := s.db.First(&rg, req.RoleGroupID).Error; err == nil {
			plan.AllowedTunnels = rg.AllowedTunnels
		}
	} else if req.AllowedTunnels != "" {
		plan.AllowedTunnels = strings.TrimSpace(req.AllowedTunnels)
	}
	if req.PriceCents != nil && *req.PriceCents >= 0 {
		plan.PriceCents = *req.PriceCents
	}
	if req.DurationDays > 0 && req.DurationDays <= 36500 {
		plan.DurationDays = req.DurationDays
	}
	if req.QuotaBytes > 0 {
		plan.QuotaBytes = req.QuotaBytes
	}
	if req.MaxRules > 0 && req.MaxRules <= 100000 {
		plan.MaxRules = req.MaxRules
	}
	if req.SpeedMbps > 0 && req.SpeedMbps <= 100000 {
		plan.SpeedMbps = req.SpeedMbps
	}
	if req.MonthlyReset != nil {
		plan.MonthlyReset = *req.MonthlyReset
	}
	if req.Active != nil {
		plan.Active = *req.Active
	}
	s.db.Save(&plan)
	s.recordAudit(c, "admin.update_plan", plan.Name, fmt.Sprintf("更新套餐 #%d 配置", plan.ID))
	c.JSON(http.StatusOK, plan)
}

func (s *Server) handleAdminDeletePlan(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	s.db.Delete(&model.Plan{}, id)
	s.recordAudit(c, "admin.delete_plan", strconv.FormatUint(id, 10), fmt.Sprintf("删除套餐 #%d", id))
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminListUsers(c *gin.Context) {
	var users []model.User
	query := s.db.Model(&model.User{}).Order("id asc")
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(strings.ToLower(q))
		if idNum, err := strconv.ParseUint(q, 10, 64); err == nil && idNum > 0 {
			query = query.Where(`(LOWER(email) LIKE ? ESCAPE '!' OR id = ?)`, like, idNum)
		} else {
			query = query.Where(`LOWER(email) LIKE ? ESCAPE '!'`, like)
		}
	}
	if planParam := strings.TrimSpace(c.Query("plan_id")); planParam != "" {
		if pid, err := strconv.ParseUint(planParam, 10, 64); err == nil {
			query = query.Where("plan_id = ?", pid)
		}
	}
	if rgParam := strings.TrimSpace(c.Query("role_group_id")); rgParam != "" {
		if rgid, err := strconv.ParseUint(rgParam, 10, 64); err == nil {
			query = query.Where("role_group_id = ?", rgid)
		}
	}

	status := strings.TrimSpace(c.Query("status"))
	page, pageSize, pagedEnvelope := parseListPagination(c, 500, 1000)
	if status == "" {
		var total int64
		query.Count(&total)
		query.Offset((page - 1) * pageSize).Limit(pageSize).Find(&users)
		respondListPayload(c, users, total, page, pageSize, pagedEnvelope)
		return
	}

	query.Find(&users)
	now := time.Now()
	filtered := make([]model.User, 0, len(users))
	for _, u := range users {
		isActive := u.Status == "active"
		isExpired := u.Role != "admin" && !u.ExpireAt.IsZero() && now.After(u.ExpireAt)
		isOverQuota := u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes
		switch status {
		case "banned":
			if !isActive {
				filtered = append(filtered, u)
			}
		case "expired":
			if isActive && isExpired {
				filtered = append(filtered, u)
			}
		case "over_quota":
			if isActive && isOverQuota {
				filtered = append(filtered, u)
			}
		case "active":
			if isActive && !isExpired && !isOverQuota {
				filtered = append(filtered, u)
			}
		default:
			filtered = append(filtered, u)
		}
	}
	total := int64(len(filtered))
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		users = []model.User{}
	} else {
		end := start + pageSize
		if end > len(filtered) {
			end = len(filtered)
		}
		users = filtered[start:end]
	}
	respondListPayload(c, users, total, page, pageSize, pagedEnvelope)
}

// parseFlexibleExpireTime parses RFC3339, datetime-local ("2006-01-02T15:04"), "2006-01-02 15:04:05",
// or date-only ("2006-01-02", treated as 23:59:59 UTC of that day).
func parseFlexibleExpireTime(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty expire time")
	}
	for _, layout := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	if d, err := time.Parse("2006-01-02", s); err == nil {
		return time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, time.UTC), nil
	}
	return time.Time{}, fmt.Errorf("invalid expire time format")
}

func (s *Server) tunnelLineEnabled(lineID uint64) bool {
	if lineID == 0 {
		return true
	}
	var line model.TunnelLine
	if err := s.db.Select("id, enabled").First(&line, lineID).Error; err != nil {
		return false
	}
	return line.Enabled
}

// resumeUserQuotaExceededRules automatically resumes any `quota_exceeded` rules of the user when the user's account
// is active, not expired, under quota, and permitted on an enabled tunnel and valid port range.
func (s *Server) resumeUserQuotaExceededRules(u *model.User) {
	now := time.Now()
	if !u.CanForward(now) {
		return
	}
	todayStr := s.orch.BillingDateString(now)
	var rules []model.ForwardRule
	s.db.Where("user_id = ? AND status = ?", u.ID, "quota_exceeded").Find(&rules)
	for i := range rules {
		if !u.HasTunnelPermission(rules[i].TunnelLineID) || !s.tunnelLineEnabled(rules[i].TunnelLineID) ||
			!rules[i].WithinRuleQuotas(todayStr) || !s.orch.RuleNodesWithinQuota(&rules[i]) ||
			s.resumeBlockedByPort(&rules[i]) {
			continue
		}
		rules[i].Enabled = true
		rules[i].Status = "running"
		if res := s.db.Model(&model.ForwardRule{}).Where("id = ? AND status = ?", rules[i].ID, "quota_exceeded").
			Updates(map[string]any{"enabled": true, "status": "running"}); res.Error != nil || res.RowsAffected == 0 {
			continue
		}
		s.db.First(&rules[i], rules[i].ID) // dispatch the current row, not a pre-lock snapshot
		s.orch.DispatchRule(&rules[i])
	}
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
		MonthlyReset   *bool  `json:"monthly_reset"`
		ExpireAt       string `json:"expire_at"`
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
	monthlyReset := false
	allowedTunnels := strings.TrimSpace(req.AllowedTunnels)
	now := time.Now()
	expireAt := now.AddDate(1, 0, 0)

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
			monthlyReset = plan.MonthlyReset
			if plan.DurationDays > 0 {
				expireAt = now.AddDate(0, 0, plan.DurationDays)
			}
		}
	}
	if req.MonthlyReset != nil {
		monthlyReset = *req.MonthlyReset
	}
	if strings.TrimSpace(req.ExpireAt) != "" {
		parsed, err := parseFlexibleExpireTime(req.ExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的到期时间格式"})
			return
		}
		expireAt = parsed
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
	if maxRules > 100000 {
		maxRules = 100000
	}
	if speed <= 0 {
		speed = 100
	}
	if speed > 100000 {
		speed = 100000
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
		MonthlyReset:   monthlyReset,
		LastResetAt:    &now,
		ExpireAt:       expireAt,
	}
	if err := s.db.Create(&u).Error; err != nil {
		log.Printf("[API] admin create user failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败，请检查参数"})
		return
	}
	s.recordAudit(c, "admin.create_user", u.Email, fmt.Sprintf("创建用户 #%d (role=%s)", u.ID, u.Role))
	c.JSON(http.StatusCreated, u)
}

func (s *Server) handleAdminDeleteUser(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	if id == s.currentUserID(c) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能删除当前登录的管理员账号"})
		return
	}
	var target model.User
	if err := s.db.First(&target, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if target.Role == "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不能直接删除管理员账号，请先降级为普通用户"})
		return
	}
	var rules []model.ForwardRule
	s.db.Where("user_id = ?", id).Find(&rules)
	for i := range rules {
		s.orch.RemoveRuleFromAgents(&rules[i])
	}
	s.db.Where("user_id = ?", id).Delete(&model.ForwardRule{})
	s.db.Delete(&model.User{}, id)
	s.recordAudit(c, "admin.delete_user", target.Email, fmt.Sprintf("删除用户 #%d 及其 %d 条转发规则", target.ID, len(rules)))
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
		MonthlyReset   *bool   `json:"monthly_reset"`
		BalanceCents   *int64  `json:"balance_cents"`
		ExpireAt       *string `json:"expire_at"`
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
	var parsedExpireAt *time.Time
	if req.ExpireAt != nil && strings.TrimSpace(*req.ExpireAt) != "" {
		t, err := parseFlexibleExpireTime(*req.ExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的到期时间格式"})
			return
		}
		parsedExpireAt = &t
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
		if req.MaxRules > 100000 {
			req.MaxRules = 100000
		}
		u.MaxRules = req.MaxRules
	}
	if req.SpeedMbps > 0 {
		if req.SpeedMbps > 100000 {
			req.SpeedMbps = 100000
		}
		u.SpeedMbps = req.SpeedMbps
	}
	if req.MonthlyReset != nil {
		u.MonthlyReset = *req.MonthlyReset
	}
	// used_bytes / balance_cents / token_version / quota_bytes / expire_at / password_hash / sub_token / totp_* change concurrently
	// (traffic reports, purchases, redeems, password changes, 2FA setup, sub token resets): save the profile without them and only
	// write them explicitly when the admin actually set them.
	s.db.Omit(
		"used_bytes", "balance_cents", "token_version", "quota_bytes", "expire_at", "password_hash", "sub_token",
		"totp_secret", "totp_enabled", "last_totp_step",
		"invite_code", "invited_by", "commission_balance_cents", "total_commission_cents", "commissioned_recharge_cents",
	).Save(&u)
	explicit := map[string]any{}
	if req.Password != "" {
		explicit["password_hash"] = u.PasswordHash
		accountGuard.reset(normalizeEmail(u.Email))
	}
	if req.QuotaBytes > 0 {
		explicit["quota_bytes"] = req.QuotaBytes
	}
	if parsedExpireAt != nil {
		explicit["expire_at"] = *parsedExpireAt
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
	if revokeTokens && u.ID == s.currentUserID(c) {
		if tok, err := GenerateToken(&u); err == nil {
			c.Header("X-Renewed-Token", tok)
		}
	}

	// 若通过修改角色或隧道权限收回了某条隧道的权限，自动暂停该用户在无权限隧道下的规则并从节点卸载
	s.enforceUserTunnelPermissions(&u)

	if !u.CanForward(time.Now()) {
		s.orch.EnforceUserQuotaCutoff(u.ID)
	} else {
		s.resumeUserQuotaExceededRules(&u)
	}
	s.recordAudit(c, "admin.update_user", u.Email, fmt.Sprintf("更新用户 #%d (status=%s, role=%s)", u.ID, u.Status, u.Role))
	c.JSON(http.StatusOK, u)
}

func (s *Server) handleAdminResetUserTraffic(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	now := time.Now()
	u.UsedBytes = 0
	u.LastResetAt = &now
	s.db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{"used_bytes": 0, "last_reset_at": &now})

	// 自动恢复该用户因流量超额暂停的转发规则（封禁 / 已过期账号以及无隧道权限的规则不恢复）
	s.resumeUserQuotaExceededRules(&u)
	c.JSON(http.StatusOK, u)
}

// handleAdminResetUserSubscription resets a user's subscription cycle: clears used traffic, refreshes quota/limits
// from their bound plan (if any), sets ExpireAt to now + duration_days (defaulting to the bound plan's duration or 30 days),
// optionally rotates SubToken, and automatically resumes any quota_exceeded rules.
func (s *Server) handleAdminResetUserSubscription(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	var req struct {
		DurationDays  int  `json:"duration_days"`
		ResetSubToken bool `json:"reset_sub_token"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	if req.DurationDays < 0 || req.DurationDays > 36500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "有效天数需在 1-36500 之间"})
		return
	}

	now := time.Now()
	durationDays := req.DurationDays
	updates := map[string]any{
		"used_bytes":    0,
		"last_reset_at": &now,
	}
	if u.PlanID > 0 {
		var plan model.Plan
		if err := s.db.First(&plan, u.PlanID).Error; err == nil {
			if durationDays <= 0 {
				durationDays = plan.DurationDays
			}
			if plan.QuotaBytes > 0 {
				updates["quota_bytes"] = plan.QuotaBytes
			}
			if plan.MaxRules > 0 {
				updates["max_rules"] = plan.MaxRules
			}
			if plan.SpeedMbps > 0 {
				updates["speed_mbps"] = plan.SpeedMbps
			}
			updates["monthly_reset"] = plan.MonthlyReset
			if plan.RoleGroupID > 0 {
				updates["role_group_id"] = plan.RoleGroupID
				if u.Role != "admin" {
					var rg model.RoleGroup
					if err := s.db.First(&rg, plan.RoleGroupID).Error; err == nil {
						updates["allowed_tunnels"] = strings.TrimSpace(rg.AllowedTunnels)
					} else if strings.TrimSpace(plan.AllowedTunnels) != "" {
						updates["allowed_tunnels"] = strings.TrimSpace(plan.AllowedTunnels)
					}
				}
			} else if strings.TrimSpace(plan.AllowedTunnels) != "" && u.Role != "admin" {
				updates["allowed_tunnels"] = strings.TrimSpace(plan.AllowedTunnels)
			}
		}
	}
	if durationDays <= 0 {
		durationDays = 30
	}
	updates["expire_at"] = now.AddDate(0, 0, durationDays)
	if req.ResetSubToken || strings.TrimSpace(u.SubToken) == "" {
		updates["sub_token"] = utils.GenerateRandomToken(16)
	}

	if err := s.db.Model(&model.User{}).Where("id = ?", u.ID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重置用户订阅失败"})
		return
	}
	_ = s.db.First(&u, u.ID).Error

	s.enforceUserTunnelPermissions(&u)
	if !u.CanForward(time.Now()) {
		s.orch.EnforceUserQuotaCutoff(u.ID)
	} else {
		s.resumeUserQuotaExceededRules(&u)
	}
	c.JSON(http.StatusOK, u)
}

// handleAdminResetUserPassword resets a user's password (either to a custom password or an auto-generated random one),
// increments token_version to revoke all existing sessions of that user, and clears any login lockout state.
func (s *Server) handleAdminResetUserPassword(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	newPassword := strings.TrimSpace(req.Password)
	generated := false
	if newPassword == "" {
		newPassword = utils.GenerateRandomToken(8) // 16 hex chars
		generated = true
	}
	if !validPassword(newPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码长度需为 8-72 位"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码重置失败"})
		return
	}
	if err := s.db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"password_hash": string(hash),
		"token_version": gorm.Expr("token_version + 1"),
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码重置失败"})
		return
	}
	accountGuard.reset(normalizeEmail(u.Email))
	_ = s.db.First(&u, u.ID).Error

	resp := gin.H{
		"message":   "密码已重置，该用户原有的登录会话已全部失效",
		"password":  newPassword,
		"generated": generated,
		"user":      u,
	}
	// 若管理员重置的是自己当前登录账号的密码，顺带签发新 JWT 以免当前管理会话掉线
	if u.ID == s.currentUserID(c) {
		if tok, err := GenerateToken(&u); err == nil {
			resp["token"] = tok
		}
	}
	c.JSON(http.StatusOK, resp)
}

// handleAdminResetUserSubToken rotates a user's subscription token on behalf of an administrator.
func (s *Server) handleAdminResetUserSubToken(c *gin.Context) {
	id, _ := strconv.ParseUint(c.Param("id"), 10, 64)
	var u model.User
	if err := s.db.First(&u, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	newToken := utils.GenerateRandomToken(16)
	if err := s.db.Model(&model.User{}).Where("id = ?", u.ID).Update("sub_token", newToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重置订阅链接失败"})
		return
	}
	u.SubToken = newToken
	c.JSON(http.StatusOK, gin.H{
		"message":   "用户订阅链接已重置，旧订阅链接已立即失效",
		"sub_token": newToken,
		"user":      u,
	})
}

func (s *Server) handleAdminListRedeemCodes(c *gin.Context) {
	statusFilter := strings.TrimSpace(c.Query("status"))
	keyword := strings.TrimSpace(c.Query("q"))

	q := s.db.Model(&model.RedeemCode{})
	switch statusFilter {
	case "unused":
		q = q.Where("used_by = 0")
	case "used":
		q = q.Where("used_by > 0")
	}
	if keyword != "" {
		like := buildSafeLike(keyword)
		q = q.Where("(code LIKE ? ESCAPE '!' OR note LIKE ? ESCAPE '!')", like, like)
	}

	var total int64
	q.Count(&total)
	page, pageSize, pagedEnvelope := parseListPagination(c, 500, 1000)

	var codes []model.RedeemCode
	if err := q.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&codes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "加载兑换码列表失败"})
		return
	}

	if len(codes) > 0 {
		var plans []model.Plan
		s.db.Select("id, name").Find(&plans)
		planMap := make(map[uint64]string, len(plans))
		for _, p := range plans {
			planMap[p.ID] = p.Name
		}

		userIDSet := make(map[uint64]struct{})
		for _, rc := range codes {
			if rc.UsedBy > 0 {
				userIDSet[rc.UsedBy] = struct{}{}
			}
		}
		userMap := make(map[uint64]string, len(userIDSet))
		if len(userIDSet) > 0 {
			userIDs := make([]uint64, 0, len(userIDSet))
			for id := range userIDSet {
				userIDs = append(userIDs, id)
			}
			var users []model.User
			s.db.Select("id, email").Where("id IN ?", userIDs).Find(&users)
			for _, u := range users {
				userMap[u.ID] = u.Email
			}
		}

		for i := range codes {
			if codes[i].PlanID > 0 {
				codes[i].PlanName = planMap[codes[i].PlanID]
			}
			if codes[i].UsedBy > 0 {
				codes[i].UsedByEmail = userMap[codes[i].UsedBy]
			}
		}
	}

	respondListPayload(c, codes, total, page, pageSize, pagedEnvelope)
}

func (s *Server) handleAdminGenerateRedeem(c *gin.Context) {
	var req struct {
		Count        int    `json:"count"`
		PlanID       uint64 `json:"plan_id"`
		BalanceCents int64  `json:"balance_cents"`
		QuotaGB      int64  `json:"quota_gb"`
		Duration     int    `json:"duration_days"`
		Prefix       string `json:"prefix"`
		Note         string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Count <= 0 || req.Count > 100 {
		req.Count = 5
	}
	if req.BalanceCents < 0 || req.BalanceCents > 100_000_000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "充值金额超出合理范围 (0 ~ 1,000,000 元)"})
		return
	}
	if req.QuotaGB < 0 || req.QuotaGB > 1_048_576 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "流量配额超出合理范围"})
		return
	}
	if req.Duration < 0 || req.Duration > 36500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "有效天数超出合理范围 (0 ~ 36500 天)"})
		return
	}

	var planName string
	quotaBytes := req.QuotaGB * 1024 * 1024 * 1024
	duration := req.Duration

	if req.PlanID > 0 {
		var plan model.Plan
		if err := s.db.First(&plan, req.PlanID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "所选绑定套餐不存在"})
			return
		}
		planName = plan.Name
		if req.QuotaGB == 0 && plan.QuotaBytes > 0 {
			quotaBytes = plan.QuotaBytes
		}
		if req.Duration == 0 && plan.DurationDays > 0 {
			duration = plan.DurationDays
		}
	} else if req.BalanceCents == 0 {
		// Traditional quota + duration card defaults when neither plan_id nor balance_cents is set
		if req.QuotaGB <= 0 {
			quotaBytes = 100 * 1024 * 1024 * 1024
		}
		if req.Duration <= 0 {
			duration = 30
		}
	}

	prefix := strings.ToUpper(strings.TrimSpace(req.Prefix))
	if prefix == "" {
		prefix = "NX"
	}
	for _, r := range prefix {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			c.JSON(http.StatusBadRequest, gin.H{"error": "卡密前缀仅允许字母、数字或连字符"})
			return
		}
	}
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}

	note := strings.TrimSpace(req.Note)
	if len(note) > 128 {
		note = note[:128]
	}

	var codes []model.RedeemCode
	for i := 0; i < req.Count; i++ {
		rc := model.RedeemCode{
			Code:         prefix + "-" + strings.ToUpper(utils.GenerateRandomToken(8)),
			PlanID:       req.PlanID,
			BalanceCents: req.BalanceCents,
			QuotaBytes:   quotaBytes,
			Duration:     duration,
			Note:         note,
		}
		if err := s.db.Create(&rc).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "生成兑换码失败"})
			return
		}
		rc.PlanName = planName
		codes = append(codes, rc)
	}
	s.recordAudit(c, "admin.generate_redeem", prefix, fmt.Sprintf("批量生成 %d 张卡密", len(codes)))
	c.JSON(http.StatusCreated, codes)
}

func (s *Server) handleAdminDeleteRedeemCode(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	res := s.db.Delete(&model.RedeemCode{}, id)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除兑换码失败"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "兑换码不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *Server) handleAdminBatchDeleteRedeemCodes(c *gin.Context) {
	var req struct {
		IDs  []uint64 `json:"ids"`
		Mode string   `json:"mode"` // "used" | "unused" | ""
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数格式错误"})
		return
	}
	var res *gorm.DB
	switch req.Mode {
	case "used":
		res = s.db.Where("used_by > 0").Delete(&model.RedeemCode{})
	case "unused":
		res = s.db.Where("used_by = 0").Delete(&model.RedeemCode{})
	default:
		if len(req.IDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请先选择要删除的兑换码"})
			return
		}
		if len(req.IDs) > 500 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "单次最多批量删除 500 条兑换码"})
			return
		}
		res = s.db.Where("id IN ?", req.IDs).Delete(&model.RedeemCode{})
	}
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "批量删除兑换码失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": res.RowsAffected})
}

func (s *Server) handleAdminListAuditLogs(c *gin.Context) {
	query := s.db.Model(&model.AuditLog{})
	if act := strings.TrimSpace(c.Query("action")); act != "" {
		query = query.Where("action = ?", act)
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		like := buildSafeLike(q)
		query = query.Where("(user_email LIKE ? ESCAPE '!' OR target LIKE ? ESCAPE '!' OR detail LIKE ? ESCAPE '!' OR client_ip LIKE ? ESCAPE '!')", like, like, like, like)
	}
	var total int64
	query.Count(&total)

	page, pageSize, pagedEnvelope := parseListPagination(c, 200, 500)
	var logs []model.AuditLog
	if err := query.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询审计日志失败"})
		return
	}
	respondListPayload(c, logs, total, page, pageSize, pagedEnvelope)
}

func (s *Server) handleAdminBackupSQLite(c *gin.Context) {
	tmpDir, err := os.MkdirTemp("", "zachary-panel-backup-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建临时备份目录失败"})
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	backupPath := filepath.Join(tmpDir, "backup.db")
	if err := s.db.Exec("VACUUM INTO ?", backupPath).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "导出 SQLite 热备快照失败 (仅支持 SQLite 数据库): " + err.Error()})
		return
	}
	_ = os.Chmod(backupPath, 0o600)

	f, err := os.Open(backupPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取备份文件失败"})
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成的备份文件无效"})
		return
	}

	filename := fmt.Sprintf("zachary-panel-backup-%s.db", time.Now().UTC().Format("20060102-150405"))
	s.recordAudit(c, "admin.backup_sqlite", filename, fmt.Sprintf("导出 SQLite 热备快照 (%d bytes)", fi.Size()))

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Length", strconv.FormatInt(fi.Size(), 10))
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, f)
}

