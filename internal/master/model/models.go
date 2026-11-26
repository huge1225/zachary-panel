package model

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"nexus-panel/pkg/protocol"
	"nexus-panel/pkg/utils"
)

// SystemConfig stores global panel settings managed by administrators.
type SystemConfig struct {
	ID                 uint64    `gorm:"primaryKey" json:"id"`
	SiteName           string    `gorm:"size:128;default:'Zachary Panel'" json:"site_name"`
	SiteLogo           string    `gorm:"size:32;default:'ZP'" json:"site_logo"`
	Announcement       string    `gorm:"size:1024;default:''" json:"announcement"`
	AllowRegister      bool      `gorm:"default:false" json:"allow_register"`
	DefaultRoleGroupID uint64    `gorm:"default:1" json:"default_role_group_id"`
	DefaultPlanID      uint64    `gorm:"default:0" json:"default_plan_id"`
	DefaultQuotaGB     int64     `gorm:"default:10" json:"default_quota_gb"`
	DefaultMaxRules    int       `gorm:"default:5" json:"default_max_rules"`
	DefaultSpeedMbps   int       `gorm:"default:50" json:"default_speed_mbps"`
	DefaultTunnels     string    `gorm:"size:512;default:'1'" json:"default_tunnels"`
	PaymentEnabled     bool      `gorm:"default:false" json:"payment_enabled"`
	EpayURL            string    `gorm:"size:255;default:''" json:"epay_url"`
	EpayPID            string    `gorm:"size:64;default:''" json:"epay_pid"`
	EpayKey                string    `gorm:"size:128;default:''" json:"epay_key"`
	USDTAddress            string    `gorm:"size:128;default:''" json:"usdt_address"`
	USDTWebhookSecret      string    `gorm:"size:128;default:''" json:"usdt_webhook_secret"`
	RechargeNotice         string    `gorm:"size:512;default:''" json:"recharge_notice"`
	NotifyTelegramBotToken string    `gorm:"size:128;default:''" json:"notify_telegram_bot_token"`
	NotifyTelegramChatID   string    `gorm:"size:64;default:''" json:"notify_telegram_chat_id"`
	NotifyWebhookURL       string    `gorm:"size:512;default:''" json:"notify_webhook_url"`
	NotifyOnNodeEvents        bool      `gorm:"default:true" json:"notify_on_node_events"`
	NotifyOnQuotaEvents       bool      `gorm:"default:true" json:"notify_on_quota_events"`
	NotifyOnTicketEvents      bool      `gorm:"default:true" json:"notify_on_ticket_events"`
	AffiliateEnabled          bool      `gorm:"default:true" json:"affiliate_enabled"`
	AffiliateCommissionRate   float64   `gorm:"default:10" json:"affiliate_commission_rate"`
	AffiliateMinWithdrawCents int64     `gorm:"default:1000" json:"affiliate_min_withdraw_cents"`
	AdminAPIKeyHash           string    `gorm:"size:128;default:''" json:"-"`
	AdminAPIKeyPrefix         string    `gorm:"size:32;default:''" json:"admin_api_key_prefix"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// RoleGroup defines a role / permission group (类似 Xboard 权限组):
// 角色决定了可以使用哪些隧道，套餐绑定角色，用户分配套餐和角色。
type RoleGroup struct {
	ID             uint64    `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"size:128;not null" json:"name"`
	Description    string    `gorm:"size:255" json:"description"`
	AllowedTunnels string    `gorm:"size:512;default:''" json:"allowed_tunnels"` // 逗号分隔的隧道 ID 列表 (如 "1,2")
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// User represents a tenant or administrator account.
type User struct {
	ID                        uint64     `gorm:"primaryKey" json:"id"`
	Email                     string     `gorm:"uniqueIndex;size:191;not null" json:"email"`
	PasswordHash              string     `gorm:"not null" json:"-"`
	Role                      string     `gorm:"size:32;default:'user'" json:"role"`                                            // "admin" | "user"
	Status                    string     `gorm:"size:32;default:'active';index:idx_user_status_expire,priority:1" json:"status"` // "active" | "banned"
	RoleGroupID               uint64     `gorm:"default:1;index" json:"role_group_id"`                                          // 所属角色 ID (决定可用隧道)
	PlanID                    uint64     `gorm:"default:0;index" json:"plan_id"`                                                // 绑定套餐 ID
	AllowedTunnels            string     `gorm:"size:512;default:''" json:"allowed_tunnels"`                                    // 逗号分隔的授权隧道 ID (随角色同步，admin 默认 "*")
	BalanceCents              int64      `gorm:"default:0" json:"balance_cents"`
	QuotaBytes                int64      `gorm:"default:107374182400" json:"quota_bytes"` // 总配额字节 (默认 100GB)
	UsedBytes                 int64      `gorm:"default:0" json:"used_bytes"`             // 已用计费字节 (含倍率折算)
	MaxRules                  int        `gorm:"default:20" json:"max_rules"`             // 最大规则数
	SpeedMbps                 int        `gorm:"default:100" json:"speed_mbps"`           // 峰值带宽限制 Mbps
	ExpireAt                  time.Time  `gorm:"index:idx_user_status_expire,priority:2" json:"expire_at"`
	MonthlyReset              bool       `gorm:"default:false" json:"monthly_reset"`               // 长周期套餐是否每满 30 天自动重置已用流量
	LastResetAt               *time.Time `json:"last_reset_at,omitempty"`                          // 最近一次流量重置时间
	SubToken                  string     `gorm:"size:64;index" json:"sub_token"`                   // 订阅链接专属 Token (可随时重置使旧链接失效)
	InviteCode                string     `gorm:"size:32;index" json:"invite_code"`                 // 专属推广邀请码
	InvitedBy                 uint64     `gorm:"default:0;index" json:"invited_by"`                // 邀请人用户 ID
	CommissionBalanceCents    int64      `gorm:"default:0" json:"commission_balance_cents"`        // 可提现/可划转返利佣金 (分)
	TotalCommissionCents      int64      `gorm:"default:0" json:"total_commission_cents"`          // 累计已获返利佣金 (分)
	CommissionedRechargeCents int64      `gorm:"default:0" json:"-"`                               // 已在充值环节结算过佣金的余额分值 (防止余额购套餐重复返佣)
	TOTPSecret                string     `gorm:"size:64;default:''" json:"-"`                      // TOTP 双因素认证密钥 (Base32)
	TOTPEnabled               bool       `gorm:"default:false" json:"totp_enabled"`                // 是否已启用双因素认证 (2FA)
	LastTOTPStep              int64      `gorm:"default:0" json:"-"`                               // 最近一次已消费的 30s TOTP 时间片 (防重放)
	TokenVersion              int        `gorm:"default:0" json:"-"`                               // 递增后使该用户所有已签发 JWT 失效 (改密/封禁)
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

// BeforeCreate ensures every newly created user receives a unique random subscription token and invite code.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if strings.TrimSpace(u.SubToken) == "" {
		u.SubToken = utils.GenerateRandomToken(16)
	}
	if strings.TrimSpace(u.InviteCode) == "" {
		u.InviteCode = GenerateInviteCode()
	}
	return nil
}

// CanForward reports whether the account may currently have active forwarding rules
// (not banned, not expired, quota not exhausted). Same criteria as the traffic-report cutoff.
// Administrators never expire (consistent with rule creation, which skips the expiry check for admins).
func (u *User) CanForward(now time.Time) bool {
	if u.Status != "active" {
		return false
	}
	if u.Role != "admin" && !u.ExpireAt.IsZero() && now.After(u.ExpireAt) {
		return false
	}
	return u.UsedBytes < u.QuotaBytes
}

// HasTunnelPermission checks whether the user is permitted to use the given tunnel ID.
func (u *User) HasTunnelPermission(tunnelID uint64) bool {
	if u.Role == "admin" {
		return true
	}
	if tunnelID == 0 {
		return false
	}
	raw := strings.TrimSpace(u.AllowedTunnels)
	if raw == "" {
		return false
	}
	if raw == "*" {
		return true
	}
	target := strconv.FormatUint(tunnelID, 10)
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == target {
			return true
		}
	}
	return false
}

// Plan defines a commercial subscription package bound to a RoleGroup.
type Plan struct {
	ID             uint64    `gorm:"primaryKey" json:"id"`
	Name           string    `gorm:"size:128;not null" json:"name"`
	Description    string    `gorm:"size:512" json:"description"`
	RoleGroupID    uint64    `gorm:"default:1;index" json:"role_group_id"` // 套餐绑定的角色 ID
	PriceCents     int64     `gorm:"not null" json:"price_cents"`
	DurationDays   int       `gorm:"default:30" json:"duration_days"`
	QuotaBytes     int64     `gorm:"not null" json:"quota_bytes"`
	MaxRules       int       `gorm:"default:20" json:"max_rules"`
	SpeedMbps      int       `gorm:"default:200" json:"speed_mbps"`
	MonthlyReset   bool      `gorm:"default:false" json:"monthly_reset"` // 是否按月(每30天)自动清零已用流量
	AllowedGroups  string    `gorm:"size:255;default:'*'" json:"allowed_groups"`
	AllowedTunnels string    `gorm:"size:512;default:'1'" json:"allowed_tunnels"` // 继承自所绑定角色的隧道 ID 列表
	Active         bool      `gorm:"default:true" json:"active"`
	CreatedAt      time.Time `json:"created_at"`
}

// NodeGroup categorizes nodes by tier (e.g. Standard BGP, Premium IEPL).
type NodeGroup struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"size:128;not null" json:"name"`
	Description string    `gorm:"size:255" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Node represents a managed forwarding server running the Agent.
type Node struct {
	ID               uint64              `gorm:"primaryKey" json:"id"`
	Name             string              `gorm:"size:128;not null" json:"name"`
	GroupID          uint64              `gorm:"default:1" json:"group_id"`
	Role             string              `gorm:"size:32;default:'all'" json:"role"`   // "relay" | "ingress" | "egress" | "all"
	ServerIP         string              `gorm:"size:191;not null" json:"server_ip"`  // 服务器通信 IP (用于节点间隧道底层对接)
	ConnectIP        string              `gorm:"size:191;not null" json:"connect_ip"` // 连接 IP / 入口显示地址 (用于添加转发后展示与一键复制)
	PublicHost       string              `gorm:"size:191" json:"public_host"`         // 兼容字段 (等同于 ConnectIP)
	InternalHost     string              `gorm:"size:191" json:"internal_host"`       // 专线内网通信 IP (选填，优先用于隧道通信)
	PortRange        string              `gorm:"size:64;default:'10000-50000'" json:"port_range"`
	TrafficRate      float64             `gorm:"default:1.0" json:"traffic_rate"`           // 节点倍率
	QuotaBytes       int64               `gorm:"default:10995116277760" json:"quota_bytes"` // 节点月流量配额 (默认 10TB, 0表示不限)
	UsedBytes        int64               `gorm:"default:0" json:"used_bytes"`               // 节点当前已用流量 (可手动设置校准)
	ResetDay         int                 `gorm:"default:0" json:"reset_day"`                // 每月自动重置流量日 (0=不开启, 1..28=每月几号)
	LastResetMonth   string              `gorm:"size:16;default:''" json:"last_reset_month"` // 最近一次自动重置月份 (YYYY-MM)
	DefaultEngine    protocol.EngineType `gorm:"size:32;default:'native'" json:"default_engine"`
	SupportedEngines string              `gorm:"size:255;default:'native'" json:"supported_engines"`       // Agent上报的可用引擎列表
	AgentVersion     string              `gorm:"size:32;default:'1.1.0-sec'" json:"agent_version"`         // Agent 上报的当前程序版本号
	SecretToken      string              `gorm:"size:128;not null" json:"secret_token,omitempty"`         // 仅在创建节点或生成对接脚本时读取
	TunnelCertPEM    string              `gorm:"type:text" json:"-"`                                      // Agent 上报的隧道 TLS 证书 (入口节点据此做证书固定)
	Status           string              `gorm:"size:32;default:'offline';index" json:"status"`           // "online" | "offline" | "maintenance"
	CPUCores         int                 `gorm:"-" json:"cpu_cores"`
	CPUUsage         float64             `gorm:"-" json:"cpu_usage"`
	Load1            float64             `gorm:"-" json:"load_1"`
	Load5            float64             `gorm:"-" json:"load_5"`
	Load15           float64             `gorm:"-" json:"load_15"`
	MemUsedBytes     uint64              `gorm:"-" json:"mem_used_bytes"`
	MemTotalBytes    uint64              `gorm:"-" json:"mem_total_bytes"`
	MemUsage         float64             `gorm:"-" json:"mem_usage"`
	DiskUsedBytes    uint64              `gorm:"-" json:"disk_used_bytes"`
	DiskTotalBytes   uint64              `gorm:"-" json:"disk_total_bytes"`
	DiskUsage        float64             `gorm:"-" json:"disk_usage"`
	NetRxBytesPerS   uint64              `gorm:"-" json:"net_rx_bytes_per_s"`
	NetTxBytesPerS   uint64              `gorm:"-" json:"net_tx_bytes_per_s"`
	ActiveRules      int                 `gorm:"-" json:"active_rules"`
	ActiveConns      int64               `gorm:"-" json:"active_conns"`
	UptimeSeconds    int64               `gorm:"-" json:"uptime_seconds"`
	LastSeenAt       *time.Time          `json:"last_seen_at"`
	CreatedAt        time.Time           `json:"created_at"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

// TunnelLine defines a Tunnel (借鉴 flux-panel 隧道设计):
// - Type == "direct": 直接转发隧道 (适用于自带内网穿透的专线节点或单台直连节点，只需指定 IngressNodeID)
// - Type == "encrypt": 加密对接隧道 (适用于国内入口 IngressNodeID 对接国外出口 EgressNodeID)
type TunnelLine struct {
	ID             uint64              `gorm:"primaryKey" json:"id"`
	Name           string              `gorm:"size:128;not null" json:"name"`
	Type           string              `gorm:"size:32;default:'direct'" json:"type"` // "direct" (直接转发隧道) | "encrypt" (加密对接隧道)
	Description    string              `gorm:"size:255" json:"description"`
	IngressNodeID  uint64              `gorm:"not null;index" json:"ingress_node_id"`          // 入口节点 ID
	EgressNodeID   uint64              `gorm:"default:0;index" json:"egress_node_id"`          // 出口节点 ID (仅 Type=="encrypt" 时需要)
	Transport      string              `gorm:"size:32;default:'tls'" json:"transport"`        // "raw" | "tls" | "ws" | "wss" | "quic" | "custom"
	Engine         protocol.EngineType `gorm:"size:32;default:'native'" json:"engine"`        // 默认转发引擎: "native" | "gost" | "realm" | "nftables"
	BillingMode    string              `gorm:"size:32;default:'two_way'" json:"billing_mode"` // "one_way" (单向计费) | "two_way" (双向计费)
	RateMultiplier float64             `gorm:"default:1.0" json:"rate_multiplier"`            // 隧道计费倍率
	MaxPortCount   int                 `gorm:"default:50" json:"max_port_count"`              // 该隧道允许的最大端口转发数
	PortRange      string              `gorm:"size:64;default:''" json:"port_range"`          // 该隧道在入口节点上可分配的端口范围 (如 "20000-20999")，留空则使用节点端口范围
	Enabled        bool                `gorm:"default:true" json:"enabled"`
	CreatedAt      time.Time           `json:"created_at"`
}

// ForwardRule represents a user-configured port/tunnel forwarding rule.
type ForwardRule struct {
	ID            uint64              `gorm:"primaryKey" json:"id"`
	UserID        uint64              `gorm:"index;index:idx_rule_user_enabled,priority:1;not null" json:"user_id"`
	Name          string              `gorm:"size:128;not null" json:"name"`
	Mode          string              `gorm:"size:32;default:'direct'" json:"mode"` // "direct" (单端直转) | "tunnel" (入口-出口专线联动)
	IngressNodeID uint64              `gorm:"index;not null" json:"ingress_node_id"`
	TunnelLineID  uint64              `gorm:"default:0;index" json:"tunnel_line_id"`  // Mode == "tunnel" 时关联的专线 ID
	Engine        protocol.EngineType `gorm:"size:32;default:'native'" json:"engine"` // 面板可选: "native" | "gost" | "realm" | "nftables"
	Protocol      string              `gorm:"size:16;default:'tcp'" json:"protocol"`  // "tcp" | "udp" | "both"
	ListenPort    int                 `gorm:"not null" json:"listen_port"`            // 入口节点分配的公网端口
	RelayPort     int                 `gorm:"default:0" json:"relay_port"`            // 双端模式下出口节点自动分配的内部隧道端口
	RelayNodeID   uint64              `gorm:"default:0;index" json:"-"`               // RelayPort 所在的出口节点（用于中继端口唯一性约束与范围校验）
	TunnelSecret  string              `gorm:"size:128" json:"-"`                      // 双端隧道自动生成的鉴权密钥
	LoadBalance   string              `gorm:"size:32;default:'round_robin'" json:"load_balance"`
	TargetsJSON   string              `gorm:"type:text;not null" json:"targets_json"` // JSON serialized []protocol.TargetEndpoint
	SpeedMbps     int                 `gorm:"default:0" json:"speed_mbps"`            // 0 表示继承用户套餐限速
	AccessMode    string              `gorm:"size:16;default:'off'" json:"access_mode"`   // "off" | "allow" | "deny"
	AccessCIDRs   string              `gorm:"size:1024;default:''" json:"access_cidrs"`   // 逗号分隔的 IP 或 CIDR 列表
	UploadBytes   int64               `gorm:"default:0" json:"upload_bytes"`
	DownBytes     int64               `gorm:"default:0" json:"down_bytes"`
	BilledBytes   int64               `gorm:"default:0" json:"billed_bytes"`
	Enabled       bool                `gorm:"default:true;index:idx_rule_user_enabled,priority:2" json:"enabled"`
	Status        string              `gorm:"size:32;default:'syncing';index" json:"status"` // "running" | "paused" | "error" | "quota_exceeded"
	LastError     string              `gorm:"size:255" json:"last_error,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	// EffectiveEngine is the engine the rule actually runs on (computed at read time, not persisted). It differs from
	// Engine when a speed-limited non-admin rule falls back from gost / realm to native.
	EffectiveEngine protocol.EngineType `gorm:"-" json:"effective_engine,omitempty"`
}

// RedeemCode allows users to top-up balance, add quota/duration, or activate plans via gift codes.
type RedeemCode struct {
	ID           uint64     `gorm:"primaryKey" json:"id"`
	Code         string     `gorm:"uniqueIndex;size:64;not null" json:"code"`
	PlanID       uint64     `gorm:"default:0" json:"plan_id"`
	BalanceCents int64      `gorm:"default:0" json:"balance_cents"`
	QuotaBytes   int64      `gorm:"default:0" json:"quota_bytes"`
	Duration     int        `gorm:"default:0" json:"duration_days"`
	Note         string     `gorm:"size:128;default:''" json:"note"`
	UsedBy       uint64     `gorm:"default:0;index" json:"used_by"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UsedByEmail  string     `gorm:"-" json:"used_by_email,omitempty"`
	PlanName     string     `gorm:"-" json:"plan_name,omitempty"`
}

// BillingOrder records recharge orders, plan purchases, paid subscription resets, affiliate transfers, and redeem code redemptions.
type BillingOrder struct {
	ID            uint64     `gorm:"primaryKey" json:"id"`
	OrderNo       string     `gorm:"uniqueIndex;size:64;not null" json:"order_no"`
	UserID        uint64     `gorm:"index;index:idx_order_user_status,priority:1;not null" json:"user_id"`
	UserEmail     string     `gorm:"size:191;default:''" json:"user_email"`
	Type          string     `gorm:"size:32;index;not null" json:"type"` // "recharge" | "plan_purchase" | "plan_reset" | "redeem" | "affiliate_transfer"
	PlanID        uint64     `gorm:"default:0" json:"plan_id"`
	PlanName      string     `gorm:"size:128;default:''" json:"plan_name"`
	OriginalCents int64      `gorm:"default:0" json:"original_cents"`
	DiscountCents int64      `gorm:"default:0" json:"discount_cents"`
	CouponCode    string     `gorm:"size:64;default:''" json:"coupon_code,omitempty"`
	AmountCents   int64      `gorm:"default:0" json:"amount_cents"`
	Status        string     `gorm:"size:32;default:'pending';index:idx_order_status_created,priority:1;index:idx_order_user_status,priority:2" json:"status"` // "pending" | "paid" | "cancelled"
	Gateway       string     `gorm:"size:32;default:'balance'" json:"gateway"`                                                                                 // "balance" | "epay" | "usdt" | "manual" | "redeem" | "affiliate"
	TradeNo       string     `gorm:"size:128;default:''" json:"trade_no"`
	PayURL        string     `gorm:"size:512;default:''" json:"pay_url,omitempty"`
	CreatedAt     time.Time  `gorm:"index:idx_order_status_created,priority:2" json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
}

// Coupon defines a promotional discount code supporting percentage or fixed-amount deductions.
type Coupon struct {
	ID               uint64     `gorm:"primaryKey" json:"id"`
	Code             string     `gorm:"uniqueIndex;size:64;not null" json:"code"`
	Name             string     `gorm:"size:128;not null" json:"name"`
	Type             string     `gorm:"size:16;not null" json:"type"`                       // "percent" (折扣比例 1..100, 如 20 表示减免 20%) | "fixed" (固定满减分值)
	Value            int64      `gorm:"not null" json:"value"`                              // percent: 1..100; fixed: cents > 0
	MinSpendCents    int64      `gorm:"default:0" json:"min_spend_cents"`                   // 最低消费门槛 (分)
	MaxDiscountCents int64      `gorm:"default:0" json:"max_discount_cents"`                // 百分比券最高抵扣上限 (分, 0 表示不封顶)
	AllowedPlanIDs   string     `gorm:"size:512;default:''" json:"allowed_plan_ids"`        // 允许使用的套餐 ID 列表 (空或 "*" 表示全部付费套餐)
	StartsAt         *time.Time `json:"starts_at,omitempty"`                                // 生效时间 (空表示立即生效)
	EndsAt           *time.Time `json:"ends_at,omitempty"`                                  // 失效时间 (空表示长期有效)
	MaxUses          int        `gorm:"default:0" json:"max_uses"`                          // 总可用次数 (0 表示不限)
	UsedCount        int        `gorm:"default:0" json:"used_count"`                        // 已核销总次数
	PerUserLimit     int        `gorm:"default:1" json:"per_user_limit"`                    // 单用户限用次数 (0 表示不限)
	Active           bool       `gorm:"default:true;index" json:"active"`                   // 是否启用
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// CouponRedemption records each atomic coupon claim against a specific purchase or cycle reset order.
type CouponRedemption struct {
	ID            uint64    `gorm:"primaryKey" json:"id"`
	CouponID      uint64    `gorm:"index:idx_coupon_user,priority:1;not null" json:"coupon_id"`
	CouponCode    string    `gorm:"size:64;not null" json:"coupon_code"`
	UserID        uint64    `gorm:"index:idx_coupon_user,priority:2;not null" json:"user_id"`
	UserEmail     string    `gorm:"size:191;default:''" json:"user_email"`
	OrderNo       string    `gorm:"size:64;index" json:"order_no"`
	Scene         string    `gorm:"size:32;default:'plan_purchase'" json:"scene"` // "plan_purchase" | "plan_reset"
	PlanID        uint64    `gorm:"default:0" json:"plan_id"`
	OriginalCents int64     `gorm:"default:0" json:"original_cents"`
	DiscountCents int64     `gorm:"default:0" json:"discount_cents"`
	PayableCents  int64     `gorm:"default:0" json:"payable_cents"`
	CreatedAt     time.Time `json:"created_at"`
}

// AffiliateCommission records automatic referral commission settled when an invited user recharges or buys a plan.
type AffiliateCommission struct {
	ID              uint64    `gorm:"primaryKey" json:"id"`
	InviterID       uint64    `gorm:"index;not null" json:"inviter_id"`
	InviteeID       uint64    `gorm:"index;not null" json:"invitee_id"`
	InviteeEmail    string    `gorm:"size:191;default:''" json:"invitee_email"`
	OrderID         uint64    `gorm:"uniqueIndex;not null" json:"order_id"`
	OrderNo         string    `gorm:"size:64;not null" json:"order_no"`
	Scene           string    `gorm:"size:32;not null" json:"scene"` // "recharge" | "plan_purchase" | "plan_reset"
	BaseAmountCents int64     `gorm:"not null" json:"base_amount_cents"`
	RatePercent     float64   `gorm:"not null" json:"rate_percent"`
	CommissionCents int64     `gorm:"not null" json:"commission_cents"`
	CreatedAt       time.Time `json:"created_at"`
}

// AffiliateWithdrawal tracks a user's commission payout request and administrator review lifecycle.
type AffiliateWithdrawal struct {
	ID          uint64     `gorm:"primaryKey" json:"id"`
	WithdrawNo  string     `gorm:"uniqueIndex;size:64;not null" json:"withdraw_no"`
	UserID      uint64     `gorm:"index;not null" json:"user_id"`
	UserEmail   string     `gorm:"size:191;default:''" json:"user_email"`
	AmountCents int64      `gorm:"not null" json:"amount_cents"`
	Method      string     `gorm:"size:32;not null" json:"method"`   // "usdt" | "alipay" | "wechat" | "bank"
	Account     string     `gorm:"size:191;not null" json:"account"` // 收款地址或账号
	RealName    string     `gorm:"size:64;default:''" json:"real_name"`
	Status      string     `gorm:"size:32;default:'pending';index" json:"status"` // "pending" | "approved" | "rejected"
	AdminRemark string     `gorm:"size:255;default:''" json:"admin_remark"`
	ReviewedBy  uint64     `gorm:"default:0" json:"reviewed_by"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// SupportTicket represents a customer support ticket optionally linked to a forwarding rule.
type SupportTicket struct {
	ID            uint64     `gorm:"primaryKey" json:"id"`
	TicketNo      string     `gorm:"uniqueIndex;size:64;not null" json:"ticket_no"`
	UserID        uint64     `gorm:"index;index:idx_ticket_user_status,priority:1;not null" json:"user_id"`
	UserEmail     string     `gorm:"size:191;default:''" json:"user_email"`
	Subject       string     `gorm:"size:160;not null" json:"subject"`
	Category      string     `gorm:"size:32;default:'general';index" json:"category"` // "network" | "rule" | "billing" | "account" | "general"
	Priority      string     `gorm:"size:16;default:'normal'" json:"priority"`        // "low" | "normal" | "high" | "urgent"
	RuleID        uint64     `gorm:"default:0;index" json:"rule_id"`
	RuleName      string     `gorm:"size:160;default:''" json:"rule_name"`
	Status        string     `gorm:"size:32;default:'open';index;index:idx_ticket_user_status,priority:2" json:"status"` // "open" | "answered" | "customer_reply" | "closed"
	LastReplyBy   string     `gorm:"size:16;default:'user'" json:"last_reply_by"`                                        // "user" | "admin"
	LastMessageAt time.Time  `gorm:"index" json:"last_message_at"`
	ClosedAt      *time.Time `json:"closed_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// TicketMessage stores a single conversational message inside a SupportTicket thread.
type TicketMessage struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	TicketID    uint64    `gorm:"index;not null" json:"ticket_id"`
	SenderID    uint64    `gorm:"not null" json:"sender_id"`
	SenderEmail string    `gorm:"size:191;default:''" json:"sender_email"`
	SenderRole  string    `gorm:"size:16;not null" json:"sender_role"` // "user" | "admin"
	Content     string    `gorm:"type:text;not null" json:"content"`
	CreatedAt   time.Time `json:"created_at"`
}

// TrafficHourlyStat stores hourly aggregated traffic for dashboard charts.
type TrafficHourlyStat struct {
	ID          uint64    `gorm:"primaryKey" json:"id"`
	UserID      uint64    `gorm:"index:idx_user_hour;index:idx_stat_user_rule_hour,priority:1" json:"user_id"`
	RuleID      uint64    `gorm:"index;index:idx_stat_user_rule_hour,priority:2" json:"rule_id"`
	NodeID      uint64    `json:"node_id"`
	HourBucket  string    `gorm:"size:16;index;index:idx_user_hour;index:idx_stat_user_rule_hour,priority:3" json:"hour_bucket"` // e.g. "2026-11-04 10:00"
	UploadBytes int64     `json:"upload_bytes"`
	DownBytes   int64     `json:"down_bytes"`
	BilledBytes int64     `json:"billed_bytes"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditLog records security-sensitive and administrative operations on the panel.
type AuditLog struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	UserID    uint64    `gorm:"index" json:"user_id"`
	UserEmail string    `gorm:"size:191;default:''" json:"user_email"`
	Action    string    `gorm:"size:64;index;index:idx_audit_action_created,priority:1;not null" json:"action"`
	Target    string    `gorm:"size:191;default:''" json:"target"`
	Detail    string    `gorm:"size:512;default:''" json:"detail"`
	ClientIP  string    `gorm:"size:64;default:''" json:"client_ip"`
	CreatedAt time.Time `gorm:"index:idx_audit_action_created,priority:2" json:"created_at"`
}

// InitDB opens a GORM connection (SQLite by default, or Postgres/MySQL via driver & dsn),
// runs schema auto-migrations, and seeds initial demo data if the database is empty.
func InitDB(driver, dsn string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch driver {
	case "postgres", "postgresql":
		dialector = postgres.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	default:
		if dsn == "" {
			dsn = "nexus_panel.db"
		}
		dialector = sqlite.Open(dsn)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		// 仅记录警告/错误与慢查询；忽略 "record not found"，避免把登录邮箱等查询参数刷进日志
		Logger: gormlogger.New(log.New(os.Stderr, "\r\n", log.LstdFlags), gormlogger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  gormlogger.Warn,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database (%s): %w", driver, err)
	}

	err = db.AutoMigrate(
		&SystemConfig{},
		&RoleGroup{},
		&User{},
		&Plan{},
		&NodeGroup{},
		&Node{},
		&TunnelLine{},
		&ForwardRule{},
		&RedeemCode{},
		&BillingOrder{},
		&Coupon{},
		&CouponRedemption{},
		&AffiliateCommission{},
		&AffiliateWithdrawal{},
		&SupportTicket{},
		&TicketMessage{},
		&TrafficHourlyStat{},
		&AuditLog{},
	)
	if err != nil {
		return nil, fmt.Errorf("schema migration failed: %w", err)
	}
	ensureRulePortUniqueIndex(db, driver)
	backfillRelayNodeIDs(db)
	ensureRelayPortUniqueIndex(db, driver)
	backfillUserSubTokens(db)
	ensureUserSubTokenUniqueIndex(db, driver)
	backfillUserInviteCodes(db)
	ensureUserInviteCodeUniqueIndex(db, driver)
	ensureOrderTradeNoUniqueIndex(db, driver)

	seedInitialData(db)
	return db, nil
}

// ensureOrderTradeNoUniqueIndex enforces DB-level uniqueness on (gateway, trade_no) for paid orders with non-empty
// external transaction references so concurrent webhook deliveries cannot reuse one trade_no/tx_hash across two orders.
func ensureOrderTradeNoUniqueIndex(db *gorm.DB, driver string) {
	const name = "idx_orders_gateway_trade_no"
	if db.Migrator().HasIndex(&BillingOrder{}, name) {
		return
	}
	var stmt string
	switch driver {
	case "mysql":
		stmt = "CREATE UNIQUE INDEX " + name + " ON billing_orders ((CASE WHEN status = 'paid' AND trade_no <> '' THEN gateway END), (CASE WHEN status = 'paid' AND trade_no <> '' THEN trade_no END))"
	default: // sqlite, postgres
		stmt = "CREATE UNIQUE INDEX IF NOT EXISTS " + name + " ON billing_orders (gateway, trade_no) WHERE status = 'paid' AND trade_no <> ''"
	}
	if err := db.Exec(stmt).Error; err != nil {
		log.Printf("[DB] WARNING: could not create unique index %s: %v", name, err)
	}
}

// GenerateInviteCode returns a clean uppercase alphanumeric invite code (e.g. "AFF8F3A12B4").
func GenerateInviteCode() string {
	return "AFF" + strings.ToUpper(utils.GenerateRandomToken(4))
}

// backfillUserInviteCodes populates InviteCode for any existing user rows created before the column existed.
func backfillUserInviteCodes(db *gorm.DB) {
	var users []User
	db.Select("id").Where("invite_code = '' OR invite_code IS NULL").Find(&users)
	for _, u := range users {
		db.Model(&User{}).Where("id = ?", u.ID).Update("invite_code", GenerateInviteCode())
	}
}

// ensureUserInviteCodeUniqueIndex guarantees non-empty user invite codes are unique across accounts.
func ensureUserInviteCodeUniqueIndex(db *gorm.DB, driver string) {
	const name = "idx_users_invite_code"
	if db.Migrator().HasIndex(&User{}, name) {
		return
	}
	var stmt string
	switch driver {
	case "mysql":
		stmt = "CREATE UNIQUE INDEX " + name + " ON users ((CASE WHEN invite_code <> '' THEN invite_code END))"
	default: // sqlite, postgres
		stmt = "CREATE UNIQUE INDEX IF NOT EXISTS " + name + " ON users (invite_code) WHERE invite_code <> ''"
	}
	if err := db.Exec(stmt).Error; err != nil {
		log.Printf("[DB] WARNING: could not create unique index %s: %v", name, err)
	}
}

// backfillUserSubTokens populates SubToken for any existing user rows created before the column existed.
func backfillUserSubTokens(db *gorm.DB) {
	var users []User
	db.Select("id").Where("sub_token = '' OR sub_token IS NULL").Find(&users)
	for _, u := range users {
		db.Model(&User{}).Where("id = ?", u.ID).Update("sub_token", utils.GenerateRandomToken(16))
	}
}

// ensureUserSubTokenUniqueIndex guarantees non-empty user subscription tokens are unique across accounts.
func ensureUserSubTokenUniqueIndex(db *gorm.DB, driver string) {
	const name = "idx_users_sub_token"
	if db.Migrator().HasIndex(&User{}, name) {
		return
	}
	var stmt string
	switch driver {
	case "mysql":
		stmt = "CREATE UNIQUE INDEX " + name + " ON users ((CASE WHEN sub_token <> '' THEN sub_token END))"
	default: // sqlite, postgres
		stmt = "CREATE UNIQUE INDEX IF NOT EXISTS " + name + " ON users (sub_token) WHERE sub_token <> ''"
	}
	if err := db.Exec(stmt).Error; err != nil {
		log.Printf("[DB] WARNING: could not create unique index %s: %v", name, err)
	}
}

// ensureRulePortUniqueIndex adds a database-level guarantee that two rules never get the same listen port on one
// node (the in-process allocation lock only covers a single master instance). Port 0 is used transiently while a
// rule is moved between nodes and is excluded. Existing duplicate data only produces a warning.
func ensureRulePortUniqueIndex(db *gorm.DB, driver string) {
	const name = "idx_rule_node_port"
	if db.Migrator().HasIndex(&ForwardRule{}, name) {
		return
	}
	var stmt string
	switch driver {
	case "mysql":
		// MySQL has no partial indexes: functional key parts that are NULL for port 0 (NULLs never collide). 8.0.13+.
		stmt = "CREATE UNIQUE INDEX " + name + " ON forward_rules ((CASE WHEN listen_port > 0 THEN ingress_node_id END), (CASE WHEN listen_port > 0 THEN listen_port END))"
	default: // sqlite, postgres
		stmt = "CREATE UNIQUE INDEX IF NOT EXISTS " + name + " ON forward_rules (ingress_node_id, listen_port) WHERE listen_port > 0"
	}
	if err := db.Exec(stmt).Error; err != nil {
		log.Printf("[DB] WARNING: could not create unique index %s (duplicate ports in existing data or unsupported database version): %v", name, err)
	}
}

// backfillRelayNodeIDs fills RelayNodeID for tunnel rules created before the column existed.
func backfillRelayNodeIDs(db *gorm.DB) {
	var rules []ForwardRule
	db.Select("id", "tunnel_line_id").Where("relay_port > 0 AND relay_node_id = 0").Find(&rules)
	for _, r := range rules {
		var l TunnelLine
		if db.Select("id", "egress_node_id").First(&l, r.TunnelLineID).Error == nil && l.EgressNodeID > 0 {
			db.Model(&ForwardRule{}).Where("id = ?", r.ID).Update("relay_node_id", l.EgressNodeID)
		} else {
			// Stale relay port of a rule whose tunnel no longer has an egress: release it (re-allocated on next deploy)
			// so leftovers can never block the unique index below.
			db.Model(&ForwardRule{}).Where("id = ?", r.ID).Update("relay_port", 0)
		}
	}
}

// ensureRelayPortUniqueIndex guarantees at database level that two tunnel rules never share a relay port on the same
// egress node (relay_port 0 = not allocated is exempt). Collisions between a relay port and a listen port on the same
// node are prevented by the allocator (single master, allocation lock).
func ensureRelayPortUniqueIndex(db *gorm.DB, driver string) {
	const name = "idx_rule_relay_node_port"
	if db.Migrator().HasIndex(&ForwardRule{}, name) {
		return
	}
	var stmt string
	switch driver {
	case "mysql":
		stmt = "CREATE UNIQUE INDEX " + name + " ON forward_rules ((CASE WHEN relay_port > 0 THEN relay_node_id END), (CASE WHEN relay_port > 0 THEN relay_port END))"
	default: // sqlite, postgres
		stmt = "CREATE UNIQUE INDEX IF NOT EXISTS " + name + " ON forward_rules (relay_node_id, relay_port) WHERE relay_port > 0"
	}
	if err := db.Exec(stmt).Error; err != nil {
		log.Printf("[DB] WARNING: could not create unique index %s (duplicate relay ports in existing data or unsupported database version): %v", name, err)
	}
}

func envBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

// seedPassword returns the password from env (when long enough) or a freshly generated random one.
func seedPassword(envKey string) (pw string, generated bool) {
	if v := os.Getenv(envKey); len(v) >= 8 && len(v) <= 72 {
		return v, false
	} else if v != "" {
		log.Printf("[DB] %s ignored: password must be 8-72 characters", envKey)
	}
	return utils.GenerateRandomToken(12), true
}

func seedInitialData(db *gorm.DB) {
	var cfgCount int64
	db.Model(&SystemConfig{}).Count(&cfgCount)
	if cfgCount == 0 {
		db.Create(&SystemConfig{
			ID:                 1,
			SiteName:           "Zachary Panel",
			SiteLogo:           "ZP",
			Announcement:       "",
			AllowRegister:      false, // 公开注册默认关闭，需管理员在系统设置中显式开启
			DefaultRoleGroupID: 1,
			DefaultPlanID:      1,
			DefaultQuotaGB:     10,
			DefaultMaxRules:    5,
			DefaultSpeedMbps:   50,
			DefaultTunnels:     "1",
		})
		// GORM skips zero-value bools on create (column default would apply), so persist explicitly.
		db.Model(&SystemConfig{}).Where("id = ?", 1).Update("allow_register", false)
	}

	var count int64
	db.Model(&User{}).Count(&count)
	if count > 0 {
		return
	}

	seedDemo := envBool("NEXUS_SEED_DEMO")
	log.Printf("[DB] Seeding default roles, plans and administrator account (demo data: %v)...", seedDemo)

	// 1. Default Role Groups (角色决定可用隧道)
	r1 := RoleGroup{
		Name:           "标准角色",
		Description:    "仅可使用标准直转隧道 (#1)",
		AllowedTunnels: "1",
	}
	r2 := RoleGroup{
		Name:           "VIP 专线角色",
		Description:    "解锁直转与双端加密隧道 (#1 + #2)",
		AllowedTunnels: "1,2",
	}
	db.Create(&r1)
	db.Create(&r2)

	// 2. Default Commercial Plans (套餐绑定角色)
	plans := []Plan{
		{
			Name:           "轻量标准版 (BGP)",
			Description:    "绑定「标准角色」，包含 200GB 月流量，10 条转发规则",
			RoleGroupID:    r1.ID,
			PriceCents:     1900,
			DurationDays:   30,
			QuotaBytes:     200 * 1024 * 1024 * 1024,
			MaxRules:       10,
			SpeedMbps:      100,
			AllowedTunnels: r1.AllowedTunnels,
			Active:         true,
		},
		{
			Name:           "IEPL 专线旗舰版",
			Description:    "绑定「VIP 专线角色」，包含 1TB 高速流量，50 条规则，解锁全部隧道",
			RoleGroupID:    r2.ID,
			PriceCents:     8900,
			DurationDays:   30,
			QuotaBytes:     1024 * 1024 * 1024 * 1024,
			MaxRules:       50,
			SpeedMbps:      500,
			AllowedTunnels: r2.AllowedTunnels,
			Active:         true,
		},
	}
	db.Create(&plans)

	// 3. Administrator account: credentials come from env, otherwise a random password is generated and
	// printed exactly once. No well-known default password is ever created.
	adminEmail := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUS_ADMIN_EMAIL")))
	if adminEmail == "" {
		adminEmail = "admin@nexus.local"
	}
	adminPass, generated := seedPassword("NEXUS_ADMIN_PASSWORD")
	hash, _ := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	admin := User{
		Email:          adminEmail,
		PasswordHash:   string(hash),
		Role:           "admin",
		Status:         "active",
		RoleGroupID:    r2.ID,
		PlanID:         plans[1].ID,
		AllowedTunnels: "*",
		BalanceCents:   0,
		QuotaBytes:     1024 * 1024 * 1024 * 1024, // 1 TB
		MaxRules:       100,
		SpeedMbps:      1000,
		ExpireAt:       time.Now().AddDate(1, 0, 0),
	}
	db.Create(&admin)
	if generated {
		log.Printf("[DB] ==== Initial administrator created: %s / %s  (change it after first login; set NEXUS_ADMIN_PASSWORD to choose your own) ====", adminEmail, adminPass)
	} else {
		log.Printf("[DB] Initial administrator created: %s (password from NEXUS_ADMIN_PASSWORD)", adminEmail)
	}

	if !seedDemo {
		return
	}
	seedDemoData(db, r1, plans)
}

// seedDemoData creates sample users, nodes and tunnels for local evaluation. Only runs when NEXUS_SEED_DEMO=true.
func seedDemoData(db *gorm.DB, r1 RoleGroup, plans []Plan) {
	userPass, generated := seedPassword("NEXUS_DEMO_USER_PASSWORD")
	userHash, _ := bcrypt.GenerateFromPassword([]byte(userPass), bcrypt.DefaultCost)
	normalUser := User{
		Email:          "user@nexus.local",
		PasswordHash:   string(userHash),
		Role:           "user",
		Status:         "active",
		RoleGroupID:    r1.ID,
		PlanID:         plans[0].ID,
		AllowedTunnels: r1.AllowedTunnels, // 由所分配的「标准角色」决定，仅授权隧道 #1
		BalanceCents:   20000,
		QuotaBytes:     200 * 1024 * 1024 * 1024, // 200 GB
		MaxRules:       10,
		SpeedMbps:      100,
		ExpireAt:       time.Now().AddDate(0, 1, 0),
	}
	db.Create(&normalUser)
	if generated {
		log.Printf("[DB] Demo user created: user@nexus.local / %s", userPass)
	}

	// Default Node Groups
	g1 := NodeGroup{Name: "BGP 标准公网中转", Description: "国内三网优化 BGP 单端直转节点组"}
	g2 := NodeGroup{Name: "IEPL 內网专线组", Description: "深港/广港/沪日低延迟加密专线"}
	db.Create(&g1)
	db.Create(&g2)

	// Demo nodes: every node gets a strong random secret token (shown in the admin node list / install command).
	n1 := Node{
		Name:             "深港 IEPL 专线节点-01 (自带内网穿透)",
		GroupID:          g2.ID,
		Role:             "all",
		ServerIP:         "120.79.88.10",
		ConnectIP:        "sz-iepl-vip.nexus.local",
		PublicHost:       "sz-iepl-vip.nexus.local",
		InternalHost:     "10.10.0.1",
		PortRange:        "10000-30000",
		TrafficRate:      1.0,
		DefaultEngine:    protocol.EngineRealm,
		SupportedEngines: "native,gost,realm,nftables",
		SecretToken:      utils.GenerateRandomToken(32),
		Status:           "offline",
	}
	n2 := Node{
		Name:             "广州公网中转入口-02",
		GroupID:          g1.ID,
		Role:             "ingress",
		ServerIP:         "183.60.92.15",
		ConnectIP:        "gz-cmcc.nexus.local",
		PublicHost:       "gz-cmcc.nexus.local",
		InternalHost:     "183.60.92.15",
		PortRange:        "20000-40000",
		TrafficRate:      1.0,
		DefaultEngine:    protocol.EngineGost,
		SupportedEngines: "native,gost,realm,nftables",
		SecretToken:      utils.GenerateRandomToken(32),
		Status:           "offline",
	}
	n3 := Node{
		Name:             "香港 BGP 落地出口-01 (境外对接)",
		GroupID:          g2.ID,
		Role:             "egress",
		ServerIP:         "45.207.19.88",
		ConnectIP:        "hk-bgp-01.nexus.local",
		PublicHost:       "hk-bgp-01.nexus.local",
		InternalHost:     "45.207.19.88",
		PortRange:        "30001-55000",
		TrafficRate:      1.0,
		DefaultEngine:    protocol.EngineGost,
		SupportedEngines: "native,gost,realm",
		SecretToken:      utils.GenerateRandomToken(32),
		Status:           "offline",
	}
	db.Create(&n1)
	db.Create(&n2)
	db.Create(&n3)

	// 1. 直接转发隧道 (适用于专线或单台直连节点，直接转发无需选出口节点)
	directTunnel := TunnelLine{
		Name:           "深港 IEPL 专线直转隧道",
		Type:           "direct",
		Description:    "专线/直连节点直接创建端口转发，低延迟零额外封装开销",
		IngressNodeID:  n1.ID,
		EgressNodeID:   0,
		Transport:      "raw",
		Engine:         protocol.EngineRealm,
		BillingMode:    "one_way",
		RateMultiplier: 1.0,
		MaxPortCount:   50,
		Enabled:        true,
	}
	// 2. 加密对接隧道 (适用于国内公网入口 ↔ 国外出口节点加密隧道对接)
	encryptTunnel := TunnelLine{
		Name:           "广港跨网 TLS 加密对接隧道 (广州入口 ⇄ 香港出口)",
		Type:           "encrypt",
		Description:    "国内入口与国外出口自动建立加密隧道，隐藏国外落地 IP 并防阻断",
		IngressNodeID:  n2.ID,
		EgressNodeID:   n3.ID,
		Transport:      "tls",
		Engine:         protocol.EngineGost,
		BillingMode:    "two_way",
		RateMultiplier: 1.5,
		MaxPortCount:   50,
		Enabled:        true,
	}
	db.Create(&directTunnel)
	db.Create(&encryptTunnel)
}
