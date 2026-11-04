package protocol

import "time"

// EngineType defines the forwarding engine driver selectable from the panel.
type EngineType string

const (
	EngineNative   EngineType = "native"   // 内置纯 Go 转发与自研加密隧道底座
	EngineGost     EngineType = "gost"     // GOST v3 引擎驱动
	EngineRealm    EngineType = "realm"    // Realm 高性能直转引擎驱动
	EngineNftables EngineType = "nftables" // Linux 内核态 nftables 零拷贝驱动
)

// RuleRole indicates how a node participates in a forwarding rule.
type RuleRole string

const (
	RoleRelay   RuleRole = "relay"   // 单端直转
	RoleIngress RuleRole = "ingress" // 隧道/专线入口封装
	RoleEgress  RuleRole = "egress"  // 隧道/专线出口解包
)

// MessageType represents the WebSocket message type between Master and Agent.
type MessageType string

const (
	MsgAgentRegister  MessageType = "agent.register"   // Agent -> Master: 握手注册与上报支持的引擎
	MsgAgentHeartbeat MessageType = "agent.heartbeat"  // Agent -> Master: 系统状态与监控心跳
	MsgTrafficReport  MessageType = "agent.traffic"    // Agent -> Master: 规则增量流量上报
	MsgProbeResult    MessageType = "agent.probe_res"  // Agent -> Master: 延迟/连通性探测结果
	MsgRuleStatusAck  MessageType = "agent.rule_ack"   // Agent -> Master: 规则下发执行结果回执

	MsgSyncAllRules   MessageType = "master.sync_all"  // Master -> Agent: 全量同步转发规则
	MsgApplyRule      MessageType = "master.apply"     // Master -> Agent: 新增或热更新单条规则
	MsgRemoveRule     MessageType = "master.remove"    // Master -> Agent: 停止并移除单条规则
	MsgProbeTask      MessageType = "master.probe"     // Master -> Agent: 触发目标/出口端到端探测
)

// Envelope wraps all Master <-> Agent messages with anti-replay Nonce and HMAC-SHA256 Signature.
type Envelope struct {
	Type      MessageType `json:"type"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp int64       `json:"timestamp"`
	Nonce     string      `json:"nonce,omitempty"`
	Signature string      `json:"signature,omitempty"`
	Payload   any         `json:"payload"`
}

// AgentRegisterPayload is sent upon WebSocket connection initialization.
type AgentRegisterPayload struct {
	NodeID           uint64       `json:"node_id"`
	AgentVersion     string       `json:"agent_version"`
	OS               string       `json:"os"`
	Arch             string       `json:"arch"`
	SupportedEngines []EngineType `json:"supported_engines"`
}

// AgentHeartbeatPayload reports live node probe metrics (CPU, Memory, Disk, Load, Network, Connections) to the Master.
type AgentHeartbeatPayload struct {
	NodeID           uint64       `json:"node_id"`
	CPUCores         int          `json:"cpu_cores"`
	CPUUsagePercent  float64      `json:"cpu_usage_percent"`
	Load1            float64      `json:"load_1"`
	Load5            float64      `json:"load_5"`
	Load15           float64      `json:"load_15"`
	MemUsedBytes     uint64       `json:"mem_used_bytes"`
	MemTotalBytes    uint64       `json:"mem_total_bytes"`
	MemUsagePercent  float64      `json:"mem_usage_percent"`
	DiskUsedBytes    uint64       `json:"disk_used_bytes"`
	DiskTotalBytes   uint64       `json:"disk_total_bytes"`
	DiskUsagePercent float64      `json:"disk_usage_percent"`
	NetRxBytesPerS   uint64       `json:"net_rx_bytes_per_s"`
	NetTxBytesPerS   uint64       `json:"net_tx_bytes_per_s"`
	ActiveRules      int          `json:"active_rules"`
	ActiveConns      int64        `json:"active_conns"`
	SupportedEngines []EngineType `json:"supported_engines"`
	UptimeSeconds    int64        `json:"uptime_seconds"`
}

// TargetEndpoint represents an upstream destination and its weight/priority.
type TargetEndpoint struct {
	Address  string `json:"address"`            // IP:Port or Domain:Port
	Weight   int    `json:"weight,omitempty"`   // 权重
	Backup   bool   `json:"backup,omitempty"`   // 是否为主备模式下的备用节点
}

// TunnelConfig holds parameters for encrypted/dedicated tunnel transport between Ingress and Egress.
type TunnelConfig struct {
	Transport   string `json:"transport"`              // "raw" | "tls" | "ws" | "wss" | "quic" | "custom"
	SecretKey   string `json:"secret_key,omitempty"`   // 隧道握手机密令牌或预共享密钥
	SNI         string `json:"sni,omitempty"`          // TLS 伪装域名
	WSPath      string `json:"ws_path,omitempty"`      // WebSocket 路径
	EnableMux   bool   `json:"enable_mux,omitempty"`   // 多路复用减少握手延迟
	ProxyProto  int    `json:"proxy_proto,omitempty"`  // 0: 关闭, 1: v1, 2: v2
}

// RuleSpec describes a single runtime rule dispatched to an Agent (either Relay, Ingress, or Egress).
type RuleSpec struct {
	RuleID         uint64           `json:"rule_id"`
	UserID         uint64           `json:"user_id"`
	Name           string           `json:"name"`
	Role           RuleRole         `json:"role"`             // relay | ingress | egress
	Engine         EngineType       `json:"engine"`           // native | gost | realm | nftables
	Protocol       string           `json:"protocol"`         // tcp | udp | both
	ListenHost     string           `json:"listen_host"`      // 默认 0.0.0.0 或内网绑定 IP
	ListenPort     int              `json:"listen_port"`      // 本地监听端口
	LoadBalance    string           `json:"load_balance"`     // round_robin | random | failover
	Targets        []TargetEndpoint `json:"targets"`          // 转发目标列表 (Ingress 角色下为出口节点的隧道地址)
	Tunnel         *TunnelConfig    `json:"tunnel,omitempty"` // 隧道参数
	SpeedLimitMbps int              `json:"speed_limit_mbps"` // 单规则/用户带宽上限 (Mbps, 0 表示不限速)
	MaxConns       int              `json:"max_conns"`        // 最大并发连接数限制
	UpdatedAt      time.Time        `json:"updated_at"`
}

// SyncAllRulesPayload pushes the complete desired state of rules to an Agent.
type SyncAllRulesPayload struct {
	Rules        []RuleSpec `json:"rules"`
	ForceRestart bool       `json:"force_restart,omitempty"`
}

// RemoveRulePayload instructs an Agent to stop and delete a rule.
type RemoveRulePayload struct {
	RuleID uint64   `json:"rule_id"`
	Role   RuleRole `json:"role"`
}

// RuleTrafficDelta reports incremental byte usage for a single rule over the reporting window.
type RuleTrafficDelta struct {
	RuleID      uint64     `json:"rule_id"`
	Role        RuleRole   `json:"role"`
	Engine      EngineType `json:"engine"`
	UploadBytes int64      `json:"upload_bytes"`
	DownBytes   int64      `json:"down_bytes"`
	ActiveConns int64      `json:"active_conns"`
}

// TrafficReportPayload batches rule traffic deltas from an Agent.
type TrafficReportPayload struct {
	NodeID    uint64             `json:"node_id"`
	Timestamp int64              `json:"timestamp"`
	Deltas    []RuleTrafficDelta `json:"deltas"`
}

// RuleStatusAckPayload confirms whether a rule was successfully applied by the Agent's engine.
type RuleStatusAckPayload struct {
	RuleID  uint64     `json:"rule_id"`
	Role    RuleRole   `json:"role"`
	Engine  EngineType `json:"engine"`
	Success bool       `json:"success"`
	Error   string     `json:"error,omitempty"`
}

// ProbeTaskPayload requests the Agent to test TCP latency to targets.
type ProbeTaskPayload struct {
	RuleID  uint64   `json:"rule_id"`
	Targets []string `json:"targets"`
}

// ProbeResultPayload returns latency measurements in milliseconds (-1 if unreachable).
type ProbeResultPayload struct {
	NodeID    uint64         `json:"node_id"`
	RuleID    uint64         `json:"rule_id"`
	Latencies map[string]int `json:"latencies"`
}
