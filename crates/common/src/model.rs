/// 核心数据模型
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// 枚举定义
// ═══════════════════════════════════════════════════════════════════

/// 节点状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    Offline,
    Disabled,
    Error,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Online => "online",
            NodeStatus::Offline => "offline",
            NodeStatus::Disabled => "disabled",
            NodeStatus::Error => "error",
        }
    }
}

/// 转发模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    Nft,
    Gost,
}

impl ForwardMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForwardMode::Nft => "nft",
            ForwardMode::Gost => "gost",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nft" => Some(ForwardMode::Nft),
            "gost" => Some(ForwardMode::Gost),
            _ => None,
        }
    }
}

/// 转发协议
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocol {
    Tcp,
    Udp,
    TcpUdp,
}

impl ForwardProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForwardProtocol::Tcp => "tcp",
            ForwardProtocol::Udp => "udp",
            ForwardProtocol::TcpUdp => "tcp_udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(ForwardProtocol::Tcp),
            "udp" => Some(ForwardProtocol::Udp),
            "tcp_udp" => Some(ForwardProtocol::TcpUdp),
            _ => None,
        }
    }

    pub fn contains_tcp(&self) -> bool {
        matches!(self, ForwardProtocol::Tcp | ForwardProtocol::TcpUdp)
    }

    pub fn contains_udp(&self) -> bool {
        matches!(self, ForwardProtocol::Udp | ForwardProtocol::TcpUdp)
    }
}

/// 隧道类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    Plain,
    Ws,
    Wss,
}

impl TunnelType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TunnelType::Plain => "plain",
            TunnelType::Ws => "ws",
            TunnelType::Wss => "wss",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "plain" => Some(TunnelType::Plain),
            "ws" => Some(TunnelType::Ws),
            "wss" => Some(TunnelType::Wss),
            _ => None,
        }
    }
}

/// 认证方式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    None,
    Basic,
    Token,
}

/// 规则状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Running,
    Stopped,
    Failed,
    Unknown,
}

impl RuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleStatus::Running => "running",
            RuleStatus::Stopped => "stopped",
            RuleStatus::Failed => "failed",
            RuleStatus::Unknown => "unknown",
        }
    }
}

/// 任务类型 - 白名单枚举
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    CreateForwardRule,
    UpdateForwardRule,
    DeleteForwardRule,
    StartForwardRule,
    StopForwardRule,
    RestartForwardRule,
    CheckPort,
    CheckTarget,
    ReloadNftables,
    InstallGost,
    CheckGostVersion,
    GetSystemInfo,
    LatencyTest,
    BatchLatencyTest,
    CheckListenPort,
    CheckTargetReachable,
    CheckForwardChain,
    DnsResolveTest,
    HttpPingTest,
    TcpPingTest,
    IcmpPingTest,
}

impl TaskType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskType::CreateForwardRule => "create_forward_rule",
            TaskType::UpdateForwardRule => "update_forward_rule",
            TaskType::DeleteForwardRule => "delete_forward_rule",
            TaskType::StartForwardRule => "start_forward_rule",
            TaskType::StopForwardRule => "stop_forward_rule",
            TaskType::RestartForwardRule => "restart_forward_rule",
            TaskType::CheckPort => "check_port",
            TaskType::CheckTarget => "check_target",
            TaskType::ReloadNftables => "reload_nftables",
            TaskType::InstallGost => "install_gost",
            TaskType::CheckGostVersion => "check_gost_version",
            TaskType::GetSystemInfo => "get_system_info",
            TaskType::LatencyTest => "latency_test",
            TaskType::BatchLatencyTest => "batch_latency_test",
            TaskType::CheckListenPort => "check_listen_port",
            TaskType::CheckTargetReachable => "check_target_reachable",
            TaskType::CheckForwardChain => "check_forward_chain",
            TaskType::DnsResolveTest => "dns_resolve_test",
            TaskType::HttpPingTest => "http_ping_test",
            TaskType::TcpPingTest => "tcp_ping_test",
            TaskType::IcmpPingTest => "icmp_ping_test",
        }
    }

    /// 白名单验证 - 只有这些类型可以被 Agent 执行
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "create_forward_rule" => Some(TaskType::CreateForwardRule),
            "update_forward_rule" => Some(TaskType::UpdateForwardRule),
            "delete_forward_rule" => Some(TaskType::DeleteForwardRule),
            "start_forward_rule" => Some(TaskType::StartForwardRule),
            "stop_forward_rule" => Some(TaskType::StopForwardRule),
            "restart_forward_rule" => Some(TaskType::RestartForwardRule),
            "check_port" => Some(TaskType::CheckPort),
            "check_target" => Some(TaskType::CheckTarget),
            "reload_nftables" => Some(TaskType::ReloadNftables),
            "install_gost" => Some(TaskType::InstallGost),
            "check_gost_version" => Some(TaskType::CheckGostVersion),
            "get_system_info" => Some(TaskType::GetSystemInfo),
            "latency_test" => Some(TaskType::LatencyTest),
            "batch_latency_test" => Some(TaskType::BatchLatencyTest),
            "check_listen_port" => Some(TaskType::CheckListenPort),
            "check_target_reachable" => Some(TaskType::CheckTargetReachable),
            "check_forward_chain" => Some(TaskType::CheckForwardChain),
            "dns_resolve_test" => Some(TaskType::DnsResolveTest),
            "http_ping_test" => Some(TaskType::HttpPingTest),
            "tcp_ping_test" => Some(TaskType::TcpPingTest),
            "icmp_ping_test" => Some(TaskType::IcmpPingTest),
            _ => None,
        }
    }
}

/// 任务状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Running,
    Success,
    Failed,
    Timeout,
    Cancelled,
}

/// 延迟测试类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LatencyTestType {
    Icmp,
    Tcp,
    Http,
    Dns,
}

/// 测试状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Pending,
    Running,
    Success,
    Failed,
    PartialFailed,
}

/// 安全事件严重级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    Info,
    Warning,
    Critical,
}

// ═══════════════════════════════════════════════════════════════════
// 节点模型
// ═══════════════════════════════════════════════════════════════════

/// 创建节点请求
#[derive(Debug, Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    pub public_ip: Option<String>,
    pub remark: Option<String>,
}

/// 更新节点请求
#[derive(Debug, Deserialize)]
pub struct UpdateNodeRequest {
    pub name: Option<String>,
    pub public_ip: Option<String>,
    pub remark: Option<String>,
}

/// 节点详情
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeInfo {
    pub id: i64,
    pub node_id: String,
    pub name: String,
    pub public_ip: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub agent_version: Option<String>,
    pub agent_sha256: Option<String>,
    pub gost_version: Option<String>,
    pub nft_status: String,
    pub gost_status: String,
    pub status: String,
    pub tls_verify: bool,
    pub tls_pinning: bool,
    pub last_signature_verified_at: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub last_task_at: Option<String>,
    pub last_ip: Option<String>,
    pub security_alerts: String,
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 安装命令响应
#[derive(Debug, Serialize)]
pub struct InstallCommandResponse {
    pub command: String,
    pub expires_at: String,
}

/// 节点安全状态
#[derive(Debug, Serialize)]
pub struct NodeSecurityStatus {
    pub node_id: String,
    pub agent_online: bool,
    pub agent_version: Option<String>,
    pub agent_sha256: Option<String>,
    pub tls_verify: bool,
    pub tls_pinning: bool,
    pub last_signature_verified_at: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub last_task_at: Option<String>,
    pub failed_task_count: u64,
    pub security_alerts: serde_json::Value,
    pub enabled: bool,
}

/// 节点质量统计
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeQualityStats {
    pub id: i64,
    pub node_id: String,
    pub target_addr: Option<String>,
    pub target_port: Option<i32>,
    pub test_type: String,
    pub avg_latency_ms: Option<f64>,
    pub loss_rate: f64,
    pub jitter_ms: Option<f64>,
    pub status: String,
    pub collected_at: String,
}

// ═══════════════════════════════════════════════════════════════════
// 转发规则模型
// ═══════════════════════════════════════════════════════════════════

/// 创建转发规则请求
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub node_id: String,
    pub mode: String,
    pub protocol: String,
    pub listen_addr: Option<String>,
    pub listen_port: i32,
    pub target_addr: String,
    pub target_port: i32,
    pub tunnel_type: Option<String>,
    pub ws_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_skip_verify: Option<bool>,
    pub auth_type: Option<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub auth_token: Option<String>,
    pub enabled: Option<bool>,
    pub remark: Option<String>,
}

/// 更新转发规则请求
#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub mode: Option<String>,
    pub protocol: Option<String>,
    pub listen_addr: Option<String>,
    pub listen_port: Option<i32>,
    pub target_addr: Option<String>,
    pub target_port: Option<i32>,
    pub tunnel_type: Option<String>,
    pub ws_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_skip_verify: Option<bool>,
    pub auth_type: Option<String>,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub auth_token: Option<String>,
    pub enabled: Option<bool>,
    pub remark: Option<String>,
}

/// 转发规则详情
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ForwardRuleInfo {
    pub id: i64,
    pub name: String,
    pub node_id: String,
    pub node_name: Option<String>,
    pub mode: String,
    pub protocol: String,
    pub listen_addr: String,
    pub listen_port: i32,
    pub target_addr: String,
    pub target_port: i32,
    pub tunnel_type: String,
    pub ws_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_skip_verify: bool,
    pub auth_type: Option<String>,
    pub auth_username: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ═══════════════════════════════════════════════════════════════════
// 任务模型
// ═══════════════════════════════════════════════════════════════════

/// 任务详情
#[derive(Debug, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: i64,
    pub task_id: String,
    pub node_id: String,
    pub node_name: Option<String>,
    pub r#type: String,
    pub payload: String,
    pub status: String,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// 任务执行结果（Agent → Server）
#[derive(Debug, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    pub message: String,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub finished_at: String,
}

// ═══════════════════════════════════════════════════════════════════
// Agent 注册 / 心跳 / 通信模型
// ═══════════════════════════════════════════════════════════════════

/// Agent 注册请求
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentRegisterRequest {
    pub node_id: String,
    pub install_token: String,
    pub agent_version: String,
    pub agent_sha256: String,
    pub os: String,
    pub arch: String,
    pub public_ip: Option<String>,
}

/// Agent 注册响应
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentRegisterResponse {
    pub node_token: String,
    pub heartbeat_interval: u64,
}

/// 心跳请求 payload
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub status: String,
    pub load_avg: [f64; 3],
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub uptime_seconds: u64,
    pub nft_status: String,
    pub gost_status: String,
    pub gost_version: Option<String>,
    pub agent_version: String,
}

/// 心跳请求（Agent WebSocket → Server）
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub payload: HeartbeatPayload,
}

/// WS 消息封装 - Agent 发送方向
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentWsMessage {
    #[serde(rename = "heartbeat")]
    Heartbeat {
        node_id: String,
        timestamp: String,
        nonce: String,
        signature: String,
        payload: HeartbeatPayload,
    },
    #[serde(rename = "task_result")]
    TaskResult {
        node_id: String,
        timestamp: String,
        nonce: String,
        signature: String,
        payload: TaskResult,
    },
    #[serde(rename = "system_info")]
    SystemInfo {
        node_id: String,
        timestamp: String,
        nonce: String,
        signature: String,
        payload: SystemInfoPayload,
    },
}

/// WS 消息封装 - Server 发送方向
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerWsMessage {
    #[serde(rename = "task")]
    Task {
        task_id: String,
        task_type: String,
        timestamp: String,
        nonce: String,
        signature: String,
        payload: serde_json::Value,
    },
    #[serde(rename = "heartbeat_ack")]
    HeartbeatAck { timestamp: String },
    #[serde(rename = "shutdown")]
    Shutdown { reason: String },
}

// ═══════════════════════════════════════════════════════════════════
// 系统信息
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInfoPayload {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpu_cores: usize,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub load_avg: [f64; 3],
    pub uptime_seconds: u64,
}

// ═══════════════════════════════════════════════════════════════════
// 延迟测试模型
// ═══════════════════════════════════════════════════════════════════

/// 延迟测试请求
#[derive(Debug, Deserialize)]
pub struct LatencyTestRequest {
    pub node_id: Option<String>,
    pub node_ids: Option<Vec<String>>,
    pub test_type: String,
    pub target_addr: String,
    pub target_port: Option<i32>,
    pub count: Option<i32>,
    pub timeout_ms: Option<i32>,
}

/// 延迟测试结果
#[derive(Debug, Serialize, Deserialize)]
pub struct LatencyTestResult {
    pub test_id: String,
    pub node_id: Option<String>,
    pub rule_id: Option<i64>,
    pub test_type: String,
    pub target_addr: String,
    pub target_port: Option<i32>,
    pub count: i32,
    pub timeout_ms: i32,
    pub interval_ms: i32,
    pub success_count: i32,
    pub fail_count: i32,
    pub loss_rate: f64,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub avg_latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub http_status: Option<i32>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
// 安全事件 / 审计日志
// ═══════════════════════════════════════════════════════════════════

/// 安全事件
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub node_id: Option<String>,
    pub node_name: Option<String>,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
}

/// 操作日志
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationLog {
    pub id: i64,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub detail: Option<String>,
    pub ip: Option<String>,
    pub created_at: String,
}

// ═══════════════════════════════════════════════════════════════════
// 仪表盘
// ═══════════════════════════════════════════════════════════════════

/// 仪表盘数据
#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub nodes: DashboardNodes,
    pub rules: DashboardRules,
    pub traffic_today: DashboardTraffic,
    pub avg_latency_ms: Option<f64>,
    pub high_latency_nodes: u64,
    pub recent_heartbeats: Vec<NodeInfo>,
    pub recent_failed_tasks: Vec<TaskInfo>,
    pub recent_security_events: Vec<SecurityEvent>,
}

#[derive(Debug, Serialize)]
pub struct DashboardNodes {
    pub total: u64,
    pub online: u64,
    pub offline: u64,
    pub disabled: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardRules {
    pub total: u64,
    pub running: u64,
    pub stopped: u64,
}

#[derive(Debug, Serialize)]
pub struct DashboardTraffic {
    pub bytes_in: i64,
    pub bytes_out: i64,
}
