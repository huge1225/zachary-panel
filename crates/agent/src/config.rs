/// Agent 配置模块
/// 配置来源优先级：环境变量 > config.yaml > 默认值

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Server URL (e.g. "https://panel.example.com")
    pub server_url: String,
    /// Node ID (assigned by server when creating node)
    pub node_id: String,
    /// Node token (received after registration)
    #[serde(skip)]
    pub node_token: Option<String>,
    /// Install token (one-time, for registration only)
    pub install_token: Option<String>,
    /// WSS path (default: /ws/agent)
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    /// Reconnect base delay in seconds
    #[serde(default = "default_reconnect_base")]
    pub reconnect_base_delay: u64,
    /// Reconnect max delay in seconds
    #[serde(default = "default_reconnect_max")]
    pub reconnect_max_delay: u64,
    /// TLS verify server certificate
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// nftables binary path
    #[serde(default = "default_nft_path")]
    pub nft_path: String,
    /// gost binary path
    #[serde(default = "default_gost_path")]
    pub gost_path: String,
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Log file path (optional, stdout if empty)
    pub log_file: Option<String>,
}

impl AgentConfig {
    /// Load from file, then overlay environment variables
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut cfg = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            serde_yaml::from_str::<Self>(&content)?
        } else {
            Self::default()
        };

        // Environment overrides
        if let Ok(v) = std::env::var("SERVER_URL") { cfg.server_url = v; }
        if let Ok(v) = std::env::var("NODE_ID") { cfg.node_id = v; }
        if let Ok(v) = std::env::var("INSTALL_TOKEN") { cfg.install_token = Some(v); }
        if let Ok(v) = std::env::var("NODE_TOKEN") { cfg.node_token = Some(v); }
        if let Ok(v) = std::env::var("HEARTBEAT_INTERVAL") { cfg.heartbeat_interval = v.parse()?; }
        if let Ok(v) = std::env::var("TLS_VERIFY") { cfg.tls_verify = v.parse()?; }
        if let Ok(v) = std::env::var("LOG_LEVEL") { cfg.log_level = v; }

        Ok(cfg)
    }

    /// Full WebSocket URL
    pub fn ws_url(&self) -> String {
        let base = self.server_url
            .trim_end_matches('/')
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        format!("{}{}", base, self.ws_path)
    }

    /// API base URL
    pub fn api_url(&self) -> String {
        format!("{}/api/agent", self.server_url.trim_end_matches('/'))
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            node_id: String::new(),
            node_token: None,
            install_token: None,
            ws_path: default_ws_path(),
            heartbeat_interval: default_heartbeat_interval(),
            reconnect_base_delay: default_reconnect_base(),
            reconnect_max_delay: default_reconnect_max(),
            tls_verify: default_tls_verify(),
            nft_path: default_nft_path(),
            gost_path: default_gost_path(),
            log_level: default_log_level(),
            log_file: None,
        }
    }
}

fn default_ws_path() -> String { "/ws/agent".into() }
fn default_heartbeat_interval() -> u64 { 30 }
fn default_reconnect_base() -> u64 { 2 }
fn default_reconnect_max() -> u64 { 60 }
fn default_tls_verify() -> bool { true }
fn default_nft_path() -> String { "/usr/sbin/nft".into() }
fn default_gost_path() -> String { "/usr/local/bin/gost".into() }
fn default_log_level() -> String { "info".into() }
