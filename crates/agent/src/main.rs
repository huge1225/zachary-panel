//! Zachary Panel Agent
//!
//! 多节点流量转发管理 Agent。
//! 功能：
//! - 使用 install_token 向 Server 注册，获取 node_token
//! - 通过 WSS 连接 Server（HMAC-SHA256 签名）
//! - 定期心跳上报节点状态
//! - 接收并执行 Server 下发的任务（nftables/gost 命令）
//! - 自动重连（指数退避）

mod config;
mod executor;
mod gost_manager;
mod register;
mod system;
mod ws;

use config::AgentConfig;
use tracing::{info, error, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load config
    let config_path = std::path::Path::new("agent.yaml");
    let config = AgentConfig::load(config_path)?;

    if config.server_url.is_empty() || config.node_id.is_empty() {
        eprintln!("Error: SERVER_URL and NODE_ID are required.");
        eprintln!("Set them via environment variables or in agent.yaml");
        std::process::exit(1);
    }

    // Setup logging
    let log_level: Level = config.log_level.parse().unwrap_or(Level::INFO);

    if let Some(ref log_file) = config.log_file {
        let file = std::fs::File::create(log_file)?;
        let appender = tracing_appender::non_blocking(file);
        let (non_blocking, _guard) = appender;
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_target(false)
            .init();
    }

    info!("🚀 Zachary Panel Agent v{}", env!("CARGO_PKG_VERSION"));
    info!("   Node ID: {}", config.node_id);
    info!("   Server:  {}", config.server_url);

    // Step 1: Register if we have install_token but no node_token
    let mut config = config;
    if config.node_token.is_none() {
        if config.install_token.is_some() {
            info!("No node_token found, registering...");
            match register::register(&config).await {
                Ok(token) => {
                    config.node_token = Some(token.clone());
                    // Persist token to file
                    if let Err(e) = save_node_token(&token) {
                        warn!("Failed to save node_token: {}", e);
                    } else {
                        info!("Node token saved to node_token");
                    }
                }
                Err(e) => {
                    error!("Registration failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Try loading saved token
            match load_node_token() {
                Ok(token) => {
                    info!("Loaded saved node_token");
                    config.node_token = Some(token);
                }
                _ => {
                    error!("No node_token and no install_token. Cannot connect.");
                    eprintln!("Error: Provide either NODE_TOKEN or INSTALL_TOKEN.");
                    std::process::exit(1);
                }
            }
        }
    }

    // Step 2: Connect to Server via WSS
    info!("Connecting to server...");
    ws::run(config).await;

    Ok(())
}

/// Save node_token to file
fn save_node_token(token: &str) -> std::io::Result<()> {
    // Only write if file doesn't exist or is empty (one-time token shouldn't be overwritten)
    if !std::path::Path::new("node_token").exists() {
        std::fs::write("node_token", token)
    } else {
        Ok(())
    }
}

/// Load node_token from file
fn load_node_token() -> anyhow::Result<String> {
    let token = std::fs::read_to_string("node_token")?;
    let token = token.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("Empty node_token file");
    }
    Ok(token)
}
