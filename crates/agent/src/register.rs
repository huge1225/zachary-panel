/// Agent 注册模块
/// 使用 install_token 向 Server 注册，获取 node_token
use crate::config::AgentConfig;
use tracing::{error, info};
use zachary_panel_common::AgentRegisterRequest;

/// 获取本机 Agent 版本
fn agent_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 获取系统信息
fn get_os_info() -> (String, String) {
    let os = sysinfo::System::long_os_version().unwrap_or_else(|| "unknown".into());
    let arch = std::env::consts::ARCH.to_string();
    (os, arch)
}

/// 获取公网 IP（可选，超时不阻塞注册）
async fn get_public_ip() -> Option<String> {
    let urls = [
        "https://api.ipify.org",
        "https://ifconfig.me",
        "https://icanhazip.com",
    ];
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;

    for url in urls {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// 向 Server 注册 Agent，返回 node_token
pub async fn register(config: &AgentConfig) -> anyhow::Result<String> {
    let install_token = config.install_token.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "No install_token provided. Set INSTALL_TOKEN env var or install_token in config.yaml"
        )
    })?;

    let (os, arch) = get_os_info();
    let public_ip = get_public_ip().await;

    // Runtime binary hash placeholder — in production, compute at build time via build.rs
    let agent_sha = format!("runtime_{}", agent_version());

    let req_body = AgentRegisterRequest {
        node_id: config.node_id.clone(),
        install_token: install_token.clone(),
        agent_version: agent_version(),
        agent_sha256: agent_sha,
        os,
        arch,
        public_ip,
    };

    let url = format!("{}/register", config.api_url());
    info!("Registering agent with server: {}", url);

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&req_body).send().await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
        let msg = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        error!("Registration failed: {} - {}", status, msg);
        anyhow::bail!("Registration failed: {}", msg);
    }

    let data = body
        .get("data")
        .ok_or_else(|| anyhow::anyhow!("No data in response"))?;
    let node_token = data
        .get("node_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No node_token in response"))?
        .to_string();

    let hb = data
        .get("heartbeat_interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    info!("✅ Agent registered! Heartbeat interval: {}s", hb);

    Ok(node_token)
}
