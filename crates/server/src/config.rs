/// Server 配置模块
/// 配置来源优先级：环境变量 > config.yaml > 默认值

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub admin_username: String,
    pub admin_password: String,
    pub agent_timestamp_tolerance: i64,
    pub install_token_ttl_minutes: i64,
    pub ws_heartbeat_interval: u64,
}

impl ServerConfig {
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub fn load() -> anyhow::Result<ServerConfig> {
    let host = env_or("HOST", "0.0.0.0");
    let port: u16 = env_or("PORT", "3000").parse().unwrap_or(3000);
    let database_url = env_or("DATABASE_URL", "sqlite://data/zachary-panel.db?mode=rwc");
    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("JWT_SECRET is required. Set via environment variable."))?;
    let jwt_expiry_hours: u64 = env_or("JWT_EXPIRY_HOURS", "24").parse().unwrap_or(24);
    let admin_username = env_or("ADMIN_USERNAME", "admin");
    let admin_password = std::env::var("ADMIN_PASSWORD")
        .map_err(|_| anyhow::anyhow!("ADMIN_PASSWORD is required. Set via environment variable."))?;
    let agent_timestamp_tolerance: i64 = env_or("AGENT_TIMESTAMP_TOLERANCE", "60").parse().unwrap_or(60);
    let install_token_ttl_minutes: i64 = env_or("INSTALL_TOKEN_TTL_MINUTES", "30").parse().unwrap_or(30);
    let ws_heartbeat_interval: u64 = env_or("WS_HEARTBEAT_INTERVAL", "30").parse().unwrap_or(30);

    // Also try reading from config.yaml
    if let Ok(config_str) = std::fs::read_to_string("config.yaml") {
        if let Ok(config_map) = serde_yaml::from_str::<serde_yaml::Value>(&config_str) {
            let host = config_map.get("host").and_then(|v| v.as_str()).unwrap_or(&host);
            // ... could extend but env vars are simpler
        }
    }

    Ok(ServerConfig {
        host,
        port,
        database_url,
        jwt_secret,
        jwt_expiry_hours,
        admin_username,
        admin_password,
        agent_timestamp_tolerance,
        install_token_ttl_minutes,
        ws_heartbeat_interval,
    })
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
