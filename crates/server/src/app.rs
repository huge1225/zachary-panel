use crate::config::ServerConfig;
use crate::middleware::rate_limit::LoginLimiter;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 全局应用状态
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<ServerConfig>,
    /// Agent WebSocket 连接池：node_id → WebSocket sender
    pub agent_connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::UnboundedSender<String>>>>,
    /// 登录限流器
    pub login_limiter: Arc<LoginLimiter>,
}

impl AppState {
    pub async fn new(pool: SqlitePool, config: ServerConfig) -> anyhow::Result<Self> {
        // 初始化默认管理员
        Self::ensure_admin(&pool, &config).await?;

        Ok(Self {
            pool,
            config: Arc::new(config),
            agent_connections: Arc::new(RwLock::new(HashMap::new())),
            login_limiter: Arc::new(LoginLimiter::new(300, 10)), // 5分钟内最多10次
        })
    }

    async fn ensure_admin(pool: &SqlitePool, config: &ServerConfig) -> anyhow::Result<()> {
        use zachary_panel_common::hash_password;

        let existing =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?")
                .bind(&config.admin_username)
                .fetch_one(pool)
                .await?;

        if existing == 0 {
            let hash = hash_password(&config.admin_password)?;
            sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')")
                .bind(&config.admin_username)
                .bind(&hash)
                .execute(pool)
                .await?;

            tracing::info!("Default admin user created: {}", config.admin_username);
        }

        Ok(())
    }
}
