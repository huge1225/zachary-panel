use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tracing::info;

use crate::config::ServerConfig;

pub async fn init(config: &ServerConfig) -> anyhow::Result<SqlitePool> {
    info!("Connecting to database: {}", mask_db_url(&config.database_url));

    // 确保数据目录存在
    if config.database_url.starts_with("sqlite://") {
        let path = config.database_url.trim_start_matches("sqlite://");
        let path = path.split('?').next().unwrap_or(path);
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    // 启用 WAL 模式
    sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await?;
    sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;

    // 运行迁移
    zachary_panel_migration::run_migrations(&pool).await?;

    info!("Database initialized successfully");
    Ok(pool)
}

fn mask_db_url(url: &str) -> String {
    // Don't mask sqlite paths, just return as-is
    url.to_string()
}
