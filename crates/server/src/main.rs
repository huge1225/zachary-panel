use zachary_panel_server::{app::AppState, config};

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    info!("Starting Zachary Panel Server v{}", env!("CARGO_PKG_VERSION"));

    let cfg = config::load()?;
    let pool = zachary_panel_server::db::init(&cfg).await?;
    let app_state = AppState::new(pool, cfg).await?;

    zachary_panel_server::routes::serve(app_state).await?;

    Ok(())
}
