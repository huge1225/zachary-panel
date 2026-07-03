use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tower_http::{cors::{CorsLayer, Any}, services::{ServeDir, ServeFile}};
use tracing::info;
use std::path::PathBuf;

use crate::app::AppState;
use crate::handlers;
use crate::middleware;

pub async fn serve(state: AppState) -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let addr = state.config.listen_addr();
    info!("Server listening on {}", addr);

    let app = Router::new()
        // 认证路由（无 JWT 中间件）
        .nest("/api/auth", auth_routes())
        // Agent 注册 API（无需 JWT，但需要 install_token 验证）
        .route("/api/agent/register", axum::routing::post(handlers::agent::register))
        // Agent WebSocket 路由
        .route("/ws/agent", get(handlers::agent::ws_handler))
        // 受保护路由
        .nest("/api", protected_routes(state.clone()))
        // 静态文件（前端 SPA）
        .fallback_service(serve_frontend())
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/login", axum::routing::post(handlers::auth::login))
        .route("/logout", axum::routing::post(handlers::auth::logout))
        .route("/me", axum::routing::get(handlers::auth::me))
        .route("/change-password", axum::routing::post(handlers::auth::change_password))
}

fn protected_routes(state: AppState) -> Router<AppState> {
    Router::new()
        // 仪表盘
        .route("/dashboard", get(handlers::dashboard::get))
        // 节点管理
        .nest("/nodes", node_routes())
        // 转发规则
        .nest("/rules", rule_routes())
        // 任务
        .nest("/tasks", task_routes())
        // 延迟测试
        .nest("/latency-tests", latency_test_routes())
        // 安全事件
        .nest("/security-events", security_event_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::jwt_auth,
        ))
}

fn node_routes() -> Router<AppState> {
    Router::new()
        .route("/", axum::routing::get(handlers::node::list))
        .route("/", axum::routing::post(handlers::node::create))
        .route("/{id}", axum::routing::get(handlers::node::get))
        .route("/{id}", axum::routing::put(handlers::node::update))
        .route("/{id}", axum::routing::delete(handlers::node::delete))
        .route("/{id}/disable", axum::routing::post(handlers::node::disable))
        .route("/{id}/enable", axum::routing::post(handlers::node::enable))
        .route("/{id}/regenerate-token", axum::routing::post(handlers::node::regenerate_token))
        .route("/{id}/install-command", axum::routing::get(handlers::node::install_command))
        .route("/{id}/security", axum::routing::get(handlers::node::security_status))
        .route("/{id}/quality", axum::routing::get(handlers::node::quality))
        .route("/{id}/latency-test", axum::routing::post(handlers::node::latency_test))
}

fn rule_routes() -> Router<AppState> {
    Router::new()
        .route("/", axum::routing::get(handlers::rule::list))
        .route("/", axum::routing::post(handlers::rule::create))
        .route("/{id}", axum::routing::get(handlers::rule::get))
        .route("/{id}", axum::routing::put(handlers::rule::update))
        .route("/{id}", axum::routing::delete(handlers::rule::delete))
        .route("/{id}/start", axum::routing::post(handlers::rule::start))
        .route("/{id}/stop", axum::routing::post(handlers::rule::stop))
        .route("/{id}/restart", axum::routing::post(handlers::rule::restart))
        .route("/{id}/test-listen", axum::routing::post(handlers::rule::test_listen))
        .route("/{id}/test-target", axum::routing::post(handlers::rule::test_target))
        .route("/{id}/test-chain", axum::routing::post(handlers::rule::test_chain))
}

fn task_routes() -> Router<AppState> {
    Router::new()
        .route("/", axum::routing::get(handlers::task::list))
        .route("/{id}", axum::routing::get(handlers::task::get))
}

fn latency_test_routes() -> Router<AppState> {
    Router::new()
        .route("/", axum::routing::get(handlers::latency_test::list))
        .route("/{id}", axum::routing::get(handlers::latency_test::get))
        .route("/{id}", axum::routing::delete(handlers::latency_test::delete))
        .route("/single", axum::routing::post(handlers::latency_test::single))
        .route("/batch", axum::routing::post(handlers::latency_test::batch))
}

fn security_event_routes() -> Router<AppState> {
    Router::new()
        .route("/", axum::routing::get(handlers::security::list))
        .route("/{id}", axum::routing::get(handlers::security::get))
}

/// Serve frontend SPA static files
/// Serves from frontend/dist/ if it exists, otherwise returns 404
fn serve_frontend() -> axum::Router {
    let dist = PathBuf::from("frontend/dist");
    if dist.join("index.html").exists() {
        let index = ServeFile::new(dist.join("index.html"));
        Router::new().nest_service("/", ServeDir::new(dist).fallback(index))
    } else {
        // No frontend built yet — 404 for non-API routes
        Router::new().fallback(|| async {
            (axum::http::StatusCode::NOT_FOUND, "Frontend not built. Run: cd frontend && npm run build")
        })
    }
}
