use axum::{routing::get, Router};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};
use tracing::info;

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
        .route(
            "/api/auth/login",
            axum::routing::post(handlers::auth::login),
        )
        .route(
            "/api/auth/logout",
            axum::routing::post(handlers::auth::logout),
        )
        .route("/api/auth/me", axum::routing::get(handlers::auth::me))
        .route(
            "/api/auth/change-password",
            axum::routing::post(handlers::auth::change_password),
        )
        // Agent 注册 API（无需 JWT，但需要 install_token 验证）
        .route(
            "/api/agent/register",
            axum::routing::post(handlers::agent::register),
        )
        // Agent WebSocket 路由
        .route("/ws/agent", get(handlers::agent::ws_handler))
        // 受保护路由（JWT 中间件）
        .route("/api/dashboard", get(handlers::dashboard::get))
        // 节点管理
        .route("/api/nodes", axum::routing::get(handlers::node::list))
        .route("/api/nodes", axum::routing::post(handlers::node::create))
        .route("/api/nodes/{id}", axum::routing::get(handlers::node::get))
        .route(
            "/api/nodes/{id}",
            axum::routing::put(handlers::node::update),
        )
        .route(
            "/api/nodes/{id}",
            axum::routing::delete(handlers::node::delete),
        )
        .route(
            "/api/nodes/{id}/disable",
            axum::routing::post(handlers::node::disable),
        )
        .route(
            "/api/nodes/{id}/enable",
            axum::routing::post(handlers::node::enable),
        )
        .route(
            "/api/nodes/{id}/regenerate-token",
            axum::routing::post(handlers::node::regenerate_token),
        )
        .route(
            "/api/nodes/{id}/install-command",
            axum::routing::get(handlers::node::install_command),
        )
        .route(
            "/api/nodes/{id}/security",
            axum::routing::get(handlers::node::security_status),
        )
        .route(
            "/api/nodes/{id}/quality",
            axum::routing::get(handlers::node::quality),
        )
        .route(
            "/api/nodes/{id}/latency-test",
            axum::routing::post(handlers::node::latency_test),
        )
        // 转发规则
        .route("/api/rules", axum::routing::get(handlers::rule::list))
        .route("/api/rules", axum::routing::post(handlers::rule::create))
        .route("/api/rules/{id}", axum::routing::get(handlers::rule::get))
        .route(
            "/api/rules/{id}",
            axum::routing::put(handlers::rule::update),
        )
        .route(
            "/api/rules/{id}",
            axum::routing::delete(handlers::rule::delete),
        )
        .route(
            "/api/rules/{id}/start",
            axum::routing::post(handlers::rule::start),
        )
        .route(
            "/api/rules/{id}/stop",
            axum::routing::post(handlers::rule::stop),
        )
        .route(
            "/api/rules/{id}/restart",
            axum::routing::post(handlers::rule::restart),
        )
        .route(
            "/api/rules/{id}/test-listen",
            axum::routing::post(handlers::rule::test_listen),
        )
        .route(
            "/api/rules/{id}/test-target",
            axum::routing::post(handlers::rule::test_target),
        )
        .route(
            "/api/rules/{id}/test-chain",
            axum::routing::post(handlers::rule::test_chain),
        )
        // 任务
        .route("/api/tasks", axum::routing::get(handlers::task::list))
        .route("/api/tasks/{id}", axum::routing::get(handlers::task::get))
        // 延迟测试
        .route(
            "/api/latency-tests",
            axum::routing::get(handlers::latency_test::list),
        )
        .route(
            "/api/latency-tests/{id}",
            axum::routing::get(handlers::latency_test::get),
        )
        .route(
            "/api/latency-tests/{id}",
            axum::routing::delete(handlers::latency_test::delete),
        )
        .route(
            "/api/latency-tests/single",
            axum::routing::post(handlers::latency_test::single),
        )
        .route(
            "/api/latency-tests/batch",
            axum::routing::post(handlers::latency_test::batch),
        )
        // 安全事件
        .route(
            "/api/security-events",
            axum::routing::get(handlers::security::list),
        )
        .route(
            "/api/security-events/{id}",
            axum::routing::get(handlers::security::get),
        )
        // 安装脚本（必须在 SPA fallback 之前）
        .route_service(
            "/install-agent.sh",
            ServeFile::new_with_mime(
                "deploy/install-agent.sh",
                &"text/x-shellscript".parse().unwrap(),
            ),
        )
        .route_service(
            "/install-server.sh",
            ServeFile::new_with_mime(
                "deploy/install-server.sh",
                &"text/x-shellscript".parse().unwrap(),
            ),
        )
        // 静态文件（前端 SPA）
        .fallback_service(serve_frontend_service())
        .layer(cors)
        // JWT 中间件（应用到 /api/* 受保护路由）
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::jwt_auth_skip_auth_routes,
        ))
        .with_state(state);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve frontend SPA static files
/// Returns a ServeDir that can be used as fallback_service
fn serve_frontend_service() -> ServeDir<ServeFile> {
    ServeDir::new("frontend/dist").fallback(ServeFile::new("frontend/dist/index.html"))
}
