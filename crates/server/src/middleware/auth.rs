use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use zachary_panel_common::ApiResponse;

use crate::services::jwt;
use crate::AppState;

/// 无需 JWT 认证的路径前缀
const SKIP_PREFIXES: &[&str] = &[
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/change-password",
    "/api/agent/register",
    "/ws/",
];

/// JWT 认证中间件（跳过公开路由）
pub async fn jwt_auth_skip_auth_routes(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let path = req.uri().path();

    // 跳过无需认证的路由
    if SKIP_PREFIXES.iter().any(|prefix| path.starts_with(prefix)) {
        return next.run(req).await;
    }

    // 非公开的 /api/* 路由需要 JWT
    if !path.starts_with("/api/") {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match auth_header {
        Some(token) => match jwt::verify_token(token, &state.config.jwt_secret) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
                next.run(req).await
            }
            Err(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(40100, "Invalid or expired token")),
            )
                .into_response(),
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                40100,
                "Missing authorization header",
            )),
        )
            .into_response(),
    }
}

/// JWT 认证中间件（严格模式，所有请求都需要认证）
pub async fn jwt_auth(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match auth_header {
        Some(token) => match jwt::verify_token(token, &state.config.jwt_secret) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
                next.run(req).await
            }
            Err(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(40100, "Invalid or expired token")),
            )
                .into_response(),
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error(
                40100,
                "Missing authorization header",
            )),
        )
            .into_response(),
    }
}
