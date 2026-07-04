use axum::{
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json},
};
use zachary_panel_common::ApiResponse;

use crate::services::jwt;
use crate::AppState;

/// JWT 认证中间件
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
