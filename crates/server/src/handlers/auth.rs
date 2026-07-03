use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use zachary_panel_common::{
    JwtClaims, LoginRequest, ChangePasswordRequest, verify_password, hash_password,
};
use sqlx::Row;

use crate::AppState;
use crate::services::jwt;

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // 登录限流（基于用户名，IP 级别在中间件层处理）
    let client_key = req.username.clone();
    if !state.login_limiter.check(&client_key).await {
        let remaining = state.login_limiter.remaining(&client_key).await;
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({
            "code": 42900, "message": format!("Too many login attempts, retry in 5 minutes (remaining: {})", remaining), "data": null
        })));
    }
    // Use sqlx::query (not query!) to avoid offline DB requirement
    let user = sqlx::query("SELECT id, username, password_hash, role FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&state.pool).await;

    let (user_id, username, password_hash, role): (i64, String, String, String) = match user {
        Ok(Some(row)) => (row.get("id"), row.get("username"), row.get("password_hash"), row.get("role")),
        _ => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "code": 40100, "message": "Invalid credentials", "data": null
        }))),
    };

    if verify_password(&req.password, &password_hash).unwrap_or(false) == false {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "code": 40100, "message": "Invalid credentials", "data": null
        })));
    }

    let token = match jwt::create_token(user_id, &username, &role, &state.config.jwt_secret, state.config.jwt_expiry_hours) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("JWT creation error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "code": 50000, "message": "Internal error", "data": null
            })));
        }
    };

    // 登录成功，清除限流计数
    state.login_limiter.clear(&client_key).await;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(state.config.jwt_expiry_hours as i64);

    (StatusCode::OK, Json(serde_json::json!({
        "code": 0, "message": "success",
        "data": {
            "token": token,
            "expires_at": expires_at.to_rfc3339(),
            "user": { "id": user_id, "username": username, "role": role }
        }
    })))
}

pub async fn logout(Extension(_claims): Extension<JwtClaims>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"code":0,"message":"Logged out","data":null})))
}

pub async fn me(Extension(claims): Extension<JwtClaims>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "code": 0, "message": "success",
        "data": { "id": claims.sub.parse::<i64>().unwrap_or(0), "username": claims.username, "role": claims.role }
    })))
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(claims): Extension<JwtClaims>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let user = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
        .bind(&claims.sub)
        .fetch_optional(&state.pool).await;

    let password_hash: String = match user {
        Ok(Some(row)) => row.get("password_hash"),
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"code":40400,"message":"User not found","data":null}))),
    };

    if !verify_password(&req.old_password, &password_hash).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":40000,"message":"Old password incorrect","data":null})));
    }

    let new_hash = match hash_password(&req.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Password hash error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"code":50000,"message":"Internal error","data":null})));
        }
    };

    let _ = sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(&new_hash).bind(&claims.sub)
        .execute(&state.pool).await;

    (StatusCode::OK, Json(serde_json::json!({"code":0,"message":"Password changed","data":null})))
}
