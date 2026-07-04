use crate::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use sqlx::Row;
use zachary_panel_common::JwtClaims;

pub async fn get(
    State(state): State<AppState>,
    Extension(_claims): Extension<JwtClaims>,
) -> impl IntoResponse {
    let total_nodes: i64 = sqlx::query("SELECT COUNT(*) FROM nodes")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let online: i64 = sqlx::query("SELECT COUNT(*) FROM nodes WHERE status = 'online'")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let offline: i64 = sqlx::query("SELECT COUNT(*) FROM nodes WHERE status = 'offline'")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let disabled: i64 = sqlx::query("SELECT COUNT(*) FROM nodes WHERE status = 'disabled'")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);

    let total_rules: i64 = sqlx::query("SELECT COUNT(*) FROM forward_rules")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let running_rules: i64 =
        sqlx::query("SELECT COUNT(*) FROM forward_rules WHERE status = 'running'")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.get(0))
            .unwrap_or(0);
    let stopped_rules: i64 =
        sqlx::query("SELECT COUNT(*) FROM forward_rules WHERE status = 'stopped'")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.get(0))
            .unwrap_or(0);

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let bytes_in: i64 =
        sqlx::query("SELECT COALESCE(SUM(bytes_in), 0) FROM traffic_stats WHERE collected_at >= ?")
            .bind(&today)
            .fetch_one(&state.pool)
            .await
            .map(|r| r.get(0))
            .unwrap_or(0);
    let bytes_out: i64 = sqlx::query(
        "SELECT COALESCE(SUM(bytes_out), 0) FROM traffic_stats WHERE collected_at >= ?",
    )
    .bind(&today)
    .fetch_one(&state.pool)
    .await
    .map(|r| r.get(0))
    .unwrap_or(0);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "code": 0, "message": "success",
            "data": {
                "nodes": { "total": total_nodes, "online": online, "offline": offline, "disabled": disabled },
                "rules": { "total": total_rules, "running": running_rules, "stopped": stopped_rules },
                "traffic_today": { "bytes_in": bytes_in, "bytes_out": bytes_out },
                "avg_latency_ms": null,
                "high_latency_nodes": 0,
                "recent_heartbeats": [],
                "recent_failed_tasks": [],
                "recent_security_events": []
            }
        })),
    )
}
