use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use sqlx::Row;
use zachary_panel_common::JwtClaims;

pub async fn list(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Query(p): Query<zachary_panel_common::SecurityEventListQuery>,
) -> impl IntoResponse {
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let off = (page - 1) * ps;
    let total: i64 = sqlx::query("SELECT COUNT(*) FROM security_events")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let rows = sqlx::query("SELECT se.id,se.node_id,n.name as node_name,se.event_type,se.severity,se.message,se.ip,se.user_agent,se.created_at FROM security_events se LEFT JOIN nodes n ON se.node_id=n.node_id ORDER BY se.id DESC LIMIT ? OFFSET ?")
        .bind(ps).bind(off).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id":r.get::<i64,_>("id"),"node_id":r.get::<Option<String>,_>("node_id"),"node_name":r.get::<Option<String>,_>("node_name"),
        "event_type":r.get::<String,_>("event_type"),"severity":r.get::<String,_>("severity"),"message":r.get::<String,_>("message"),
        "ip":r.get::<Option<String>,_>("ip"),"user_agent":r.get::<Option<String>,_>("user_agent"),"created_at":r.get::<String,_>("created_at"),
    })).collect();
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"items":items,"total":total,"page":page,"page_size":ps}}),
        ),
    )
}

pub async fn get(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let r = sqlx::query("SELECT se.id,se.node_id,n.name as node_name,se.event_type,se.severity,se.message,se.ip,se.user_agent,se.created_at FROM security_events se LEFT JOIN nodes n ON se.node_id=n.node_id WHERE se.id=?")
        .bind(id).fetch_optional(&state.pool).await;
    match r {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(serde_json::json!({"code":0,"message":"success","data":{
                "id":row.get::<i64,_>("id"),"node_id":row.get::<Option<String>,_>("node_id"),"node_name":row.get::<Option<String>,_>("node_name"),
                "event_type":row.get::<String,_>("event_type"),"severity":row.get::<String,_>("severity"),"message":row.get::<String,_>("message"),
                "ip":row.get::<Option<String>,_>("ip"),"user_agent":row.get::<Option<String>,_>("user_agent"),"created_at":row.get::<String,_>("created_at"),
            }})),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"code":50000,"message":"Error","data":null})),
        ),
    }
}
