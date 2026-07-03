use axum::{extract::{Path, Query, State}, http::StatusCode, response::{IntoResponse, Json}, Extension};
use zachary_panel_common::JwtClaims;
use sqlx::Row;
use crate::AppState;

pub async fn list(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Query(p): Query<zachary_panel_common::TaskListQuery>) -> impl IntoResponse {
    let page=p.page.unwrap_or(1).max(1); let ps=p.page_size.unwrap_or(20).min(100); let off=(page-1)*ps;
    let total: i64 = sqlx::query("SELECT COUNT(*) FROM tasks").fetch_one(&state.pool).await.map(|r| r.get(0)).unwrap_or(0);
    let rows = sqlx::query("SELECT t.id,t.task_id,t.node_id,n.name as node_name,t.type,t.payload,t.status,t.stdout,t.stderr,t.exit_code,t.message,t.created_at,t.started_at,t.finished_at FROM tasks t LEFT JOIN nodes n ON t.node_id=n.node_id ORDER BY t.id DESC LIMIT ? OFFSET ?")
        .bind(ps).bind(off).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id":r.get::<i64,_>("id"),"task_id":r.get::<String,_>("task_id"),"node_id":r.get::<String,_>("node_id"),"node_name":r.get::<Option<String>,_>("node_name"),
        "type":r.get::<String,_>("type"),"payload":r.get::<String,_>("payload"),"status":r.get::<String,_>("status"),
        "stdout":r.get::<Option<String>,_>("stdout"),"stderr":r.get::<Option<String>,_>("stderr"),"exit_code":r.get::<Option<i32>,_>("exit_code"),
        "message":r.get::<Option<String>,_>("message"),"created_at":r.get::<String,_>("created_at"),
        "started_at":r.get::<Option<String>,_>("started_at"),"finished_at":r.get::<Option<String>,_>("finished_at"),
    })).collect();
    (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"success","data":{"items":items,"total":total,"page":page,"page_size":ps}})))
}

pub async fn get(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Path(id): Path<i64>) -> impl IntoResponse {
    let r = sqlx::query("SELECT t.id,t.task_id,t.node_id,n.name as node_name,t.type,t.payload,t.status,t.stdout,t.stderr,t.exit_code,t.message,t.created_at,t.started_at,t.finished_at FROM tasks t LEFT JOIN nodes n ON t.node_id=n.node_id WHERE t.id=?")
        .bind(id).fetch_optional(&state.pool).await;
    match r { Ok(Some(row)) => {
        (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"success","data":{
            "id":row.get::<i64,_>("id"),"task_id":row.get::<String,_>("task_id"),"node_id":row.get::<String,_>("node_id"),"node_name":row.get::<Option<String>,_>("node_name"),
            "type":row.get::<String,_>("type"),"payload":row.get::<String,_>("payload"),"status":row.get::<String,_>("status"),
            "stdout":row.get::<Option<String>,_>("stdout"),"stderr":row.get::<Option<String>,_>("stderr"),"exit_code":row.get::<Option<i32>,_>("exit_code"),
            "message":row.get::<Option<String>,_>("message"),"created_at":row.get::<String,_>("created_at"),
            "started_at":row.get::<Option<String>,_>("started_at"),"finished_at":row.get::<Option<String>,_>("finished_at"),
        }})))
    }, Ok(None) => (StatusCode::NOT_FOUND,Json(serde_json::json!({"code":40400,"message":"Not found","data":null}))),
        _ => (StatusCode::INTERNAL_SERVER_ERROR,Json(serde_json::json!({"code":50000,"message":"Error","data":null}))) }
}
