use axum::{extract::{Path, Query, State}, http::StatusCode, response::{IntoResponse, Json}, Extension};
use zachary_panel_common::{JwtClaims, LatencyTestRequest};
use sqlx::Row;
use crate::AppState;

pub async fn list(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Query(p): Query<zachary_panel_common::LatencyTestListQuery>) -> impl IntoResponse {
    let page=p.page.unwrap_or(1).max(1); let ps=p.page_size.unwrap_or(20).min(100); let off=(page-1)*ps;
    let total: i64 = sqlx::query("SELECT COUNT(*) FROM latency_tests").fetch_one(&state.pool).await.map(|r| r.get(0)).unwrap_or(0);
    let rows = sqlx::query("SELECT test_id,node_id,rule_id,test_type,target_addr,target_port,count,timeout_ms,interval_ms,success_count,fail_count,loss_rate,min_latency_ms,max_latency_ms,avg_latency_ms,jitter_ms,http_status,status,error_message,created_by,created_at,started_at,finished_at FROM latency_tests ORDER BY id DESC LIMIT ? OFFSET ?")
        .bind(ps).bind(off).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "test_id":r.get::<String,_>("test_id"),"node_id":r.get::<Option<String>,_>("node_id"),"rule_id":r.get::<Option<i64>,_>("rule_id"),
        "test_type":r.get::<String,_>("test_type"),"target_addr":r.get::<String,_>("target_addr"),"target_port":r.get::<Option<i32>,_>("target_port"),
        "count":r.get::<i32,_>("count"),"timeout_ms":r.get::<i32,_>("timeout_ms"),"interval_ms":r.get::<i32,_>("interval_ms"),
        "success_count":r.get::<i32,_>("success_count"),"fail_count":r.get::<i32,_>("fail_count"),"loss_rate":r.get::<f64,_>("loss_rate"),
        "min_latency_ms":r.get::<Option<f64>,_>("min_latency_ms"),"max_latency_ms":r.get::<Option<f64>,_>("max_latency_ms"),
        "avg_latency_ms":r.get::<Option<f64>,_>("avg_latency_ms"),"jitter_ms":r.get::<Option<f64>,_>("jitter_ms"),
        "http_status":r.get::<Option<i32>,_>("http_status"),"status":r.get::<String,_>("status"),"error_message":r.get::<Option<String>,_>("error_message"),
        "created_by":r.get::<Option<String>,_>("created_by"),"created_at":r.get::<String,_>("created_at"),
        "started_at":r.get::<Option<String>,_>("started_at"),"finished_at":r.get::<Option<String>,_>("finished_at"),
    })).collect();
    (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"success","data":{"items":items,"total":total,"page":page,"page_size":ps}})))
}

pub async fn get(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Path(id): Path<i64>) -> impl IntoResponse {
    let r = sqlx::query("SELECT test_id,node_id,rule_id,test_type,target_addr,target_port,count,timeout_ms,interval_ms,success_count,fail_count,loss_rate,min_latency_ms,max_latency_ms,avg_latency_ms,jitter_ms,http_status,status,error_message,created_by,created_at,started_at,finished_at FROM latency_tests WHERE id=?")
        .bind(id).fetch_optional(&state.pool).await;
    match r { Ok(Some(row)) => (StatusCode::OK,Json(latency_to_json(&row))), Ok(None) => (StatusCode::NOT_FOUND,Json(serde_json::json!({"code":40400,"message":"Not found","data":null}))),
        _ => (StatusCode::INTERNAL_SERVER_ERROR,Json(serde_json::json!({"code":50000,"message":"Error","data":null}))) }
}

pub async fn delete(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Path(id): Path<i64>) -> impl IntoResponse {
    let _=sqlx::query("DELETE FROM latency_tests WHERE id=?").bind(id).execute(&state.pool).await;
    (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"Test deleted","data":null})))
}

pub async fn single(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Json(req): Json<LatencyTestRequest>) -> impl IntoResponse {
    let nid = match &req.node_id { Some(id) => id.clone(), None => return (StatusCode::BAD_REQUEST,Json(serde_json::json!({"code":40001,"message":"node_id required","data":null}))) };
    let tid = format!("task_{}",zachary_panel_common::random_hex(16));
    let _=sqlx::query("INSERT INTO tasks(task_id,node_id,type,payload,status) VALUES(?,?,?,?,'pending')")
        .bind(&tid).bind(&nid).bind("latency_test")
        .bind(serde_json::to_string(&serde_json::json!({"test_type":req.test_type,"target_addr":req.target_addr,"target_port":req.target_port,"count":req.count.unwrap_or(4),"timeout_ms":req.timeout_ms.unwrap_or(5000)})).unwrap_or_default())
        .execute(&state.pool).await;
    (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"success","data":{"task_id":tid}})))
}

pub async fn batch(State(state): State<AppState>, Extension(_c): Extension<JwtClaims>, Json(req): Json<LatencyTestRequest>) -> impl IntoResponse {
    let ids = match &req.node_ids { Some(ids) if !ids.is_empty() => ids.clone(), _ => return (StatusCode::BAD_REQUEST,Json(serde_json::json!({"code":40001,"message":"node_ids required","data":null}))) };
    let payload = serde_json::to_string(&serde_json::json!({"test_type":req.test_type,"target_addr":req.target_addr,"target_port":req.target_port,"count":req.count.unwrap_or(4),"timeout_ms":req.timeout_ms.unwrap_or(5000)})).unwrap_or_default();
    let mut tids = Vec::new();
    for nid in &ids {
        let tid = format!("task_{}",zachary_panel_common::random_hex(16));
        let _=sqlx::query("INSERT INTO tasks(task_id,node_id,type,payload,status) VALUES(?,?,?,?,'pending')").bind(&tid).bind(nid).bind("latency_test").bind(&payload).execute(&state.pool).await;
        tids.push(tid);
    }
    (StatusCode::OK,Json(serde_json::json!({"code":0,"message":"success","data":{"task_ids":tids,"count":tids.len()}})))
}

fn latency_to_json(r: &sqlx::sqlite::SqliteRow) -> serde_json::Value {serde_json::json!({
    "test_id":r.get::<String,_>("test_id"),"node_id":r.get::<Option<String>,_>("node_id"),"rule_id":r.get::<Option<i64>,_>("rule_id"),
    "test_type":r.get::<String,_>("test_type"),"target_addr":r.get::<String,_>("target_addr"),"target_port":r.get::<Option<i32>,_>("target_port"),
    "count":r.get::<i32,_>("count"),"timeout_ms":r.get::<i32,_>("timeout_ms"),"interval_ms":r.get::<i32,_>("interval_ms"),
    "success_count":r.get::<i32,_>("success_count"),"fail_count":r.get::<i32,_>("fail_count"),"loss_rate":r.get::<f64,_>("loss_rate"),
    "min_latency_ms":r.get::<Option<f64>,_>("min_latency_ms"),"max_latency_ms":r.get::<Option<f64>,_>("max_latency_ms"),
    "avg_latency_ms":r.get::<Option<f64>,_>("avg_latency_ms"),"jitter_ms":r.get::<Option<f64>,_>("jitter_ms"),
    "http_status":r.get::<Option<i32>,_>("http_status"),"status":r.get::<String,_>("status"),"error_message":r.get::<Option<String>,_>("error_message"),
    "created_by":r.get::<Option<String>,_>("created_by"),"created_at":r.get::<String,_>("created_at"),
    "started_at":r.get::<Option<String>,_>("started_at"),"finished_at":r.get::<Option<String>,_>("finished_at"),
})}
