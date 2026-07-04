use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use sqlx::Row;
use zachary_panel_common::{
    validate_hostname, validate_port, CreateRuleRequest, ForwardMode, ForwardProtocol, JwtClaims,
    TunnelType, UpdateRuleRequest,
};

pub async fn list(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Query(p): Query<zachary_panel_common::RuleListQuery>,
) -> impl IntoResponse {
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let off = (page - 1) * ps;
    let total: i64 = sqlx::query("SELECT COUNT(*) FROM forward_rules")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let rows = sqlx::query("SELECT fr.id,fr.name,fr.node_id,n.name as node_name,fr.mode,fr.protocol,fr.listen_addr,fr.listen_port,fr.target_addr,fr.target_port,fr.tunnel_type,fr.ws_path,fr.tls_cert_path,fr.tls_key_path,fr.tls_skip_verify,fr.auth_type,fr.auth_username,fr.enabled,fr.status,fr.remark,fr.created_at,fr.updated_at FROM forward_rules fr LEFT JOIN nodes n ON fr.node_id=n.node_id ORDER BY fr.id DESC LIMIT ? OFFSET ?")
        .bind(ps).bind(off).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id":r.get::<i64,_>("id"),"name":r.get::<String,_>("name"),"node_id":r.get::<String,_>("node_id"),"node_name":r.get::<Option<String>,_>("node_name"),
        "mode":r.get::<String,_>("mode"),"protocol":r.get::<String,_>("protocol"),"listen_addr":r.get::<String,_>("listen_addr"),"listen_port":r.get::<i32,_>("listen_port"),
        "target_addr":r.get::<String,_>("target_addr"),"target_port":r.get::<i32,_>("target_port"),"tunnel_type":r.get::<String,_>("tunnel_type"),
        "ws_path":r.get::<Option<String>,_>("ws_path"),"tls_cert_path":r.get::<Option<String>,_>("tls_cert_path"),"tls_key_path":r.get::<Option<String>,_>("tls_key_path"),
        "tls_skip_verify":r.get::<i32,_>("tls_skip_verify")!=0,"auth_type":r.get::<Option<String>,_>("auth_type"),"auth_username":r.get::<Option<String>,_>("auth_username"),
        "enabled":r.get::<i32,_>("enabled")!=0,"status":r.get::<String,_>("status"),"remark":r.get::<Option<String>,_>("remark"),
        "created_at":r.get::<String,_>("created_at"),"updated_at":r.get::<String,_>("updated_at")
    })).collect();
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"items":items,"total":total,"page":page,"page_size":ps}}),
        ),
    )
}

pub async fn create(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Json(req): Json<CreateRuleRequest>,
) -> impl IntoResponse {
    if !validate_port(req.listen_port) || !validate_port(req.target_port) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":40001,"message":"Invalid port","data":null})),
        );
    }
    if !validate_hostname(&req.target_addr) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":40001,"message":"Invalid target address","data":null})),
        );
    }
    if ForwardMode::parse(&req.mode).is_none() || ForwardProtocol::parse(&req.protocol).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":40001,"message":"Invalid mode/protocol","data":null})),
        );
    }
    let tt = req.tunnel_type.clone().unwrap_or_else(|| "plain".into());
    if TunnelType::parse(&tt).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":40001,"message":"Invalid tunnel type","data":null})),
        );
    }
    let la = req.listen_addr.unwrap_or_else(|| "0.0.0.0".into());
    use sha2::Digest;
    let ape = req
        .auth_password
        .as_ref()
        .map(|p| hex::encode(sha2::Sha256::digest(p.as_bytes())));
    let ate = req
        .auth_token
        .as_ref()
        .map(|t| hex::encode(sha2::Sha256::digest(t.as_bytes())));
    if let Err(e)=sqlx::query("INSERT INTO forward_rules(name,node_id,mode,protocol,listen_addr,listen_port,target_addr,target_port,tunnel_type,ws_path,tls_cert_path,tls_key_path,tls_skip_verify,auth_type,auth_username,auth_password_encrypted,auth_token_encrypted,enabled,remark) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&req.name).bind(&req.node_id).bind(&req.mode).bind(&req.protocol).bind(&la).bind(req.listen_port).bind(&req.target_addr).bind(req.target_port)
        .bind(&tt).bind(&req.ws_path).bind(&req.tls_cert_path).bind(&req.tls_key_path).bind(req.tls_skip_verify.unwrap_or(false))
        .bind(&req.auth_type).bind(&req.auth_username).bind(&ape).bind(&ate).bind(req.enabled.unwrap_or(true)).bind(&req.remark)
        .execute(&state.pool).await {tracing::error!("Rule create: {e}");return (StatusCode::INTERNAL_SERVER_ERROR,Json(serde_json::json!({"code":50000,"message":"Failed","data":null})));}
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"code":0,"message":"Rule created","data":null})),
    )
}

pub async fn get(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let r = sqlx::query("SELECT fr.id,fr.name,fr.node_id,n.name as node_name,fr.mode,fr.protocol,fr.listen_addr,fr.listen_port,fr.target_addr,fr.target_port,fr.tunnel_type,fr.ws_path,fr.tls_cert_path,fr.tls_key_path,fr.tls_skip_verify,fr.auth_type,fr.auth_username,fr.enabled,fr.status,fr.remark,fr.created_at,fr.updated_at FROM forward_rules fr LEFT JOIN nodes n ON fr.node_id=n.node_id WHERE fr.id=?")
        .bind(id).fetch_optional(&state.pool).await;
    match r {
        Ok(Some(row)) => (StatusCode::OK, Json(rule_to_json(&row))),
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

pub async fn update(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleRequest>,
) -> impl IntoResponse {
    let _ = sqlx::query("UPDATE forward_rules SET name=COALESCE(?,name),remark=COALESCE(?,remark),updated_at=datetime('now') WHERE id=?")
        .bind(&req.name).bind(&req.remark).bind(id).execute(&state.pool).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Rule updated","data":null})),
    )
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let _ = sqlx::query("DELETE FROM forward_rules WHERE id=?")
        .bind(id)
        .execute(&state.pool)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Rule deleted","data":null})),
    )
}

pub async fn start(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "start_forward_rule").await
}
pub async fn stop(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "stop_forward_rule").await
}
pub async fn restart(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "restart_forward_rule").await
}
pub async fn test_listen(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "check_listen_port").await
}
pub async fn test_target(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "check_target_reachable").await
}
pub async fn test_chain(
    State(state): State<AppState>,
    Extension(c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    create_rule_task(&state, id, "check_forward_chain").await
}

async fn create_rule_task(state: &AppState, rule_id: i64, task_type: &str) -> impl IntoResponse {
    let r = sqlx::query("SELECT id,node_id,mode,protocol,listen_addr,listen_port,target_addr,target_port,tunnel_type,ws_path,tls_cert_path,tls_key_path,tls_skip_verify FROM forward_rules WHERE id=?")
        .bind(rule_id).fetch_optional(&state.pool).await;
    let (nid, mode, proto, la, lp, ta, tp, tt, wp, tcp, tkp, tsv): (
        String,
        String,
        String,
        String,
        i32,
        String,
        i32,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i32,
    ) = match r {
        Ok(Some(row)) => (
            row.get("node_id"),
            row.get("mode"),
            row.get("protocol"),
            row.get("listen_addr"),
            row.get("listen_port"),
            row.get("target_addr"),
            row.get("target_port"),
            row.get("tunnel_type"),
            row.get("ws_path"),
            row.get("tls_cert_path"),
            row.get("tls_key_path"),
            row.get("tls_skip_verify"),
        ),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let tid = format!("task_{}", zachary_panel_common::random_hex(16));
    let payload = serde_json::json!({"rule_id":rule_id,"mode":mode,"protocol":proto,"listen_addr":la,"listen_port":lp,"target_addr":ta,"target_port":tp,"tunnel_type":tt,"ws_path":wp,"tls_cert_path":tcp,"tls_key_path":tkp,"tls_skip_verify":tsv!=0});
    let _ = sqlx::query(
        "INSERT INTO tasks(task_id,node_id,type,payload,status) VALUES(?,?,?,?,'pending')",
    )
    .bind(&tid)
    .bind(&nid)
    .bind(task_type)
    .bind(payload.to_string())
    .execute(&state.pool)
    .await;
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"task_id":tid,"message":format!("Task {task_type} created")}}),
        ),
    )
}

fn rule_to_json(r: &sqlx::sqlite::SqliteRow) -> serde_json::Value {
    serde_json::json!({
        "id":r.get::<i64,_>("id"),"name":r.get::<String,_>("name"),"node_id":r.get::<String,_>("node_id"),"node_name":r.get::<Option<String>,_>("node_name"),
        "mode":r.get::<String,_>("mode"),"protocol":r.get::<String,_>("protocol"),"listen_addr":r.get::<String,_>("listen_addr"),"listen_port":r.get::<i32,_>("listen_port"),
        "target_addr":r.get::<String,_>("target_addr"),"target_port":r.get::<i32,_>("target_port"),"tunnel_type":r.get::<String,_>("tunnel_type"),
        "ws_path":r.get::<Option<String>,_>("ws_path"),"tls_cert_path":r.get::<Option<String>,_>("tls_cert_path"),"tls_key_path":r.get::<Option<String>,_>("tls_key_path"),
        "tls_skip_verify":r.get::<i32,_>("tls_skip_verify")!=0,"auth_type":r.get::<Option<String>,_>("auth_type"),"auth_username":r.get::<Option<String>,_>("auth_username"),
        "enabled":r.get::<i32,_>("enabled")!=0,"status":r.get::<String,_>("status"),"remark":r.get::<Option<String>,_>("remark"),
        "created_at":r.get::<String,_>("created_at"),"updated_at":r.get::<String,_>("updated_at")
    })
}
