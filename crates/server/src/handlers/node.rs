use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use sqlx::Row;
use zachary_panel_common::{
    generate_install_token, generate_node_token, sha256_hex, validate_node_name, CreateNodeRequest,
    JwtClaims, UpdateNodeRequest,
};

pub async fn list(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Query(p): Query<zachary_panel_common::NodeListQuery>,
) -> impl IntoResponse {
    let page = p.page.unwrap_or(1).max(1);
    let ps = p.page_size.unwrap_or(20).min(100);
    let off = (page - 1) * ps;
    let total: i64 = sqlx::query("SELECT COUNT(*) FROM nodes")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let rows = sqlx::query("SELECT id,node_id,name,public_ip,os,arch,agent_version,agent_sha256,gost_version,nft_status,gost_status,status,tls_verify,tls_pinning,last_signature_verified_at,last_heartbeat_at,last_task_at,last_ip,security_alerts,remark,created_at,updated_at,cpu_usage,cpu_cores,disk_total_gb,disk_used_gb,network_rx_bytes,network_tx_bytes,swap_total_mb,swap_used_mb,kernel,hostname FROM nodes ORDER BY id DESC LIMIT ? OFFSET ?")
        .bind(ps).bind(off).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<i64,_>("id"), "node_id": r.get::<String,_>("node_id"), "name": r.get::<String,_>("name"),
        "public_ip": r.get::<Option<String>,_>("public_ip"), "os": r.get::<Option<String>,_>("os"),
        "arch": r.get::<Option<String>,_>("arch"), "agent_version": r.get::<Option<String>,_>("agent_version"),
        "agent_sha256": r.get::<Option<String>,_>("agent_sha256"), "gost_version": r.get::<Option<String>,_>("gost_version"),
        "nft_status": r.get::<String,_>("nft_status"), "gost_status": r.get::<String,_>("gost_status"),
        "status": r.get::<String,_>("status"), "tls_verify": r.get::<i32,_>("tls_verify") != 0,
        "tls_pinning": r.get::<i32,_>("tls_pinning") != 0,
        "last_signature_verified_at": r.get::<Option<String>,_>("last_signature_verified_at"),
        "last_heartbeat_at": r.get::<Option<String>,_>("last_heartbeat_at"),
        "last_task_at": r.get::<Option<String>,_>("last_task_at"),
        "last_ip": r.get::<Option<String>,_>("last_ip"),
        "security_alerts": r.get::<String,_>("security_alerts"),
        "remark": r.get::<Option<String>,_>("remark"),
        "created_at": r.get::<String,_>("created_at"), "updated_at": r.get::<String,_>("updated_at"),
        "cpu_usage": r.get::<f64,_>("cpu_usage"),
        "cpu_cores": r.get::<Option<i64>,_>("cpu_cores").map(|v| v as usize),
        "disk_total_gb": r.get::<Option<f64>,_>("disk_total_gb"),
        "disk_used_gb": r.get::<Option<f64>,_>("disk_used_gb"),
        "network_rx_bytes": r.get::<i64,_>("network_rx_bytes") as u64,
        "network_tx_bytes": r.get::<i64,_>("network_tx_bytes") as u64,
        "swap_total_mb": r.get::<i64,_>("swap_total_mb") as u64,
        "swap_used_mb": r.get::<i64,_>("swap_used_mb") as u64,
        "kernel": r.get::<Option<String>,_>("kernel"),
        "hostname": r.get::<Option<String>,_>("hostname"),
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
    Json(req): Json<CreateNodeRequest>,
) -> impl IntoResponse {
    if !validate_node_name(&req.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"code":40001,"message":"Invalid node name","data":null})),
        );
    }
    let node_id = format!("node_{}", zachary_panel_common::random_hex(12));
    let node_token = generate_node_token();
    let nt_hash = sha256_hex(node_token.as_bytes());
    let install_token = generate_install_token();
    let it_hash = sha256_hex(install_token.as_bytes());
    let it_exp = (chrono::Utc::now()
        + chrono::Duration::minutes(state.config.install_token_ttl_minutes))
    .to_rfc3339();
    if let Err(e) = sqlx::query("INSERT INTO nodes (node_id,name,node_token_hash,install_token_hash,install_token_expired_at,public_ip,remark) VALUES (?,?,?,?,?,?,?)")
        .bind(&node_id).bind(&req.name).bind(&nt_hash).bind(&it_hash).bind(&it_exp).bind(&req.public_ip).bind(&req.remark)
        .execute(&state.pool).await { tracing::error!("Node create: {e}"); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"code":50000,"message":"Failed","data":null}))); }
    (
        StatusCode::CREATED,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"node_id":node_id,"node_token":node_token,"install_token":install_token,"install_token_expires_at":it_exp}}),
        ),
    )
}

pub async fn get(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let r = sqlx::query("SELECT id,node_id,name,public_ip,os,arch,agent_version,agent_sha256,gost_version,nft_status,gost_status,status,tls_verify,tls_pinning,last_signature_verified_at,last_heartbeat_at,last_task_at,last_ip,security_alerts,remark,created_at,updated_at,cpu_usage,cpu_cores,disk_total_gb,disk_used_gb,network_rx_bytes,network_tx_bytes,swap_total_mb,swap_used_mb,kernel,hostname FROM nodes WHERE id=?")
        .bind(id).fetch_optional(&state.pool).await;
    match r {
        Ok(Some(row)) => (StatusCode::OK, Json(node_to_json(&row))),
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
    Json(req): Json<UpdateNodeRequest>,
) -> impl IntoResponse {
    let _ = sqlx::query("UPDATE nodes SET name=COALESCE(?,name), public_ip=COALESCE(?,public_ip), remark=COALESCE(?,remark), updated_at=datetime('now') WHERE id=?")
        .bind(&req.name).bind(&req.public_ip).bind(&req.remark).bind(id).execute(&state.pool).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Node updated","data":null})),
    )
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let _ = sqlx::query("DELETE FROM nodes WHERE id=?")
        .bind(id)
        .execute(&state.pool)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Node deleted","data":null})),
    )
}

pub async fn disable(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let _ = sqlx::query("UPDATE nodes SET status='disabled',updated_at=datetime('now') WHERE id=?")
        .bind(id)
        .execute(&state.pool)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Node disabled","data":null})),
    )
}
pub async fn enable(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let _ = sqlx::query("UPDATE nodes SET status='offline',updated_at=datetime('now') WHERE id=?")
        .bind(id)
        .execute(&state.pool)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"Node enabled","data":null})),
    )
}

pub async fn regenerate_token(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT node_id FROM nodes WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let node_id: String = match row {
        Ok(Some(r)) => r.get("node_id"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let new_token = generate_node_token();
    let new_hash = sha256_hex(new_token.as_bytes());
    let _ = sqlx::query("UPDATE nodes SET node_token_hash=?,updated_at=datetime('now') WHERE id=?")
        .bind(&new_hash)
        .bind(id)
        .execute(&state.pool)
        .await;
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"node_id":node_id,"node_token":new_token,"message":"Token regenerated"}}),
        ),
    )
}

pub async fn install_command(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT node_id FROM nodes WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let node_id: String = match row {
        Ok(Some(r)) => r.get("node_id"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let it = generate_install_token();
    let ith = sha256_hex(it.as_bytes());
    let exp = (chrono::Utc::now()
        + chrono::Duration::minutes(state.config.install_token_ttl_minutes))
    .to_rfc3339();
    let _ = sqlx::query("UPDATE nodes SET install_token_hash=?,install_token_expired_at=?,updated_at=datetime('now') WHERE id=?").bind(&ith).bind(&exp).bind(id).execute(&state.pool).await;
    // Determine server URL: env override > Host header > config default
    let server = std::env::var("SERVER_URL").unwrap_or_else(|_| {
        let host = headers
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or(&state.config.host);
        let scheme = if state.config.port == 443 {
            "https"
        } else {
            "http"
        };
        format!("{}://{}", scheme, host)
    });
    let cmd = format!("curl -fsSL {server}/install-agent.sh | bash -s -- --server {server} --node-id {node_id} --install-token {it}");
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"command":cmd,"expires_at":exp}}),
        ),
    )
}

pub async fn security_status(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT node_id,agent_version,agent_sha256,tls_verify,tls_pinning,last_signature_verified_at,last_heartbeat_at,last_task_at,security_alerts,status FROM nodes WHERE id=?")
        .bind(id).fetch_optional(&state.pool).await;
    let node = match row {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let nid: String = node.get("node_id");
    let fc: i64 = sqlx::query("SELECT COUNT(*) FROM tasks WHERE node_id=? AND status='failed'")
        .bind(&nid)
        .fetch_one(&state.pool)
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"success","data":{
            "node_id": nid, "agent_online": node.get::<String,_>("status") == "online",
            "agent_version": node.get::<Option<String>,_>("agent_version"),
            "agent_sha256": node.get::<Option<String>,_>("agent_sha256"),
            "tls_verify": node.get::<i32,_>("tls_verify") != 0,
            "tls_pinning": node.get::<i32,_>("tls_pinning") != 0,
            "last_signature_verified_at": node.get::<Option<String>,_>("last_signature_verified_at"),
            "last_heartbeat_at": node.get::<Option<String>,_>("last_heartbeat_at"),
            "last_task_at": node.get::<Option<String>,_>("last_task_at"),
            "failed_task_count": fc, "security_alerts": node.get::<String,_>("security_alerts"),
            "enabled": node.get::<String,_>("status") != "disabled"
        }})),
    )
}

pub async fn quality(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT node_id FROM nodes WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let nid: String = match row {
        Ok(Some(r)) => r.get("node_id"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let stats = sqlx::query("SELECT id,node_id,target_addr,target_port,test_type,avg_latency_ms,loss_rate,jitter_ms,status,collected_at FROM node_quality_stats WHERE node_id=? ORDER BY collected_at DESC LIMIT 20")
        .bind(&nid).fetch_all(&state.pool).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = stats.iter().map(|r| serde_json::json!({
        "id": r.get::<i64,_>("id"), "node_id": r.get::<String,_>("node_id"),
        "target_addr": r.get::<Option<String>,_>("target_addr"), "target_port": r.get::<Option<i32>,_>("target_port"),
        "test_type": r.get::<String,_>("test_type"), "avg_latency_ms": r.get::<Option<f64>,_>("avg_latency_ms"),
        "loss_rate": r.get::<f64,_>("loss_rate"), "jitter_ms": r.get::<Option<f64>,_>("jitter_ms"),
        "status": r.get::<String,_>("status"), "collected_at": r.get::<String,_>("collected_at"),
    })).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({"code":0,"message":"success","data":items})),
    )
}

pub async fn latency_test(
    State(state): State<AppState>,
    Extension(_c): Extension<JwtClaims>,
    Path(id): Path<i64>,
    Json(req): Json<zachary_panel_common::LatencyTestRequest>,
) -> impl IntoResponse {
    let row = sqlx::query("SELECT node_id FROM nodes WHERE id=?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let nid: String = match row {
        Ok(Some(r)) => r.get("node_id"),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"code":40400,"message":"Not found","data":null})),
            )
        }
    };
    let tid = format!("task_{}", zachary_panel_common::random_hex(16));
    let _ = sqlx::query("INSERT INTO tasks (task_id,node_id,type,payload,status) VALUES (?,?,?,?,'pending')")
        .bind(&tid).bind(&nid).bind("latency_test")
        .bind(serde_json::to_string(&serde_json::json!({"test_type":req.test_type,"target_addr":req.target_addr,"target_port":req.target_port,"count":req.count.unwrap_or(4),"timeout_ms":req.timeout_ms.unwrap_or(5000)})).unwrap_or_default())
        .execute(&state.pool).await;
    (
        StatusCode::OK,
        Json(
            serde_json::json!({"code":0,"message":"success","data":{"task_id":tid,"message":"Latency test task created"}}),
        ),
    )
}

fn node_to_json(r: &sqlx::sqlite::SqliteRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.get::<i64,_>("id"), "node_id": r.get::<String,_>("node_id"), "name": r.get::<String,_>("name"),
        "public_ip": r.get::<Option<String>,_>("public_ip"), "os": r.get::<Option<String>,_>("os"), "arch": r.get::<Option<String>,_>("arch"),
        "agent_version": r.get::<Option<String>,_>("agent_version"), "agent_sha256": r.get::<Option<String>,_>("agent_sha256"),
        "gost_version": r.get::<Option<String>,_>("gost_version"), "nft_status": r.get::<String,_>("nft_status"), "gost_status": r.get::<String,_>("gost_status"),
        "status": r.get::<String,_>("status"), "tls_verify": r.get::<i32,_>("tls_verify") != 0, "tls_pinning": r.get::<i32,_>("tls_pinning") != 0,
        "last_signature_verified_at": r.get::<Option<String>,_>("last_signature_verified_at"),
        "last_heartbeat_at": r.get::<Option<String>,_>("last_heartbeat_at"), "last_task_at": r.get::<Option<String>,_>("last_task_at"),
        "last_ip": r.get::<Option<String>,_>("last_ip"), "security_alerts": r.get::<String,_>("security_alerts"),
        "remark": r.get::<Option<String>,_>("remark"), "created_at": r.get::<String,_>("created_at"), "updated_at": r.get::<String,_>("updated_at"),
        "cpu_usage": r.get::<f64,_>("cpu_usage"),
        "cpu_cores": r.get::<Option<i64>,_>("cpu_cores").map(|v| v as usize),
        "disk_total_gb": r.get::<Option<f64>,_>("disk_total_gb"),
        "disk_used_gb": r.get::<Option<f64>,_>("disk_used_gb"),
        "network_rx_bytes": r.get::<i64,_>("network_rx_bytes") as u64,
        "network_tx_bytes": r.get::<i64,_>("network_tx_bytes") as u64,
        "swap_total_mb": r.get::<i64,_>("swap_total_mb") as u64,
        "swap_used_mb": r.get::<i64,_>("swap_used_mb") as u64,
        "kernel": r.get::<Option<String>,_>("kernel"),
        "hostname": r.get::<Option<String>,_>("hostname"),
    })
}
