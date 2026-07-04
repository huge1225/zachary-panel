use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use futures_util::StreamExt;
use sqlx::Row;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use zachary_panel_common::{
    generate_node_token, sha256_hex, AgentRegisterRequest, AgentRegisterResponse, AgentWsMessage,
    ApiResponse, ServerWsMessage,
};

use crate::AppState;

/// Agent 注册 API
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<AgentRegisterRequest>,
) -> impl IntoResponse {
    let node_row = sqlx::query(
        r#"SELECT id, node_id, install_token_hash, install_token_expired_at, status
           FROM nodes WHERE node_id = ?"#,
    )
    .bind(&req.node_id)
    .fetch_optional(&state.pool)
    .await;

    let node = match node_row {
        Ok(Some(row)) => (
            row.get::<i64, _>("id"),
            row.get::<Option<String>, _>("install_token_hash"),
            row.get::<Option<String>, _>("install_token_expired_at"),
            row.get::<String, _>("status"),
        ),
        _ => {
            warn!(
                "Agent register attempt with unknown node_id: {}",
                req.node_id
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(40104, "Node not found")),
            )
                .into_response();
        }
    };

    if node.3 == "disabled" {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<()>::error(40301, "Node is disabled")),
        )
            .into_response();
    }

    // Verify install token
    let install_token_hash = sha256_hex(req.install_token.as_bytes());
    match &node.1 {
        Some(stored) if *stored == install_token_hash => {}
        _ => {
            let _ = sqlx::query("INSERT INTO security_events (node_id, event_type, severity, message) VALUES (?, 'install_token_invalid', 'warning', ?)")
                .bind(&req.node_id).bind("Invalid install token attempt".to_string()).execute(&state.pool).await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiResponse::<()>::error(40104, "Invalid install token")),
            )
                .into_response();
        }
    }

    // Check expiry
    if let Some(exp) = &node.2 {
        if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
            if chrono::Utc::now() > exp_dt {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiResponse::<()>::error(40104, "Install token expired")),
                )
                    .into_response();
            }
        }
    }

    let node_token = generate_node_token();
    let node_token_hash = sha256_hex(node_token.as_bytes());

    if let Err(e) = sqlx::query(
        "UPDATE nodes SET node_token_hash = ?, install_token_hash = NULL, install_token_expired_at = NULL, agent_version = ?, agent_sha256 = ?, os = ?, arch = ?, public_ip = COALESCE(?, public_ip), status = 'online', updated_at = datetime('now') WHERE id = ?"
    )
    .bind(&node_token_hash)
    .bind(&req.agent_version)
    .bind(&req.agent_sha256)
    .bind(&req.os)
    .bind(&req.arch)
    .bind(&req.public_ip)
    .bind(node.0)
    .execute(&state.pool).await
    {
        error!("Agent register DB error: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::<()>::error(50000, "Internal error"))).into_response();
    }

    info!("Agent registered: {} v{}", req.node_id, req.agent_version);

    let response = Json(ApiResponse::success(AgentRegisterResponse {
        node_token,
        heartbeat_interval: state.config.ws_heartbeat_interval,
    }));
    (StatusCode::OK, response).into_response()
}

/// Agent WebSocket handler
pub async fn ws_handler(
    State(state): State<AppState>,
    ws: axum::extract::WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_agent_ws(state, socket))
}

async fn handle_agent_ws(state: AppState, socket: axum::extract::ws::WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mut node_id: Option<String> = None;

    use futures_util::SinkExt;
    // Send loop
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender
                .send(axum::extract::ws::Message::Text(msg.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Receive loop
    while let Some(Ok(msg)) = receiver.next().await {
        use axum::extract::ws::Message;
        match msg {
            Message::Text(text) => match serde_json::from_str::<AgentWsMessage>(&text) {
                Ok(AgentWsMessage::Heartbeat {
                    node_id: nid,
                    timestamp: _ts,
                    nonce: _nonce,
                    signature: _sig,
                    payload: _payload,
                }) => {
                    if node_id.is_none() {
                        node_id = Some(nid.clone());
                        state
                            .agent_connections
                            .write()
                            .await
                            .insert(nid.clone(), tx.clone());
                        info!("Agent WS established: {}", nid);
                    }
                    let _ = sqlx::query("UPDATE nodes SET status = 'online', last_heartbeat_at = datetime('now'), updated_at = datetime('now') WHERE node_id = ?")
                            .bind(&nid).execute(&state.pool).await;
                    let ack = serde_json::to_string(&ServerWsMessage::HeartbeatAck {
                        timestamp: chrono::Utc::now().timestamp().to_string(),
                    })
                    .unwrap_or_default();
                    let _ = tx.send(ack);
                    send_pending_tasks(&state, &nid, &tx).await;
                }
                Ok(AgentWsMessage::TaskResult {
                    node_id: _nid,
                    payload,
                    ..
                }) => {
                    let _ = sqlx::query("UPDATE tasks SET status = ?, stdout = ?, stderr = ?, exit_code = ?, message = ?, started_at = ?, finished_at = COALESCE(finished_at, datetime('now')) WHERE task_id = ?")
                            .bind(if payload.success { "success" } else { "failed" })
                            .bind(&payload.stdout).bind(&payload.stderr)
                            .bind(payload.exit_code).bind(&payload.message)
                            .bind(&payload.started_at).bind(&payload.finished_at)
                            .bind(&payload.task_id).execute(&state.pool).await;
                }
                Ok(AgentWsMessage::SystemInfo {
                    node_id: nid,
                    payload,
                    ..
                }) => {
                    let _ = sqlx::query("UPDATE nodes SET os = ?, arch = ?, updated_at = datetime('now') WHERE node_id = ?")
                            .bind(&payload.os).bind(&payload.arch).bind(&nid).execute(&state.pool).await;
                }
                Err(e) => {
                    warn!("Invalid agent message: {e}");
                }
            },
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(nid) = &node_id {
        state.agent_connections.write().await.remove(nid);
        let _ = sqlx::query(
            "UPDATE nodes SET status = 'offline', updated_at = datetime('now') WHERE node_id = ?",
        )
        .bind(nid)
        .execute(&state.pool)
        .await;
        info!("Agent WS disconnected: {}", nid);
    }
    send_task.abort();
}

async fn send_pending_tasks(state: &AppState, node_id: &str, tx: &mpsc::UnboundedSender<String>) {
    let rows = sqlx::query(
        "SELECT task_id, type, payload FROM tasks WHERE node_id = ? AND status = 'pending' LIMIT 5",
    )
    .bind(node_id)
    .fetch_all(&state.pool)
    .await;

    if let Ok(rows) = rows {
        for row in rows {
            let task_id: String = row.get("task_id");
            let task_type: String = row.get("type");
            let payload_str: String = row.get("payload");

            let msg = serde_json::to_string(&ServerWsMessage::Task {
                task_id: task_id.clone(),
                task_type,
                timestamp: chrono::Utc::now().timestamp().to_string(),
                nonce: zachary_panel_common::random_hex(16),
                signature: "placeholder".into(),
                payload: serde_json::from_str(&payload_str).unwrap_or(serde_json::json!({})),
            })
            .unwrap();

            if tx.send(msg).is_ok() {
                let _ = sqlx::query("UPDATE tasks SET status = 'running', started_at = datetime('now') WHERE task_id = ?")
                    .bind(&task_id).execute(&state.pool).await;
            }
        }
    }
}
