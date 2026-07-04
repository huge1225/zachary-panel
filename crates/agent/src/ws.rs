/// Agent WebSocket 客户端模块
/// 负责 WSS 连接、HMAC-SHA256 签名、心跳、任务接收、自动重连
use crate::config::AgentConfig;
use crate::executor::TaskExecutor;
use crate::system;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};
use zachary_panel_common::{hmac_sha256_hex, random_hex, ServerWsMessage};

/// 启动 Agent WebSocket 连接（含自动重连）
pub async fn run(config: AgentConfig) {
    let executor = TaskExecutor::new(&config.nft_path, &config.gost_path);
    let mut reconnect_delay = config.reconnect_base_delay;

    loop {
        info!("🔌 Connecting to {}", config.ws_url());
        match connect_and_run(&config, &executor).await {
            Ok(()) => {
                info!("WebSocket disconnected (clean close)");
                reconnect_delay = config.reconnect_base_delay;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
            }
        }

        warn!("⏳ Reconnecting in {}s...", reconnect_delay);
        tokio::time::sleep(std::time::Duration::from_secs(reconnect_delay)).await;
        reconnect_delay = (reconnect_delay * 2).min(config.reconnect_max_delay);
    }
}

/// 建立 WSS 连接并运行主循环
async fn connect_and_run(config: &AgentConfig, executor: &TaskExecutor) -> anyhow::Result<()> {
    let node_token = config
        .node_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No node_token — register first"))?;

    let url = config.ws_url();

    // Use connect_async_tls_with_config for WSS
    let connector = if config.tls_verify {
        let tls =
            native_tls::TlsConnector::new().map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    } else {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    };
    let (ws_stream, _) =
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, connector).await?;

    info!("✅ WebSocket connected to {}", url);

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Channel for sending messages from heartbeat/executor to WS write
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    // Spawn WS write task
    let write_handle = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_write.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn heartbeat task (with cloned sender)
    let node_id_hb = config.node_id.clone();
    let token_hb = node_token.to_string();
    let nft_hb = config.nft_path.clone();
    let gost_hb = config.gost_path.clone();
    let out_tx_hb = out_tx.clone();
    let hb_handle = tokio::spawn(async move {
        heartbeat_sender(node_id_hb, token_hb, nft_hb, gost_hb, out_tx_hb).await;
    });

    // Send initial system info
    let sys_info = system::collect();
    let sys_msg = build_signed_json(
        &config.node_id,
        node_token,
        "system_info",
        &serde_json::to_value(&sys_info).unwrap_or_default(),
    );
    if out_tx.send(Message::Text(sys_msg)).is_err() {
        anyhow::bail!("Failed to send initial system info");
    }

    // Main read loop
    while let Some(msg) = ws_read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                handle_server_message(&text, &config.node_id, node_token, executor, &out_tx).await;
            }
            Ok(Message::Ping(data)) => {
                // tungstenite auto-responds to pings, but just in case
                let _ = data;
            }
            Ok(Message::Close(frame)) => {
                info!("Server sent close frame: {:?}", frame);
                break;
            }
            Err(e) => {
                error!("WS read error: {}", e);
                break;
            }
            _ => {}
        }
    }

    write_handle.abort();
    hb_handle.abort();
    info!("WebSocket session ended");
    Ok(())
}

/// 处理 Server 下发的消息
async fn handle_server_message(
    text: &str,
    node_id: &str,
    node_token: &str,
    executor: &TaskExecutor,
    out_tx: &mpsc::UnboundedSender<Message>,
) {
    match serde_json::from_str::<ServerWsMessage>(text) {
        Ok(ServerWsMessage::Task {
            task_id,
            task_type,
            payload,
            ..
        }) => {
            info!("📥 Received task: {} ({})", task_id, task_type);

            // Execute task
            let result = executor.execute(&task_id, &task_type, &payload).await;

            // Build and send result
            let result_msg = build_signed_json(
                node_id,
                node_token,
                "task_result",
                &serde_json::to_value(&result).unwrap_or_default(),
            );

            if out_tx.send(Message::Text(result_msg)).is_err() {
                error!("Failed to send task result for {}", task_id);
            }

            info!(
                "📤 Task {} result: {}",
                task_id,
                if result.success { "OK" } else { "FAIL" }
            );
        }

        Ok(ServerWsMessage::HeartbeatAck { timestamp }) => {
            tracing::debug!("💓 Heartbeat ack: {}", timestamp);
        }

        Ok(ServerWsMessage::Shutdown { reason }) => {
            warn!("⛔ Server requested shutdown: {}", reason);
        }

        Err(e) => {
            warn!(
                "⚠️ Failed to parse server message: {} | body: {}",
                e,
                text.chars().take(200).collect::<String>()
            );
        }
    }
}

/// 心跳发送循环
pub async fn heartbeat_sender(
    node_id: String,
    node_token: String,
    nft_path: String,
    gost_path: String,
    tx: mpsc::UnboundedSender<Message>,
) {
    let mut nft_status;
    let mut gost_status;

    loop {
        // Wait between heartbeats
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        // Refresh tool status
        nft_status = system::nft_available(&nft_path);
        gost_status = system::gost_available(&gost_path);

        // Collect system stats
        let sys = system::collect();
        let payload = serde_json::json!({
            "status": "online",
            "load_avg": sys.load_avg,
            "memory_used_mb": sys.memory_used_mb,
            "memory_total_mb": sys.memory_total_mb,
            "uptime_seconds": sys.uptime_seconds,
            "nft_status": nft_status,
            "gost_status": gost_status,
            "agent_version": env!("CARGO_PKG_VERSION"),
        });

        let msg = build_signed_json(&node_id, &node_token, "heartbeat", &payload);

        if tx.send(Message::Text(msg)).is_err() {
            break; // Channel closed, connection dead
        }

        tracing::debug!("💓 Heartbeat sent");
    }
}

/// 构建带 HMAC-SHA256 签名的 JSON 消息
fn build_signed_json(
    node_id: &str,
    node_token: &str,
    msg_type: &str,
    payload: &serde_json::Value,
) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());
    let nonce = random_hex(16);

    let unsigned = serde_json::json!({
        "type": msg_type,
        "node_id": node_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "payload": payload,
    });

    let unsigned_str = serde_json::to_string(&unsigned).unwrap_or_default();
    let signature = hmac_sha256_hex(node_token.as_bytes(), unsigned_str.as_bytes());

    let signed = serde_json::json!({
        "type": msg_type,
        "node_id": node_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
        "payload": payload,
    });

    serde_json::to_string(&signed).unwrap_or_default()
}
