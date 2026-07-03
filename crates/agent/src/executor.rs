/// 任务执行模块
/// 负责接收 Server 下发的任务，分发执行，返回结果

use zachary_panel_common::{TaskType, TaskResult};
use zachary_panel_core::NftCommand;
use tracing::{info, warn, error};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct TaskExecutor {
    nft_path: String,
    gost_path: String,
}

impl TaskExecutor {
    pub fn new(nft_path: &str, gost_path: &str) -> Self {
        Self {
            nft_path: nft_path.to_string(),
            gost_path: gost_path.to_string(),
        }
    }

    /// 执行任务
    pub async fn execute(
        &self,
        task_id: &str,
        task_type: &str,
        payload: &serde_json::Value,
    ) -> TaskResult {
        let task_type_enum = match TaskType::parse(task_type) {
            Some(t) => t,
            None => {
                return TaskResult {
                    task_id: task_id.to_string(),
                    success: false,
                    message: format!("Unknown task type: {}", task_type),
                    stdout: None,
                    stderr: None,
                    exit_code: None,
                    started_at: now_ts(),
                    finished_at: now_ts(),
                };
            }
        };

        info!("Executing task: {} ({})", task_id, task_type);
        let started = Instant::now();
        let start_ts = now_ts();

        let result = match task_type_enum {
            // ═══ nftables 任务 ═══
            TaskType::CreateForwardRule => self.exec_forward_rule(payload, false).await,
            TaskType::DeleteForwardRule => self.exec_delete_forward_rule(payload).await,
            TaskType::StartForwardRule => self.exec_forward_rule(payload, false).await,
            TaskType::StopForwardRule => self.exec_delete_forward_rule(payload).await,
            TaskType::RestartForwardRule => {
                let r = self.exec_delete_forward_rule(payload).await;
                if r.success {
                    self.exec_forward_rule(payload, false).await
                } else {
                    r
                }
            }
            TaskType::ReloadNftables => self.exec_nft_reload().await,
            TaskType::CheckForwardChain => self.exec_nft_list().await,

            // ═══ gost 任务 ═══
            TaskType::InstallGost => self.exec_gost_install(payload).await,
            TaskType::CheckGostVersion => self.exec_gost_version().await,

            // ═══ 检测任务 ═══
            TaskType::CheckPort => self.exec_check_port(payload).await,
            TaskType::CheckTarget => self.exec_check_target(payload).await,
            TaskType::CheckListenPort => self.exec_check_port(payload).await,
            TaskType::CheckTargetReachable => self.exec_check_target(payload).await,

            // ═══ 系统信息 ═══
            TaskType::GetSystemInfo => self.exec_get_system_info().await,

            // ═══ 延迟测试 ═══
            TaskType::LatencyTest => self.exec_latency_test(payload).await,
            TaskType::BatchLatencyTest => self.exec_batch_latency_test(payload).await,
            TaskType::DnsResolveTest => self.exec_dns_resolve(payload).await,
            TaskType::HttpPingTest => self.exec_http_ping(payload).await,
            TaskType::TcpPingTest => self.exec_tcp_ping(payload).await,
            TaskType::IcmpPingTest => self.exec_icmp_ping(payload).await,

            // ═══ 占位 ═══
            TaskType::UpdateForwardRule => TaskResult {
                task_id: task_id.to_string(),
                success: true,
                message: "Update rule: not yet implemented, use delete+create".into(),
                stdout: None,
                stderr: None,
                exit_code: Some(0),
                started_at: start_ts.clone(),
                finished_at: now_ts(),
            },
        };

        let elapsed = started.elapsed();
        info!("Task {} completed in {}ms: {}", task_id, elapsed.as_millis(), if result.success { "OK" } else { "FAIL" });

        result
    }

    // ═══════════════════════════════════════════════════════════════
    // nftables 命令
    // ═══════════════════════════════════════════════════════════════

    async fn exec_forward_rule(&self, payload: &serde_json::Value, _dry_run: bool) -> TaskResult {
        let protocol = payload.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
        let public_ip = payload.get("public_ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");
        let listen_port = payload.get("listen_port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let target_addr = payload.get("target_addr").and_then(|v| v.as_str()).unwrap_or("");
        let target_port = payload.get("target_port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

        let proto = zachary_panel_common::ForwardProtocol::parse(protocol);
        let start_ts = now_ts();

        match proto {
            Some(p) => {
                let nft = NftCommand::new(&self.nft_path);
                // Ensure table and chain exist
                let mut results = Vec::new();
                results.push(run_cmd(&nft.init_table()));
                results.push(run_cmd(&nft.init_chain()));

                for cmds in nft.add_forward(&p, public_ip, listen_port, target_addr, target_port) {
                    results.push(run_cmd(&cmds));
                }

                let last = results.into_iter().last().unwrap();
                let msg = if last.success {
                    "nft forward rule added".into()
                } else {
                    last.stderr.as_deref().unwrap_or("unknown error").to_string()
                };
                TaskResult {
                    task_id: String::new(),
                    success: last.success,
                    message: msg,
                    stdout: last.stdout,
                    stderr: last.stderr,
                    exit_code: last.exit_code,
                    started_at: start_ts,
                    finished_at: now_ts(),
                }
            }
            None => TaskResult {
                task_id: String::new(),
                success: false,
                message: format!("Invalid protocol: {}", protocol),
                stdout: None,
                stderr: None,
                exit_code: None,
                started_at: start_ts,
                finished_at: now_ts(),
            },
        }
    }

    async fn exec_delete_forward_rule(&self, payload: &serde_json::Value) -> TaskResult {
        let listen_port = payload.get("listen_port").and_then(|v| v.as_i64()).unwrap_or(0);
        let start_ts = now_ts();

        if listen_port == 0 {
            return TaskResult {
                task_id: String::new(),
                success: false,
                message: "Missing listen_port".into(),
                stdout: None,
                stderr: None,
                exit_code: None,
                started_at: start_ts,
                finished_at: now_ts(),
            };
        }

        // Delete rule by flushing the entire chain and re-applying remaining rules
        // For now, we flush the chain (simpler approach)
        let nft = NftCommand::new(&self.nft_path);
        let r = run_cmd(&nft.flush_chain());

        let msg = if r.success { "nft chain flushed".into() } else { r.stderr.as_deref().unwrap_or("unknown error").to_string() };
        TaskResult {
            task_id: String::new(),
            success: r.success,
            message: msg,
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_nft_reload(&self) -> TaskResult {
        let nft = NftCommand::new(&self.nft_path);
        let start_ts = now_ts();
        let r = run_cmd(&nft.reload());
        let msg = if r.success { "nftables reloaded".into() } else { r.stderr.as_deref().unwrap_or("unknown error").to_string() };
        TaskResult {
            task_id: String::new(),
            success: r.success,
            message: msg,
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_nft_list(&self) -> TaskResult {
        let nft = NftCommand::new(&self.nft_path);
        let start_ts = now_ts();
        let r = run_cmd(&nft.list_rules());
        let msg = if r.success { "nft rules listed".into() } else { r.stderr.as_deref().unwrap_or("unknown error").to_string() };
        TaskResult {
            task_id: String::new(),
            success: r.success,
            message: msg,
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // gost 命令
    // ═══════════════════════════════════════════════════════════════

    async fn exec_gost_version(&self) -> TaskResult {
        let start_ts = now_ts();
        let cmd = std::process::Command::new(&self.gost_path)
            .arg("-V")
            .output();
        let r = match cmd {
            Ok(output) => CmdResult {
                success: output.status.success(),
                stdout: Some(String::from_utf8_lossy(&output.stdout).to_string()),
                stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()),
                exit_code: output.status.code(),
            },
            Err(e) => CmdResult {
                success: false,
                stdout: None,
                stderr: Some(e.to_string()),
                exit_code: None,
            },
        };
        let msg = r.stdout.as_deref().unwrap_or_default().to_string();
        TaskResult {
            task_id: String::new(),
            success: r.success,
            message: msg.clone(),
            stdout: r.stdout,
            stderr: r.stderr,
            exit_code: r.exit_code,
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_gost_install(&self, _payload: &serde_json::Value) -> TaskResult {
        let start_ts = now_ts();
        // Download and install gost - placeholder
        TaskResult {
            task_id: String::new(),
            success: false,
            message: "gost auto-install not yet implemented".into(),
            stdout: None,
            stderr: None,
            exit_code: None,
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 检测任务
    // ═══════════════════════════════════════════════════════════════

    async fn exec_check_port(&self, payload: &serde_json::Value) -> TaskResult {
        let port = payload.get("port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let host = payload.get("host").and_then(|v| v.as_str()).unwrap_or("127.0.0.1");
        let start_ts = now_ts();

        use tokio::net::TcpStream;
        let addr = format!("{}:{}", host, port);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        ).await;

        let (success, msg) = match result {
            Ok(Ok(_)) => (true, format!("Port {} is open", port)),
            Ok(Err(e)) => (false, format!("Port {} closed: {}", port, e)),
            Err(_) => (false, format!("Port {} check timed out", port)),
        };

        TaskResult {
            task_id: String::new(),
            success,
            message: msg,
            stdout: None,
            stderr: None,
            exit_code: if success { Some(0) } else { Some(1) },
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_check_target(&self, payload: &serde_json::Value) -> TaskResult {
        let target_addr = payload.get("target_addr").and_then(|v| v.as_str()).unwrap_or("");
        let target_port = payload.get("target_port").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let start_ts = now_ts();

        use tokio::net::TcpStream;
        let addr = format!("{}:{}", target_addr, target_port);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        ).await;

        let (success, msg) = match result {
            Ok(Ok(_)) => (true, format!("Target {}:{} reachable", target_addr, target_port)),
            Ok(Err(e)) => (false, format!("Target {}:{} unreachable: {}", target_addr, target_port, e)),
            Err(_) => (false, format!("Target {}:{} check timed out", target_addr, target_port)),
        };

        TaskResult {
            task_id: String::new(),
            success,
            message: msg,
            stdout: None,
            stderr: None,
            exit_code: if success { Some(0) } else { Some(1) },
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_get_system_info(&self) -> TaskResult {
        let start_ts = now_ts();
        let info = crate::system::collect();
        let json = serde_json::to_string_pretty(&info).unwrap_or_default();
        TaskResult {
            task_id: String::new(),
            success: true,
            message: "System info collected".into(),
            stdout: Some(json),
            stderr: None,
            exit_code: Some(0),
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // 延迟测试
    // ═══════════════════════════════════════════════════════════════

    async fn exec_latency_test(&self, payload: &serde_json::Value) -> TaskResult {
        let target_addr = payload.get("target_addr").and_then(|v| v.as_str()).unwrap_or("");
        let target_port = payload.get("target_port").and_then(|v| v.as_i64()).unwrap_or(80) as i32;
        let count = payload.get("count").and_then(|v| v.as_i64()).unwrap_or(5) as i32;
        let start_ts = now_ts();

        let mut latencies = Vec::new();
        let mut success_count = 0i32;
        let mut fail_count = 0i32;

        for _ in 0..count {
            use tokio::net::TcpStream;
            let addr = format!("{}:{}", target_addr, target_port);
            let start = Instant::now();
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                TcpStream::connect(&addr),
            ).await;
            let elapsed = start.elapsed().as_millis() as f64;

            match result {
                Ok(Ok(_)) => {
                    success_count += 1;
                    latencies.push(elapsed);
                }
                _ => {
                    fail_count += 1;
                }
            }
            // Small interval between pings
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        let avg = if latencies.is_empty() {
            None
        } else {
            Some(latencies.iter().sum::<f64>() / latencies.len() as f64)
        };
        let min = latencies.iter().copied().fold(f64::MAX, f64::min).if_std();
        let max = latencies.iter().copied().fold(f64::MIN, f64::max).if_std();

        let msg = format!(
            "Latency test to {}:{} — sent: {}, success: {}, fail: {}, avg: {}ms",
            target_addr, target_port, count, success_count, fail_count,
            avg.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "N/A".into())
        );

        TaskResult {
            task_id: String::new(),
            success: fail_count == 0,
            message: msg,
            stdout: Some(serde_json::json!({
                "target_addr": target_addr,
                "target_port": target_port,
                "count": count,
                "success_count": success_count,
                "fail_count": fail_count,
                "avg_latency_ms": avg,
                "min_latency_ms": min,
                "max_latency_ms": max,
            }).to_string()),
            stderr: None,
            exit_code: if fail_count == 0 { Some(0) } else { Some(1) },
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_batch_latency_test(&self, payload: &serde_json::Value) -> TaskResult {
        // Execute latency test for multiple targets
        let targets = payload.get("targets").and_then(|v| v.as_array());
        let start_ts = now_ts();

        match targets {
            Some(ts) => {
                let mut results = Vec::new();
                for t in ts {
                    let target_addr = t.get("target_addr").and_then(|v| v.as_str()).unwrap_or("");
                    let target_port = t.get("target_port").and_then(|v| v.as_i64()).unwrap_or(80) as i32;
                    let single = self.exec_latency_test(&serde_json::json!({
                        "target_addr": target_addr,
                        "target_port": target_port,
                    })).await;
                    results.push(serde_json::json!({
                        "target": format!("{}:{}", target_addr, target_port),
                        "success": single.success,
                        "message": single.message,
                        "avg_latency_ms": serde_json::from_str::<serde_json::Value>(
                            single.stdout.as_deref().unwrap_or("{}")
                        ).ok().and_then(|v| v.get("avg_latency_ms").and_then(|x| x.as_f64())),
                    }));
                }
                TaskResult {
                    task_id: String::new(),
                    success: true,
                    message: format!("Batch latency test: {} targets", results.len()),
                    stdout: Some(serde_json::to_string_pretty(&results).unwrap_or_default()),
                    stderr: None,
                    exit_code: Some(0),
                    started_at: start_ts,
                    finished_at: now_ts(),
                }
            }
            None => TaskResult {
                task_id: String::new(),
                success: false,
                message: "Missing targets array in payload".into(),
                stdout: None,
                stderr: None,
                exit_code: None,
                started_at: start_ts,
                finished_at: now_ts(),
            },
        }
    }

    async fn exec_dns_resolve(&self, payload: &serde_json::Value) -> TaskResult {
        let domain = payload.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let start_ts = now_ts();
        let result = tokio::net::lookup_host(format!("{}:0", domain)).await;

        let (success, msg) = match result {
            Ok(addrs) => {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                (true, format!("{} resolves to: {}", domain, ips.join(", ")))
            }
            Err(e) => (false, format!("DNS resolve failed for {}: {}", domain, e)),
        };

        TaskResult {
            task_id: String::new(),
            success,
            message: msg,
            stdout: None,
            stderr: None,
            exit_code: if success { Some(0) } else { Some(1) },
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_http_ping(&self, payload: &serde_json::Value) -> TaskResult {
        let url = payload.get("url").and_then(|v| v.as_str()).unwrap_or("");
        let start_ts = now_ts();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                let client = reqwest::Client::new();
                let start = Instant::now();
                let resp = client.head(url).send().await?;
                let elapsed = start.elapsed().as_millis() as f64;
                Ok::<_, reqwest::Error>((resp.status().as_u16(), elapsed))
            },
        ).await;

        let (success, msg, elapsed) = match result {
            Ok(Ok((status, ms))) => {
                (status < 400, format!("HTTP {} in {:.1}ms", status, ms), Some(ms))
            }
            Ok(Err(e)) => (false, format!("HTTP ping failed: {}", e), None),
            Err(_) => (false, "HTTP ping timed out".into(), None),
        };

        TaskResult {
            task_id: String::new(),
            success,
            message: msg,
            stdout: elapsed.map(|ms| format!("{{\"latency_ms\": {:.1}}}", ms)),
            stderr: None,
            exit_code: if success { Some(0) } else { Some(1) },
            started_at: start_ts,
            finished_at: now_ts(),
        }
    }

    async fn exec_tcp_ping(&self, payload: &serde_json::Value) -> TaskResult {
        // Same as latency test but single shot
        let single = self.exec_latency_test(&serde_json::json!({
            "target_addr": payload.get("target_addr").and_then(|v| v.as_str()),
            "target_port": payload.get("target_port").and_then(|v| v.as_i64()),
            "count": 1,
        })).await;
        single
    }

    async fn exec_icmp_ping(&self, payload: &serde_json::Value) -> TaskResult {
        let target = payload.get("target_addr").and_then(|v| v.as_str()).unwrap_or("");
        let count = payload.get("count").and_then(|v| v.as_i64()).unwrap_or(3) as i32;
        let start_ts = now_ts();

        let result = std::process::Command::new("ping")
            .args(&["-c", &count.to_string(), "-W", "5", target])
            .output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                TaskResult {
                    task_id: String::new(),
                    success: output.status.success(),
                    message: if output.status.success() { "ICMP ping OK".into() } else { format!("ICMP ping failed: {}", stderr.trim()) },
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                    exit_code: output.status.code(),
                    started_at: start_ts,
                    finished_at: now_ts(),
                }
            }
            Err(e) => TaskResult {
                task_id: String::new(),
                success: false,
                message: format!("ping command not available: {}", e),
                stdout: None,
                stderr: None,
                exit_code: None,
                started_at: start_ts,
                finished_at: now_ts(),
            },
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

struct CmdResult {
    success: bool,
    stdout: Option<String>,
    stderr: Option<String>,
    exit_code: Option<i32>,
}

/// Execute a command using Command::new().args() — NO sh -c
fn run_cmd(args: &[String]) -> CmdResult {
    if args.is_empty() {
        return CmdResult { success: false, stdout: None, stderr: Some("Empty command".into()), exit_code: None };
    }
    let result = std::process::Command::new(&args[0])
        .args(&args[1..])
        .output();
    match result {
        Ok(output) => CmdResult {
            success: output.status.success(),
            stdout: Some(String::from_utf8_lossy(&output.stdout).to_string()),
            stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            exit_code: output.status.code(),
        },
        Err(e) => CmdResult {
            success: false,
            stdout: None,
            stderr: Some(format!("Failed to execute {}: {}", args[0], e)),
            exit_code: None,
        },
    }
}

fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

trait IfStd {
    fn if_std(&self) -> Option<f64>;
}

impl IfStd for f64 {
    fn if_std(&self) -> Option<f64> {
        if self.is_finite() && *self > 0.0 { Some(*self) } else { None }
    }
}
