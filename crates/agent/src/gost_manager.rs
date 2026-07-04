//! gost 进程管理模块
//! 借鉴 flux-panel 的方式：用配置文件管理 gost 转发，支持热重载
#![allow(dead_code)]
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// gost 进程管理器
#[derive(Debug)]
pub struct GostManager {
    gost_path: String,
    config_dir: String,
    /// 运行中的 gost 进程: rule_name → child PID
    processes: Arc<Mutex<HashMap<String, u32>>>,
}

impl GostManager {
    pub fn new(gost_path: &str, config_dir: &str) -> Self {
        let config_dir = if config_dir.is_empty() {
            "/etc/zachary-panel/gost".to_string()
        } else {
            config_dir.to_string()
        };
        std::fs::create_dir_all(&config_dir).ok();

        Self {
            gost_path: gost_path.to_string(),
            config_dir,
            processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 启动一条 gost 转发规则
    pub async fn start_forward(&self, rule_name: &str, args: &[String]) -> anyhow::Result<()> {
        let mut procs = self.processes.lock().await;
        if procs.contains_key(rule_name) {
            warn!("gost rule {} already running", rule_name);
            return Ok(());
        }

        // Write config file for this rule
        let config_file = format!("{}/{}.conf", self.config_dir, sanitize(rule_name));
        let config_content = args.join(" ");
        std::fs::write(&config_file, &config_content)?;

        // Start gost process
        let mut child = tokio::process::Command::new(&self.gost_path)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let pid = child.id();
        info!("gost started for rule '{}', PID: {:?}", rule_name, pid);

        // Spawn a monitor task
        let rule_name_clone = rule_name.to_string();
        let procs_clone = self.processes.clone();
        tokio::spawn(async move {
            let _ = child.wait().await;
            warn!("gost process for '{}' exited", rule_name_clone);
            procs_clone.lock().await.remove(&rule_name_clone);
        });

        if let Some(pid) = pid {
            procs.insert(rule_name.to_string(), pid);
        }
        Ok(())
    }

    /// 停止一条 gost 转发规则
    pub async fn stop_forward(&self, rule_name: &str) -> anyhow::Result<()> {
        let mut procs = self.processes.lock().await;
        if let Some(pid) = procs.remove(rule_name) {
            let _ = tokio::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .output()
                .await;
            info!("gost rule '{}' stopped (PID {})", rule_name, pid);

            let config_file = format!("{}/{}.conf", self.config_dir, sanitize(rule_name));
            std::fs::remove_file(&config_file).ok();
        }
        Ok(())
    }

    /// 热重载：SIGHUP
    pub async fn reload(&self, rule_name: &str) -> anyhow::Result<()> {
        let procs = self.processes.lock().await;
        if let Some(pid) = procs.get(rule_name) {
            let _ = tokio::process::Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .output()
                .await;
            info!("gost rule '{}' reloaded (SIGHUP {})", rule_name, pid);
        }
        Ok(())
    }

    /// 停止所有 gost 进程
    pub async fn stop_all(&self) {
        let mut procs = self.processes.lock().await;
        for (name, pid) in procs.drain() {
            let _ = tokio::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .output()
                .await;
            info!("gost rule '{}' stopped", name);
        }
    }

    /// 列出运行中的规则
    pub async fn list_running(&self) -> Vec<(String, u32)> {
        self.processes
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// 获取规则流量统计（通过 gost API）
    pub async fn get_stats(&self, api_port: u16) -> anyhow::Result<serde_json::Value> {
        let url = format!("http://127.0.0.1:{}/api/services", api_port);
        let resp = reqwest::get(&url).await?;
        let data: serde_json::Value = resp.json().await?;
        Ok(data)
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
