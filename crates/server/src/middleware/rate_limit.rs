/// 登录限流模块
/// 基于 IP 的滑动窗口限流，防止暴力破解
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct LoginLimiter {
    /// IP → 登录尝试记录
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    /// 时间窗口（秒）
    window_secs: u64,
    /// 窗口内最大尝试次数
    max_attempts: usize,
}

impl LoginLimiter {
    pub fn new(window_secs: u64, max_attempts: usize) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            window_secs,
            max_attempts,
        }
    }

    /// 检查是否允许登录尝试
    pub async fn check(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        let entry = attempts.entry(ip.to_string()).or_default();
        // Remove expired entries
        entry.retain(|t| now.duration_since(*t) < window);

        if entry.len() >= self.max_attempts {
            return false;
        }

        entry.push(now);
        true
    }

    /// 登录成功时清除 IP 记录
    pub async fn clear(&self, ip: &str) {
        let mut attempts = self.attempts.lock().await;
        attempts.remove(ip);
    }

    /// 获取剩余尝试次数
    pub async fn remaining(&self, ip: &str) -> usize {
        let attempts = self.attempts.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        let entry = attempts.get(ip);
        match entry {
            Some(list) => {
                let count = list
                    .iter()
                    .filter(|t| now.duration_since(**t) < window)
                    .count();
                self.max_attempts.saturating_sub(count)
            }
            None => self.max_attempts,
        }
    }
}

use axum::extract::ConnectInfo;
use std::net::SocketAddr;

/// 从请求中提取客户端 IP
pub fn extract_ip(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}
