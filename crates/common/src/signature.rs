/// 签名/验证相关类型
use serde::{Deserialize, Serialize};

/// Agent 请求签名头
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSignatureHeaders {
    pub node_id: String,
    pub timestamp: String, // Unix 秒级 timestamp
    pub nonce: String,     // 随机一次性值
    pub signature: String, // HMAC-SHA256 hex
}

/// 签名负载（用于计算签名）
#[derive(Debug)]
pub struct SigningPayload {
    pub method: String,
    pub path: String,
    pub timestamp: String,
    pub nonce: String,
    pub body_hash: String, // SHA256 hex of request body
}

impl SigningPayload {
    /// 生成签名原始字符串
    pub fn signing_string(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}",
            self.method, self.path, self.timestamp, self.nonce, self.body_hash
        )
    }
}

/// 签名验证配置
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// 允许的时间偏差（秒）
    pub timestamp_tolerance: i64,
    /// nonce 过期时间（秒）
    pub nonce_ttl_seconds: i64,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            timestamp_tolerance: 60,
            nonce_ttl_seconds: 120,
        }
    }
}
