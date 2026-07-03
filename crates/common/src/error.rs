/// 公共错误类型
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("Nonce replay detected: {0}")]
    NonceReplay(String),

    #[error("Timestamp expired: {0}")]
    TimestampExpired(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Agent not registered: {0}")]
    AgentNotRegistered(String),

    #[error("Node disabled: {0}")]
    NodeDisabled(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl From<AppError> for (i32, String) {
    fn from(err: AppError) -> Self {
        let code = match &err {
            AppError::AuthError(_) => 40100,
            AppError::NotFound(_) => 40400,
            AppError::BadRequest(_) => 40000,
            AppError::Forbidden(_) => 40300,
            AppError::Conflict(_) => 40900,
            AppError::Internal(_) => 50000,
            AppError::Database(_) => 50001,
            AppError::Validation(_) => 40001,
            AppError::SignatureError(_) => 40101,
            AppError::NonceReplay(_) => 40102,
            AppError::TimestampExpired(_) => 40103,
            AppError::RateLimit(_) => 42900,
            AppError::AgentNotRegistered(_) => 40104,
            AppError::NodeDisabled(_) => 40301,
            AppError::Io(_) => 50000,
            AppError::Serde(_) => 40000,
        };
        (code, err.to_string())
    }
}
