/// 统一 API 响应格式
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success".into(),
            data: Some(data),
        }
    }

    pub fn success_msg(message: impl Into<String>, data: T) -> Self {
        Self {
            code: 0,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn error(code: i32, message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            code,
            message: message.into(),
            data: None,
        }
    }
}

/// 分页查询参数
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl PaginationQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }
    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(20).min(100).max(1)
    }
    pub fn offset(&self) -> u32 {
        (self.page() - 1) * self.page_size()
    }
    pub fn limit(&self) -> u32 {
        self.page_size()
    }
}

/// 分页响应
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedData<T: Serialize> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

/// 节点列表查询参数
#[derive(Debug, Deserialize)]
pub struct NodeListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub status: Option<String>,
    pub search: Option<String>,
}

/// 规则列表查询参数
#[derive(Debug, Deserialize)]
pub struct RuleListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub node_id: Option<String>,
    pub status: Option<String>,
    pub mode: Option<String>,
    pub search: Option<String>,
}

/// 任务列表查询参数
#[derive(Debug, Deserialize)]
pub struct TaskListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub node_id: Option<String>,
    pub r#type: Option<String>,
    pub status: Option<String>,
}

/// 安全事件列表查询参数
#[derive(Debug, Deserialize)]
pub struct SecurityEventListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub node_id: Option<String>,
    pub severity: Option<String>,
    pub event_type: Option<String>,
}

/// 延迟测试列表查询参数
#[derive(Debug, Deserialize)]
pub struct LatencyTestListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub node_id: Option<String>,
    pub test_type: Option<String>,
    pub status: Option<String>,
}
