# Zachary Panel - API 设计

## 1. 通用规范

- Base URL: `https://{host}/api`
- Content-Type: `application/json`
- 认证方式: `Authorization: Bearer {jwt_token}`
- 分页参数: `?page=1&page_size=20`
- 响应格式:

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

错误响应：

```json
{
  "code": 40001,
  "message": "Invalid request parameters",
  "data": null
}
```

## 2. 认证模块 `POST /api/auth/login`

请求：
```json
{
  "username": "admin",
  "password": "password123"
}
```

响应：
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "token": "eyJhbGci...",
    "expires_at": "2026-07-04T15:00:00+08:00",
    "user": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  }
}
```

### POST /api/auth/logout

无请求体。使当前 token 失效。

### GET /api/auth/me

返回当前登录用户信息。

### POST /api/auth/change-password

```json
{
  "old_password": "old",
  "new_password": "new"
}
```

## 3. 节点管理

### GET /api/nodes

查询参数：
- `page`, `page_size` - 分页
- `status` - 筛选状态 (online/offline/disabled/error)
- `search` - 搜索节点名称或 IP

响应 data 字段：
```json
{
  "items": [...],
  "total": 10,
  "page": 1,
  "page_size": 20
}
```

节点对象：
```json
{
  "id": 1,
  "node_id": "node_abc123",
  "name": "东京节点",
  "public_ip": "1.2.3.4",
  "os": "Debian 12",
  "arch": "amd64",
  "agent_version": "0.1.0",
  "agent_sha256": "abc...",
  "gost_version": "2.12.0",
  "nft_status": "available",
  "gost_status": "installed",
  "status": "online",
  "tls_verify": true,
  "tls_pinning": false,
  "last_signature_verified_at": "2026-07-03T14:50:00+08:00",
  "last_heartbeat_at": "2026-07-03T15:00:00+08:00",
  "last_task_at": "2026-07-03T14:55:00+08:00",
  "last_ip": "1.2.3.4",
  "security_alerts": [],
  "remark": "nearby",
  "created_at": "2026-07-01T10:00:00+08:00",
  "updated_at": "2026-07-03T15:00:00+08:00"
}
```

### POST /api/nodes

创建节点：
```json
{
  "name": "东京节点",
  "public_ip": "1.2.3.4",
  "remark": "nearby"
}
```

### GET /api/nodes/:id

获取节点详情（含安全状态）。

### PUT /api/nodes/:id

更新节点信息（名称、IP、备注）。

### DELETE /api/nodes/:id

删除节点（二次确认，级联删除规则和任务）。

### POST /api/nodes/:id/disable

禁用节点。

### POST /api/nodes/:id/enable

启用节点。

### POST /api/nodes/:id/regenerate-token

重新生成 node_token（旧 token 立即失效）。

### GET /api/nodes/:id/install-command

获取安装命令：
```json
{
  "command": "curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- --server https://panel.example.com --node-id node_abc123 --install-token it_xyz789",
  "expires_at": "2026-07-03T15:30:00+08:00"
}
```

### GET /api/nodes/:id/security

获取节点安全状态。

### GET /api/nodes/:id/quality

获取节点质量统计。

### POST /api/nodes/:id/latency-test

单节点延迟测试：
```json
{
  "test_type": "tcp",
  "target_addr": "8.8.8.8",
  "target_port": 53,
  "count": 4,
  "timeout_ms": 5000
}
```

## 4. 转发规则管理

### GET /api/rules

查询参数：`page`, `page_size`, `node_id`, `status`, `mode`, `search`

规则对象：
```json
{
  "id": 1,
  "name": "Web转发",
  "node_id": "node_abc123",
  "node_name": "东京节点",
  "mode": "nft",
  "protocol": "tcp",
  "listen_addr": "0.0.0.0",
  "listen_port": 8080,
  "target_addr": "10.0.0.5",
  "target_port": 80,
  "tunnel_type": "plain",
  "ws_path": null,
  "tls_cert_path": null,
  "tls_key_path": null,
  "tls_skip_verify": false,
  "auth_type": null,
  "enabled": true,
  "status": "running",
  "remark": "Web 80 proxy",
  "created_at": "2026-07-02T10:00:00+08:00",
  "updated_at": "2026-07-02T10:00:00+08:00"
}
```

### POST /api/rules

创建转发规则：
```json
{
  "name": "Web转发",
  "node_id": "node_abc123",
  "mode": "nft",
  "protocol": "tcp",
  "listen_addr": "0.0.0.0",
  "listen_port": 8080,
  "target_addr": "10.0.0.5",
  "target_port": 80,
  "tunnel_type": "plain",
  "enabled": true,
  "remark": "Web proxy"
}
```

### GET /api/rules/:id

获取规则详情。

### PUT /api/rules/:id

更新规则（会创建 update_forward_rule 任务）。

### DELETE /api/rules/:id

删除规则（会创建 delete_forward_rule 任务）。

### POST /api/rules/:id/start

启动规则。

### POST /api/rules/:id/stop

停止规则。

### POST /api/rules/:id/restart

重启规则。

### POST /api/rules/:id/test-listen

测试监听端口是否正常。

### POST /api/rules/:id/test-target

测试目标连通性。

### POST /api/rules/:id/test-chain

测试完整转发链路。

## 5. 任务系统

### GET /api/tasks

查询参数：`page`, `page_size`, `node_id`, `type`, `status`

### GET /api/tasks/:id

获取单个任务详情和结果。

## 6. 延迟测试

### GET /api/latency-tests

查询参数：`page`, `page_size`, `node_id`, `test_type`, `status`

### POST /api/latency-tests/single

单节点测试：
```json
{
  "node_id": "node_abc123",
  "test_type": "tcp",
  "target_addr": "8.8.8.8",
  "target_port": 53,
  "count": 4,
  "timeout_ms": 5000
}
```

### POST /api/latency-tests/batch

批量测试：
```json
{
  "node_ids": ["node_abc123", "node_def456"],
  "test_type": "tcp",
  "target_addr": "8.8.8.8",
  "target_port": 53,
  "count": 4,
  "timeout_ms": 5000
}
```

### GET /api/latency-tests/:id

查看测试详情和结果。

### DELETE /api/latency-tests/:id

删除测试记录。

## 7. Agent API (WebSocket + HTTP)

Agent 与 Server 通信主要通过 WSS 长连接，以下为消息格式：

### 心跳

Agent → Server:
```json
{
  "type": "heartbeat",
  "data": {
    "node_id": "node_abc123",
    "timestamp": "2026-07-03T15:00:00+08:00",
    "nonce": "random_nonce_string",
    "signature": "hmac_sha256_hex",
    "payload": {
      "status": "online",
      "load_avg": [0.5, 0.3, 0.2],
      "memory_used_mb": 1024,
      "uptime_seconds": 86400
    }
  }
}
```

### 任务分发

Server → Agent:
```json
{
  "type": "task",
  "data": {
    "task_id": "task_xyz",
    "task_type": "start_forward_rule",
    "timestamp": "...",
    "nonce": "...",
    "signature": "...",
    "payload": {
      "rule_id": 1,
      "mode": "nft",
      "protocol": "tcp",
      "listen_addr": "0.0.0.0",
      "listen_port": 8080,
      "target_addr": "10.0.0.5",
      "target_port": 80
    }
  }
}
```

### 任务回报

Agent → Server:
```json
{
  "type": "task_result",
  "data": {
    "task_id": "task_xyz",
    "node_id": "node_abc123",
    "timestamp": "...",
    "nonce": "...",
    "signature": "...",
    "payload": {
      "success": true,
      "message": "Rule started successfully",
      "stdout": "",
      "stderr": "",
      "exit_code": 0,
      "started_at": "...",
      "finished_at": "..."
    }
  }
}
```

## 8. 安全事件

### GET /api/security-events

查询参数：`page`, `page_size`, `node_id`, `severity`, `event_type`

### GET /api/security-events/:id

获取单个安全事件详情。

## 9. 仪表盘

### GET /api/dashboard

```json
{
  "nodes": {
    "total": 10,
    "online": 8,
    "offline": 1,
    "disabled": 1
  },
  "rules": {
    "total": 25,
    "running": 20,
    "stopped": 5
  },
  "traffic_today": {
    "bytes_in": 1073741824,
    "bytes_out": 2147483648
  },
  "avg_latency_ms": 45.2,
  "high_latency_nodes": 2,
  "recent_heartbeats": [...],
  "recent_failed_tasks": [...],
  "recent_security_events": [...]
}
```

## 10. Agent 注册 (HTTP)

### POST /api/agent/register

Agent 首次注册（使用 install_token）：

```json
{
  "node_id": "node_abc123",
  "install_token": "it_xyz789",
  "agent_version": "0.1.0",
  "agent_sha256": "abc...",
  "os": "Debian 12",
  "arch": "amd64",
  "public_ip": "1.2.3.4"
}
```

响应：
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "node_token": "nt_sensitive_token_here",
    "heartbeat_interval": 10
  }
}
```

## 11. 限流策略

| 端点 | 限流 | 窗口 |
|------|------|------|
| /api/auth/login | 5次 | 1分钟 |
| /api/auth/* | 20次 | 1分钟 |
| /api/agent/* | 100次 | 1分钟 per node |
| 其他 /api/* | 60次 | 1分钟 |
