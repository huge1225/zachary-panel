# Zachary Panel - 数据库设计

## 1. 概述

默认使用 SQLite，通过 SQLx 访问，预留 PostgreSQL/MySQL 扩展能力。

## 2. 表结构

### 2.1 users - 管理员用户表

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

字段说明：
- `id`: 自增主键
- `username`: 用户名，唯一
- `password_hash`: bcrypt/argon2 密码哈希
- `role`: 角色，默认 admin
- `created_at`: 创建时间
- `updated_at`: 更新时间

### 2.2 nodes - 转发节点表

```sql
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    node_token_hash TEXT NOT NULL,
    install_token_hash TEXT,
    install_token_expired_at TEXT,
    public_ip TEXT,
    os TEXT,
    arch TEXT,
    agent_version TEXT,
    agent_sha256 TEXT,
    gost_version TEXT,
    nft_status TEXT DEFAULT 'unknown',
    gost_status TEXT DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'offline',
    tls_verify INTEGER NOT NULL DEFAULT 1,
    tls_pinning INTEGER NOT NULL DEFAULT 0,
    pinned_cert_sha256 TEXT,
    last_signature_verified_at TEXT,
    last_heartbeat_at TEXT,
    last_task_at TEXT,
    last_ip TEXT,
    security_alerts TEXT DEFAULT '[]',
    remark TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

字段说明：
- `node_id`: 节点唯一标识 (node_xxxxx)
- `node_token_hash`: node_token 的 SHA256 哈希
- `install_token_hash`: 一次性安装 token 的哈希
- `install_token_expired_at`: 安装 token 过期时间
- `public_ip`: 节点公网 IP
- `os`: 操作系统信息
- `arch`: CPU 架构 (amd64/arm64)
- `agent_version`: Agent 版本号
- `agent_sha256`: Agent 二进制 SHA256
- `gost_version`: gost 版本
- `nft_status`: nftables 状态 (available/unavailable)
- `gost_status`: gost 状态 (installed/not_installed)
- `status`: 节点状态 (online/offline/disabled/error)
- `tls_verify`: 是否启用 TLS 校验
- `tls_pinning`: 是否启用 TLS Pinning
- `pinned_cert_sha256`: 绑定的证书 SHA256
- `last_signature_verified_at`: 最近签名校验时间
- `last_heartbeat_at`: 最近心跳时间
- `last_task_at`: 最近任务执行时间
- `last_ip`: 最近连接 IP
- `security_alerts`: 安全告警 JSON 数组
- `remark`: 备注

### 2.3 forward_rules - 转发规则表

```sql
CREATE TABLE IF NOT EXISTS forward_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    node_id TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'nft',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    listen_addr TEXT NOT NULL DEFAULT '0.0.0.0',
    listen_port INTEGER NOT NULL,
    target_addr TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    tunnel_type TEXT NOT NULL DEFAULT 'plain',
    ws_path TEXT,
    tls_cert_path TEXT,
    tls_key_path TEXT,
    tls_skip_verify INTEGER NOT NULL DEFAULT 0,
    auth_type TEXT,
    auth_username TEXT,
    auth_password_encrypted TEXT,
    auth_token_encrypted TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'stopped',
    remark TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);
```

字段说明：
- `mode`: 转发方式 (nft/gost)
- `protocol`: 协议 (tcp/udp/tcp_udp)
- `tunnel_type`: 隧道类型 (plain/ws/wss)
- `auth_type`: 认证类型 (none/basic/token)
- `status`: 当前状态 (running/stopped/failed/unknown)

### 2.4 tasks - 任务表

```sql
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL UNIQUE,
    node_id TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);
```

任务类型 (type) 枚举：
- `create_forward_rule`
- `update_forward_rule`
- `delete_forward_rule`
- `start_forward_rule`
- `stop_forward_rule`
- `restart_forward_rule`
- `check_port`
- `check_target`
- `reload_nftables`
- `install_gost`
- `check_gost_version`
- `get_system_info`
- `latency_test`
- `batch_latency_test`
- `check_listen_port`
- `check_target_reachable`
- `check_forward_chain`
- `dns_resolve_test`
- `http_ping_test`
- `tcp_ping_test`
- `icmp_ping_test`

任务状态 (status)：pending / running / success / failed / timeout / cancelled

### 2.5 traffic_stats - 流量统计表

```sql
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    packets_in INTEGER NOT NULL DEFAULT 0,
    packets_out INTEGER NOT NULL DEFAULT 0,
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);
```

### 2.6 latency_tests - 延迟测试表

```sql
CREATE TABLE IF NOT EXISTS latency_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL UNIQUE,
    node_id TEXT,
    rule_id INTEGER,
    test_type TEXT NOT NULL,
    target_addr TEXT NOT NULL,
    target_port INTEGER,
    count INTEGER NOT NULL DEFAULT 4,
    timeout_ms INTEGER NOT NULL DEFAULT 5000,
    interval_ms INTEGER NOT NULL DEFAULT 1000,
    success_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    loss_rate REAL NOT NULL DEFAULT 0.0,
    min_latency_ms REAL,
    max_latency_ms REAL,
    avg_latency_ms REAL,
    jitter_ms REAL,
    http_status INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    finished_at TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL,
    FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
);
```

测试类型 (test_type)：icmp / tcp / http / dns

测试状态 (status)：pending / running / success / failed / partial_failed

### 2.7 node_quality_stats - 节点质量统计表

```sql
CREATE TABLE IF NOT EXISTS node_quality_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    target_addr TEXT,
    target_port INTEGER,
    test_type TEXT NOT NULL DEFAULT 'icmp',
    avg_latency_ms REAL,
    loss_rate REAL DEFAULT 0.0,
    jitter_ms REAL,
    status TEXT NOT NULL DEFAULT 'unknown',
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);
```

### 2.8 operation_logs - 操作日志表

```sql
CREATE TABLE IF NOT EXISTS operation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    detail TEXT,
    ip TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
```

操作类型 (action) 示例：
- `login` / `logout`
- `create_node` / `update_node` / `delete_node` / `disable_node` / `enable_node`
- `regenerate_node_token`
- `create_rule` / `update_rule` / `delete_rule` / `start_rule` / `stop_rule` / `restart_rule`
- `latency_test`
- `change_password`

### 2.9 security_events - 安全事件表

```sql
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
);
```

事件类型 (event_type)：
- `signature_verification_failed`
- `nonce_replay_attempt`
- `timestamp_expired`
- `unauthorized_agent`
- `install_token_expired`
- `install_token_invalid`
- `agent_version_outdated`
- `node_heartbeat_lost`
- `task_execution_failed`
- `config_permission_warning`
- `agent_ip_changed`

严重级别 (severity)：info / warning / critical

### 2.10 agent_nonces - Agent Nonce 表

```sql
CREATE TABLE IF NOT EXISTS agent_nonces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expired_at TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
);
```

用于防重放攻击，记录已使用的 nonce 值并在过期后清理。

## 3. 索引

```sql
CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_forward_rules_node_id ON forward_rules(node_id);
CREATE INDEX IF NOT EXISTS idx_forward_rules_status ON forward_rules(status);
CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON tasks(task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_node_id ON tasks(node_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_traffic_stats_rule_id ON traffic_stats(rule_id);
CREATE INDEX IF NOT EXISTS idx_traffic_stats_collected_at ON traffic_stats(collected_at);
CREATE INDEX IF NOT EXISTS idx_latency_tests_test_id ON latency_tests(test_id);
CREATE INDEX IF NOT EXISTS idx_latency_tests_node_id ON latency_tests(node_id);
CREATE INDEX IF NOT EXISTS idx_latency_tests_created_at ON latency_tests(created_at);
CREATE INDEX IF NOT EXISTS idx_node_quality_stats_node_id ON node_quality_stats(node_id);
CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_operation_logs_user_id ON operation_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_node_id ON security_events(node_id);
CREATE INDEX IF NOT EXISTS idx_agent_nonces_node_id ON agent_nonces(node_id);
CREATE INDEX IF NOT EXISTS idx_agent_nonces_expired_at ON agent_nonces(expired_at);
```

## 4. 定期清理

- `agent_nonces`：每天清理过期 nonce 记录（expired_at < now）
- `tasks`：保留 30 天，超期可归档或删除
- `traffic_stats`：保留 90 天
- `latency_tests`：保留 30 天
- `security_events`：保留 90 天
- `operation_logs`：保留 90 天，超期可归档
