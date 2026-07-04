# Zachary Panel 改进方案
## 节点探针 UI + Agent 安全加固

---

## 一、数据模型变更

### 1.1 HeartbeatPayload 增加监控字段
**文件:** `crates/common/src/model.rs` (约 498 行)

在现有 HeartbeatPayload 的 `agent_version` 字段后添加：

```rust
pub cpu_usage: f64,           // CPU 使用率 %
pub cpu_cores: usize,         // CPU 核心数
pub disk_total_gb: f64,       // 磁盘总量 GB
pub disk_used_gb: f64,        // 磁盘已用 GB
pub network_rx_bytes: u64,    // 网络接收字节数（累计）
pub network_tx_bytes: u64,    // 网络发送字节数（累计）
pub swap_total_mb: u64,       // Swap 总量 MB
pub swap_used_mb: u64,        // Swap 已用 MB
pub kernel: Option<String>,   // 内核版本
pub hostname: Option<String>, // 主机名
```

### 1.2 数据库 nodes 表增加字段
**文件:** `crates/server/src/db.rs` — v2 migration 的 ALTER TABLE 部分

添加以下列：
```sql
ALTER TABLE nodes ADD COLUMN cpu_usage REAL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN cpu_cores INTEGER;
ALTER TABLE nodes ADD COLUMN disk_total_gb REAL;
ALTER TABLE nodes ADD COLUMN disk_used_gb REAL;
ALTER TABLE nodes ADD COLUMN network_rx_bytes INTEGER DEFAULT 0;
ALTER TABLE nodes ADD COLUMN network_tx_bytes INTEGER DEFAULT 0;
ALTER TABLE nodes ADD COLUMN swap_total_mb INTEGER DEFAULT 0;
ALTER TABLE nodes ADD COLUMN swap_used_mb INTEGER DEFAULT 0;
ALTER TABLE nodes ADD COLUMN kernel TEXT;
ALTER TABLE nodes ADD COLUMN hostname TEXT;
```

### 1.3 NodeInfo 增加对应字段
**文件:** `crates/common/src/model.rs` (约 295 行)

在 NodeInfo 结构体添加同样的字段（pub xxx: 类型）。

---

## 二、Agent 系统信息采集

### 2.1 system.rs 增加采集函数
**文件:** `crates/agent/src/system.rs`

需要采集的新数据：

```rust
// CPU 使用率：读取 /proc/stat 两次取差值
fn collect_cpu_usage() -> f64

// 磁盘使用：statvfs("/") 
fn collect_disk_usage() -> (f64, f64)  // (used_gb, total_gb)

// 网络流量：读取 /proc/net/dev 的 rx/tx 累计值
fn collect_network_stats() -> (u64, u64)  // (rx_bytes, tx_bytes)

// Swap：读取 /proc/meminfo 的 SwapTotal/SwapFree
fn collect_swap() -> (u64, u64)  // (used_mb, total_mb)

// 主机名：sysinfo::hostname() 或读取 /etc/hostname
// 内核：uname -r
```

### 2.2 心跳构建函数更新
**文件:** `crates/agent/src/ws.rs`

在 build_heartbeat() 中调用新的采集函数，填充 HeartbeatPayload 的新字段。

---

## 三、Server 心跳处理更新

### 3.1 心跳 handler 保存新字段
**文件:** `crates/server/src/handlers/agent.rs`

WebSocket 收到心跳时，UPDATE nodes SQL 增加新字段：

```sql
UPDATE nodes SET 
  cpu_usage = ?, cpu_cores = ?, disk_total_gb = ?, disk_used_gb = ?,
  network_rx_bytes = ?, network_tx_bytes = ?, swap_total_mb = ?, 
  swap_used_mb = ?, kernel = ?, hostname = ?,
  memory_used_mb = ?, memory_total_mb = ?, load_avg = ?,
  status = 'online', last_heartbeat_at = datetime('now')
WHERE node_id = ?
```

### 3.2 节点列表 API 返回完整数据
**文件:** `crates/server/src/handlers/node.rs`

list() 的 SELECT 语句增加新字段，返回给前端。

---

## 四、前端探针 UI

### 4.1 重写 NodesView.vue
**文件:** `frontend/src/views/NodesView.vue`

改为卡片网格布局，每个节点一张卡片：

```
┌─────────────────────────────────┐
│ 🟢 node-hk1          🐧 Linux  │
│ 203.0.113.50                   │
│                                │
│ CPU  ████████░░  76%  (4核)    │
│ MEM  ██████░░░░  58%  5.8/16G  │
│ DISK ████░░░░░░  38%  38/100G  │
│ SWAP ██░░░░░░░░   5%  0.2/4G   │
│                                │
│ ↑ 1.2 GB    ↓ 3.4 GB           │
│ Agent v0.1.0  gost v2.12.1     │
│ 心跳: 2秒前                     │
│                                │
│ [详情]  [安装命令]  [禁用]      │
└─────────────────────────────────┘
```

关键实现：
- 使用 CSS Grid 响应式布局（auto-fill, minmax(360px, 1fr)）
- CPU/MEM/DISK/SWAP 用进度条组件
- 进度条颜色：< 70% 绿色，70-90% 橙色，> 90% 红色
- 在线状态用圆点指示器
- 自动刷新（setInterval 5秒拉一次数据）
- 离线节点灰显
- 空状态提示"添加你的第一个节点"

### 4.2 添加格式化工具函数
```typescript
function formatBytes(bytes: number): string  // → "1.2 GB"
function formatUptime(seconds: number): string  // → "3天 5小时"
function usagePercent(used: number, total: number): number  // → 76.5
function usageColor(pct: number): string  // → "green" | "orange" | "red"
```

---

## 五、Agent 安全加固

### 5.1 nftables 精确删除规则
**文件:** `crates/agent/src/executor.rs`

当前问题：`exec_delete_forward_rule` 直接 `flush_chain()`，删除所有规则。

改为：按 listen_port 精确匹配删除：

```rust
async fn exec_delete_forward_rule(&self, payload) {
    // 1. 列出当前规则，找到匹配 listen_port 的 handle
    // nft list ruleset -a → 解析出 handle 号
    // 2. 按 handle 删除
    // nft delete rule zachary_panel forward handle <N>
}
```

### 5.2 移除危险任务类型
**文件:** `crates/common/src/model.rs` + `crates/agent/src/executor.rs`

从 TaskType 枚举中移除：
- `InstallGost` — Agent 不应自行下载安装软件

executor.rs 中对应的 `exec_gost_install` 删除。

### 5.3 nftables 专属 table 隔离
**文件:** `crates/core/src/gost.rs` + `crates/agent/src/executor.rs`

所有 nft 操作限定在 `zachary_panel` table，不触碰其他 table：
- init_table() 只创建 `inet zachary_panel`
- flush 时只 flush `zachary_panel forward` chain，不影响系统其他规则
- 添加验证：所有 nft 命令必须包含 "zachary_panel" 字符串

### 5.4 命令注入防护
**文件:** `crates/agent/src/executor.rs`

在 run_cmd() 前增加参数验证：
```rust
fn validate_nft_args(args: &[String]) -> Result<(), String> {
    // 检查所有参数不包含 ; | & $ ` ( ) < > \n 等特殊字符
    // 检查 table 名必须是 zachary_panel
}
```

### 5.5 WebSocket HMAC 强制验证
**文件:** `crates/agent/src/ws.rs` + `crates/server/src/handlers/agent.rs`

确保 WebSocket 每条消息的 HMAC-SHA256 签名被验证：
- Agent 发送：timestamp + nonce + HMAC(node_token, node_id + timestamp + nonce + payload)
- Server 验证：检查 timestamp 是否在 ±5 分钟内、nonce 是否未用过（防重放）、HMAC 是否匹配
- 如果验证失败，立即断开 WebSocket 连接

---

## 六、执行顺序

1. 数据模型变更 (model.rs + db.rs)
2. Agent system.rs 采集函数
3. Agent ws.rs 心跳构建
4. Server agent.rs 心跳处理
5. Server node.rs 列表 API
6. 前端 NodesView.vue 重写
7. Agent executor.rs 安全加固
8. Agent ws.rs HMAC 强制验证
9. cargo clippy + cargo build
10. npm run build
11. docker compose build + deploy
12. git push

---

## 验证清单

- [ ] cargo clippy 无 warning
- [ ] cargo build --release 成功
- [ ] npm run build 成功
- [ ] Docker 容器启动无 panic
- [ ] 登录 admin/admin123 成功
- [ ] 节点列表显示探针卡片
- [ ] 添加节点 → 安装命令地址正确（非 0.0.0.0）
- [ ] 离线节点灰显
- [ ] CI 全绿
