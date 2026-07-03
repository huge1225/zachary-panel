# Zachary Panel - Agent 使用文档

## 1. Agent 概述

Zachary Panel Agent 是部署在转发节点上的 Rust 程序，负责：

- 与主控 Server 建立 WSS 加密长连接
- 定时上报心跳和系统状态
- 接收并执行转发规则任务
- 执行 nftables 规则管理
- 管理 gost 进程
- 执行延迟测试和连通性检测
- 上报流量统计

## 2. 安装

### 前提条件

- 操作系统：Debian 12/13 或 Ubuntu 22.04+
- root 权限
- 节点已安装 nftables（`apt install -y nftables`）
- 可选：已安装 gost

### 快速安装

在面板中创建节点后，获取安装命令并在节点上执行：

```bash
curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- \
  --server https://panel.example.com \
  --node-id node_xxxxx \
  --install-token it_yyyyy
```

### 手动安装步骤

```bash
# 1. 下载二进制
wget https://github.com/zachary-su/zachary-panel/releases/latest/download/agent-linux-amd64
wget https://github.com/zachary-su/zachary-panel/releases/latest/download/agent-linux-amd64.sha256

# 2. 校验哈希
sha256sum -c agent-linux-amd64.sha256

# 3. 安装
sudo install -m 755 agent-linux-amd64 /usr/local/bin/zachary-agent

# 4. 创建配置目录
sudo mkdir -p /etc/zachary-agent
sudo chmod 700 /etc/zachary-agent

# 5. 创建配置文件
sudo cat > /etc/zachary-agent/config.yaml << 'EOF'
server_url: "https://panel.example.com"
node_id: "node_xxxxx"
node_token: "YOUR_NODE_TOKEN"
heartbeat_interval: 10
log_level: "info"
gost_path: "/usr/local/bin/gost"
nft_path: "/usr/sbin/nft"
tls_verify: true
tls_pinning: false
pinned_cert_sha256: ""
EOF

# 6. 安装 systemd 服务
sudo cat > /etc/systemd/system/zachary-agent.service << 'EOF'
[Unit]
Description=Zachary Panel Agent
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/zachary-agent -c /etc/zachary-agent/config.yaml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/zachary-agent /var/log/zachary-agent /etc/nftables.conf /etc/systemd/system
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 7. 启动服务
sudo systemctl daemon-reload
sudo systemctl enable zachary-agent
sudo systemctl start zachary-agent
sudo systemctl status zachary-agent
```

## 3. 配置说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| server_url | string | 是 | 主控 Server URL（必须 HTTPS） |
| node_id | string | 是 | 节点唯一标识 |
| node_token | string | 是 | 节点认证令牌 |
| heartbeat_interval | int | 否 | 心跳间隔（秒），默认 10 |
| log_level | string | 否 | 日志级别 (debug/info/warn/error)，默认 info |
| gost_path | string | 否 | gost 二进制路径，默认 /usr/local/bin/gost |
| nft_path | string | 否 | nft 命令路径，默认 /usr/sbin/nft |
| tls_verify | bool | 否 | 是否验证 TLS 证书，默认 true |
| tls_pinning | bool | 否 | 是否启用 TLS Pinning，默认 false |
| pinned_cert_sha256 | string | 否 | 绑定的证书 SHA256（TLS Pinning 开启时需设置） |

## 4. 配置文件权限

Agent 启动时会检查配置文件权限：
- 要求权限为 600（owner read/write only）
- 属主为当前运行用户（root）
- 如果权限过宽，Agent 会输出警告（可通过安全事件查看）

## 5. 通信安全

### 连接建立
1. Agent 启动后使用 WSS (WebSocket Secure) 连接 Server
2. TLS 证书验证（可选的 TLS Pinning）
3. 连接成功后开始心跳循环

### 请求签名
所有 Agent 请求必须携带 HMAC-SHA256 签名：

```
body_hash = sha256(request_body)
signing_string = method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + body_hash
signature = hmac_sha256(node_secret, signing_string)
```

Header 要求：
- X-Node-Id: 节点 ID
- X-Timestamp: 请求时间戳
- X-Nonce: 随机 nonce
- X-Signature: HMAC 签名

### 心跳
每 `heartbeat_interval` 秒发送一次心跳，包含节点运行状态。

## 6. 任务执行

Agent 支持以下任务类型：

- `create_forward_rule` - 创建转发规则
- `update_forward_rule` - 更新转发规则
- `delete_forward_rule` - 删除转发规则
- `start_forward_rule` - 启动转发规则
- `stop_forward_rule` - 停止转发规则
- `restart_forward_rule` - 重启转发规则
- `check_listen_port` - 检查监听端口
- `check_target_reachable` - 检查目标连通性
- `check_forward_chain` - 检查转发链路
- `reload_nftables` - 重载 nftables
- `install_gost` - 安装 gost
- `check_gost_version` - 检查 gost 版本
- `get_system_info` - 获取系统信息
- `latency_test` - 延迟测试
- `batch_latency_test` - 批量延迟测试
- `dns_resolve_test` - DNS 解析测试
- `http_ping_test` - HTTP Ping 测试
- `tcp_ping_test` - TCP Ping 测试
- `icmp_ping_test` - ICMP Ping 测试

所有任务执行都使用 `Command::new()` + 参数数组方式，不接受任意 shell 命令。

## 7. nftables 转发

Agent 通过执行 nft 命令管理 nftables 转发规则。

### TCP 转发规则示例

```bash
nft add table ip zachary-panel
nft add chain ip zachary-panel prerouting { type nat hook prerouting priority dstnat\; }
nft add rule ip zachary-panel prerouting \
  ip daddr <public_ip> tcp dport <listen_port> \
  counter dnat to <target_addr>:<target_port>
```

### UDP 转发规则示例

```bash
nft add rule ip zachary-panel prerouting \
  ip daddr <public_ip> udp dport <listen_port> \
  counter dnat to <target_addr>:<target_port>
```

## 8. gost 转发

Agent 通过启动 gost 子进程管理 gost 转发。

### 普通转发

```bash
gost -L "tcp://:<listen_port>/<target_addr>:<target_port>"
gost -L "udp://:<listen_port>/<target_addr>:<target_port>"
```

### WebSocket 隧道（服务端）

```bash
gost -L "tcp+wss://:<listen_port>?path=/ws&cert=/path/cert.pem&key=/path/key.pem"
```

### WebSocket 隧道（客户端）

```bash
gost -L "rtcp://:<listen_port>/<target_addr>:<target_port>" \
     -F "tcp+wss://<server>:<port>?path=/ws"
```

## 9. 日志

Agent 日志默认输出到 journald（systemd 管理时）或 stdout。

日志级别：
- `debug`: 详细的调试信息
- `info`: 一般操作信息
- `warn`: 警告信息
- `error`: 错误信息

敏感信息（token、签名）不会出现在日志中。

## 10. 卸载

```bash
sudo systemctl stop zachary-agent
sudo systemctl disable zachary-agent
sudo rm -f /usr/local/bin/zachary-agent
sudo rm -rf /etc/zachary-agent
sudo rm -f /etc/systemd/system/zachary-agent.service
sudo systemctl daemon-reload
```

## 11. 故障排查

### Agent 无法连接 Server
- 检查网络：`curl -v https://panel.example.com`
- 检查防火墙：确保 443 端口可出站
- 检查 TLS 证书是否有效

### Agent 心跳失败
- 检查 node_id 是否正确
- 检查 node_token 是否有效
- 查看 Server 安全事件日志

### nftables 规则不生效
- 检查 net.ipv4.ip_forward 是否启用：`sysctl net.ipv4.ip_forward`
- 启用：`sysctl -w net.ipv4.ip_forward=1`
- 检查 nftables 是否安装：`nft --version`

### gost 转发不生效
- 检查 gost 是否安装：`/usr/local/bin/gost -V`
- 检查进程是否运行：`systemctl status gost-rule-*`
- 查看 gost 日志
