# Zachary Panel 部署指南

本文档涵盖 Docker 部署（推荐）、手动部署、升级流程和完整配置说明。

---

## 一、Docker 部署（推荐）

### 1.1 准备环境

```bash
# 安装 Docker（如未安装）
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel
```

### 1.2 配置 .env

```bash
cp .env.example .env
vim .env
```

**必改项：**

```env
# ─── 必须修改 ───
JWT_SECRET=<用 openssl rand -hex 32 生成>
ADMIN_PASSWORD=<你的管理员密码>

# ─── 可选配置 ───
ADMIN_USERNAME=admin                    # 管理员用户名
HOST=0.0.0.0                            # 监听地址
PORT=38088                              # 监听端口
DATABASE_URL=sqlite:///app/data/zachary-panel.db?mode=rwc
RUST_LOG=info,zachary_panel_server=debug
WS_HEARTBEAT_INTERVAL=30                # 心跳间隔（秒）
JWT_EXPIRY_HOURS=24                     # JWT 有效期
INSTALL_TOKEN_TTL_MINUTES=30            # 安装令牌有效期
```

### 1.3 构建并启动

```bash
# 构建并后台启动
docker compose up -d --build

# 查看日志
docker compose logs -f

# 查看状态
docker compose ps
```

### 1.4 访问面板

```
http://<服务器IP>:38088
用户名: admin（或你设置的 ADMIN_USERNAME）
密码: 你设置的 ADMIN_PASSWORD
```

### 1.5 反向代理（Nginx + HTTPS）

生产环境**强烈建议**使用 Nginx 反向代理 + HTTPS：

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:38088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket 支持（Agent WSS 连接）
    location /ws/ {
        proxy_pass http://127.0.0.1:38088;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

用 Let's Encrypt 免费证书：

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d panel.example.com
```

---

## 二、添加转发节点

### 2.1 面板添加节点

1. 登录面板 → **节点管理** → **+ 添加节点**
2. 输入节点名称、公网 IP（可选）、备注
3. 点击创建后，获取安装命令

### 2.2 在目标 VPS 上安装 Agent

**方式一：一键脚本**（推荐）

在面板中点击「安装命令」按钮，复制完整命令，到目标节点执行：

```bash
curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- \
  --server https://panel.example.com \
  --node-id node_xxxxxxxxxxxx \
  --install-token it_xxxxxxxxxxxx
```

**方式二：Docker 部署 Agent**

```bash
# 拉取 Agent 镜像
docker run -d --name zachary-agent \
  --restart unless-stopped \
  --network host \
  --cap-add=NET_ADMIN \
  -e SERVER_URL=https://panel.example.com \
  -e NODE_ID=node_xxxxxxxxxxxx \
  -e INSTALL_TOKEN=it_xxxxxxxxxxxx \
  -e TLS_VERIFY=true \
  -e RUST_LOG=info \
  huge1225/zachary-panel-agent:latest
```

> ⚠️ Agent 需要 `NET_ADMIN` capability 来操作 nftables。

**方式三：手动安装**

```bash
# 下载二进制
curl -fSL https://github.com/huge1225/zachary-panel/releases/latest/download/zachary-panel-agent-linux-x86_64.tar.gz \
  | tar xz -C /opt/zachary-panel-agent --strip-components=1

# 写配置
cat > /opt/zachary-panel-agent/agent.yaml <<'EOF'
server_url: "https://panel.example.com"
node_id: "node_xxxxxxxxxxxx"
install_token: "it_xxxxxxxxxxxx"
ws_path: "/ws/agent"
heartbeat_interval: 30
tls_verify: true
nft_path: "/usr/sbin/nft"
gost_path: "/usr/local/bin/gost"
log_level: "info"
EOF

# 安装 systemd 服务
cp /opt/zachary-panel-agent/zachary-panel-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zachary-panel-agent
```

### 2.3 验证连接

安装后几秒内，面板节点列表应显示节点状态为 🟢 在线。
如果显示离线，检查：

- Agent 服务器出站 443 是否畅通
- TLS 证书是否有效
- install_token 是否过期（30 分钟有效期）

---

## 三、转发规则

### 3.1 nftables 转发（内核层，高性能）

| 协议 | 支持 |
|------|------|
| TCP | ✅ |
| UDP | ✅ |
| TCP + UDP | ✅ |

适用场景：大流量转发，性能要求高。需要在目标节点启用 IP 转发：

```bash
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
```

### 3.2 gost 转发（应用层，功能丰富）

| 隧道类型 | 协议 | 支持 |
|---------|------|------|
| Plain（直连） | TCP / UDP / TCP+UDP | ✅ |
| WebSocket | tcp+ws | ✅ |
| WSS（TLS） | tcp+wss+TLS | ✅ |

适用场景：需要隧道穿透、TLS 加密、复杂转发链路。

**WSS 隧道需要提供：**
- TLS 证书路径（如 `/etc/ssl/certs/your-cert.pem`）
- TLS 私钥路径（如 `/etc/ssl/private/your-key.pem`）

> ⚠️ gost 转发需要在目标节点预装 gost 二进制文件。

### 3.3 创建规则

1. 面板 → **转发规则** → **新增规则**
2. 选择节点、模式（nft / gost）、协议
3. 填写监听端口、目标地址、目标端口
4. gost 模式下选择隧道类型（plain / ws / wss）
5. wss 模式下填写证书和私钥路径
6. 保存并启动

---

## 四、升级

### 4.1 Docker 升级（Server）

```bash
cd zachary-panel

# 拉取最新代码
git pull origin main

# 重新构建并启动（数据卷保留）
docker compose up -d --build

# 确认服务正常
docker compose logs -f --tail=20
```

> 数据库存储在 Docker volume `zachary-data` 中，升级不会丢失数据。

### 4.2 手动升级（Server）

```bash
cd /opt/zachary-panel

# 停止服务
systemctl stop zachary-panel

# 备份数据
cp data/zachary-panel.db data/zachary-panel.db.bak.$(date +%Y%m%d)

# 下载新版本
curl -fSL https://github.com/huge1225/zachary-panel/releases/latest/download/zachary-panel-server-linux-x86_64.tar.gz \
  | tar xz --overwrite

# 启动
systemctl start zachary-panel
systemctl status zachary-panel
```

### 4.3 升级 Agent

```bash
# 在 Agent 节点上执行
systemctl stop zachary-panel-agent

curl -fSL https://github.com/huge1225/zachary-panel/releases/latest/download/zachary-panel-agent-linux-x86_64.tar.gz \
  | tar xz -C /opt/zachary-panel-agent --strip-components=1 --overwrite

systemctl start zachary-panel-agent
systemctl status zachary-panel-agent
```

### 4.4 版本兼容

- 数据库迁移自动执行（ALTER TABLE），无需手动操作
- Server 和 Agent 版本建议保持一致
- Agent 向下兼容：旧 Agent 可以连接新 Server
- 不保证向上兼容：新 Agent 连旧 Server 可能有问题

---

## 五、完整 .env 配置参考

```env
# ═══════════════════════════════════════
# 必须修改
# ═══════════════════════════════════════

# JWT 密钥（openssl rand -hex 32）
JWT_SECRET=your-64-char-hex-secret

# 管理员密码（首次启动会写入数据库）
ADMIN_PASSWORD=your-secure-password

# ═══════════════════════════════════════
# 可选配置（有默认值）
# ═══════════════════════════════════════

# 管理员用户名
ADMIN_USERNAME=admin

# 监听设置
HOST=0.0.0.0
PORT=38088

# 数据库
DATABASE_URL=sqlite:///app/data/zachary-panel.db?mode=rwc

# 日志级别: trace, debug, info, warn, error
RUST_LOG=info,zachary_panel_server=debug

# WebSocket 心跳间隔（秒）
WS_HEARTBEAT_INTERVAL=30

# JWT 有效期（小时）
JWT_EXPIRY_HOURS=24

# 安装令牌有效期（分钟）
INSTALL_TOKEN_TTL_MINUTES=30
```

---

## 六、Agent 配置参考（agent.yaml）

```yaml
# Server 地址（必填）
server_url: "https://panel.example.com"

# 节点 ID（面板创建节点时获得）
node_id: "node_xxxxxxxxxxxx"

# 安装令牌（一次性，注册后自动保存 node_token）
install_token: "it_xxxxxxxxxxxxxxxxxxxxxxxx"

# WebSocket 路径
ws_path: "/ws/agent"

# 心跳间隔（秒）
heartbeat_interval: 30

# 重连配置（指数退避）
reconnect_base_delay: 2
reconnect_max_delay: 60

# TLS 证书验证（生产环境必须 true）
tls_verify: true

# 二进制路径
nft_path: "/usr/sbin/nft"
gost_path: "/usr/local/bin/gost"

# 日志
log_level: "info"
# log_file: "/var/log/zachary-agent.log"
```

---

## 七、运维操作

### 备份

```bash
# Docker 部署
docker exec zachary-panel cp /app/data/zachary-panel.db /app/data/backup.db
# 或直接复制卷
docker run --rm -v zachary-data:/data -v $(pwd):/backup alpine cp /data/zachary-panel.db /backup/

# 手动部署
cp /opt/zachary-panel/data/zachary-panel.db /backup/zachary-panel-$(date +%Y%m%d).db
```

### 恢复

```bash
# 停止服务 → 覆盖数据库 → 启动
docker compose down
cp /backup/zachary-panel-20260101.db data/zachary-panel.db
docker compose up -d
```

### 查看日志

```bash
# Docker
docker compose logs -f --tail=100

# systemd
journalctl -u zachary-panel -f --tail=100
journalctl -u zachary-panel-agent -f --tail=100
```

### 重启令牌（安全）

如果 Agent token 疑似泄露：

1. 面板 → 节点详情 → **重新生成 Token**
2. 将新 token 写入 Agent 的 `agent.yaml`（`node_token` 字段）
3. 重启 Agent 服务

---

## 八、故障排查

| 症状 | 排查 |
|------|------|
| Agent 显示离线 | 检查出站 443、TLS 证书、token 是否正确 |
| nft 转发不生效 | `sysctl net.ipv4.ip_forward` 确认为 1 |
| gost 转发不生效 | 检查 gost 二进制是否存在 `which gost` |
| WSS 隧道连接失败 | 检查证书路径是否正确、证书是否过期 |
| 面板无法访问 | `docker compose ps` 检查容器状态、检查端口 |
| 登录 401 | 确认密码正确，检查 JWT_SECRET 是否变更 |
| 数据库锁定 | 确保只有一个 Server 实例在运行 |
