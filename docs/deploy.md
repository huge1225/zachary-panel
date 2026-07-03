# Zachary Panel - 部署指南

## 1. 环境要求

### 主控 VPS
- 操作系统：Debian 12/13 或 Ubuntu 22.04+
- 内存：≥ 1GB
- 磁盘：≥ 20GB
- 端口：80 (HTTP → HTTPS 重定向), 443 (HTTPS)
- 域名：已解析到 VPS IP

### 转发节点 VPS
- 操作系统：Debian 12/13 或 Ubuntu 22.04+
- 内存：≥ 512MB
- 端口：按转发规则需要开放
- 需要 root 权限

## 2. Docker Compose 部署（主控）

### 2.1 准备

```bash
# 安装 Docker
curl -fsSL https://get.docker.com | bash

# 安装 Docker Compose
apt install -y docker-compose-plugin
```

### 2.2 配置文件

创建 `.env` 文件：

```env
# 管理员初始密码（首次启动使用）
ADMIN_PASSWORD=YourSecurePassword123!

# JWT 密钥（随机生成，不能为空）
JWT_SECRET=$(openssl rand -base64 32)

# 数据库路径
DATABASE_URL=sqlite:///data/zachary-panel.db?mode=rwc

# Server 端口
SERVER_PORT=3000

# 域名
DOMAIN=panel.example.com
```

### 2.3 docker-compose.yml

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./data/certbot/conf:/etc/letsencrypt:ro
      - ./data/certbot/www:/var/www/certbot:ro
      - ./web/dist:/usr/share/nginx/html:ro
    depends_on:
      - server
    restart: unless-stopped

  server:
    image: zachary-panel-server:latest
    build:
      context: .
      dockerfile: deploy/docker/Dockerfile.server
    environment:
      - ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_URL=${DATABASE_URL}
      - SERVER_PORT=3000
      - RUST_LOG=info
    volumes:
      - ./data:/app/data
    expose:
      - "3000"
    restart: unless-stopped
```

### 2.4 启动

```bash
# 创建数据目录
mkdir -p data

# 启动服务
docker compose up -d

# 查看日志
docker compose logs -f
```

## 3. Nginx 配置

### nginx.conf

```nginx
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;

    # 限流
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;

    # 日志
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" "$http_user_agent"';

    server {
        listen 80;
        server_name panel.example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name panel.example.com;

        ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

        # 前端静态文件
        location / {
            root /usr/share/nginx/html;
            try_files $uri $uri/ /index.html;
        }

        # API 代理
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://server:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Agent WebSocket 代理
        location /ws/ {
            proxy_pass http://server:3000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }

        # Agent 安装脚本
        location /install-agent.sh {
            alias /usr/share/nginx/html/install-agent.sh;
        }
    }
}
```

## 4. Agent 部署

### 4.1 一键安装

```bash
curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- \
  --server https://panel.example.com \
  --node-id node_xxxxx \
  --install-token it_yyyyy
```

### 4.2 手动安装

```bash
# 下载 Agent
wget https://github.com/zachary-su/zachary-panel/releases/download/v0.1.0/agent-linux-amd64

# 验证 SHA256
sha256sum -c agent-linux-amd64.sha256

# 安装
sudo install -m 755 agent-linux-amd64 /usr/local/bin/zachary-agent

# 创建配置目录
sudo mkdir -p /etc/zachary-agent
sudo chmod 700 /etc/zachary-agent

# 编辑配置
sudo vi /etc/zachary-agent/config.yaml
```

配置文件 `/etc/zachary-agent/config.yaml`：

```yaml
server_url: "https://panel.example.com"
node_id: "node_xxxxx"
node_token: "nt_sensitive_token"
heartbeat_interval: 10
log_level: "info"
gost_path: "/usr/local/bin/gost"
nft_path: "/usr/sbin/nft"
tls_verify: true
tls_pinning: false
pinned_cert_sha256: ""
```

### 4.3 systemd 服务

```bash
sudo cp deploy/systemd/zachary-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zachary-agent
sudo systemctl start zachary-agent
sudo systemctl status zachary-agent
```

### 4.4 systemd service 文件

```ini
[Unit]
Description=Zachary Panel Agent
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/zachary-agent -c /etc/zachary-agent/config.yaml
Restart=always
RestartSec=5

# 安全限制
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/zachary-agent /var/log/zachary-agent /etc/nftables.conf /etc/systemd/system

# 日志
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

## 5. 卸载

### Agent 卸载

```bash
sudo systemctl stop zachary-agent
sudo systemctl disable zachary-agent
sudo rm -f /usr/local/bin/zachary-agent
sudo rm -rf /etc/zachary-agent
sudo rm -f /etc/systemd/system/zachary-agent.service
sudo systemctl daemon-reload
```

### Server 卸载

```bash
docker compose down -v
```

## 6. 防火墙配置

### 主控 VPS

```bash
# 只开放 HTTP 和 HTTPS
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

### 转发节点

```bash
# 开放 SSH
ufw allow 22/tcp

# 根据转发规则开放对应端口
ufw allow 8080/tcp
ufw allow 9090/udp

ufw enable
```

## 7. HTTPS 证书

使用 Certbot 获取免费证书：

```bash
# 安装 certbot
apt install -y certbot

# 获取证书
certbot certonly --webroot -w /var/www/certbot -d panel.example.com

# 证书路径
# /etc/letsencrypt/live/panel.example.com/fullchain.pem
# /etc/letsencrypt/live/panel.example.com/privkey.pem

# 自动续期
echo "0 3 * * * certbot renew --quiet" | crontab -
```
