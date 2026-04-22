# Zachary Panel 部署指南

## 🚀 快速开始 - 本地开发

### 1. 克隆项目并编译

```bash
# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel

# 编译后端
cd backend
go mod tidy
go build -o ../bin/panel-server ./cmd/server
go build -o ../bin/panel-agent ./cmd/agent
cd ..

# 启动 panel server
DATA_DIR=/tmp/zachary-data ./bin/panel-server

# 在另一个窗口，测试 API
curl -s http://localhost:8080/api/v1/dashboard
```

## 🚀 生产部署

### 服务器要求

- **操作系统**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+)
- **内存**: 512MB 最小，推荐 1GB+
- **存储**: 1GB 可用空间
- **网络**: 端口 80, 443, 9090 开放

### Panel 端部署

```bash
# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git /opt/zachary-panel
cd /opt/zachary-panel

# 创建数据目录
mkdir -p /data/zachary-panel

# 设置环境变量
export DATA_DIR=/data/zachary-panel
export LISTEN=:8080
export GRPC_ADDR=:9090

# 使用 Docker 或直接运行二进制
cd backend
CGO_ENABLED=1 go build -o /usr/local/bin/zachary-panel-server ./cmd/server

# 创建 systemd 服务
cat > /etc/systemd/system/zachary-panel.service << EOF
[Unit]
Description=Zachary Panel Server
After=network.target

[Service]
Type=simple
User=root
Environment=DATA_DIR=/data/zachary-panel
Environment=LISTEN=:8080
Environment=GRPC_ADDR=:9090
ExecStart=/usr/local/bin/zachary-panel-server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable zachary-panel
systemctl start zachary-panel
systemctl status zachary-panel
```

### Agent 端部署

1. 在 Panel 的 Web UI 或通过 API 添加节点，获取 Agent ID 和 Token
2. 下载 Agent 证书 ZIP（API: `GET /api/v1/agents/:id/certs.zip`）
3. 在目标 VPS 部署 Agent

```bash
# 创建目录
sudo mkdir -p /opt/zachary-agent
sudo mkdir -p /etc/zachary-agent/certs

# 复制 Agent 证书到 /etc/zachary-agent/certs/
# (解压之前下载的 certs.zip)

# 下载 Agent 二进制
cd /opt/zachary-agent
sudo wget -O agent https://github.com/huge1225/zachary-panel/releases/latest/download/panel-agent-linux-amd64
sudo chmod +x agent

# 创建 systemd 服务
sudo cat > /etc/systemd/system/zachary-agent.service << EOF
[Unit]
Description=Zachary Panel Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/zachary-agent/agent
Environment=PANEL_ADDR=panel.example.com:9090
Environment=AGENT_ID=node-1
Environment=AGENT_TOKEN=your-token-here
Environment=CERT_DIR=/etc/zachary-agent/certs
Environment=AGENT_GRPC_PORT=:9091
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable zachary-agent
sudo systemctl start zachary-agent
sudo systemctl status zachary-agent
```

## 🛠️ 配置项

### Panel 端环境变量

| 变量          | 默认值          | 说明                      |
|---------------|----------------|--------------------------|
| DATA_DIR      | /data          | 数据存储目录                |
| LISTEN        | :8080          | HTTP 监听地址              |
| GRPC_ADDR     | :9090          | gRPC 服务监听地址          |

### Agent 端环境变量

| 变量              | 默认值                  | 说明                        |
|------------------|------------------------|---------------------------|
| PANEL_ADDR       | panel.example.com:9090| Panel gRPC 地址            |
| AGENT_ID         | (hostname)             | Agent ID                  |
| AGENT_TOKEN      | (required)             | Agent 认证 Token           |
| CERT_DIR         | /etc/zachary-agent/certs | 证书目录                  |
| AGENT_GRPC_PORT  | :9091                 | Agent gRPC 服务端口        |

## 📦 Docker 部署（可选）

### 使用 Docker Compose

```yaml
version: '3.8'

services:
  panel:
    image: huge1225/zachary-panel:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - panel-data:/data
    environment:
      - DATA_DIR=/data
      - LISTEN=:8080
      - GRPC_ADDR=:9090

volumes:
  panel-data:
```

```bash
docker compose up -d panel
```

## 🔐 安全配置

### 1. 防火墙

```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9090/tcp
sudo ufw enable

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=9090/tcp
sudo firewall-cmd --reload
```

### 2. 使用 HTTPS

配置 Nginx 反向代理（见 nginx.conf）并使用 Let's Encrypt 证书。

## 🔧 故障排除

### Panel 问题

- **日志**: `journalctl -u zachary-panel -f`
- **重启**: `systemctl restart zachary-panel`
- **检查端口**: `ss -tlnp | grep -E '(8080|9090)'`

### Agent 问题

- **日志**: `journalctl -u zachary-agent -f`
- **重启**: `systemctl restart zachary-agent`
- **检查 mTLS**: 确认证书目录存在且权限正确 (0600 或 0644)

## 📚 更多文档

- [README.md](./README.md) - 项目介绍和功能特性
- [API Reference](#) - 完整 API 文档（规划中）

---

**⚡ 轻量化 Web 转发面板 — 流量转发统一管控**
