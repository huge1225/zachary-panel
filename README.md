# Zachary Panel ⚡

轻量化 Web 转发面板 — 流量转发统一管控

## 🎯 功能特性

- **🌐 Web 界面管理**: 直观的仪表盘，节点管理和规则配置
- **🔀 流量转发**: 基于 gost 的高性能多协议转发
- **🛡️ 安全通信**: mTLS 双向证书认证，数据加密传输
- **⚡ 实时监控**: 节点状态、规则状态实时监控
- **🐳 Docker 部署**: 一键部署，支持生产环境
- **📊 统计报表**: 流量统计和活跃度分析

## 🏗️ 架构设计

```
┌─────────────┐       mTLS        ┌─────────────┐
│  Web Panel  │◄──────────────────►│   Agent(VPS) │
│  (主控端)    │   gRPC 双向加密    │  gost + nft  │
└─────────────┘                    └─────────────┘
```

### 组件说明

- **Panel 主控端**: Web 管理界面 + HTTP API + gRPC 服务
- **Agent 节点**: 部署在 VPS 上，管理 gost 和 nftables
- **数据库**: SQLite，零运维配置
- **安全**: 自签 CA + mTLS 双向证书认证
- **前端**: Vue 3 + Naive UI，响应式设计

## 🚀 快速开始

### 开源部署（学习测试）

```bash
# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel

# 启动服务（开发模式）
./start.sh dev

# 启动服务（生产模式）
./start.sh prod
```

### 闭源部署（生产环境）

⚠️ **注意**: 闭源部署请参考 [HTTP/HTTPS 一键部署方案](#方案一-httphttps-一键部署推荐)

## 📱 界面预览

### 仪表盘
- 📊 总节点数、在线节点数统计
- 🔀 转发规则总数、活跃规则数
- 📈 最近活动时间线

### 节点管理
- 🖥️ 节点列表（ID、名称、IP、状态）
- ➕ 添加新节点
- 🔄 刷新节点状态
- 🗑️ 删除节点

### 转发规则
- 🔀 规则列表（监听地址、目标地址、协议、状态）
- ➕ 添加转发规则
- ⏯️ 启用/禁用规则
- 🗑️ 删除规则

## 🔧 配置说明

### 环境变量

```bash
# Panel 配置
PANEL_URL=http://your-domain.com:8080    # Panel 访问地址
GRPC_URL=your-domain.com:9090            # gRPC 服务地址
LOG_LEVEL=info                           # 日志级别

# Agent 配置
PANEL_ADDR=panel.example.com:9090       # Panel 地址
AGENT_ID=node-1                          # 节点 ID
AGENT_TOKEN=your-token-here              # 认证 Token
```

### 支持的协议

- **TCP**: 通用 TCP 转发
- **UDP**: UDP 转发
- **HTTP**: HTTP 协议转发
- **HTTPS**: HTTPS 协议转发
- **WS**: WebSocket 转发
- **WSS**: WebSocket Secure 转发

## 🛡️ 安全设计

### 通信安全

- **mTLS 双向认证**: 所有 Panel ↔ Agent 通信强制 mTLS
- **自签 CA**: 自动生成和管理 CA 证书
- **证书隔离**: 每个 Agent 唯一证书，可单独吊销
- **数据加密**: 所有传输数据加密

### 访问控制

- **Token 认证**: 节点注册需要 Token 认证
- **IP 白名单**: 可配置访问 IP 白名单
- **HTTPS 支持**: 支持 HTTPS 访问
- **防火墙集成**: 自动配置 nftables 规则

## 🔍 监控和日志

### 实时监控

- 节点在线状态
- 规则启用状态
- 连接数统计
- 流量监控

### 日志管理

```bash
# 查看 Panel 日志
docker compose logs -f panel

# 查看 Agent 日志
journalctl -u zachary-agent -f

# 查看访问日志
tail -f logs/access.log
```

## 🚀 部署方案

### 方案一：HTTP/HTTPS 一键部署（推荐）

适用于闭源项目，无需 Git 认证，通过 HTTP/HTTPS 直接下载部署文件，适合生产环境。

#### 1. 准备发布服务器

首先需要准备一个 HTTP/HTTPS 服务器来存放部署文件：

```bash
# 创建发布目录
mkdir -p /var/www/zachary-panel
cd /var/www/zachary-panel

# 上传以下文件到服务器：
# - docker-compose.yml
# - .env.example
# - start.sh
# - nginx.conf
# - install.sh
# - install-agent.sh

# 设置权限
chmod +x *.sh

# 启动 Web 服务
python3 -m http.server 8080
```

#### 2. Panel 端部署

**一键安装：**
```bash
# 下载并运行安装脚本
curl -fsSL https://your-domain.com/install.sh | sudo bash

# 或者分步执行
wget https://your-domain.com/install.sh
chmod +x install.sh
sudo ./install.sh
```

**安装脚本功能：**
- 🎯 **自动检测**: 检测操作系统和架构
- 🔧 **自动安装**: 安装 Docker、Docker Compose 和依赖
- 🌐 **自动配置**: 获取服务器 IP 并配置环境
- 🛡️ **自动安全**: 配置防火墙和 SSL 证书
- 🚀 **自动启动**: 下载部署文件并启动服务
- 📊 **自动检查**: 验证服务启动状态

#### 3. Agent 端部署

**一键安装：**
```bash
# 下载并运行 Agent 安装脚本
curl -fsSL https://your-domain.com/install-agent.sh | sudo bash

# 或者分步执行
wget https://your-domain.com/install-agent.sh
chmod +x install-agent.sh
sudo ./install-agent.sh
```

**Agent 安装脚本功能：**
- 🎯 **自动检测**: 检测操作系统和架构
- 🔧 **自动下载**: 下载对应架构的 Agent 二进制文件
- 🛡️ **安全配置**: 配置 Token 认证和服务
- 🚀 **自动启动**: 创建 systemd 服务并启动
- 📊 **状态监控**: 检查服务运行状态

#### 4. 使用方法

**Panel 端管理：**
```bash
# 启动服务
./start.sh

# 停止服务
./start.sh stop

# 重启服务
./start.sh restart

# 更新服务
./start.sh update

# 查看日志
./start.sh logs -f

# 查看状态
./start.sh status
```

**Agent 端管理：**
```bash
# 查看日志
journalctl -u zachary-agent -f

# 重启服务
systemctl restart zachary-agent

# 停止服务
systemctl stop zachary-agent

# 状态检查
systemctl status zachary-agent
```

#### 5. 配置说明

**环境变量配置 (.env)：**
```bash
# Panel 配置
PANEL_URL=http://your-domain.com:8080
GRPC_URL=your-domain.com:9090
LOG_LEVEL=info

# 数据库配置
DB_PATH=/data/panel.db

# 开发/生产环境
ENV=prod
```

**Agent 配置：**
```bash
# 在 Panel 管理界面创建 Agent 后，会获得 Token
PANEL_ADDR=panel.example.com:9090
AGENT_ID=node-1
AGENT_TOKEN=your-token-here
CERT_DIR=/etc/zachary-agent/certs
```

### 方案二：私有仓库部署

适用于需要完全控制代码源的场景，需要 GitHub 认证。

#### 1. 创建私有仓库

```bash
# 在 GitHub 上创建私有仓库：zachary-panel-private

# 或将现有仓库转为私有
git remote set-url origin https://github.com/your-username/zachary-panel-private.git
git push origin main
```

#### 2. VPS 安装步骤

```bash
#!/bin/bash
# Zachary Panel 私有仓库安装脚本

set -e

# 安装依赖
apt update && apt upgrade -y
apt install -y git curl wget docker.io docker-compose nginx

# 创建工作目录
cd /opt/zachary-panel

# 克隆私有仓库（需要 GitHub Token）
echo "请输入 GitHub Token:"
read -s GITHUB_TOKEN
git clone https://${GITHUB_TOKEN}@github.com/your-username/zachary-panel-private.git .

# 配置环境
SERVER_IP=$(curl -s ifconfig.me)
cat > .env << EOF
PANEL_URL=http://${SERVER_IP}:8080
GRPC_URL=${SERVER_IP}:9090
LOG_LEVEL=info
EOF

# 启动服务
docker compose up -d panel

echo "✅ 安装完成！访问: http://${SERVER_IP}:8080"
```

## 🔧 故障排除

### 常见问题

1. **端口被占用**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep :8080
   
   # 修改端口
   sed -i 's/8080:8080/8081:8080/' docker-compose.yml
   ```

2. **证书问题**
   ```bash
   # 重新生成证书
   docker compose exec panel sh -c "rm -rf /data/certs && mkdir -p /data/certs"
   docker compose restart panel
   ```

3. **Agent 连接失败**
   ```bash
   # 检查 Agent 状态
   systemctl status zachary-agent
   
   # 检查网络连通性
   telnet panel.example.com 9090
   ```

### 性能优化

```bash
# 优化 gost 配置
gost -C config.json

# 优化 nftables
nft add rule zachary_panel forward tcp dport 8080 dnat to 192.168.1.100:80
```

## 📚 API 文档

### REST API

```bash
# 获取节点列表
GET /api/v1/agents

# 添加节点
POST /api/v1/agents
{
  "id": "node-1",
  "hostname": "server-1",
  "ip": "192.168.1.100",
  "token": "your-token"
}

# 获取规则
GET /api/v1/agents/{id}/rules

# 添加规则
POST /api/v1/agents/{id}/rules
{
  "listen_addr": "0.0.0.0:8080",
  "target_addr": "example.com:80",
  "protocol": "tcp",
  "enabled": true
}
```

### gRPC 接口

```protobuf
service PanelService {
  rpc RegisterAgent(RegisterRequest) returns (RegisterResponse);
  rpc GetForwardRules(GetRulesRequest) returns (GetRulesResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}
```

## 🤝 技术支持

- **GitHub Issues**: [提交问题](https://github.com/huge1225/zachary-panel/issues)
- **文档**: [详细部署指南](DEPLOYMENT.md)
- **讨论**: [GitHub Discussions](https://github.com/huge1225/zachary-panel/discussions)

## 📄 许可证

闭源项目 - 仅供授权用户使用

## 🙏 致谢

- [gin](https://github.com/gin-gonic/gin) - Go Web 框架
- [naive-ui](https://www.naiveui.com/) - Vue 3 UI 组件库
- [gost](https://github.com/ginuerzh/gost) - 多协议代理转发
- [nftables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) - Linux 包过滤

---

**⚡ 轻量化 Web 转发面板 — 流量转发统一管控**