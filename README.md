# Zachary Panel ⚡

轻量化 Web 转发面板 — 流量转发统一管控

## 🎯 功能特性

- **🌐 Web 界面管理**: 直观的仪表盘，节点管理和规则配置
- **🔀 流量转发**: 基于 gost 的高性能多协议转发
- **🛡️ 安全通信**: mTLS 双向证书认证，数据加密传输
- **📦 Agent 证书一键下载**: ZIP 包包含 CA/Agent 证书
- **⚡ 实时规则推送**: 规则变更自动推送到 Agent
- **🐳 Docker 部署**: 一键部署，支持生产环境
- **📊 统计报表**: 流量统计和活跃度分析（规划中）

## 🏗️ 架构设计

```
┌─────────────┐       mTLS        ┌─────────────┐
│  Web Panel  │◄──────────────────►│   Agent(VPS)│
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

### 本地开发

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

### 生产部署

见 [DEPLOYMENT.md](./DEPLOYMENT.md)

## 📱 界面预览

### 仪表盘
- 📊 总节点数、在线节点数统计
- 🔀 转发规则总数、活跃规则数

### 节点管理
- 🖥️ 节点列表（ID、名称、IP、状态）
- ➕ 添加新节点
- 📦 下载 Agent 证书 ZIP
- 🗑️ 删除节点

### 转发规则
- 🔀 规则列表（监听地址、目标地址、协议、状态）
- ➕ 添加转发规则
- ⏯️ 启用/禁用规则
- 🗑️ 删除规则

## 🔧 配置说明

### 环境变量 (Panel 端)

```bash
DATA_DIR=/data/zachary-panel  # 数据存储目录
LISTEN=:8080                  # HTTP 监听地址
GRPC_ADDR=:9090              # gRPC 服务监听地址
```

### 环境变量 (Agent 端)

```bash
PANEL_ADDR=panel.example.com:9090  # Panel gRPC 地址
AGENT_ID=node-1                    # Agent ID
AGENT_TOKEN=your-token-here        # Agent 认证 Token
CERT_DIR=/etc/zachary-agent/certs  # 证书目录
AGENT_GRPC_PORT=:9091              # Agent gRPC 服务端口
```

### 支持的协议

- **TCP**: 通用 TCP 转发
- **UDP**: UDP 转发
- **HTTP**: HTTP 协议转发
- **HTTPS**: HTTPS 协议转发
- **WS**: WebSocket 转发
- **WSS**: WebSocket Secure 转发

## 📚 API 文档

### REST API

#### Dashboard
```bash
GET /api/v1/dashboard
```

#### Agent 管理
```bash
# 获取节点列表
GET /api/v1/agents

# 添加节点
POST /api/v1/agents
{
  "id": "node-1",
  "hostname": "my-server",
  "ip": "192.168.1.100",
  "token": "your-token"
}

# 获取单个节点
GET /api/v1/agents/:id

# 删除节点
DELETE /api/v1/agents/:id

# 下载 Agent 证书 ZIP
GET /api/v1/agents/:id/certs.zip
```

#### 转发规则管理
```bash
# 获取节点规则列表
GET /api/v1/agents/:id/rules

# 添加规则
POST /api/v1/agents/:id/rules
{
  "listen_addr": "0.0.0.0:8080",
  "target_addr": "example.com:80",
  "protocol": "tcp",
  "enabled": true,
  "extra": "{}"
}

# 更新规则
PUT /api/v1/rules/:rule_id
{
  "listen_addr": "0.0.0.0:8081",
  "enabled": false
}

# 删除规则
DELETE /api/v1/rules/:rule_id
```

### gRPC 接口

见 [backend/internal/grpc/panel.proto](./backend/internal/grpc/panel.proto)

## 🛡️ 安全设计

### 通信安全
- **mTLS 双向认证**: 所有 Panel ↔ Agent 通信强制 mTLS
- **自签 CA**: 自动生成和管理 CA 证书
- **证书隔离**: 每个 Agent 唯一证书，可单独吊销
- **数据加密**: 所有传输数据加密

### 访问控制
- **Token 认证**: 节点注册需要 Token 认证
- **HTTPS 支持**: 支持 HTTPS 访问（见 DEPLOYMENT.md）

## 🤝 开发指南

### 项目结构
```
zachary-panel/
├── backend/            # Go 后端
│   ├── cmd/            # 入口点
│   ├── internal/       # 内部包
│   └── go.mod/go.sum
├── frontend/           # Vue 3 前端
│   ├── src/
│   └── package.json
└── README.md
```

### 开发流程
1. 修改后端代码 → `cd backend && go build -o /tmp/...`
2. 修改前端代码 → `cd frontend && npm run dev`
3. 测试功能
4. 提交 PR

## 🙏 致谢

- [gin](https://github.com/gin-gonic/gin) - Go Web 框架
- [naive-ui](https://www.naiveui.com/) - Vue 3 UI 组件库
- [gost](https://github.com/ginuerzh/gost) - 多协议代理转发

---

**⚡ 轻量化 Web 转发面板 — 流量转发统一管控**
