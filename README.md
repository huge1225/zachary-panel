# Zachary Panel

一个基于 Rust 开发的现代化流量转发管理面板，支持多节点管理、nftables/gost 转发、延迟测试和安全审计。

## ⚠️ 安全声明

本项目**仅用于合法的服务器流量转发、内网穿透、运维测试和个人网络管理**。

**禁止用于：**
- 任何形式的攻击、扫描
- 绕过网络限制
- 未授权代理
- 恶意流量转发
- 任何违法用途

## 功能特性

- 🔐 **安全架构**：Agent 全程 WSS 加密通信、HMAC-SHA256 签名、timestamp + nonce 防重放
- 🖥️ **多节点管理**：批量管理转发节点，自助添加、一键安装 Agent
- 🔄 **多种转发模式**：nftables 内核转发（TCP/UDP）、gost 应用层转发
- 🌐 **隧道支持**：WebSocket / WSS 隧道转发
- 📊 **延迟测试**：ICMP/TCP/HTTP/DNS 延迟测试，多节点批量测试
- 📈 **流量统计**：nftables counter 流量统计
- 📋 **完整审计**：操作日志、安全事件、任务记录
- 🎨 **现代 UI**：Vue 3 + TypeScript，深色/浅色模式

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Rust + Axum + Tokio + SQLx |
| 前端 | Vue 3 + TypeScript + Naive UI + Vite |
| 数据库 | SQLite（默认），预留 PostgreSQL |
| Agent | Rust + tokio-tungstenite + sysinfo |
| 部署 | Docker Compose + systemd |

## 架构

```
浏览器 → Nginx (HTTPS) → Server (Axum) ← WSS → Agent (转发节点)
                            ↓
                        SQLite
```

详细架构见 [docs/architecture.md](docs/architecture.md)

## 快速开始

### 前置条件

- Docker & Docker Compose
- 域名已解析到 VPS
- 端口 80/443 可访问

### 部署主控

```bash
# 克隆项目
git clone https://github.com/zachary-su/zachary-panel.git
cd zachary-panel

# 配置环境变量
cp .env.example .env
# 编辑 .env：设置 ADMIN_PASSWORD、JWT_SECRET、DOMAIN

# 启动
docker compose up -d

# 访问
# https://your-domain.com
# 默认管理员: admin / 你的 ADMIN_PASSWORD
```

### 添加转发节点

1. 登录面板 → 节点管理 → 添加节点
2. 复制生成的安装命令
3. 在目标 VPS 上执行安装命令
4. 节点自动注册并与主控建立 WSS 连接

## Agent 安装

```bash
curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- \
  --server https://panel.example.com \
  --node-id node_xxxxx \
  --install-token it_yyyyy
```

详细 Agent 文档见 [docs/agent.md](docs/agent.md)

## 转发规则创建

1. 面板 → 转发规则 → 新增规则
2. 选择节点、转发方式（nft/gost）、协议、端口
3. 配置源/目标地址和端口
4. 启动规则
5. 查看运行状态和日志

## 延迟测试

1. 面板 → 延迟测试
2. 选择测试类型（ICMP/TCP/HTTP/DNS）
3. 输入目标地址和端口
4. 选择节点（单个或多个）
5. 开始测试
6. 查看测试结果和历史记录

## GitHub 开发流程

```bash
# 克隆
git clone https://github.com/zachary-su/zachary-panel.git
cd zachary-panel

# 功能开发
git checkout dev
git checkout -b feature/your-feature
git add .
git commit -m "feat(scope): description"
git push origin feature/your-feature
# 创建 PR → dev

# 版本发布
git tag v0.1.0
git push origin v0.1.0
```

详见 [docs/github-flow.md](docs/github-flow.md)

## 版本规划

| 版本 | 内容 |
|------|------|
| v0.1.0 | 基础框架、登录认证、节点管理、运营基础 |
| v0.2.0 | Agent 任务系统、HMAC 签名、nftables TCP/UDP |
| v0.3.0 | gost 转发、进程管理 |
| v0.4.0 | WebSocket/WSS 隧道 |
| v0.5.0 | 延迟测试、连通性测试 |
| v0.6.0 | 流量统计、UI 优化、安全事件 |
| v1.0.0 | 稳定发布 |

## 安全注意事项

- ⚠️ 生产环境**必须**使用 HTTPS
- ⚠️ 生产环境**必须**修改默认管理员密码
- ⚠️ 建议定期轮换 node_token
- ⚠️ 建议开启防火墙，仅暴露必要端口
- ℹ️ Agent 已做加密通信和签名校验，但**任何客户端程序都不能保证绝对无法被逆向**
- ℹ️ 安全核心依赖 Server 端鉴权、签名校验、token 轮换、节点禁用和审计日志

详细安全文档见 [docs/security.md](docs/security.md)

## 文档列表

- [架构设计](docs/architecture.md)
- [API 设计](docs/api.md)
- [数据库设计](docs/database.md)
- [部署指南](docs/deploy.md)
- [Agent 文档](docs/agent.md)
- [安全文档](docs/security.md)
- [GitHub 流程](docs/github-flow.md)

## 常见问题

### Agent 连接不上主控？
检查：防火墙是否开放 443 出站、TLS 证书是否有效、node_token 是否正确。

### nftables 转发不生效？
确认 `net.ipv4.ip_forward=1` 已启用：`sysctl net.ipv4.ip_forward`

### 如何重新生成 node_token？
面板 → 节点管理 → 节点详情 → 重新生成 Token → 更新 Agent 配置文件。

### 如何禁用节点？
面板 → 节点管理 → 禁用节点。Agent 连接会立即被拒绝。

## License

MIT License - 见 [LICENSE](LICENSE)
