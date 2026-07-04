# Zachary Panel

[![CI](https://github.com/huge1225/zachary-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/huge1225/zachary-panel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一个基于 Rust 的现代化流量转发管理面板，支持 nftables 内核转发和 gost 应用层转发（含 WS/WSS 隧道），自带多节点管理、延迟测试和安全审计。

## ⚠️ 安全声明

本项目**仅用于合法的服务器流量转发、内网穿透、运维测试和个人网络管理**。禁止用于任何违法用途。

## ✨ 功能特性

- 🔐 **安全通信**：WSS 加密 + HMAC-SHA256 签名 + timestamp/nonce 防重放
- 🖥️ **多节点管理**：一键安装 Agent、实时探针监控（CPU/MEM/DISK/SWAP/网络流量）
- 🔄 **多种转发**：
  - **nftables DNAT**（内核层）— TCP / UDP / TCP+UDP，高性能
  - **gost**（应用层）— Plain / WebSocket / WSS+TLS 隧道
- 📊 **延迟测试**：ICMP / TCP / HTTP / DNS，多节点批量测试
- 📋 **完整审计**：操作日志、安全事件、任务记录
- 🎨 **现代 UI**：Vue 3 + TypeScript，响应式探针卡片

## 🚀 快速开始

### 前置条件

- Docker & Docker Compose（Server）
- 任意 Linux（Agent 节点）

### 1. 部署主控

```bash
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel

# 配置
cp .env.example .env
# 生成 JWT 密钥
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
# 设置管理员密码
vim .env

# 启动
docker compose up -d --build

# 访问
# http://<服务器IP>:38088
```

### 2. 添加转发节点

面板 → 节点管理 → 添加节点 → 复制安装命令 → 在目标 VPS 执行：

```bash
curl -fsSL https://panel.example.com/install-agent.sh | bash -s -- \
  --server https://panel.example.com \
  --node-id node_xxxxx \
  --install-token it_yyyyy
```

### 3. 创建转发规则

面板 → 转发规则 → 新增 → 选择节点、模式（nft/gost）、协议、隧道类型 → 启动

📖 **完整部署文档**: [docs/deploy.md](docs/deploy.md)

## 转发能力一览

| 模式 | 协议 | 隧道 | 说明 |
|------|------|------|------|
| nftables | TCP / UDP / TCP+UDP | — | 内核 DNAT，最高性能 |
| gost Plain | TCP / UDP / TCP+UDP | 直连 | 应用层转发，兼容性好 |
| gost WS | — | tcp+ws | WebSocket 隧道，穿 CDN |
| gost WSS | — | tcp+wss+TLS | TLS 加密隧道 |

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Rust + Axum + Tokio + SQLx |
| 前端 | Vue 3 + TypeScript + Vite |
| 数据库 | SQLite (WAL 模式) |
| Agent | Rust + tokio-tungstenite + sysinfo |
| 部署 | Docker Compose / systemd |

## 升级

```bash
cd zachary-panel
git pull origin main
docker compose up -d --build
```

数据库自动迁移，数据不丢失。详见 [部署文档](docs/deploy.md#四升级)。

## .env 配置

```env
# 必须修改
JWT_SECRET=<openssl rand -hex 32>
ADMIN_PASSWORD=<你的密码>

# 可选
ADMIN_USERNAME=admin
PORT=38088
RUST_LOG=info
```

完整配置项见 [部署文档](docs/deploy.md#五完整-env-配置参考)。

## 常见问题

<details>
<summary><b>Agent 连接不上？</b></summary>

检查：① Agent 出站 443 是否畅通 ② TLS 证书是否有效 ③ install_token 是否过期（30 分钟）
</details>

<details>
<summary><b>nftables 转发不生效？</b></summary>

```bash
sysctl net.ipv4.ip_forward
# 如果不是 1，执行：
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf && sysctl -p
```
</details>

<details>
<summary><b>gost 转发报错？</b></summary>

确认目标节点已安装 gost：`which gost`。WSS 模式还需要有效的 TLS 证书和私钥。
</details>

<details>
<summary><b>如何重置管理员密码？</b></summary>

修改 `.env` 中的 `ADMIN_PASSWORD`，重启服务。首次启动时会初始化，之后需要通过面板修改。
</details>

## License

MIT
