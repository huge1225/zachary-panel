# Zachary Panel — 分布式多引擎网络流量中转与专线管理面板

采用 **Master-Agent (主控 + 被控)** 架构开发的企业级端口转发与加密隧道中转面板，结合 **三级权限模型（角色权限组 -> 订阅套餐 -> 用户授权）**，支持在控制台**按节点或按单条规则动态切换四大底层转发引擎**：

- **`native` (内置/自研协议底座)**：纯 Go 零外部依赖高性能 TCP/UDP 转发 + 令牌桶限速 + TLS/自研隧道扩展接口 (`CustomTunnelWrapper`)
- **`gost` (GOST v3 引擎驱动)**：自动生成并托管 GOST v3 进程，支持 `TLS` / `WS` / `WSS` / `QUIC` / `KCP` 多跳加密隧道
- **`realm` (Realm 引擎驱动)**：生成并热重载 Realm 配置文件，极速低内存转发
- **`nftables` (Linux 内核零拷贝驱动)**：自动维护 `inet nexus_forward` 内核 NAT 表并从内核 Counter 采集精确字节统计

> 📖 **完整生产环境部署、节点对接、隧道创建与角色/套餐配置手册**：请查阅 **[DEPLOYMENT_AND_USAGE.md](./DEPLOYMENT_AND_USAGE.md)**

---

## 核心特性

1. **三级权限与计费体系 (`RoleGroup -> Plan -> User`)**
   - **角色权限组 (`RoleGroup`)**：定义允许调度的节点与隧道范围（支持 `*` 全通配或指定节点/隧道白名单）。
   - **订阅套餐 (`Plan`)**：绑定默认角色权限组，定义周期流量配额、最大并发规则数与单条带宽峰值。
   - **精细化用户鉴权 (`User`)**：普通用户仅能查看和使用所属角色授权的节点/隧道，内置防水平越权（IDOR）、抗 SSRF/内网探测与端口冲突预检。
2. **双模节点探针部署（Systemd 守护进程 / Docker 容器）**
   - 控制台内置一键安装与一键卸载脚本生成器，支持 **Systemd 服务模式** 与 **Docker Host 网络模式**。
   - 实时采集节点 CPU、内存、磁盘容量与负载，支持设置节点月度流量封顶并在超额时自动熔断。
   - **断线重连与规则持久化自愈**：节点或主控重启后自动下发全量活跃规则快照，毫秒级无感恢复转发进程。
3. **双端加密专线编排（Relay Line）**
   - 创建一条专线规则即可由主控自动生成随机预共享密钥（`TunnelPSK`），向出口节点下发 `tunnel_server` 监听任务、向入口节点下发 `tunnel_client` 封装任务，并按隧道倍率自动折算计费流量。

---

## 目录结构

```text
.
├── DEPLOYMENT_AND_USAGE.md  # 详细生产部署、节点对接、隧道与角色/套餐配置手册
├── README.md                # 项目概览与快速启动说明
├── go.mod                   # Go 模块依赖定义
├── cmd/
│   ├── master/              # 主控端入口 (REST API + WebSocket AgentHub + 计费调度)
│   └── agent/               # 被控节点守护进程 (单二进制，支持多引擎插件驱动)
├── internal/
│   ├── master/
│   │   ├── api/             # JWT 认证、用户端/管理端 RESTful API 与 RBAC/安全自测
│   │   ├── hub/             # Agent WebSocket 双向长连接网关与延迟探测
│   │   ├── model/           # GORM 数据模型 (RoleGroup, Plan, User, Node, Tunnel, Rule)
│   │   └── service/         # 规则编排器 (单端直转 + 入口/出口专线自动配对 + 倍率计费)
│   └── agent/
│       ├── client/          # WebSocket 自动重连、心跳上报、流量增量同步与规则快照持久化
│       ├── engine/          # 多引擎可插拔驱动层 (driver, native, gost, realm, nftables)
│       ├── limiter/         # 令牌桶带宽限速器与原子流量计数器
│       ├── monitor/         # CPU/内存/磁盘系统负载采集与端到端 TCP 延迟探测
│       └── security/        # 进程级沙箱与双端隧道 HMAC-SHA256 双向挑战认证
├── pkg/
│   ├── protocol/            # Master <-> Agent 共享通信协议与安全防篡改签名
│   └── utils/               # 端口池自动分配与安全令牌工具
├── web/                     # Vue 3 + TypeScript + Vite + Tailwind 控制台前端 & 独立演示页
└── deploy/                  # Docker Compose、Dockerfile.master 与被控节点一键安装脚本
```

---

## 快速启动指南

### 方式一：Docker Compose 一键部署（推荐）
```bash
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel/deploy
docker compose up -d --build
```

### 方式二：源码启动

#### 1. 启动主控后端 (Master)
默认使用开箱即用的 SQLite (`nexus_panel.db`)，首次启动会自动初始化默认管理员、演示普通用户、角色权限组、订阅套餐、演示节点及双端专线：
```bash
go mod tidy
go run ./cmd/master -listen :8080
```
- **默认管理员账号**：`admin@nexus.local` / 密码：`admin123`
- **默认普通用户账号**：`user@nexus.local` / 密码：`user123`
- **内置演示兑换码**：`NEXUS-VIP-2026`

#### 2. 启动被控节点 (Agent)
```bash
go run ./cmd/agent -master "ws://127.0.0.1:8080/api/v1/agent/ws" -id 1 -token "dev-node-secret"
```

#### 3. 启动前端控制台 (Web UI)
```bash
cd web
npm install
npm run dev
```

---

## 详细文档

关于 **HTTPS 反向代理、节点 Systemd/Docker 对接、双端加密隧道创建、角色权限组/套餐/用户分配及安全防护规范**，请直接阅读：
👉 **[DEPLOYMENT_AND_USAGE.md](./DEPLOYMENT_AND_USAGE.md)**
