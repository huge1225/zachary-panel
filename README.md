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
   - 创建一条专线规则即可由主控自动生成 32 字节随机隧道密钥，向出口节点下发 TLS 隧道监听任务、向入口节点下发加密客户端任务（固定校验出口节点证书 + HMAC 防重放鉴权，UDP 同样走加密隧道），并按隧道倍率自动折算计费流量。
4. **隧道端口规划与带宽保障**
   - 创建隧道时可单独规划入口节点上的端口段（如 `20000-20999`），该隧道下的规则只在此范围内分配端口；同一节点端口由数据库唯一索引兜底防重复。
   - 套餐限速对所有引擎有效：`gost` / `realm` 无法限速时，普通用户带限速的规则自动改用 `native` 下发；`nftables` 使用内核 `limit` 限速，并提供 `nexus-agent -nft-selfcheck` 上线前自检。规则列表直接显示实际运行引擎。
   - 收窄节点或隧道端口范围时，范围外的规则（含加密隧道出口节点上的中继端口）自动迁移到新范围内的空闲端口并重新下发，无可用端口的规则会安全停用；中继端口同样有数据库唯一索引兜底。
5. **批量规则维护（批量导入 / 导出 / 批量删除）**
   - 支持通过文本粘贴或本地文件（`.txt` / `.csv` / `.json`）一次性批量导入最多 50 条转发规则，支持单行独立指定协议（`tcp` / `udp` / `both`）与多目标负载均衡地址（`;` 分隔）。
   - 支持勾选规则后一键导出已选或全部规则，以及勾选多条规则（支持全选）一键批量卸载并删除（单次最多 200 条，含跨用户越权原子校验）。
6. **订阅中心与账号生命周期维护（订阅链接 / 订阅重置 / 密码重置）**
   - **专属订阅链接 (`/api/v1/sub/:token`)**：每位用户自动生成 128-bit 专属订阅 Token，支持获取 Base64 文本订阅（含 `Subscription-Userinfo` 流量/到期响应头）与 `?format=json` 结构化订阅，支持用户自助或管理员一键重置订阅链接（旧链接立即失效）。
   - **订阅重置与到期管理**：管理员可在「用户管理」中一键重置用户订阅（按绑定套餐刷新到期周期、清零已用流量、自动恢复因超额暂停的规则）或自定义编辑到期日期；普通用户可在「套餐管理」中使用余额付费提前重置当月流量与周期。
   - **一键重置用户密码**：管理员可为用户指定新密码或一键生成 16 位高强度随机密码并自动复制，同时递增 `token_version` 立即吊销该用户的所有旧登录会话并解除登录锁定。
7. **安全默认值**
   - 不内置任何固定账号密码/兑换码；首次启动的管理员密码来自环境变量或随机生成；公开注册默认关闭。
   - JWT 密钥持久化、改密/封禁即时吊销令牌、登录限流与账号锁定、目标地址防 SSRF / DNS 重绑定、节点控制通道签名防重放。

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
# 先编辑 docker-compose.yml：设置 NEXUS_PUBLIC_URL、NEXUS_ADMIN_EMAIL、NEXUS_ADMIN_PASSWORD
docker compose up -d --build
```

### 方式二：源码启动

#### 1. 启动主控后端 (Master)
默认使用开箱即用的 SQLite (`nexus_panel.db`)，首次启动会自动初始化默认角色、套餐与管理员账号：
```bash
go mod download
NEXUS_ADMIN_EMAIL=admin@example.com NEXUS_ADMIN_PASSWORD='至少8位的强密码' \
  go run ./cmd/master -listen 127.0.0.1:8080
```
- 未设置 `NEXUS_ADMIN_PASSWORD` 时会随机生成管理员密码，并仅在首次启动日志中打印一次。
- 本地体验可额外设置 `NEXUS_SEED_DEMO=true` 生成演示节点、隧道与普通用户（生产环境请勿开启）。
- 全部环境变量说明见 [DEPLOYMENT_AND_USAGE.md 2.6 节](./DEPLOYMENT_AND_USAGE.md#26-主控端环境变量与安全配置)。

#### 2. 启动被控节点 (Agent)
在面板「节点管理」中新增节点，点击「对接」获取节点 ID 与 Token，然后：
```bash
go run ./cmd/agent -master "ws://127.0.0.1:8080/api/v1/agent/ws" -id 1 -token "<面板生成的节点Token>"
```
> 本机回环地址可直接使用 `ws://`；连接远程主控时必须使用 `wss://`（或显式加 `-allow-insecure-ws`，不推荐）。

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
