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
5. **批量规则维护与进阶转发特性（端口段展开 / 规则独立限速 / IP 黑白名单 / 主动健康探测）**
   - 支持通过文本粘贴或本地文件（`.txt` / `.csv` / `.json`）一次性批量导入最多 50 条转发规则，支持单行独立指定协议（`tcp` / `udp` / `both`）、多目标负载均衡地址（`;` 分隔）以及**端口段一对一展开**（例如监听 `20001-20010` 对应目标 `1.2.3.4:30001-30010` 自动展开为 10 条独立规则）。
   - 支持按单条规则设置**独立限速 (`speed_mbps`)** 与 **客户端来源 IP/CIDR 访问控制（`allow` 白名单 / `deny` 黑名单）**；`native` 引擎内置多目标**主动 TCP 健康检查**，后台每 10 秒自动探测并在故障时无感摘除离线落地目标、恢复后自动加回。
   - 支持按关键词、状态、隧道、协议与引擎多维筛选规则，以及勾选多条规则一键导出或批量卸载删除（单次最多 200 条，含跨用户越权原子校验）。
6. **商业化计费、卡密中心与在线充值闭环（兑换码 / 账单明细 / EPay 易支付 & USDT 回调）**
   - **兑换码 / 卡密管理中心 (`RedeemCode`)**：管理员可批量生成三种类型卡密——**套餐激活卡 (`plan`)**、**余额充值卡 (`balance`)**、**流量时长叠加卡 (`traffic`)**，支持自定义前缀、可用次数、过期时间、按批次/类型筛选、一键复制未核销卡密及禁用/删除。
   - **订单账单明细 (`BillingOrder`) 与在线充值**：自动记录每一笔余额充值、套餐购买、付费重置与卡密核销流水；支持对接标准 **易支付 (EPay MD5 签名回调)** 与 **USDT-TRC20 (HMAC-SHA256 Webhook 回调)** 实现用户自助在线充值自动入账。
   - **周期性自动流量结算**：支持为节点设置每月固定流量结算日 (`reset_day` 1–28 号)，以及开启年付/长周期套餐按每 30 天自动清零已用流量并恢复因超额暂停的转发规则。
7. **可观测性、告警通知与远程运维（24h 流量趋势 / Webhook & Telegram 告警 / Agent 远程升级 / 审计与热备）**
   - **24 小时流量趋势与 Top 5 排行**：概览页内置 24 小时逐时上下行流量趋势图及节点/用户/规则实时流量 Top 5 排行榜。
   - **实时运维告警通知**：支持配置通用 JSON Webhook 或 Telegram Bot，在节点离线/恢复上线、节点月度流量达到预警阈值（默认 85%）、用户流量即将耗尽或订阅即将到期时自动推送通知，并支持后台一键发送测试告警。
   - **被控节点版本上报与远程一键升级**：实时展示各节点 Agent 版本号、系统架构与运行引擎，管理员可在面板内一键下发远程热升级指令（Agent 自动校验 SHA-256 原子替换二进制并平滑重启）。
   - **操作审计日志 (`AuditLog`) 与 SQLite 在线热备**：完整记录登录、改密、2FA 变更、卡密生成、用户调配、节点升级及系统设置变更等敏感操作日志；支持管理员在面板内基于 `VACUUM INTO` 一键导出一致性 SQLite 数据库热备文件。
8. **订阅中心与高安全账号防护（订阅链接 / 订阅重置 / 密码重置 / TOTP 2FA / 管理 API Key）**
   - **专属订阅链接 (`/api/v1/sub/:token`)**：每位用户自动生成 128-bit 专属订阅 Token，支持 Base64 与 `?format=json` 订阅拉取及自助/管理员一键重置。
   - **TOTP 双因素认证 (2FA) 与外部对接 API Key**：支持绑定 Google Authenticator / 1Password 等 RFC 6238 动态口令验证器；支持生成与吊销 `zp_live_...` 外部管理 API Key（仅存储 SHA-256 哈希，支持 `X-API-Key` 请求头调用管理接口）。
   - **零默认弱口令与纵深防御**：首次启动密码来自环境变量或随机生成；公开注册默认关闭；具备 JWT 密钥持久化、`token_version` 即时吊销令牌、登录限流与防枚举锁定、目标地址防 SSRF / DNS 重绑定、节点控制通道 HMAC-SHA256 防重放签名。

---

## 目录结构

```text
.
├── DEPLOYMENT_AND_USAGE.md  # 详细生产部署、节点对接、隧道与角色/套餐配置手册
├── README.md                # 项目概览与快速启动说明
├── go.mod                   # Go 模块依赖定义
├── cmd/
│   ├── master/              # 主控端入口 (REST API + WebSocket AgentHub + 计费调度)
│   └── agent/               # 被控节点守护进程 (单二进制，支持多引擎插件驱动与远程自升级)
├── internal/
│   ├── master/
│   │   ├── api/             # JWT/2FA/API-Key 认证、用户端/管理端 RESTful API、账单回调与安全自测
│   │   ├── hub/             # Agent WebSocket 双向长连接网关、延迟探测与远程升级下发
│   │   ├── model/           # GORM 数据模型 (RoleGroup, Plan, User, Node, Tunnel, Rule, RedeemCode, BillingOrder, AuditLog)
│   │   └── service/         # 规则编排器、周期流量自动重置、节点/用户预警通知 (Webhook / Telegram)
│   └── agent/
│       ├── client/          # WebSocket 自动重连、心跳上报、流量增量同步、规则快照持久化与安全自升级
│       ├── engine/          # 多引擎可插拔驱动层 (driver, native, gost, realm, nftables) + IP ACL & 健康检查
│       ├── limiter/         # 令牌桶带宽限速器与原子流量计数器
│       ├── monitor/         # CPU/内存/磁盘系统负载采集与端到端 TCP 延迟探测
│       └── security/        # 进程级沙箱与双端隧道 HMAC-SHA256 双向挑战认证
├── pkg/
│   ├── protocol/            # Master <-> Agent 共享通信协议与安全防篡改签名
│   └── utils/               # 端口池自动分配与安全令牌工具
├── web/                     # Vue 3 + TypeScript + Vite + Tailwind 控制台前端 & 独立演示页
└── deploy/                  # Docker Compose、Dockerfile.master 与主控/被控一键安装脚本
```

---

## 快速启动指南

### 方式一：交互式一键部署向导（推荐，自动引导填写配置）
克隆仓库后直接运行 `./install.sh`（或通过 `curl` 远程一键拉起），脚本会按 **`[进度 1/6]` $\rightarrow$ `[进度 6/6]`** 引导选择部署模式（`docker` 容器 / `systemd` 服务 / `local` 本地免 root）、监听端口、数据库类型、管理员邮箱与密码（直接回车可自动生成 16 位高强度随机密码），并自动完成编译/构建、启动与健康检查：

```bash
# 远程一键拉取并启动交互式部署向导
curl -fsSL https://raw.githubusercontent.com/huge1225/zachary-panel/main/deploy/install-panel.sh | sudo bash

# 或在已克隆的代码目录中运行交互式向导
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel
./install.sh
```

也支持**非交互式一条命令直接部署**（适合自动化脚本）：
```bash
# Docker Compose 模式一键静默部署
./install.sh -y --mode docker --port 8080 --bind 127.0.0.1 --public-url https://panel.example.com --admin-email admin@example.com

# 本地免 root 模式一键静默部署
./install.sh -y --mode local --port 8080 --bind 127.0.0.1 --admin-email admin@example.com
```

日常一键运维命令：
```bash
./install.sh --status     # 查看运行状态
./install.sh --logs       # 查看实时日志
./install.sh --restart    # 重启面板服务
./install.sh --upgrade    # 拉取最新代码并重新构建升级
./install.sh --uninstall  # 停止并卸载服务
```

### 方式二：手动 Docker Compose 启动
```bash
cd zachary-panel/deploy
cp .env.example .env   # 按需修改 .env 中的 NEXUS_PUBLIC_URL、NEXUS_ADMIN_EMAIL 等
docker compose up -d --build
```

### 方式三：手动源码编译启动

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

---

## 详细文档

关于 **交互式一键部署向导、HTTPS 反向代理、节点 Systemd/Docker 对接、双端加密隧道创建、角色权限组/套餐/用户分配及安全防护规范**，请直接阅读：
👉 **[DEPLOYMENT_AND_USAGE.md](./DEPLOYMENT_AND_USAGE.md)**
