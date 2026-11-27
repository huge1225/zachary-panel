# Zachary Panel — 分布式多引擎网络流量中转与专线管理面板

采用 **Master-Agent (主控 + 被控)** 架构开发的企业级端口转发与加密隧道中转面板，结合 **三级权限模型（角色权限组 -> 订阅套餐 -> 用户授权）**，支持在控制台**按节点或按单条规则动态切换四大底层转发引擎**：

- **`native` (内置自研多跳与聚合底座)**：纯 Go 零外部依赖高性能 TCP/UDP 转发，原生支持 **3+ 跳链式转发**、**多出口池分流**、**Mux 长连接复用池**、**Bonding 单流多通道带宽聚合**、**零解密 TLS SNI / HTTP Host 共享端口路由**、**PROXY Protocol v1/v2 真实源 IP 透传**、**指定出站源 IP**、令牌桶限速与 `CustomTunnelWrapper` 协议扩展接口
- **`gost` (GOST v3 引擎驱动)**：自动生成并托管 GOST v3 进程，支持 `TLS` / `WS` / `WSS` / `QUIC` / `KCP` 加密隧道、PROXY Protocol 与指定出站接口
- **`realm` (Realm 引擎驱动)**：生成并热重载 Realm 配置文件，支持极速低内存转发、PROXY Protocol 与 `through` 源地址绑定
- **`nftables` (Linux 内核零拷贝驱动)**：自动维护 `inet nexus_forward` 内核 `DNAT/SNAT` 表（支持指定源 IP `snat to` 与内核 `limit` 限速）并从内核 Counter 采集精确字节统计

> 📖 **完整生产环境部署、节点对接、多跳与带宽聚合隧道编排、DNS 自动容灾及商业化配置手册**：请查阅 **[DEPLOYMENT_AND_USAGE.md](./DEPLOYMENT_AND_USAGE.md)**

---

## 核心特性

1. **三级权限与精细化配额体系 (`RoleGroup -> Plan -> User`)**
   - **角色权限组 (`RoleGroup`)**：定义允许调度的节点与隧道范围（支持 `*` 全通配或指定隧道白名单）。
   - **订阅套餐 (`Plan`)**：绑定默认角色权限组，定义周期流量配额、最大并发规则数与单条带宽峰值。
   - **多维配额与分时段闲时计费**：支持全局及隧道专属**闲时流量倍率 (`Off-Peak Billing`)**（支持跨午夜时段如 `23:00–07:00`），同时支持为单条规则设置**累计总流量上限 (`rule_quota_bytes`)** 与**每日流量上限 (`daily_quota_bytes`，次日自动清零恢复)**。
2. **多跳链式转发与三维带宽聚合 (`Multi-Hop Chain & Multipath / Mux / Bonding`)**
   - **有序多跳链式编排 (`Ingress -> Hop_1 -> ... -> Hop_K -> Egress`)**：单条加密隧道最多支持串联 **8 个中间跳点**，主控自动校验无环有向图 (DAG)、自动分配各跳中继端口并逐跳固定校验证书 + `HMAC-SHA256` 防重放鉴权；测速接口返回**逐跳分段延迟 (`legs`)**，流量上报按单次业务计费、节点物理带宽独立统计，杜绝多跳重复扣费。
   - **多出口带宽聚合池 (`Egress Pool`)**：单条隧道可绑定多个出口节点（格式 `节点ID:权重[:backup]`），支持轮询 (`round_robin`)、加权 (`weighted`)、最低延迟 (`least_rtt`)、主备容灾 (`failover`) 与随机 (`random`) 调度。
   - **Mux 常驻连接复用池与 Bonding 单流多通道条带化聚合**：支持开启 **Mux 多路复用连接池**（消除逐连接 TLS+HMAC 握手 RTT，内置单流 256 KiB 滑动窗口背压）或 **Bonding 单连接多通道聚合**（建立 `2–8` 条并行加密子通道按 16 KiB 数据块条带化并发传输，有界序列重组突破单 TCP 窗口瓶颈）。
3. **多入口高可用与 DNS 自动容灾切换 (`IngressFailoverGroup`)**
   - 支持配置主入口节点与有序备用入口节点队列，实时感知节点掉线与**维护模式 (`maintenance`)**；满足离线阈值后自动通过 **Cloudflare API v4**、**腾讯云 DNSPod API** 或 **HMAC-SHA256 签名自定义 Webhook** 切换 `A / AAAA` 解析记录，内置切换防抖冷却 (`Cooldown`) 与主入口恢复自动回切 (`Auto-Failback`)。
4. **零解密 SNI / HTTP Host 共享端口路由、PROXY Protocol v1/v2 与指定出站源 IP**
   - **共享端口域名分流 (`MatchDomains`)**：支持多条 TCP 规则（含不同租户）共享同一 `(入口节点, 监听端口)`，在首包无解密提取 TLS `ClientHello` SNI 或 HTTP `Host` 精准路由至对应后端或加密隧道，内置通配符冲突与覆盖防劫持校验。
   - **端到端真实客户端 IP 透传 (`PROXY Protocol v1 / v2`)**：支持直转规则（`native` / `realm` / `gost`）及 `native` 跨多跳加密隧道将原始客户端 `IP:Port` 透传至最终出口并向后端注入标准 `PROXY v1 / v2` 协议头。
   - **多 IP 主机指定出站源 IP (`OutboundIP`)**：节点可配置默认出站源 IP 与租户可选出站 IP 白名单 (`AllowedOutboundIPs`)，普通用户仅可选用已授权的源 IP 出站。
5. **双模探针部署、端口规划与批量规则编排**
   - 控制台内置 **Systemd 服务** 与 **Docker Host 网络模式** 一键安装/卸载脚本生成器，支持断线重连本地快照秒级自愈与远程 `SHA-256` 校验热升级。
   - 支持隧道专属端口段规划与收窄范围自动端口迁移（含多跳中继端口、多出口池端口及共享端口域名组同步迁移）；支持批量导入（最多 50 条，含端口段一对一展开）、安全 CSV/剪贴板导出、单规则独立限速、来源 IP/CIDR 黑白名单 (`ACL`) 与多目标主动健康检查。
6. **商业化计费、优惠券、推广返利与在线支付闭环**
   - **优惠券 / 折扣码系统 (`Coupon`)**：支持**百分比折扣券**（可设最高减免封顶）与**固定金额满减券**（可设最低消费门槛），支持限定适用套餐、起止有效期、总可用次数与单用户限用次数；购买套餐与付费重置时实时试算抵扣。
   - **推广返利与邀请分销 (`Affiliate`)**：专属邀请码与推广链接（`/?ref=<CODE>`），受邀人充值或购套餐自动按比例结算返佣（内置防重复计佣），支持佣金**一键划转余额**或**申请提现审核**。
   - **兑换码 (`RedeemCode`) 与在线支付 (`BillingOrder`)**：支持套餐卡/余额卡/流量卡批量生成；原生支持 **易支付 (EPay MD5 验签回调)** 与 **USDT-TRC20 (`HMAC-SHA256` 防重放 Webhook 回调)** 自动入账，30 分钟超时未支付订单自动关闭。
7. **工单客服中心、可观测性与数据热备**
   - **工单客服中心 (`SupportTicket`)**：支持按分类与优先级提交工单、关联名下转发规则、多轮对话追问回复、后台结单流转及 **Webhook / Telegram Bot** 实时联动提醒。
   - **全景监控与审计热备**：24 小时逐时流量趋势图、用户/节点 Top 5 排行、全量安全审计日志 (`AuditLog`) 与基于 `VACUUM INTO` 的 SQLite 一键在线热备导出。
8. **现代化控制台体验与纵深安全防护**
   - **高效交互与性能**：支持深浅色主题切换、移动端抽屉导航、全局 `Ctrl/Cmd + K` 快速检索面板、`Esc` 关闭弹窗、`tabular-nums` 等宽排版、后台标签页自动暂停轮询（Page Visibility API）、防抖检索与大列表分页渲染。
   - **纵深安全体系**：零默认弱口令；TOTP 双因素认证 (2FA) 含 **30 秒时间片单调防重放 (`last_totp_step`)**；管理 `X-API-Key` 常量时间比对与按 IP 失败限流；全局 `1 MiB` 请求体大小上限；`token_version` 会话即时吊销；外链协议白名单与导出防公式注入；目标地址与 Webhook 严格防 SSRF / DNS 重绑定；控制面与数据面全链路 `HMAC-SHA256` 防重放签名及多级 TCP/UDP 会话上限保护。

---

## 目录结构

```text
.
├── DEPLOYMENT_AND_USAGE.md  # 详细生产部署、多跳/聚合隧道、DNS 容灾、商业增长与安全运维手册
├── README.md                # 项目概览与快速启动说明
├── go.mod                   # Go 模块依赖定义
├── cmd/
│   ├── master/              # 主控端入口 (REST API + WebSocket AgentHub + 计费/容灾调度)
│   └── agent/               # 被控节点守护进程 (单二进制，支持四引擎驱动与远程自升级)
├── internal/
│   ├── master/
│   │   ├── api/             # JWT/2FA/API-Key 鉴权、REST API、DNS 容灾、支付回调与测试套件
│   │   ├── hub/             # Agent WebSocket 双向长连接网关、分段延迟探测与远程升级下发
│   │   ├── model/           # GORM 数据模型、多跳/聚合拓扑结构与复合/部分唯一索引
│   │   └── service/         # 多跳图编译器、流量与闲时计费、规则双限额、DNS 自动容灾与通知
│   └── agent/
│       ├── client/          # WebSocket 自动重连、心跳上报、流量增量同步、快照持久化与安全自升级
│       ├── engine/          # 四引擎驱动 + Mux 复用池 / Bonding 多通道聚合 / SNI 路由 / PROXY v1&v2
│       ├── limiter/         # 令牌桶带宽限速器与原子流量计数器
│       ├── monitor/         # CPU/内存/磁盘系统负载采集与端到端 TCP 延迟探测
│       └── security/        # 沙箱校验、出站源 IP 绑定、SSRF 防护与隧道多模式 HMAC-SHA256 认证
├── pkg/
│   ├── protocol/            # Master <-> Agent 共享通信协议、多跳角色与防篡改签名
│   └── utils/               # 端口池自动分配与安全令牌工具
├── web/                     # Vue 3 + TypeScript + Vite 响应式控制台前端（含深浅色设计系统）
└── deploy/                  # Docker Compose、Dockerfile 与主控/被控加固安装脚本
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
