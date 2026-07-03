# Zachary Panel 开发路线图

> 最后更新: 2026-07-03

## 当前状态

| 模块 | 状态 | 技术栈 |
|------|------|--------|
| Server | ✅ 完成 | Rust + Axum + SQLite |
| Agent | ✅ 完成 | Rust + tokio-tungstenite + native-tls |
| Common | ✅ 完成 | Rust (共享类型 + 加密 + 签名) |
| Core | ✅ 完成 | Rust (nftables + gost 命令生成) |
| Migration | ✅ 完成 | Rust (10表 + 20索引 + v2增量) |
| Frontend | ✅ 基础完成 | Vue 3 + TypeScript + Tailwind CSS |
| Deploy | ✅ 完成 | Docker + systemd + 安装脚本 |

## 借鉴 flux-panel 后的优化计划

### Phase 1: 核心功能补全 (当前)

- [x] gost 进程管理器（启动/停止/热重载/流量统计）
- [x] 登录限流中间件
- [x] v2 数据库迁移（流量字段、系统信息字段）
- [ ] Server 端集成 LoginLimiter 到 auth handler
- [ ] Agent 心跳中携带流量统计数据
- [ ] 前端流量显示（规则列表中加入站/出站流量）

### Phase 2: 安全 + 用户体验

- [ ] 滑块验证码（登录页防暴力破解）
- [ ] 操作审计日志 UI 页面
- [ ] 节点/规则批量操作（导入导出）
- [ ] 前端移动端适配（Tailwind responsive breakpoints）
- [ ] 深色模式
- [ ] WebSocket 实时推送（节点状态变化、任务完成）

### Phase 3: 高级转发功能

- [ ] gost 进程持续监控 + 自动恢复
- [ ] gost 配置文件热重载（SIGHUP 信号）
- [ ] 流量归因（借鉴 flux-panel 的 service_name 编码方案）
- [ ] 按规则/节点的流量统计图表（Recharts/ECharts）
- [ ] 端口段转发（批量创建连续端口）
- [ ] 转发链路诊断（检测端口占用 → 目标可达 → nft链 → 实际连通）
- [ ] 流量告警阈值（每条规则可配月流量上限）

### Phase 4: 多租户 + 用户体系

- [ ] 用户注册/登录（非管理员用户）
- [ ] RBAC 权限系统（管理员/操作员/只读）
- [ ] 用户分配规则（每用户只能看到自己的规则）
- [ ] 用户流量配额管理
- [ ] API Token 系统（第三方集成用）

### Phase 5: 运维 + 监控

- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Grafana 仪表盘模板
- [ ] Agent 自动更新（检查版本 → 下载 → 热切换）
- [ ] 数据库备份/恢复（一键导出/导入）
- [ ] Caddy/Nginx 反向代理一键配置
- [ ] 健康检查 + 告警通知（Telegram/邮件/Webhook）
- [ ] 多架构 Docker 镜像（amd64 + arm64）

### Phase 6: 扩展性

- [ ] PostgreSQL 支持（feature flag）
- [ ] 集群模式（多 Server 实例 + Redis 共享状态）
- [ ] 插件系统（自定义任务类型）
- [ ] gRPC Agent 协议（替代 WebSocket，强类型 + 高性能）
- [ ] IPv6 完整支持
- [ ] 国际化 (i18n, 中/英)

## 技术原则

1. **Rust 优先** — Server/Agent/Core 必须用 Rust，保证性能和安全
2. **安全第一** — bcrypt 密码、HMAC 签名、JWT、限流（不做 flux-panel 的 MD5 + URL secret）
3. **SQLite 默认** — 零配置启动，PostgreSQL 作为可选
4. **Command::new().args()** — 绝不用 `sh -c` 执行用户输入
5. **白名单枚举** — 所有任务类型必须通过枚举验证
6. **RESTful API** — 正确使用 HTTP 方法（GET/POST/PUT/DELETE）
