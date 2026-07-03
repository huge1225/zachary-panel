# Zachary Panel - GitHub 开发流程

## 1. 分支策略

### 分支命名规范

| 分支类型 | 命名格式 | 示例 |
|----------|----------|------|
| 主分支 | main | main |
| 开发分支 | dev | dev |
| 功能分支 | feature/* | feature/auth-login |
| 修复分支 | fix/* | fix/agent-reconnect |
| 发布分支 | release/* | release/v0.1.0 |
| 热修复 | hotfix/* | hotfix/login-token-expire |

### 分支生命周期

```
main ────────────────────────────────────●─────● v0.1.0
                                          │     │
                                          │     │ merge
                                          │     │
dev  ──────────────────────●──────────────┼─────┼─────
                           │              │     │
                           │ PR merge     │     │
feature/auth-login ────────┘              │     │
                                          │     │
release/v0.1.0 ───────────────────────────┘     │
                                                │
hotfix/critical ────────────────────────────────┘
```

## 2. 开发流程

### 2.1 新功能开发

```bash
# 1. 切换到 dev 分支
git checkout dev
git pull origin dev

# 2. 创建功能分支
git checkout -b feature/nft-tcp-forward

# 3. 开发和提交
git add .
git commit -m "feat(nft): add TCP forward rule support"

# 4. 推送
git push origin feature/nft-tcp-forward

# 5. 创建 Pull Request 到 dev
# 在 GitHub 上创建 PR: feature/nft-tcp-forward → dev
```

### 2.2 Bug 修复

```bash
git checkout dev
git checkout -b fix/gost-process-stop
git add .
git commit -m "fix(gost): fix process stop timeout issue"
git push origin fix/gost-process-stop
# 创建 PR: fix/gost-process-stop → dev
```

### 2.3 版本发布

```bash
# 1. 从 dev 创建 release 分支
git checkout dev
git pull origin dev
git checkout -b release/v0.1.0

# 2. 在 release 分支上做最后的测试和修复
# 更新版本号、CHANGELOG 等
git add .
git commit -m "chore(release): prepare v0.1.0 release"

# 3. 合并到 main
git checkout main
git pull origin main
git merge --no-ff release/v0.1.0

# 4. 打标签
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# 5. 合并回 dev
git checkout dev
git merge --no-ff release/v0.1.0
git push origin dev

# 6. 清理
git branch -d release/v0.1.0
git push origin --delete release/v0.1.0
```

### 2.4 热修复

```bash
# 1. 从 main 创建 hotfix
git checkout main
git checkout -b hotfix/critical-login-fix

# 2. 修复
git add .
git commit -m "fix(auth): fix JWT token expiration validation"
git push origin hotfix/critical-login-fix

# 3. 合并到 main
git checkout main
git merge --no-ff hotfix/critical-login-fix
git tag -a v0.1.1 -m "Hotfix v0.1.1"
git push origin v0.1.1

# 4. 合并回 dev
git checkout dev
git merge --no-ff hotfix/critical-login-fix
git push origin dev
```

## 3. 提交规范

使用 Conventional Commits：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### 类型 (type)

| 类型 | 说明 |
|------|------|
| feat | 新功能 |
| fix | Bug 修复 |
| docs | 文档变更 |
| style | 代码格式（不影响功能） |
| refactor | 代码重构 |
| perf | 性能优化 |
| test | 测试相关 |
| chore | 构建/工具配置 |
| ci | CI/CD 配置 |

### 范围 (scope)

| 范围 | 说明 |
|------|------|
| auth | 认证相关 |
| agent | Agent 相关 |
| server | Server 相关 |
| nft | nftables 相关 |
| gost | gost 相关 |
| tunnel | 隧道相关 |
| latency | 延迟测试 |
| traffic | 流量统计 |
| node | 节点管理 |
| rule | 规则管理 |
| security | 安全相关 |
| frontend | 前端 |
| dashboard | 仪表盘 |
| deploy | 部署相关 |
| ci | CI/CD |
| docs | 文档 |

### 示例

```
feat(auth): add JWT login API
feat(agent): add HMAC signature verification
feat(agent): add timestamp + nonce replay protection
feat(nft): add TCP/UDP forward rule support
feat(gost): add gost process management
feat(latency): add TCP ping test support
feat(latency): add multi-node batch test
feat(frontend): add node management page
feat(frontend): add latency test page
fix(gost): fix process stop timeout
fix(agent): fix heartbeat reconnect issue
docs(deploy): add Docker Compose guide
ci(release): add GitHub Release workflow
```

## 4. Pull Request 流程

### 4.1 创建 PR

1. 推送到功能分支
2. 在 GitHub 创建 Pull Request
3. 填写 PR 模板
4. 等待 Review 和 CI 检查通过
5. Squash Merge 到目标分支

### 4.2 PR 要求

- 标题符合 Conventional Commits
- 描述清楚变更内容和原因
- 关联相关 Issue
- CI 必须通过（fmt、clippy、test、build）
- 至少需要一次 Review（核心成员）
- 需要更新相关文档

### 4.3 Merge 策略

- 功能分支 → dev：Squash Merge
- dev → release：普通 Merge
- release → main：普通 Merge（保留历史）
- hotfix → main：普通 Merge

## 5. CI/CD

### 5.1 CI（每次 PR/Push）

- `cargo fmt --check`：格式检查
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`：单元测试
- 前端 `npm run type-check` + `npm run build`
- Docker 构建检查

### 5.2 Release（推送 tag v*）

- 构建 server-linux-amd64 / agent-linux-amd64
- 生成 SHA256 校验文件
- 创建 GitHub Release
- 上传 release 文件

## 6. 版本管理

### 6.1 版本号规则

Semantic Versioning: MAJOR.MINOR.PATCH

- MAJOR：不兼容的 API 变更
- MINOR：向后兼容的新功能
- PATCH：向后兼容的 Bug 修复

### 6.2 版本规划

| 版本 | 内容 |
|------|------|
| v0.1.0 | 基础框架 + 认证 + 节点管理 |
| v0.2.0 | Agent 任务系统 + 签名 + nftables |
| v0.3.0 | gost 转发 + 进程管理 |
| v0.4.0 | WebSocket/WSS 隧道 |
| v0.5.0 | 延迟测试 + 连通性测试 |
| v0.6.0 | 流量统计 + 安全事件 + UI 优化 |
| v1.0.0 | 稳定发布 |

## 7. 代码审查 Checklist

- [ ] 代码风格符合项目规范
- [ ] 没有硬编码的密钥或密码
- [ ] 所有用户输入有校验
- [ ] 命令执行使用参数数组，不使用 sh -c
- [ ] 错误处理完整
- [ ] 日志不输出敏感信息
- [ ] 有新功能时更新文档
- [ ] 有数据库迁移时添加迁移文件
- [ ] 安全相关变更经过安全审查
