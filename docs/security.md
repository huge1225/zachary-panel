# Zachary Panel - 安全文档

## 1. 概述

Zachary Panel 的安全设计围绕一个核心原则：**Agent 是部署在外部的潜在不可信组件，Server 必须对所有 Agent 请求做严格验证。**

本文档详细描述 Zachary Panel 的安全架构、机制和最佳实践。

## 2. Agent 通信安全

### 2.1 传输层加密

- Agent 与 Server 之间全程使用 **WSS (WebSocket Secure)** = WebSocket over TLS 1.3
- **禁止 HTTP 明文通信**
- Server URL 必须以 `https://` 开头

### 2.2 TLS 校验

Agent 默认启用 TLS 证书校验：
- 验证 Server 证书是否由可信 CA 签发
- 验证证书域名是否匹配

### 2.3 TLS Pinning（可选）

```yaml
tls_pinning: true
pinned_cert_sha256: "sha256_of_server_certificate"
```

启用后 Agent 只接受指纹匹配的 Server 证书，防止中间人攻击。

注意：证书更新时需要同步更新 `pinned_cert_sha256`。

### 2.4 HMAC-SHA256 请求签名

所有 Agent 与 Server 之间的消息必须签名。

**签名流程：**

```
body_hash = SHA256(request_body)
signing_string = method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + body_hash
signature = HMAC-SHA256(node_token, signing_string)
```

**请求头：**

| 头 | 说明 |
|----|------|
| X-Node-Id | 节点 ID |
| X-Timestamp | Unix 时间戳（秒） |
| X-Nonce | 随机字符串（一次性） |
| X-Signature | 签名 hex 字符串 |

**Server 验证步骤：**
1. 检查 X-Node-Id 对应的节点是否存在且启用
2. 检查 X-Timestamp 是否在允许范围内（±60秒）
3. 检查 X-Nonce 是否已被使用过
4. 重新计算签名并比对
5. 记录已使用的 nonce

### 2.5 防重放机制

- **timestamp 窗口**：默认 ±60 秒，超时请求直接拒绝
- **nonce 去重**：每次请求携带唯一 nonce，Server 记录已使用 nonce
- **nonce 过期清理**：每天自动清理过期 nonce 记录

## 3. Token 生命周期

### 3.1 install_token（安装令牌）

```
创建：面板管理员创建节点时自动生成
格式：it_ + 32位随机hex字符串
有效期：30分钟（可配置）
使用：Agent 首次注册时使用一次
存储：Server 仅存储 SHA256 哈希
```

**生命周期：**
1. 管理员创建节点 → Server 生成 install_token
2. 返回明文 token 给管理员（仅在创建时）
3. 管理员复制安装命令到节点执行
4. Agent 携带 install_token 调用注册 API
5. Server 校验后标记 install_token 已使用
6. install_token 立即失效

### 3.2 node_token（节点令牌）

```
创建：Agent 注册成功后由 Server 生成
格式：nt_ + 64位随机hex字符串
有效期：直到被吊销或重新生成
存储：Server 仅存储 SHA256 哈希
```

**生命周期：**
1. Agent 注册成功后，Server 生成 node_token 并返回
2. Agent 保存到 `/etc/zachary-agent/config.yaml`
3. 后续所有通信使用 node_token 派生密钥签名
4. 管理员可通过面板吊销或重新生成

### 3.3 Token 安全特性

- 每个节点独立 token，互不影响
- token 明文只在首次生成时出现一次
- Server 只存储哈希，不存储明文
- 支持单独吊销
- 重新生成时旧 token 立即失效
- 日志中不输出 token 明文字段

## 4. Agent 二进制安全

### 4.1 编译保护

```toml
[profile.release]
opt-level = "z"      # 最小体积
lto = true           # 链接时优化
codegen-units = 1    # 单代码生成单元
panic = "abort"      # panic 直接终止
strip = true         # 去除符号表
```

### 4.2 设计原则

- **不硬编码密钥**：Agent 二进制中不包含任何 Server 全局密钥
- **不写死 Server 配置**：所有配置从配置文件读取
- **运行中从 Server 获取关键配置**：而不是预置在二进制中
- **每个节点独立密钥**：一个节点被破解不影响其他节点

### 4.3 防破解边界

**必须承认：任何客户端程序都无法保证绝对不被逆向。**

我们的策略是：
1. **Server 端做强校验**：即使 Agent 被逆向，也无法绕过 Server 的签名验证
2. **密钥独立**：每节点独立密钥，破解一个不影响全局
3. **可快速吊销**：管理员可立即禁用节点或重新生成 token
4. **IP 绑定检测**：如果 Agent IP 变化，产生安全告警
5. **版本校验**：Server 可拒绝旧版本 Agent 连接
6. **nonce 防重放**：即使完整复制请求，也会被 nonce 去重拦截

### 4.4 完整性校验

- Release 包自动生成 SHA256 校验文件
- 可选：使用 ed25519 签名校验更新包

## 5. Agent 权限控制

### 5.1 运行环境

Agent 以 root 运行（因为需要操作 nftables 和创建网络规则），但通过 systemd 限制：

```ini
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/etc/zachary-agent /var/log/zachary-agent /etc/nftables.conf /etc/systemd/system
```

### 5.2 命令执行安全

**绝对禁止：**
- 使用 `sh -c` 执行拼接命令
- 直接将用户输入拼接到命令行
- 通过任务 payload 传递任意 shell 命令

**必须使用：**
- `std::process::Command::new("program").args([...])` 参数数组方式
- 所有参数必须经过合法性校验
- 所有任务类型必须是白名单枚举

### 5.3 参数校验规则

| 参数类型 | 校验规则 |
|----------|----------|
| IP 地址 | 必须是合法 IPv4 或 IPv6 地址 |
| 端口 | 必须在 1-65535 范围内 |
| 域名 | 必须符合域名格式，长度 ≤ 253 |
| 路径 | 不允许 `..`、反斜杠、特殊字符 |
| 协议 | 必须是白名单中的值 |
| 任务类型 | 必须是预定义枚举值 |

## 6. Server 端安全控制

### 6.1 多层验证

每个 Agent 请求需要经过以下验证：

1. ✅ TLS 层（传输加密）
2. ✅ Agent 版本校验
3. ✅ 节点状态检查（是否启用）
4. ✅ timestamp 有效性（±60秒）
5. ✅ nonce 唯一性
6. ✅ HMAC 签名验证
7. ✅ 参数白名单校验
8. ✅ 限流检查

### 6.2 认证和鉴权

- 管理员：JWT Bearer Token
- Agent：HMAC 签名 + node_id
- JWT 过期时间可配置
- 登录失败限制（5次/分钟）
- 登录成功/失败记录审计日志

### 6.3 操作审计

所有重要操作记录审计日志：
- 登录/登出
- 节点创建/编辑/删除
- Token 重新生成
- 规则创建/编辑/删除/启停
- 密码修改
- 节点禁用/启用

### 6.4 安全事件监控

自动检测并记录安全事件：
- 签名校验失败
- nonce 重放尝试
- timestamp 过期请求
- 节点心跳丢失
- Agent IP 发生变化
- Agent 版本过旧
- 未授权 Agent 尝试连接

## 7. 安全告警处理

### 7.1 告警级别

| 级别 | 说明 | 处理 |
|------|------|------|
| info | 常规安全事件 | 记录日志 |
| warning | 需要注意 | 记录日志 + 面板显示 |
| critical | 疑似攻击 | 记录日志 + 面板高亮 + 可自动禁用节点 |

### 7.2 告警场景

#### 签名校验失败（critical）

可能原因：
- Agent token 被修改或泄露
- 中间人攻击尝试
- Agent 配置文件损坏

处理：
1. 记录安全事件
2. 累积失败次数
3. 达到阈值自动禁用节点
4. 管理员需检查节点安全

#### nonce 重放（critical）

可能原因：
- 请求被截获并重放
- Agent 实现异常

处理：
1. 记录安全事件
2. 注意观察是否有进一步异常

#### 心跳丢失（warning）

可能原因：
- 节点宕机
- 网络不通
- Agent 被停止

处理：
1. 标记节点离线
2. 超过阈值产生安全事件
3. 通知管理员

#### IP 变化（warning）

可能原因：
- 节点更换公网 IP
- Agent 被复制到其他机器

处理：
1. 记录安全事件
2. 更新节点 IP
3. 如果频繁变化则标记异常

## 8. 最佳实践

### 8.1 生产环境

- ✅ 使用 HTTPS / WSS，不要用 HTTP
- ✅ 修改默认管理员密码
- ✅ 定期轮换 node_token
- ✅ 开启防火墙，只暴露必要端口
- ✅ 使用强密码和 JWT 密钥
- ✅ 定期检查安全事件日志
- ✅ 及时更新 Agent 版本
- ✅ 配置 TLS Pinning（如果可行）
- ✅ 监控磁盘使用（nonce 表增长）

### 8.2 应急响应

如果怀疑节点被破解：

1. **立即禁用节点**：面板 → 禁用节点
2. **吊销 token**：重新生成 node_token
3. **检查日志**：查看该节点的安全事件
4. **检查规则**：确认没有异常转发规则
5. **检查流量**：查看是否有异常流量
6. **重新部署**：清除节点后重新安装 Agent
7. **分析原因**：确认破解方式和影响范围

## 9. 合规说明

本项目仅用于合法用途：

✅ 允许：
- 合法服务器流量转发
- 内网穿透
- 运维测试
- 个人网络管理
- 自有节点管理

❌ 禁止：
- 任何形式的攻击
- 端口扫描
- 绕过网络限制
- 未授权代理
- 恶意流量转发
- 任何违法用途

## 10. 安全更新

安全漏洞请通过 GitHub Issues 或私下联系报告，不要公开披露。
