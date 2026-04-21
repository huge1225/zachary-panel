# Zachary Panel 部署指南

## 🚀 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git
cd zachary-panel

# 创建必要目录
mkdir -p logs nginx/ssl certs/{ca,server,agent}
```

### 2. 环境变量配置

创建 `.env` 文件：

```bash
# Panel 配置
PANEL_URL=http://your-domain.com:8080
GRPC_URL=your-domain.com:9090

# 数据库配置
DB_PATH=/data/panel.db

# 日志级别
LOG_LEVEL=info
```

### 3. 启动服务

```bash
# 启动 Panel 主控端
docker compose up -d panel

# 查看日志
docker compose logs -f panel

# 启动 Nginx 反向代理（可选）
docker compose --profile nginx up -d nginx
```

## 🔧 VPS 部署

### 服务器要求

- **操作系统**: Linux (Ubuntu 20.04+ / CentOS 8+)
- **内存**: 最少 512MB，推荐 1GB+
- **存储**: 最少 1GB 可用空间
- **网络**: 支持 TCP 80, 443, 9090 端口

### 一键部署脚本

```bash
#!/bin/bash
# deploy.sh - 部署脚本

set -e

# 安装 Docker 和 Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# 安装 Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 创建部署目录
mkdir -p /opt/zachary-panel
cd /opt/zachary-panel

# 克隆项目
git clone https://github.com/huge1225/zachary-panel.git .

# 配置环境
cat > .env << EOF
PANEL_URL=$(curl -s ifconfig.me):8080
GRPC_URL=$(curl -s ifconfig.me):9090
DB_PATH=/data/panel.db
LOG_LEVEL=info
EOF

# 启动服务
docker compose up -d panel

# 设置开机自启
systemctl enable docker
systemctl enable docker-compose

echo "✅ 部署完成！"
echo "Panel 地址: http://$(curl -s ifconfig.me):8080"
echo "Nginx 地址: http://$(curl -s ifconfig.me)"
```

### Agent 部署

在每个需要转发的 VPS 上运行：

```bash
#!/bin/bash
# deploy-agent.sh - Agent 部署脚本

set -e

# 创建 Agent 目录
sudo mkdir -p /opt/zachary-agent
cd /opt/zachary-agent

# 下载 Agent
wget -O agent https://github.com/huge1225/zachary-panel/releases/latest/download/agent-linux-amd64
chmod +x agent

# 创建服务文件
cat > /etc/systemd/system/zachary-agent.service << EOF
[Unit]
Description=Zachary Panel Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/zachary-agent/agent
Environment=PANEL_ADDR=panel.example.com:9090
Environment=AGENT_ID=$(hostname)
Environment=AGENT_TOKEN=your-token-here
Environment=CERT_DIR=/etc/zachary-agent/certs
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable zachary-agent
systemctl start zachary-agent

echo "✅ Agent 部署完成！"
```

## 🔐 安全配置

### 1. 防火墙设置

```bash
# Ubuntu/Debian
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 9090/tcp
ufw enable

# CentOS/RHEL
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --permanent --add-port=9090/tcp
firewall-cmd --reload
```

### 2. SSL 证书配置

```bash
# 使用 Let's Encrypt
sudo apt install certbot
sudo certbot certonly --standalone -d your-domain.com

# 复制证书到 Nginx
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/nginx/ssl/
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/nginx/ssl/

# 更新 Nginx 配置启用 HTTPS
```

### 3. 安全加固

```bash
# 禁用 root 登录
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

# 配置 fail2ban
apt install fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
EOF

systemctl restart fail2ban
```

## 📊 监控和维护

### 1. 日志管理

```bash
# 查看 Panel 日志
docker compose logs -f panel

# 查看 Agent 日志
journalctl -u zachary-agent -f

# 日志轮转配置
cat > /etc/logrotate.d/zachary-panel << EOF
/opt/zachary-panel/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
```

### 2. 性能监控

```bash
# 安装监控工具
apt install htop iotop nethogs

# 监控 Docker 容器
docker stats

# 查看系统资源
htop
```

### 3. 备份策略

```bash
#!/bin/bash
# backup.sh - 备份脚本

BACKUP_DIR="/backup/zachary-panel"
DATE=$(date +%Y%m%d_%H%M%S)

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
docker compose exec -T panel sh -c "cp /data/panel.db /tmp/panel.db"
docker cp panel:/tmp/panel.db $BACKUP_DIR/panel_$DATE.db

# 备份配置
cp -r $BACKUP_DIR/../config $BACKUP_DIR/config_$DATE

# 压缩备份
tar -czf $BACKUP_DIR/backup_$DATE.tar.gz -C $BACKUP_DIR panel_$DATE.db config_$DATE

# 清理旧备份（保留7天）
find $BACKUP_DIR -name "backup_*.tar.gz" -mtime +7 -delete

echo "✅ 备份完成: $BACKUP_DIR/backup_$DATE.tar.gz"
```

## 🔧 故障排除

### 常见问题

1. **端口占用**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep :8080
   netstat -tlnp | grep :9090
   
   # 修改端口
   sed -i 's/8080:8080/8081:8080/' docker-compose.yml
   sed -i 's/9090:9090/9091:9090/' docker-compose.yml
   ```

2. **证书问题**
   ```bash
   # 重新生成证书
   docker compose exec panel sh -c "rm -rf /data/certs && mkdir -p /data/certs"
   docker compose restart panel
   ```

3. **数据库损坏**
   ```bash
   # 备份旧数据库
   docker compose exec panel sh -c "cp /data/panel.db /data/panel.db.bak"
   
   # 重新初始化
   docker compose exec panel sh -c "rm /data/panel.db"
   docker compose restart panel
   ```

### 性能优化

```bash
# 优化 Docker 配置
cat > /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
EOF

systemctl restart docker
```

## 📚 API 文档

### Panel API

- `GET /api/v1/agents` - 获取所有节点
- `POST /api/v1/agents` - 添加节点
- `GET /api/v1/agents/{id}` - 获取节点详情
- `DELETE /api/v1/agents/{id}` - 删除节点
- `GET /api/v1/agents/{id}/rules` - 获取节点规则
- `POST /api/v1/agents/{id}/rules` - 添加规则
- `PUT /api/v1/rules/{id}` - 更新规则
- `DELETE /api/v1/rules/{id}` - 删除规则
- `GET /api/v1/dashboard` - 获取仪表盘数据

### gRPC 接口

- `RegisterAgent` - 节点注册
- `GetForwardRules` - 获取转发规则
- `UpdateRuleStatus` - 更新规则状态
- `Heartbeat` - 心跳检测
- `PushConfig` - 配置推送

## 🤝 技术支持

- GitHub Issues: https://github.com/huge1225/zachary-panel/issues
- 文档: https://github.com/huge1225/zachary-panel/wiki
- 讨论: https://github.com/huge1225/zachary-panel/discussions

---

**⚡ 轻量化 Web 转发面板 — 流量转发统一管控**