#!/bin/bash
set -euo pipefail

# Zachary Panel Server 一键安装脚本
# Usage: curl -sSL https://raw.githubusercontent.com/huge1225/zachary-panel/main/deploy/install-server.sh | bash

INSTALL_DIR="/opt/zachary-panel"
RELEASE_URL="https://github.com/huge1225/zachary-panel/releases/latest/download"

echo "🚀 Zachary Panel Server 安装脚本"

# Check arch
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="x86_64" ;;
    aarch64) ARCH_SUFFIX="aarch64" ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

# Create user
id zachary &>/dev/null || useradd -r -s /bin/false zachary

# Create dirs
mkdir -p "$INSTALL_DIR/data"

# Download binary
echo "📥 下载 zachary-panel-server..."
curl -fSL "${RELEASE_URL}/zachary-panel-server-linux-${ARCH_SUFFIX}.tar.gz" \
    | tar xz -C "$INSTALL_DIR" --strip-components=1

# Install systemd service
echo "📋 安装 systemd 服务..."
# Try local copy first, fall back to GitHub
cp "$INSTALL_DIR/zachary-panel.service" /etc/systemd/system/ 2>/dev/null || \
    curl -sSL "https://raw.githubusercontent.com/huge1225/zachary-panel/main/deploy/zachary-panel.service" \
    > /etc/systemd/system/zachary-panel.service
systemctl daemon-reload

# Config
if [ ! -f "$INSTALL_DIR/.env" ]; then
    read -rp "设置管理员密码: " -s ADMIN_PASS
    echo
    JWT_SECRET=$(openssl rand -hex 32)
    cat > "$INSTALL_DIR/.env" <<EOF
JWT_SECRET=${JWT_SECRET}
ADMIN_PASSWORD=${ADMIN_PASS}
ADMIN_USERNAME=admin
DATABASE_URL=sqlite://${INSTALL_DIR}/data/zachary-panel.db?mode=rwc
HOST=0.0.0.0
PORT=3000
RUST_LOG=info
EOF
    chown zachary:zachary "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
fi

# Fix permissions
chown -R zachary:zachary "$INSTALL_DIR"

echo "✅ 安装完成！"
echo "启动: systemctl start zachary-panel"
echo "开机启动: systemctl enable zachary-panel"
echo "访问: http://$(hostname -I | awk '{print $1}'):3000"
