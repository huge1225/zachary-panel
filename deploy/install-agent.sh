#!/bin/bash
set -euo pipefail

# Zachary Panel Agent 一键安装脚本
# Usage: bash install-agent.sh <SERVER_URL> <NODE_ID> <INSTALL_TOKEN>

SERVER_URL="${1:?用法: $0 <SERVER_URL> <NODE_ID> <INSTALL_TOKEN>}"
NODE_ID="${2:?缺少 NODE_ID}"
INSTALL_TOKEN="${3:?缺少 INSTALL_TOKEN}"

INSTALL_DIR="/opt/zachary-panel-agent"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="x86_64" ;;
    aarch64) ARCH_SUFFIX="aarch64" ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

# Create user
id zachary &>/dev/null || useradd -r -s /bin/false zachary

# Create dirs
mkdir -p "$INSTALL_DIR"

# Download binary
echo "📥 下载 zachary-panel-agent..."
RELEASE_URL="https://github.com/huge1225/zachary-panel/releases/latest/download"
curl -fSL "${RELEASE_URL}/zachary-panel-agent-linux-${ARCH_SUFFIX}.tar.gz" \
    | tar xz -C "$INSTALL_DIR" --strip-components=1

# Write config
cat > "$INSTALL_DIR/agent.yaml" <<EOF
server_url: "${SERVER_URL}"
node_id: "${NODE_ID}"
install_token: "${INSTALL_TOKEN}"
ws_path: "/ws/agent"
heartbeat_interval: 30
tls_verify: true
nft_path: "/usr/sbin/nft"
gost_path: "/usr/local/bin/gost"
log_level: "info"
EOF

# Write env
cat > "$INSTALL_DIR/.env" <<EOF
RUST_LOG=info
NODE_ID=${NODE_ID}
SERVER_URL=${SERVER_URL}
INSTALL_TOKEN=${INSTALL_TOKEN}
EOF

# Install systemd service
cp "$INSTALL_DIR/deploy/zachary-panel-agent.service" /etc/systemd/system/ 2>/dev/null || \
    curl -sSL "https://raw.githubusercontent.com/huge1225/zachary-panel/main/deploy/zachary-panel-agent.service" \
    > /etc/systemd/system/zachary-panel-agent.service
systemctl daemon-reload

chown -R zachary:zachary "$INSTALL_DIR"

echo "✅ Agent 安装完成！"
echo "启动: systemctl start zachary-panel-agent"
echo "开机启动: systemctl enable zachary-panel-agent"
