#!/bin/bash
set -euo pipefail

# Zachary Panel Agent 安装脚本
# Usage: bash install-agent.sh --server <URL> --node-id <ID> --install-token <TOKEN>

# Parse args
SERVER_URL=""
NODE_ID=""
INSTALL_TOKEN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift 2;;
        --node-id) NODE_ID="$2"; shift 2;;
        --install-token) INSTALL_TOKEN="$2"; shift 2;;
        *) shift;;
    esac
done

if [ -z "$SERVER_URL" ] || [ -z "$NODE_ID" ] || [ -z "$INSTALL_TOKEN" ]; then
    echo "Usage: $0 --server <URL> --node-id <ID> --install-token <TOKEN>"
    exit 1
fi

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

# Try downloading pre-built binary from GitHub Releases
BINARY_OK=false
RELEASE_URL="https://github.com/huge1225/zachary-panel/releases/latest/download"
echo "📥 尝试下载预编译 Agent..."
if curl -fSL "${RELEASE_URL}/zachary-panel-agent-linux-${ARCH_SUFFIX}.tar.gz" 2>/dev/null | tar xz -C "$INSTALL_DIR" --strip-components=1 2>/dev/null; then
    BINARY_OK=true
    echo "✅ 预编译二进制下载成功"
fi

# Fallback: build from source
if [ "$BINARY_OK" = false ]; then
    echo "📦 预编译二进制不可用，从源码编译..."
    
    # Install Rust if needed
    if ! command -v cargo &>/dev/null; then
        echo "   安装 Rust 工具链..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # Install build deps
    apt-get update -qq && apt-get install -y -qq build-essential pkg-config libssl-dev git
    
    # Clone and build
    echo "   编译中... (可能需要几分钟)"
    git clone --depth 1 https://github.com/huge1225/zachary-panel.git /tmp/zachary-panel-build
    cd /tmp/zachary-panel-build
    cargo build --release --bin zachary-panel-agent
    cp target/release/zachary-panel-agent "$INSTALL_DIR/"
    cp deploy/zachary-panel-agent.service "$INSTALL_DIR/" 2>/dev/null || true
    rm -rf /tmp/zachary-panel-build
    BINARY_OK=true
    echo "✅ 编译完成"
fi

# Install gost if not present
GOST_PATH="/usr/local/bin/gost"
if [ ! -f "$GOST_PATH" ]; then
    echo "📥 安装 gost..."
    GOST_VERSION="2.12.5"
    curl -fSL "https://github.com/ginuerzh/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_${ARCH_SUFFIX}.gz" \
        | gunzip > "$GOST_PATH" 2>/dev/null || true
    chmod +x "$GOST_PATH" 2>/dev/null || true
fi

# Write config
cat > "$INSTALL_DIR/agent.yaml" <<EOF
server_url: "${SERVER_URL}"
node_id: "${NODE_ID}"
install_token: "${INSTALL_TOKEN}"
ws_path: "/ws/agent"
heartbeat_interval: 30
tls_verify: false
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
cp "$INSTALL_DIR/zachary-panel-agent.service" /etc/systemd/system/ 2>/dev/null || \
    curl -sSL "https://raw.githubusercontent.com/huge1225/zachary-panel/main/deploy/zachary-panel-agent.service" \
    > /etc/systemd/system/zachary-panel-agent.service 2>/dev/null || true
systemctl daemon-reload

# Fix permissions
chown -R zachary:zachary "$INSTALL_DIR"

# Enable IP forwarding (needed for nftables DNAT)
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

echo ""
echo "✅ Agent 安装完成！"
echo "   启动: systemctl start zachary-panel-agent"
echo "   开机启动: systemctl enable zachary-panel-agent"
echo "   日志: journalctl -u zachary-panel-agent -f"
echo ""
echo "   配置文件: $INSTALL_DIR/agent.yaml"
