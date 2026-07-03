#!/bin/bash
set -euo pipefail

# Zachary Panel — Release Packaging Script
# Builds and packages server + agent binaries for Linux amd64 and arm64
#
# Usage:
#   ./scripts/build-release.sh [version]
#   version defaults to the git tag or "0.1.0"

set -a
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo '0.1.0')}"
RELEASE_DIR="$PROJECT_ROOT/release"
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

echo "🔨 Building Zachary Panel v$VERSION"

# ─── Build frontend ───
echo ""
echo "📦 Building frontend..."
cd "$PROJECT_ROOT/frontend"
npm ci --silent 2>/dev/null || npm install --silent
npm run build

# ─── Build Rust binaries ───
echo ""
echo "🦀 Building Rust binaries (release)..."
cd "$PROJECT_ROOT"
cargo build --release --bin zachary-panel-server --bin zachary-panel-agent

# ─── Package Server ───
for ARCH_PAIR in "x86_64:x86_64" "aarch64:aarch64"; do
    ARCH_RUST="${ARCH_PAIR%%:*}"
    ARCH_NAME="${ARCH_PAIR##*:}"

    if [ "$ARCH_RUST" != "$(uname -m)" ]; then
        echo "⚠️  Skipping $ARCH_NAME (cross-compile not configured for native build)"
        continue
    fi

    echo ""
    echo "📦 Packaging server-linux-$ARCH_NAME..."

    SERVER_PKG="zachary-panel-server-linux-$ARCH_NAME"
    SERVER_DIR="$RELEASE_DIR/$SERVER_PKG"
    mkdir -p "$SERVER_PKG"

    cp target/release/zachary-panel-server "$SERVER_PKG/"
    cp -r frontend/dist "$SERVER_PKG/frontend/dist"
    cp deploy/zachary-panel.service "$SERVER_PKG/"
    cp deploy/install-server.sh "$SERVER_PKG/"
    cp .env.example "$SERVER_PKG/" 2>/dev/null || true
    cp README.md "$SERVER_PKG/" 2>/dev/null || true

    tar czf "$RELEASE_DIR/$SERVER_PKG.tar.gz" "$SERVER_PKG"
    rm -rf "$SERVER_PKG"
    echo "  ✅ $SERVER_PKG.tar.gz"

    # ─── Package Agent ───
    echo "📦 Packaging agent-linux-$ARCH_NAME..."

    AGENT_PKG="zachary-panel-agent-linux-$ARCH_NAME"
    AGENT_DIR="$RELEASE_DIR/$AGENT_PKG"
    mkdir -p "$AGENT_PKG"

    cp target/release/zachary-panel-agent "$AGENT_PKG/"
    cp deploy/zachary-panel-agent.service "$AGENT_PKG/"
    cp deploy/install-agent.sh "$AGENT_PKG/"

    tar czf "$RELEASE_DIR/$AGENT_PKG.tar.gz" "$AGENT_PKG"
    rm -rf "$AGENT_PKG"
    echo "  ✅ $AGENT_PKG.tar.gz"
done

# ─── Summary ───
echo ""
echo "============================================"
echo "✅ Release v$VERSION built successfully!"
echo "============================================"
echo ""
echo "Artifacts in $RELEASE_DIR/:"
ls -lh "$RELEASE_DIR/"*.tar.gz 2>/dev/null || echo "  (no artifacts)"
