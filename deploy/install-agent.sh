#!/usr/bin/env bash
set -euo pipefail

ACTION="install"
PANEL_URL=""
MASTER_URL=""
NODE_ID=""
NODE_TOKEN=""
SHA256_AMD64=""
SHA256_ARM64=""
ALLOW_INSECURE_WS="false"

die() { echo "==> [Nexus Agent] ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --uninstall|uninstall) ACTION="uninstall"; shift ;;
    --panel)        PANEL_URL="${2:-}"; shift 2 ;;
    --master)       MASTER_URL="${2:-}"; shift 2 ;;
    --id)           NODE_ID="${2:-}"; shift 2 ;;
    --token)        NODE_TOKEN="${2:-}"; shift 2 ;;
    --sha256-amd64) SHA256_AMD64="${2:-}"; shift 2 ;;
    --sha256-arm64) SHA256_ARM64="${2:-}"; shift 2 ;;
    --allow-insecure-ws) ALLOW_INSECURE_WS="true"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "please run as root (sudo)"

if [[ "${ACTION}" == "uninstall" ]]; then
  echo "==> [Nexus Agent] Uninstalling Nexus Agent service and cleaning forwarding tables..."
  systemctl stop nexus-agent 2>/dev/null || true
  systemctl disable nexus-agent 2>/dev/null || true
  rm -f /etc/systemd/system/nexus-agent.service
  systemctl daemon-reload 2>/dev/null || true

  # Clean up kernel nftables tables if present
  nft delete table inet nexus_forward 2>/dev/null || true
  nft delete table inet nexus_acct 2>/dev/null || true

  rm -rf /etc/nexus-agent /var/lib/nexus-agent
  rm -f /usr/local/bin/nexus-agent
  echo "==> [Nexus Agent] Uninstalled cleanly!"
  exit 0
fi

# ---- Input validation (values end up in config files; reject anything unexpected) ----
[[ "${NODE_ID}" =~ ^[0-9]{1,19}$ ]] || die "invalid --id"
[[ "${NODE_TOKEN}" =~ ^[A-Za-z0-9._~-]{16,256}$ ]] || die "invalid --token"
[[ "${PANEL_URL}" =~ ^https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?$ ]] || die "invalid --panel URL"
[[ "${MASTER_URL}" =~ ^wss?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?$ ]] || die "invalid --master URL"
if [[ "${MASTER_URL}" == ws://* && "${ALLOW_INSECURE_WS}" != "true" ]]; then
  die "refusing plaintext ws:// control channel; use wss:// or pass --allow-insecure-ws"
fi
PANEL_URL="${PANEL_URL%/}"

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64"; EXPECTED_SHA="${SHA256_AMD64}" ;;
  aarch64|arm64) ARCH="arm64"; EXPECTED_SHA="${SHA256_ARM64}" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
[[ "${EXPECTED_SHA}" =~ ^[0-9a-f]{64}$ ]] || die "missing or invalid --sha256-${ARCH} (binary integrity cannot be verified)"

echo "==> [Nexus Agent] Installing hardened Node ID=${NODE_ID} connecting to ${MASTER_URL}"
if [[ "${MASTER_URL}" == ws://* ]]; then
  echo "==> [Nexus Agent] WARNING: control channel is NOT encrypted (ws://). Use HTTPS/WSS in production."
fi

# ---- Download and verify agent binary ----
TMP_BIN="$(mktemp)"
trap 'rm -f "${TMP_BIN}"' EXIT
curl -fsSL --proto '=https,http' --retry 3 -o "${TMP_BIN}" "${PANEL_URL}/deploy/releases/nexus-agent-linux-${ARCH}" \
  || die "failed to download agent binary"
ACTUAL_SHA="$(sha256sum "${TMP_BIN}" | awk '{print $1}')"
[[ "${ACTUAL_SHA}" == "${EXPECTED_SHA}" ]] || die "SHA-256 mismatch (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}); aborting"
install -m 0755 -o root -g root "${TMP_BIN}" /usr/local/bin/nexus-agent

# Enable IPv4 forwarding for nftables / kernel relay
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Create dedicated unprivileged system user and restricted environment file (0600) so secrets do not leak in `ps aux`
id -u nexus-agent &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin nexus-agent
install -d -m 0700 -o root -g root /etc/nexus-agent

umask 077
cat >/etc/nexus-agent/agent.env <<ENVEOF
NEXUS_MASTER_URL=${MASTER_URL}
NEXUS_NODE_ID=${NODE_ID}
NEXUS_NODE_TOKEN=${NODE_TOKEN}
NEXUS_ALLOW_PRIVATE_TARGETS=false
NEXUS_ALLOW_INSECURE_WS=${ALLOW_INSECURE_WS}
NEXUS_STATE_DIR=/var/lib/nexus-agent
ENVEOF
chmod 0600 /etc/nexus-agent/agent.env

cat >/etc/systemd/system/nexus-agent.service <<'UNITEOF'
[Unit]
Description=Nexus Forwarding Panel Node Agent (Hardened)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nexus-agent
Group=nexus-agent
EnvironmentFile=/etc/nexus-agent/agent.env
ExecStart=/usr/local/bin/nexus-agent -report-interval 3s
Restart=always
RestartSec=3
LimitNOFILE=1048576

# Private state directory (/var/lib/nexus-agent, 0700, owned by nexus-agent)
StateDirectory=nexus-agent
StateDirectoryMode=0700

# Systemd Security Hardening & Least Privilege Capabilities
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable nexus-agent
systemctl restart nexus-agent
echo "==> [Nexus Agent] Hardened service started (auto-restores rules on restart, 3s sync interval)!"
