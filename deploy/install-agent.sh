#!/usr/bin/env bash
set -euo pipefail

ACTION="install"
MASTER_URL=""
NODE_ID=""
NODE_TOKEN=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --uninstall|uninstall)
      ACTION="uninstall"
      shift
      ;;
    --master)
      MASTER_URL="$2"
      shift 2
      ;;
    --id)
      NODE_ID="$2"
      shift 2
      ;;
    --token)
      NODE_TOKEN="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "${ACTION}" == "uninstall" ]]; then
  echo "==> [Nexus Agent] Uninstalling Nexus Agent service and cleaning forwarding tables..."
  systemctl stop nexus-agent 2>/dev/null || true
  systemctl disable nexus-agent 2>/dev/null || true
  rm -f /etc/systemd/system/nexus-agent.service
  systemctl daemon-reload 2>/dev/null || true

  # Clean up kernel nftables tables if present
  nft delete table inet nexus_forward 2>/dev/null || true
  nft delete table inet nexus_acct 2>/dev/null || true

  rm -rf /etc/nexus-agent /tmp/nexus-agent-state /tmp/nexus-agent-gost /tmp/nexus-agent-realm
  rm -f /usr/local/bin/nexus-agent
  echo "==> [Nexus Agent] Uninstalled cleanly!"
  exit 0
fi

echo "==> [Nexus Agent] Installing hardened Node ID=${NODE_ID} connecting to ${MASTER_URL}"

# Enable IPv4/IPv6 forwarding for nftables / kernel relay
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Create dedicated unprivileged system user and restricted environment file (0600) so secrets do not leak in `ps aux`
id -u nexus-agent &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin nexus-agent
mkdir -p /etc/nexus-agent
chmod 0700 /etc/nexus-agent

cat >/etc/nexus-agent/agent.env <<EOF
NEXUS_MASTER_URL=${MASTER_URL}
NEXUS_NODE_ID=${NODE_ID}
NEXUS_NODE_TOKEN=${NODE_TOKEN}
NEXUS_ALLOW_PRIVATE_TARGETS=false
EOF
chmod 0600 /etc/nexus-agent/agent.env
chown -R root:root /etc/nexus-agent

cat >/etc/systemd/system/nexus-agent.service <<EOF
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

# Systemd Security Hardening & Least Privilege Capabilities
NoNewPrivileges=true
PrivateTmp=false
ProtectSystem=strict
ReadWritePaths=/tmp
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nexus-agent
systemctl restart nexus-agent
echo "==> [Nexus Agent] Hardened service started (auto-restores rules on restart, 3s sync interval)!"
