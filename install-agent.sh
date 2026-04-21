#!/bin/bash
# install-agent.sh - Zachary Panel Agent 一键安装脚本 (HTTP/HTTPS 部署)

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置变量
SCRIPT_VERSION="1.0.0"
DEFAULT_AGENT_URL="https://your-releases.com/agent"
DEFAULT_PANEL_ADDR="panel.example.com:9090"

echo -e "${GREEN}🚀 Zachary Panel Agent 一键安装脚本 v${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}=================================${NC}"
echo -e "${CYAN}轻量化 Web 转发面板 — Agent 部署${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# 检查是否为 root 用户
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ 错误：请使用 root 用户运行此脚本${NC}"
   echo -e "${YELLOW}运行方式: sudo ${BASH_SOURCE[0]}${NC}"
   exit 1
fi

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        echo -e "${RED}❌ 错误：无法检测操作系统${NC}"
        exit 1
    fi
}

# 检测架构
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        arm*)
            ARCH="arm"
            ;;
        *)
            echo -e "${RED}❌ 错误：不支持的架构 $ARCH${NC}"
            exit 1
            ;;
    esac
}

# 安装依赖
install_dependencies() {
    echo -e "${YELLOW}🔧 安装系统依赖...${NC}"
    
    # 更新包管理器
    case $OS in
        "Ubuntu"|"Debian")
            apt update >/dev/null 2>&1
            apt upgrade -y >/dev/null 2>&1
            apt install -y curl wget unzip tar openssl ca-certificates >/dev/null 2>&1
            ;;
        "CentOS"|"Red Hat Enterprise Linux"|"AlmaLinux"|"Rocky Linux")
            yum update -y >/dev/null 2>&1
            yum install -y curl wget unzip tar openssl ca-certificates >/dev/null 2>&1
            ;;
        *)
            echo -e "${RED}❌ 错误：不支持的操作系统 $OS${NC}"
            exit 1
            ;;
    esac
}

# 创建工作目录
setup_directories() {
    AGENT_DIR="/opt/zachary-agent"
    echo -e "${YELLOW}📁 创建 Agent 目录: $AGENT_DIR${NC}"
    
    mkdir -p $AGENT_DIR
    mkdir -p /etc/zachary-agent/certs
    mkdir -p /var/log/zachary-agent
    mkdir -p /etc/systemd/system
    
    chmod 755 $AGENT_DIR
    chmod 755 /etc/zachary-agent
    chmod 755 /etc/zachary-agent/certs
    chmod 755 /var/log/zachary-agent
    
    cd $AGENT_DIR
}

# 获取服务器信息
get_server_info() {
    SERVER_HOSTNAME=$(hostname)
    SERVER_IP=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "localhost")
    
    echo -e "${GREEN}🌐 服务器信息:${NC}"
    echo -e "${CYAN}   主机名: $SERVER_HOSTNAME${NC}"
    echo -e "${CYAN}   外网 IP: $SERVER_IP${NC}"
}

# 下载 Agent 二进制文件
download_agent() {
    echo -e "${YELLOW}📥 下载 Agent 二进制文件...${NC}"
    
    # 根据架构下载对应的二进制文件
    AGENT_BINARY="agent-linux-${ARCH}"
    DOWNLOAD_URL="${DEFAULT_AGENT_URL}/${AGENT_BINARY}"
    
    echo -e "${CYAN}   下载地址: $DOWNLOAD_URL${NC}"
    
    # 下载二进制文件
    if ! curl -s -L -o agent "$DOWNLOAD_URL"; then
        echo -e "${RED}❌ 下载 Agent 失败${NC}"
        echo -e "${YELLOW}请手动下载二进制文件到 $AGENT_DIR/agent${NC}"
        exit 1
    fi
    
    # 设置执行权限
    chmod +x agent
    
    # 验证二进制文件
    if [[ ! -x agent ]]; then
        echo -e "${RED}❌ Agent 二进制文件无效${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Agent 下载完成${NC}"
}

# 配置 Agent
configure_agent() {
    echo -e "${YELLOW}⚙️ 配置 Agent...${NC}"
    
    # 读取用户输入
    echo ""
    echo -e "${BLUE}📝 Agent 配置信息:${NC}"
    
    # Panel 地址
    read -p "Panel 地址 (默认: $DEFAULT_PANEL_ADDR): " PANEL_ADDR
    PANEL_ADDR=${PANEL_ADDR:-$DEFAULT_PANEL_ADDR}
    
    # Agent ID
    read -p "Agent ID (默认: $SERVER_HOSTNAME): " AGENT_ID
    AGENT_ID=${AGENT_ID:-$SERVER_HOSTNAME}
    
    # Agent Token
    while [[ -z "$AGENT_TOKEN" ]]; do
        read -s -p "Agent Token (必填): " AGENT_TOKEN
        echo ""
        if [[ -z "$AGENT_TOKEN" ]]; then
            echo -e "${RED}❌ Agent Token 不能为空${NC}"
        fi
    done
    
    # 创建配置文件
    cat > agent.conf << EOF
# Zachary Panel Agent 配置文件
PANEL_ADDR=$PANEL_ADDR
AGENT_ID=$AGENT_ID
AGENT_TOKEN=$AGENT_TOKEN
CERT_DIR=/etc/zachary-agent/certs
LOG_LEVEL=info
EOF
    
    echo -e "${GREEN}✅ Agent 配置完成${NC}"
}

# 创建 systemd 服务
create_systemd_service() {
    echo -e "${YELLOW}🔧 创建 systemd 服务...${NC}"
    
    cat > /etc/systemd/system/zachary-agent.service << EOF
[Unit]
Description=Zachary Panel Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
ExecStart=$AGENT_DIR/agent
Environment=PANEL_ADDR=$PANEL_ADDR
Environment=AGENT_ID=$AGENT_ID
Environment=AGENT_TOKEN=$AGENT_TOKEN
Environment=CERT_DIR=/etc/zachary-agent/certs
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}✅ systemd 服务创建完成${NC}"
}

# 配置防火墙
configure_firewall() {
    echo -e "${YELLOW}🔥 配置防火墙...${NC}"
    
    # Agent 需要的权限已经在 systemd 中配置
    # 这里可以添加额外的防火墙规则
    
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian
        ufw reload >/dev/null 2>&1
        echo -e "${GREEN}✅ UFW 防火墙配置完成${NC}"
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "${GREEN}✅ Firewalld 防火墙配置完成${NC}"
    fi
}

# 启动 Agent
start_agent() {
    echo -e "${YELLOW}🚀 启动 Agent 服务...${NC}"
    
    # 启动服务
    systemctl enable zachary-agent
    systemctl start zachary-agent
    
    # 等待服务启动
    sleep 5
    
    # 检查服务状态
    if systemctl is-active --quiet zachary-agent; then
        echo -e "${GREEN}✅ Agent 服务启动成功${NC}"
    else
        echo -e "${RED}❌ Agent 服务启动失败${NC}"
        echo -e "${YELLOW}请查看错误日志: journalctl -u zachary-agent -n 50${NC}"
        exit 1
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo -e "${GREEN}🎉 Zachary Panel Agent 安装完成！${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo ""
    echo -e "${YELLOW}📊 Agent 信息:${NC}"
    echo "   - Agent ID: $AGENT_ID"
    echo "   - Panel 地址: $PANEL_ADDR"
    echo "   - 服务器 IP: $SERVER_IP"
    echo ""
    echo -e "${YELLOW}📝 常用命令:${NC}"
    echo "   - 查看日志: journalctl -u zachary-agent -f"
    echo "   - 重启服务: systemctl restart zachary-agent"
    echo "   - 停止服务: systemctl stop zachary-agent"
    echo "   - 状态检查: systemctl status zachary-agent"
    echo ""
    echo -e "${YELLOW}📁 重要文件:${NC}"
    echo "   - Agent 二进制: $AGENT_DIR/agent"
    echo "   - 配置文件: /etc/zachary-agent/certs"
    echo "   - 日志文件: /var/log/zachary-agent"
    echo ""
    echo -e "${CYAN}🔒 Agent 部署完成！请确保 Panel 端已正确配置。${NC}"
    echo -e "${BLUE}=================================${NC}"
}

# 主函数
main() {
    echo -e "${CYAN}开始检测系统环境...${NC}"
    
    # 检测系统信息
    detect_os
    detect_arch
    
    echo -e "${GREEN}✅ 系统检测完成:${NC}"
    echo -e "${CYAN}   操作系统: $OS $VERSION${NC}"
    echo -e "${CYAN}   系统架构: $ARCH${NC}"
    echo ""
    
    # 执行安装步骤
    install_dependencies
    setup_directories
    get_server_info
    download_agent
    configure_agent
    create_systemd_service
    configure_firewall
    start_agent
    show_completion
}

# 运行主函数
main "$@"