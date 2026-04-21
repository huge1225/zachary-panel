#!/bin/bash
# install.sh - Zachary Panel 一键安装脚本 (HTTP/HTTPS 部署)

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
DEFAULT_PANEL_URL="https://your-releases.com/install"
DEFAULT_AGENT_URL="https://your-releases.com/install-agent"

echo -e "${GREEN}🚀 Zachary Panel 一键安装脚本 v${SCRIPT_VERSION}${NC}"
echo -e "${BLUE}=================================${NC}"
echo -e "${CYAN}轻量化 Web 转发面板 — 流量转发统一管控${NC}"
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

# 安装 Docker
install_docker() {
    echo -e "${YELLOW}🐳 安装 Docker...${NC}"
    
    # 检查 Docker 是否已安装
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}✅ Docker 已安装${NC}"
        return
    fi
    
    # 根据操作系统安装 Docker
    case $OS in
        "Ubuntu"|"Debian")
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            ;;
        "CentOS"|"Red Hat Enterprise Linux"|"AlmaLinux"|"Rocky Linux")
            yum install -y docker-ce docker-ce-cli containerd.io
            ;;
    esac
    
    # 启动 Docker
    systemctl enable docker
    systemctl start docker
}

# 安装 Docker Compose
install_docker_compose() {
    echo -e "${YELLOW}🐳 安装 Docker Compose...${NC}"
    
    if command -v docker-compose &> /dev/null; then
        echo -e "${GREEN}✅ Docker Compose 已安装${NC}"
        return
    fi
    
    # 下载 Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
}

# 创建工作目录
setup_directories() {
    INSTALL_DIR="/opt/zachary-panel"
    echo -e "${YELLOW}📁 创建工作目录: $INSTALL_DIR${NC}"
    
    mkdir -p $INSTALL_DIR
    mkdir -p $INSTALL_DIR/logs
    mkdir -p $INSTALL_DIR/certs/{ca,server,agent}
    mkdir -p $INSTALL_DIR/nginx/ssl
    mkdir -p $INSTALL_DIR/data
    
    chmod 755 $INSTALL_DIR
    chmod 755 $INSTALL_DIR/logs
    chmod 755 $INSTALL_DIR/certs
    chmod 755 $INSTALL_DIR/certs/ca
    chmod 755 $INSTALL_DIR/certs/server
    chmod 755 $INSTALL_DIR/certs/agent
    chmod 755 $INSTALL_DIR/nginx/ssl
    
    cd $INSTALL_DIR
}

# 获取服务器信息
get_server_info() {
    SERVER_HOSTNAME=$(hostname)
    SERVER_IP=$(curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "localhost")
    
    echo -e "${GREEN}🌐 服务器信息:${NC}"
    echo -e "${CYAN}   主机名: $SERVER_HOSTNAME${NC}"
    echo -e "${CYAN}   外网 IP: $SERVER_IP${NC}"
}

# 下载部署文件
download_files() {
    echo -e "${YELLOW}📥 下载部署文件...${NC}"
    
    # 下载 docker-compose.yml
    if ! curl -s -o docker-compose.yml $DEFAULT_PANEL_URL/docker-compose.yml; then
        echo -e "${RED}❌ 下载 docker-compose.yml 失败${NC}"
        exit 1
    fi
    
    # 下载环境配置文件
    if ! curl -s -o .env.example $DEFAULT_PANEL_URL/.env.example; then
        echo -e "${RED}❌ 下载环境配置文件失败${NC}"
        exit 1
    fi
    
    # 下载启动脚本
    if ! curl -s -o start.sh $DEFAULT_PANEL_URL/start.sh; then
        echo -e "${RED}❌ 下载启动脚本失败${NC}"
        exit 1
    fi
    
    # 下载 Nginx 配置
    if ! curl -s -o nginx.conf $DEFAULT_PANEL_URL/nginx.conf; then
        echo -e "${RED}❌ 下载 Nginx 配置失败${NC}"
        exit 1
    fi
    
    # 设置执行权限
    chmod +x start.sh
    
    echo -e "${GREEN}✅ 部署文件下载完成${NC}"
}

# 配置环境变量
configure_env() {
    echo -e "${YELLOW}⚙️ 配置环境变量...${NC}"
    
    # 复制环境配置文件
    if [[ -f .env ]]; then
        echo -e "${CYAN}   检测到已有配置文件，跳过创建${NC}"
    else
        cp .env.example .env
        
        # 自动配置基础信息
        sed -i "s/PANEL_URL=.*/PANEL_URL=http:\/\/${SERVER_IP}:8080/" .env
        sed -i "s/GRPC_URL=.*/GRPC_URL=${SERVER_IP}:9090/" .env
        sed -i "s/LOG_LEVEL=.*/LOG_LEVEL=info/" .env
        
        echo -e "${GREEN}✅ 环境变量配置完成${NC}"
    fi
}

# 生成 SSL 证书
generate_ssl() {
    echo -e "${YELLOW}🛡️ 生成 SSL 证书...${NC}"
    
    # 检查是否已有证书
    if [[ -f nginx/ssl/server.crt && -f nginx/ssl/server.key ]]; then
        echo -e "${CYAN}   检测到已有证书，跳过生成${NC}"
        return
    fi
    
    # 生成自签名证书
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/server.key \
        -out nginx/ssl/server.crt \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=Zachary Panel/OU=IT Department/CN=${SERVER_IP}" >/dev/null 2>&1
    
    echo -e "${GREEN}✅ SSL 证书生成完成${NC}"
}

# 配置防火墙
configure_firewall() {
    echo -e "${YELLOW}🔥 配置防火墙...${NC}"
    
    # 检查防火墙状态
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        ufw allow 9090/tcp >/dev/null 2>&1
        ufw --force enable >/dev/null 2>&1
        echo -e "${GREEN}✅ UFW 防火墙配置完成${NC}"
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=9090/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        echo -e "${GREEN}✅ Firewalld 防火墙配置完成${NC}"
    else
        echo -e "${YELLOW}⚠️  未检测到支持的防火墙，请手动开放端口${NC}"
    fi
}

# 启动服务
start_services() {
    echo -e "${YELLOW}🚀 启动服务...${NC}"
    
    # 拉取镜像
    docker compose pull
    
    # 启动服务
    docker compose up -d
    
    # 等待服务启动
    echo -e "${YELLOW}⏳ 等待服务启动...${NC}"
    sleep 15
    
    # 检查服务状态
    if docker compose ps | grep -q "panel.*Up"; then
        echo -e "${GREEN}✅ Panel 服务启动成功${NC}"
    else
        echo -e "${RED}❌ Panel 服务启动失败${NC}"
        echo -e "${YELLOW}请检查日志: docker compose logs${NC}"
        exit 1
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo -e "${GREEN}🎉 Zachary Panel 安装完成！${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo ""
    echo -e "${YELLOW}📱 访问地址:${NC}"
    echo "   - Panel 管理界面: http://${SERVER_IP}:8080"
    echo "   - Nginx 反向代理: http://${SERVER_IP}"
    echo ""
    echo -e "${YELLOW}📝 常用命令:${NC}"
    echo "   - 查看日志: docker compose logs -f"
    echo "   - 重启服务: docker compose restart"
    echo "   - 停止服务: docker compose down"
    echo "   - 更新服务: ./start.sh update"
    echo ""
    echo -e "${YELLOW}📚 更多信息:${NC}"
    echo "   - 配置文件: $INSTALL_DIR/.env"
    echo "   - 日志目录: $INSTALL_DIR/logs"
    echo "   - 数据目录: $INSTALL_DIR/data"
    echo ""
    echo -e "${CYAN}🔒 部署完成！请访问管理界面开始使用。${NC}"
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
    install_docker
    install_docker_compose
    setup_directories
    get_server_info
    download_files
    configure_env
    generate_ssl
    configure_firewall
    start_services
    show_completion
}

# 运行主函数
main "$@"