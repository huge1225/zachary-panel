#!/bin/bash
# start.sh - Zachary Panel 启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 显示帮助信息
show_help() {
    echo -e "${GREEN}Zachary Panel 启动脚本${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo ""
    echo "用法: $0 [命令] [选项]"
    echo ""
    echo "命令:"
    echo "  start     启动服务 (默认)"
    echo "  stop      停止服务"
    echo "  restart   重启服务"
    echo "  update    更新服务"
    echo "  logs      查看日志"
    echo "  status    查看状态"
    echo "  reset     重置配置"
    echo "  help      显示帮助"
    echo ""
    echo "选项:"
    echo "  -d, --dev    开发模式"
    echo "  -p, --prod   生产模式 (默认)"
    echo "  -f, --force  强制执行"
    echo ""
    echo "示例:"
    echo "  $0 start          # 启动服务"
    echo "  $0 start -d      # 开发模式启动"
    echo "  $0 update        # 更新服务"
    echo "  $0 logs -f       # 查看实时日志"
}

# 检查 Docker 是否运行
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker 未运行，请先启动 Docker${NC}"
        exit 1
    fi
}

# 检查 Docker Compose 是否安装
check_docker_compose() {
    if ! command -v docker-compose >/dev/null 2>&1; then
        echo -e "${RED}❌ Docker Compose 未安装${NC}"
        exit 1
    fi
}

# 启动服务
start_services() {
    echo -e "${YELLOW}🚀 启动服务...${NC}"
    
    # 检查配置文件
    if [[ ! -f .env ]]; then
        echo -e "${YELLOW}📝 创建环境配置文件...${NC}"
        cp .env.example .env
        echo -e "${GREEN}✅ 已创建 .env 文件，请根据需要修改${NC}"
    fi
    
    # 启动服务
    if [[ "$ENV" == "dev" ]]; then
        docker-compose --profile nginx up -d
    else
        docker-compose up -d
    fi
    
    echo -e "${GREEN}✅ 服务启动完成${NC}"
}

# 停止服务
stop_services() {
    echo -e "${YELLOW}🛑 停止服务...${NC}"
    docker-compose down
    echo -e "${GREEN}✅ 服务已停止${NC}"
}

# 重启服务
restart_services() {
    echo -e "${YELLOW}🔄 重启服务...${NC}"
    docker-compose restart
    echo -e "${GREEN}✅ 服务已重启${NC}"
}

# 更新服务
update_services() {
    echo -e "${YELLOW}🔄 更新服务...${NC}"
    
    # 拉取最新镜像
    docker-compose pull
    
    # 重新构建并启动
    docker-compose up -d --build
    
    echo -e "${GREEN}✅ 服务已更新${NC}"
}

# 查看日志
show_logs() {
    if [[ "$1" == "-f" ]]; then
        echo -e "${YELLOW}📋 查看实时日志...${NC}"
        docker-compose logs -f
    else
        echo -e "${YELLOW}📋 查看最近日志...${NC}"
        docker-compose logs --tail=100
    fi
}

# 查看状态
show_status() {
    echo -e "${YELLOW}📊 服务状态${NC}"
    docker-compose ps
}

# 重置配置
reset_config() {
    echo -e "${YELLOW}🔄 重置配置...${NC}"
    
    # 停止服务
    docker-compose down
    
    # 删除配置文件
    if [[ -f .env ]]; then
        rm .env
        echo -e "${GREEN}✅ 已删除 .env 文件${NC}"
    fi
    
    # 删除数据目录
    if [[ -d data ]]; then
        rm -rf data
        echo -e "${GREEN}✅ 已删除数据目录${NC}"
    fi
    
    # 重新创建配置
    cp .env.example .env
    echo -e "${GREEN}✅ 配置已重置${NC}"
}

# 主函数
main() {
    # 设置默认值
    ENV="prod"
    COMMAND="start"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            start)
                COMMAND="start"
                shift
                ;;
            stop)
                COMMAND="stop"
                shift
                ;;
            restart)
                COMMAND="restart"
                shift
                ;;
            update)
                COMMAND="update"
                shift
                ;;
            logs)
                COMMAND="logs"
                shift
                ;;
            status)
                COMMAND="status"
                shift
                ;;
            reset)
                COMMAND="reset"
                shift
                ;;
            help|--help|-h)
                show_help
                exit 0
                ;;
            -d|--dev)
                ENV="dev"
                shift
                ;;
            -p|--prod)
                ENV="prod"
                shift
                ;;
            -f|--force)
                FORCE="true"
                shift
                ;;
            *)
                echo -e "${RED}❌ 未知参数: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 执行命令
    case $COMMAND in
        start)
            check_docker
            check_docker_compose
            start_services
            ;;
        stop)
            check_docker
            check_docker_compose
            stop_services
            ;;
        restart)
            check_docker
            check_docker_compose
            restart_services
            ;;
        update)
            check_docker
            check_docker_compose
            update_services
            ;;
        logs)
            check_docker
            check_docker_compose
            show_logs "$@"
            ;;
        status)
            check_docker
            check_docker_compose
            show_status
            ;;
        reset)
            if [[ "$FORCE" != "true" ]]; then
                echo -e "${RED}⚠️  重置配置将删除所有数据！${NC}"
                read -p "确定要继续吗？(y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}取消重置${NC}"
                    exit 0
                fi
            fi
            check_docker
            check_docker_compose
            reset_config
            ;;
        *)
            echo -e "${RED}❌ 未知命令: $COMMAND${NC}"
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"