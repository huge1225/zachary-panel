#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Zachary Panel — 交互式向导 & 命令行一键部署脚本
# 支持模式:
#   1) docker  : Docker Compose 容器化一键部署（生产推荐）
#   2) systemd : Systemd 系统守护服务裸机部署（自动编译主控+双架构Agent+前端）
#   3) local   : 免 Root 本地目录快速编译与后台守护运行
# ==============================================================================

REPO_URL="${NEXUS_REPO_URL:-https://github.com/huge1225/zachary-panel.git}"
DEFAULT_INSTALL_DIR="/opt/zachary-panel"

ACTION="install"
NON_INTERACTIVE="false"
MODE=""
PORT=""
BIND_HOST=""
PUBLIC_URL=""
DB_DRIVER=""
DB_DSN=""
ADMIN_EMAIL=""
ADMIN_PASSWORD=""
TRUSTED_PROXIES=""
ALLOW_PRIVATE_TARGETS=""
SEED_DEMO=""
INSTALL_DIR=""
SKIP_WEB_BUILD="false"

# Colors (disabled when not a terminal)
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
else
  C_RESET="" C_BOLD="" C_CYAN="" C_GREEN="" C_YELLOW="" C_RED=""
fi

info()  { echo "${C_CYAN}==> [Zachary Panel]${C_RESET} $*"; }
ok()    { echo "${C_GREEN}==> [OK]${C_RESET} $*"; }
warn()  { echo "${C_YELLOW}==> [WARN]${C_RESET} $*" >&2; }
die()   { echo "${C_RED}==> [ERROR]${C_RESET} $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Zachary Panel 一键部署与运维脚本

用法:
  ./install.sh                           启动交互式分步部署向导（推荐）
  ./install.sh [选项]                    按命令行参数直接部署或管理服务

部署选项:
  --mode <docker|systemd|local>          部署方式: docker(容器) | systemd(系统服务) | local(本地后台)
  --port <1-65535>                       面板 HTTP 监听端口 (默认: 8080)
  --bind <127.0.0.1|0.0.0.0|IP>          监听绑定地址 (默认: 127.0.0.1)
  --public-url <https://...>             面板对外访问地址，用于生成节点对接命令
  --db-driver <sqlite|postgres|mysql>    数据库驱动 (默认: sqlite)
  --db-dsn <DSN>                         数据库连接串 (默认按模式自动设置 SQLite 路径)
  --admin-email <email>                  初始管理员邮箱 (默认: admin@example.com)
  --admin-password <password>            初始管理员密码 (8-72位；留空自动生成16位随机强密码)
  --trusted-proxies <CIDRs>              受信任反向代理网段 (逗号分隔)
  --allow-private-targets <true|false>   是否允许转发内网地址 (默认: false)
  --seed-demo <true|false>               是否生成演示数据 (默认: false)
  --install-dir <path>                   远程一键安装时的代码目录 (默认: /opt/zachary-panel)
  --skip-web-build                       若已有 web/dist 则跳过前端重新构建
  -y, --non-interactive                  非交互模式，未指定项全部使用安全默认值

运维动作:
  --status                               查看当前面板服务状态
  --logs                                 查看面板运行日志
  --restart                              重启面板服务
  --stop                                 停止面板服务
  --upgrade                              拉取最新代码并重新编译/构建重启
  --uninstall                            停止并卸载面板服务
  -h, --help                             显示此帮助信息
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)                   MODE="${2:-}"; shift 2 ;;
    --port)                   PORT="${2:-}"; shift 2 ;;
    --bind)                   BIND_HOST="${2:-}"; shift 2 ;;
    --public-url)             PUBLIC_URL="${2:-}"; shift 2 ;;
    --db-driver)              DB_DRIVER="${2:-}"; shift 2 ;;
    --db-dsn)                 DB_DSN="${2:-}"; shift 2 ;;
    --admin-email)            ADMIN_EMAIL="${2:-}"; shift 2 ;;
    --admin-password)         ADMIN_PASSWORD="${2:-}"; shift 2 ;;
    --trusted-proxies)        TRUSTED_PROXIES="${2:-}"; shift 2 ;;
    --allow-private-targets)  ALLOW_PRIVATE_TARGETS="${2:-}"; shift 2 ;;
    --seed-demo)              SEED_DEMO="${2:-}"; shift 2 ;;
    --install-dir)            INSTALL_DIR="${2:-}"; shift 2 ;;
    --skip-web-build)         SKIP_WEB_BUILD="true"; shift ;;
    -y|--non-interactive)     NON_INTERACTIVE="true"; shift ;;
    --status|status)          ACTION="status"; shift ;;
    --logs|logs)              ACTION="logs"; shift ;;
    --restart|restart)        ACTION="restart"; shift ;;
    --stop|stop)              ACTION="stop"; shift ;;
    --upgrade|upgrade)        ACTION="upgrade"; shift ;;
    --uninstall|uninstall)    ACTION="uninstall"; shift ;;
    -h|--help|help)           usage; exit 0 ;;
    *) die "未知参数: $1 (使用 --help 查看帮助)" ;;
  esac
done

# Locate repository root (or clone if invoked via curl | bash outside repo)
resolve_repo_root() {
  local script_dir=""
  if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  fi
  if [[ -n "${script_dir}" && -f "${script_dir}/../go.mod" && -d "${script_dir}/../cmd/master" ]]; then
    REPO_ROOT="$(cd "${script_dir}/.." && pwd)"
    return 0
  fi
  if [[ -n "${script_dir}" && -f "${script_dir}/go.mod" && -d "${script_dir}/cmd/master" ]]; then
    REPO_ROOT="${script_dir}"
    return 0
  fi
  if [[ -f "./go.mod" && -d "./cmd/master" ]]; then
    REPO_ROOT="$(pwd)"
    return 0
  fi

  local target_dir="${INSTALL_DIR:-${DEFAULT_INSTALL_DIR}}"
  if [[ -f "${target_dir}/go.mod" && -d "${target_dir}/cmd/master" ]]; then
    REPO_ROOT="${target_dir}"
    return 0
  fi

  command -v git >/dev/null 2>&1 || die "未检测到 git，请先安装 git (如: apt-get install -y git 或 yum install -y git)"
  info "未在当前目录检测到项目源码，正在克隆仓库至 ${target_dir} ..."
  git clone --depth 1 "${REPO_URL}" "${target_dir}" || die "克隆仓库失败: ${REPO_URL}"
  REPO_ROOT="${target_dir}"
}

resolve_repo_root
cd "${REPO_ROOT}"

# Determine input stream for interactive prompts (/dev/tty when available, or stdin when NEXUS_TEST_STDIN=1)
PROMPT_FD=""
setup_prompt_input() {
  if [[ "${NON_INTERACTIVE}" == "true" ]]; then
    return 0
  fi
  if [[ "${NEXUS_TEST_STDIN:-0}" == "1" ]]; then
    PROMPT_FD="0"
    return 0
  fi
  if [[ -t 0 ]]; then
    PROMPT_FD="0"
    return 0
  fi
  if [[ -r /dev/tty ]]; then
    exec 3</dev/tty
    PROMPT_FD="3"
    return 0
  fi
  NON_INTERACTIVE="true"
}

prompt_line() {
  local prompt_text="$1"
  local default_val="${2:-}"
  local out_var="$3"
  if [[ "${NON_INTERACTIVE}" == "true" || -z "${PROMPT_FD}" ]]; then
    printf -v "${out_var}" '%s' "${default_val}"
    return 0
  fi
  local ans=""
  if [[ -n "${default_val}" ]]; then
    printf "  %s [%s]: " "${prompt_text}" "${default_val}"
  else
    printf "  %s: " "${prompt_text}"
  fi
  if ! IFS= read -r -u "${PROMPT_FD}" ans; then
    ans=""
  fi
  if [[ ! -t "${PROMPT_FD}" ]]; then
    echo ""
  fi
  ans="${ans#"${ans%%[![:space:]]*}"}"
  ans="${ans%"${ans##*[![:space:]]}"}"
  if [[ -z "${ans}" ]]; then
    ans="${default_val}"
  fi
  printf -v "${out_var}" '%s' "${ans}"
}

# Generate 16-char alphanumeric CSPRNG password (safe in all env files without special shell/compose characters)
generate_random_password() {
  local pw=""
  pw="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16 || true)"
  if [[ ${#pw} -lt 16 ]] && command -v openssl >/dev/null 2>&1; then
    pw="$(openssl rand -hex 8)"
  fi
  [[ ${#pw} -ge 16 ]] || die "无法从 /dev/urandom 生成安全随机密码"
  printf '%s' "${pw}"
}

generate_random_hex32() {
  local key=""
  key="$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || true)"
  if [[ ${#key} -lt 64 ]] && command -v openssl >/dev/null 2>&1; then
    key="$(openssl rand -hex 32)"
  fi
  [[ ${#key} -ge 64 ]] || die "无法生成 JWT 签名密钥"
  printf '%s' "${key}"
}

# Reject control characters / newlines to prevent env file injection
assert_no_control_chars() {
  local name="$1"
  local val="$2"
  if [[ "${val}" == *$'\n'* || "${val}" == *$'\r'* ]]; then
    die "${name} 包含非法换行或控制字符"
  fi
}

validate_port() {
  local p="$1"
  [[ "${p}" =~ ^[0-9]{1,5}$ ]] && (( p >= 1 && p <= 65535 ))
}

validate_bind_host() {
  local h="$1"
  [[ "${h}" =~ ^[A-Za-z0-9.:_-]+$ ]]
}

validate_email() {
  local e="$1"
  [[ "${e}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || [[ "${e}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]
}

# Safe loader for KEY=VALUE files without executing shell code
load_env_file() {
  local file="$1"
  [[ -f "${file}" ]] || return 0
  local line key val
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    if [[ "${line}" == *=* ]]; then
      key="${line%%=*}"
      val="${line#*=}"
      key="${key#"${key%%[![:space:]]*}"}"
      key="${key%"${key##*[![:space:]]}"}"
      if [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        export "${key}=${val}"
      fi
    fi
  done < "${file}"
}

detect_compose_cmd() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
    return 0
  fi
  return 1
}

detect_active_mode() {
  if [[ -n "${MODE}" ]]; then
    printf '%s' "${MODE}"
    return 0
  fi
  if [[ -f "${REPO_ROOT}/.panel.env" ]]; then
    printf 'local'
    return 0
  fi
  if [[ -f "${REPO_ROOT}/deploy/.env" ]]; then
    printf 'docker'
    return 0
  fi
  if [[ -f "/etc/systemd/system/zachary-panel.service" ]]; then
    printf 'systemd'
    return 0
  fi
  if command -v docker >/dev/null 2>&1 && detect_compose_cmd; then
    printf 'docker'
    return 0
  fi
  printf 'local'
}

# Setup Go and C compiler paths for systemd/local builds
setup_build_toolchain() {
  if ! command -v go >/dev/null 2>&1 && [[ -x "${HOME}/sdk/go/bin/go" ]]; then
    export PATH="${HOME}/sdk/go/bin:${PATH}"
  fi
  command -v go >/dev/null 2>&1 || die "未检测到 Go 编译器 (go)，请先安装 Go 1.23+ 或改用 Docker 模式部署"

  if [[ -z "${CC:-}" ]]; then
    if command -v gcc >/dev/null 2>&1; then
      export CC="gcc"
    elif command -v clang >/dev/null 2>&1; then
      export CC="clang"
    elif [[ -x "${HOME}/bin/zcc" ]]; then
      export CC="${HOME}/bin/zcc"
    else
      die "SQLite 编译需要 C 编译器 (gcc / clang)，请先安装 build-essential / gcc"
    fi
  fi
}

build_binaries_and_web() {
  setup_build_toolchain

  if [[ "${SKIP_WEB_BUILD}" == "true" && -f "${REPO_ROOT}/web/dist/index.html" ]]; then
    info "检测到已有 web/dist/index.html，跳过前端重新构建 (--skip-web-build)"
  else
    command -v npm >/dev/null 2>&1 || die "未检测到 npm，请先安装 Node.js 18+ (或先构建好 web/dist 后加 --skip-web-build)"
    info "正在构建前端控制台 (web/dist) ..."
    if [[ ! -d "${REPO_ROOT}/web/node_modules" ]]; then
      npm --prefix "${REPO_ROOT}/web" install --no-audit --no-fund
    fi
    npm --prefix "${REPO_ROOT}/web" run build
  fi

  info "正在编译主控端 (nexus-master) 与双架构被控端安装包 (amd64 / arm64) ..."
  mkdir -p "${REPO_ROOT}/bin" "${REPO_ROOT}/deploy/releases"
  CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o "${REPO_ROOT}/bin/nexus-master" ./cmd/master
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${REPO_ROOT}/deploy/releases/nexus-agent-linux-amd64" ./cmd/agent
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "${REPO_ROOT}/deploy/releases/nexus-agent-linux-arm64" ./cmd/agent
  ok "主控端与节点安装包编译完成"
}

sync_systemd_assets() {
  install -m 0755 -o root -g root "${REPO_ROOT}/bin/nexus-master" /usr/local/bin/zachary-master
  id -u zachary-panel &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin zachary-panel
  install -d -m 0700 -o zachary-panel -g zachary-panel /var/lib/zachary-panel
  install -d -m 0755 -o root -g root /var/lib/zachary-panel/static/releases
  install -m 0755 -o root -g root "${REPO_ROOT}/deploy/install-agent.sh" /var/lib/zachary-panel/static/install-agent.sh
  install -m 0755 -o root -g root "${REPO_ROOT}/deploy/releases/nexus-agent-linux-amd64" /var/lib/zachary-panel/static/releases/nexus-agent-linux-amd64
  install -m 0755 -o root -g root "${REPO_ROOT}/deploy/releases/nexus-agent-linux-arm64" /var/lib/zachary-panel/static/releases/nexus-agent-linux-arm64
  rm -rf /var/lib/zachary-panel/web
  install -d -m 0755 -o root -g root /var/lib/zachary-panel/web
  cp -r "${REPO_ROOT}/web/dist/." /var/lib/zachary-panel/web/
  chmod -R u=rwX,go=rX /var/lib/zachary-panel/web /var/lib/zachary-panel/static
}

wait_for_panel_ready() {
  local port="$1"
  local url="http://127.0.0.1:${port}/"
  info "正在等待面板服务就绪 (${url}) ..."
  local i
  for i in $(seq 1 30); do
    if curl -fsS --noproxy '*' -o /dev/null "${url}" 2>/dev/null; then
      ok "面板 HTTP 服务已就绪！"
      return 0
    fi
    sleep 1
  done
  warn "等待 ${url} 超时，请使用 ./install.sh --logs 检查启动日志"
  return 1
}

# ==============================================================================
# Lifecycle Actions: status / logs / restart / stop / upgrade / uninstall
# ==============================================================================
handle_lifecycle_action() {
  local m
  m="$(detect_active_mode)"
  case "${ACTION}" in
    status)
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" ps
          ;;
        systemd)
          systemctl status zachary-panel --no-pager
          ;;
        local)
          if [[ -f "${REPO_ROOT}/panel.pid" ]] && kill -0 "$(cat "${REPO_ROOT}/panel.pid")" 2>/dev/null; then
            load_env_file "${REPO_ROOT}/.panel.env"
            ok "本地面板运行中 (PID=$(cat "${REPO_ROOT}/panel.pid"), 监听=${NEXUS_LISTEN:-:8080})"
          else
            warn "本地面板未运行"
            exit 1
          fi
          ;;
      esac
      ;;
    logs)
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" logs --tail=100 -f
          ;;
        systemd)
          journalctl -u zachary-panel -n 100 -f
          ;;
        local)
          tail -n 100 "${REPO_ROOT}/panel.log"
          ;;
      esac
      ;;
    stop)
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" stop
          ok "Docker 容器已停止"
          ;;
        systemd)
          [[ $EUID -eq 0 ]] || die "停止 systemd 服务需要 root 权限 (sudo)"
          systemctl stop zachary-panel
          ok "zachary-panel.service 已停止"
          ;;
        local)
          if [[ -f "${REPO_ROOT}/panel.pid" ]]; then
            kill "$(cat "${REPO_ROOT}/panel.pid")" 2>/dev/null || true
            rm -f "${REPO_ROOT}/panel.pid"
            ok "本地面板进程已停止"
          else
            warn "未找到运行中的 panel.pid"
          fi
          ;;
      esac
      ;;
    restart)
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" --env-file "${REPO_ROOT}/deploy/.env" restart
          ok "Docker 容器已重启"
          ;;
        systemd)
          [[ $EUID -eq 0 ]] || die "重启 systemd 服务需要 root 权限 (sudo)"
          systemctl restart zachary-panel
          ok "zachary-panel.service 已重启"
          ;;
        local)
          if [[ -f "${REPO_ROOT}/panel.pid" ]]; then
            kill "$(cat "${REPO_ROOT}/panel.pid")" 2>/dev/null || true
            sleep 1
          fi
          load_env_file "${REPO_ROOT}/.panel.env"
          nohup "${REPO_ROOT}/bin/nexus-master" >>"${REPO_ROOT}/panel.log" 2>&1 &
          echo $! > "${REPO_ROOT}/panel.pid"
          ok "本地面板已重启 (PID=$(cat "${REPO_ROOT}/panel.pid"))"
          ;;
      esac
      ;;
    upgrade)
      info "正在拉取最新代码并升级 (${m} 模式) ..."
      if [[ -d "${REPO_ROOT}/.git" ]]; then
        git -C "${REPO_ROOT}" pull --ff-only
      fi
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" --env-file "${REPO_ROOT}/deploy/.env" up -d --build
          ok "Docker 镜像已重新构建并启动"
          ;;
        systemd)
          [[ $EUID -eq 0 ]] || die "升级 systemd 服务需要 root 权限 (sudo)"
          build_binaries_and_web
          sync_systemd_assets
          systemctl restart zachary-panel
          ok "systemd 服务已更新并重启"
          ;;
        local)
          build_binaries_and_web
          ACTION="restart"
          handle_lifecycle_action
          ;;
      esac
      ;;
    uninstall)
      case "${m}" in
        docker)
          detect_compose_cmd || die "未找到 docker compose"
          "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" down
          ok "Docker 容器已移除（数据命名卷 zachary-data 已保留，如需彻底删除请执行 docker volume rm deploy_zachary-data）"
          ;;
        systemd)
          [[ $EUID -eq 0 ]] || die "卸载 systemd 服务需要 root 权限 (sudo)"
          systemctl stop zachary-panel 2>/dev/null || true
          systemctl disable zachary-panel 2>/dev/null || true
          rm -f /etc/systemd/system/zachary-panel.service
          systemctl daemon-reload 2>/dev/null || true
          rm -f /usr/local/bin/zachary-master
          ok "systemd 服务已卸载（配置文件 /etc/zachary-panel 与数据目录 /var/lib/zachary-panel 已保留）"
          ;;
        local)
          if [[ -f "${REPO_ROOT}/panel.pid" ]]; then
            kill "$(cat "${REPO_ROOT}/panel.pid")" 2>/dev/null || true
            rm -f "${REPO_ROOT}/panel.pid"
          fi
          rm -f "${REPO_ROOT}/.panel.env"
          ok "本地后台进程已停止并清理 .panel.env（数据目录 ./data 已保留）"
          ;;
      esac
      ;;
  esac
}

if [[ "${ACTION}" != "install" ]]; then
  handle_lifecycle_action
  exit 0
fi

# ==============================================================================
# Interactive Step-by-Step Deployment Wizard ([1/6] -> [6/6])
# ==============================================================================
setup_prompt_input

if [[ "${NON_INTERACTIVE}" != "true" ]]; then
  echo ""
  echo "${C_BOLD}======================================================================${C_RESET}"
  echo "${C_BOLD}   Zachary Panel — 交互式分步部署向导 (按回车直接使用括号内默认值)${C_RESET}"
  echo "${C_BOLD}======================================================================${C_RESET}"
fi

# ---- [进度 1/6] 选择部署方式 ----
if [[ -z "${MODE}" ]]; then
  default_mode="1"
  if ! command -v docker >/dev/null 2>&1; then
    if [[ $EUID -eq 0 ]]; then
      default_mode="2"
    else
      default_mode="3"
    fi
  fi
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo ""
    echo "${C_BOLD}[进度 1/6] 选择部署模式${C_RESET}"
    echo "  1) docker  — Docker Compose 容器化一键部署（推荐生产环境）"
    echo "  2) systemd — Systemd 系统服务裸机部署（需 root + Go + Node 环境）"
    echo "  3) local   — 本地目录免 root 编译并后台启动（适合快速体验与开发测试）"
    prompt_line "请输入选项编号 (1/2/3 或 docker/systemd/local)" "${default_mode}" mode_choice
  else
    mode_choice="${default_mode}"
  fi
  case "${mode_choice}" in
    1|docker)  MODE="docker" ;;
    2|systemd) MODE="systemd" ;;
    3|local)   MODE="local" ;;
    *) die "无效的部署模式: ${mode_choice}" ;;
  esac
fi
[[ "${MODE}" =~ ^(docker|systemd|local)$ ]] || die "部署模式仅支持 docker | systemd | local"

# ---- [进度 2/6] 配置监听网络与对外访问地址 ----
if [[ -z "${PORT}" || -z "${BIND_HOST}" ]]; then
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo ""
    echo "${C_BOLD}[进度 2/6] 配置网络监听与访问地址${C_RESET}"
  fi
  if [[ -z "${PORT}" ]]; then
    prompt_line "面板 HTTP 监听端口 (1-65535)" "8080" PORT
  fi
  validate_port "${PORT}" || die "无效的监听端口: ${PORT} (必须为 1-65535)"

  if [[ -z "${BIND_HOST}" ]]; then
    if [[ "${NON_INTERACTIVE}" != "true" ]]; then
      echo "  1) 127.0.0.1 — 仅监听本机回环（配合 Nginx/Caddy HTTPS 反代，生产推荐）"
      echo "  2) 0.0.0.0   — 监听所有网卡（允许直接通过 http://服务器IP:${PORT} 访问）"
      prompt_line "请选择监听范围 (1/2 或直接填绑定 IP)" "1" bind_choice
    else
      bind_choice="127.0.0.1"
    fi
    case "${bind_choice}" in
      1) BIND_HOST="127.0.0.1" ;;
      2) BIND_HOST="0.0.0.0" ;;
      *) BIND_HOST="${bind_choice}" ;;
    esac
  fi
  validate_bind_host "${BIND_HOST}" || die "无效的监听绑定地址: ${BIND_HOST}"

  if [[ -z "${PUBLIC_URL}" && "${NON_INTERACTIVE}" != "true" ]]; then
    prompt_line "面板对外访问 URL (如 https://panel.example.com，留空则按访问地址自动推断)" "" PUBLIC_URL
  fi
fi
assert_no_control_chars "PUBLIC_URL" "${PUBLIC_URL}"
if [[ -n "${PUBLIC_URL}" ]]; then
  PUBLIC_URL="${PUBLIC_URL%/}"
  [[ "${PUBLIC_URL}" =~ ^https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?$ ]] || die "无效的 --public-url 格式: ${PUBLIC_URL}"
fi

# ---- [进度 3/6] 配置数据库 ----
if [[ -z "${DB_DRIVER}" ]]; then
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo ""
    echo "${C_BOLD}[进度 3/6] 配置数据库存储${C_RESET}"
    echo "  1) sqlite   — 内置 SQLite 数据库（零外部依赖，开箱即用，推荐）"
    echo "  2) postgres — PostgreSQL 数据库"
    echo "  3) mysql    — MySQL / MariaDB 数据库"
    prompt_line "请选择数据库类型 (1/2/3 或 sqlite/postgres/mysql)" "1" db_choice
  else
    db_choice="sqlite"
  fi
  case "${db_choice}" in
    1|sqlite)   DB_DRIVER="sqlite" ;;
    2|postgres) DB_DRIVER="postgres" ;;
    3|mysql)    DB_DRIVER="mysql" ;;
    *) die "无效的数据库类型: ${db_choice}" ;;
  esac
fi
[[ "${DB_DRIVER}" =~ ^(sqlite|postgres|mysql)$ ]] || die "数据库驱动仅支持 sqlite | postgres | mysql"

if [[ -z "${DB_DSN}" ]]; then
  case "${DB_DRIVER}" in
    sqlite)
      case "${MODE}" in
        docker)  default_dsn="/data/nexus_panel.db" ;;
        systemd) default_dsn="/var/lib/zachary-panel/nexus_panel.db" ;;
        local)   default_dsn="${REPO_ROOT}/data/nexus_panel.db" ;;
      esac
      if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        prompt_line "SQLite 数据库文件路径" "${default_dsn}" DB_DSN
      else
        DB_DSN="${default_dsn}"
      fi
      ;;
    postgres)
      if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        prompt_line "PostgreSQL 主机地址" "127.0.0.1" pg_host
        prompt_line "PostgreSQL 端口" "5432" pg_port
        prompt_line "PostgreSQL 用户名" "zachary" pg_user
        prompt_line "PostgreSQL 密码" "" pg_pass
        prompt_line "PostgreSQL 数据库名" "zachary_panel" pg_db
        prompt_line "PostgreSQL SSL 模式 (disable/require)" "disable" pg_ssl
        DB_DSN="host=${pg_host} user=${pg_user} password=${pg_pass} dbname=${pg_db} port=${pg_port} sslmode=${pg_ssl}"
      else
        die "使用 postgres 时必须通过 --db-dsn 指定连接串"
      fi
      ;;
    mysql)
      if [[ "${NON_INTERACTIVE}" != "true" ]]; then
        prompt_line "MySQL 主机地址" "127.0.0.1" my_host
        prompt_line "MySQL 端口" "3306" my_port
        prompt_line "MySQL 用户名" "zachary" my_user
        prompt_line "MySQL 密码" "" my_pass
        prompt_line "MySQL 数据库名" "zachary_panel" my_db
        DB_DSN="${my_user}:${my_pass}@tcp(${my_host}:${my_port})/${my_db}?charset=utf8mb4&parseTime=True&loc=Local"
      else
        die "使用 mysql 时必须通过 --db-dsn 指定连接串"
      fi
      ;;
  esac
fi
assert_no_control_chars "DB_DSN" "${DB_DSN}"

# ---- [进度 4/6] 配置初始管理员账号 ----
if [[ -z "${ADMIN_EMAIL}" ]]; then
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo ""
    echo "${C_BOLD}[进度 4/6] 配置初始管理员账号${C_RESET}"
    prompt_line "管理员登录邮箱" "admin@example.com" ADMIN_EMAIL
  else
    ADMIN_EMAIL="admin@example.com"
  fi
fi
validate_email "${ADMIN_EMAIL}" || die "管理员邮箱格式无效: ${ADMIN_EMAIL}"
assert_no_control_chars "ADMIN_EMAIL" "${ADMIN_EMAIL}"

PASSWORD_GENERATED="false"
if [[ -z "${ADMIN_PASSWORD}" ]]; then
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    prompt_line "管理员初始密码 (8-72位，直接回车将自动生成16位随机强密码)" "" ADMIN_PASSWORD
  fi
  if [[ -z "${ADMIN_PASSWORD}" ]]; then
    ADMIN_PASSWORD="$(generate_random_password)"
    PASSWORD_GENERATED="true"
  fi
fi
assert_no_control_chars "ADMIN_PASSWORD" "${ADMIN_PASSWORD}"
if (( ${#ADMIN_PASSWORD} < 8 || ${#ADMIN_PASSWORD} > 72 )); then
  die "管理员密码长度必须在 8 到 72 个字符之间"
fi

# ---- [进度 5/6] 安全与高级选项 ----
if [[ -z "${TRUSTED_PROXIES}" || -z "${ALLOW_PRIVATE_TARGETS}" || -z "${SEED_DEMO}" ]]; then
  if [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo ""
    echo "${C_BOLD}[进度 5/6] 配置安全与高级选项${C_RESET}"
  fi
  if [[ -z "${TRUSTED_PROXIES}" ]]; then
    if [[ "${MODE}" == "docker" ]]; then
      default_proxies="172.16.0.0/12,127.0.0.1/32"
    else
      default_proxies="127.0.0.1/32"
    fi
    prompt_line "受信任反向代理 IP/CIDR (逗号分隔)" "${default_proxies}" TRUSTED_PROXIES
  fi
  if [[ -z "${ALLOW_PRIVATE_TARGETS}" ]]; then
    prompt_line "是否允许转发规则目标为内网私有地址? (y/N)" "N" priv_ans
    if [[ "${priv_ans}" =~ ^([yY]|[yY][eE][sS]|true)$ ]]; then
      ALLOW_PRIVATE_TARGETS="true"
    else
      ALLOW_PRIVATE_TARGETS="false"
    fi
  fi
  if [[ -z "${SEED_DEMO}" ]]; then
    prompt_line "是否生成演示节点/隧道/测试用户数据? (y/N，生产环境请选 N)" "N" demo_ans
    if [[ "${demo_ans}" =~ ^([yY]|[yY][eE][sS]|true)$ ]]; then
      SEED_DEMO="true"
    else
      SEED_DEMO="false"
    fi
  fi
fi
assert_no_control_chars "TRUSTED_PROXIES" "${TRUSTED_PROXIES}"
[[ "${ALLOW_PRIVATE_TARGETS}" =~ ^(true|false)$ ]] || die "--allow-private-targets 必须为 true 或 false"
[[ "${SEED_DEMO}" =~ ^(true|false)$ ]] || die "--seed-demo 必须为 true 或 false"

# ---- [进度 6/6] 汇总确认并开始部署 ----
if [[ "${NON_INTERACTIVE}" != "true" ]]; then
  echo ""
  echo "${C_BOLD}[进度 6/6] 部署配置确认${C_RESET}"
  echo "  ----------------------------------------------------------"
  echo "  部署模式         : ${MODE}"
  echo "  监听地址         : ${BIND_HOST}:${PORT}"
  echo "  对外访问 URL     : ${PUBLIC_URL:-<自动按请求 Host 推断>}"
  echo "  数据库驱动       : ${DB_DRIVER} (${DB_DSN})"
  echo "  管理员邮箱       : ${ADMIN_EMAIL}"
  if [[ "${PASSWORD_GENERATED}" == "true" ]]; then
    echo "  管理员初始密码   : ${ADMIN_PASSWORD} (已自动生成)"
  else
    echo "  管理员初始密码   : ******** (自定义已设置)"
  fi
  echo "  受信任反向代理   : ${TRUSTED_PROXIES}"
  echo "  允许内网转发目标 : ${ALLOW_PRIVATE_TARGETS}"
  echo "  生成演示数据     : ${SEED_DEMO}"
  echo "  ----------------------------------------------------------"
  prompt_line "确认以上配置并开始一键部署? (Y/n)" "Y" confirm_ans
  if [[ "${confirm_ans}" =~ ^([nN]|[nN][oO])$ ]]; then
    warn "已取消部署。"
    exit 0
  fi
fi

umask 077

# ==============================================================================
# Execute Deployment by Mode
# ==============================================================================
case "${MODE}" in
  docker)
    detect_compose_cmd || die "未检测到 docker compose，请先安装 Docker 与 Docker Compose 插件"
    ENV_FILE="${REPO_ROOT}/deploy/.env"
    # Escape '$' as '$$' for docker compose .env interpolation safety
    esc_dsn="${DB_DSN//\$/\$\$}"
    esc_pw="${ADMIN_PASSWORD//\$/\$\$}"
    cat > "${ENV_FILE}" <<EOF
NEXUS_BIND_HOST=${BIND_HOST}
NEXUS_PORT=${PORT}
NEXUS_LISTEN=:8080
NEXUS_DB_DRIVER=${DB_DRIVER}
NEXUS_DB_DSN=${esc_dsn}
NEXUS_PUBLIC_URL=${PUBLIC_URL}
NEXUS_TRUSTED_PROXIES=${TRUSTED_PROXIES}
NEXUS_ADMIN_EMAIL=${ADMIN_EMAIL}
NEXUS_ADMIN_PASSWORD=${esc_pw}
NEXUS_ALLOW_PRIVATE_TARGETS=${ALLOW_PRIVATE_TARGETS}
NEXUS_SEED_DEMO=${SEED_DEMO}
EOF
    chmod 0600 "${ENV_FILE}"
    info "已写入容器配置文件 ${ENV_FILE} (权限 0600)"
    info "正在启动 Docker Compose 构建与后台部署 ..."
    "${COMPOSE_CMD[@]}" -f "${REPO_ROOT}/deploy/docker-compose.yml" --env-file "${ENV_FILE}" up -d --build
    wait_for_panel_ready "${PORT}" || true
    ;;

  systemd)
    [[ $EUID -eq 0 ]] || die "systemd 模式需要 root 权限，请使用 sudo ./install.sh"
    build_binaries_and_web
    sync_systemd_assets

    install -d -m 0700 -o root -g root /etc/zachary-panel
    JWT_KEY="$(generate_random_hex32)"
    if [[ -f /etc/zachary-panel/panel.env ]]; then
      existing_jwt="$(grep '^NEXUS_JWT_SECRET=' /etc/zachary-panel/panel.env | head -n1 | cut -d= -f2- || true)"
      [[ ${#existing_jwt} -ge 32 ]] && JWT_KEY="${existing_jwt}"
    fi
    cat > /etc/zachary-panel/panel.env <<EOF
NEXUS_LISTEN=${BIND_HOST}:${PORT}
NEXUS_DB_DRIVER=${DB_DRIVER}
NEXUS_DB_DSN=${DB_DSN}
NEXUS_DATA_DIR=/var/lib/zachary-panel
NEXUS_STATIC_DIR=/var/lib/zachary-panel/static
NEXUS_WEB_DIR=/var/lib/zachary-panel/web
NEXUS_PUBLIC_URL=${PUBLIC_URL}
NEXUS_TRUSTED_PROXIES=${TRUSTED_PROXIES}
NEXUS_ADMIN_EMAIL=${ADMIN_EMAIL}
NEXUS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
NEXUS_JWT_SECRET=${JWT_KEY}
NEXUS_ALLOW_PRIVATE_TARGETS=${ALLOW_PRIVATE_TARGETS}
NEXUS_SEED_DEMO=${SEED_DEMO}
EOF
    chmod 0600 /etc/zachary-panel/panel.env

    cat > /etc/systemd/system/zachary-panel.service <<'UNITEOF'
[Unit]
Description=Zachary Panel Master Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=zachary-panel
Group=zachary-panel
WorkingDirectory=/var/lib/zachary-panel
EnvironmentFile=/etc/zachary-panel/panel.env
ExecStart=/usr/local/bin/zachary-master
Restart=always
RestartSec=3
LimitNOFILE=1048576

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/zachary-panel
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload
    systemctl enable zachary-panel
    systemctl restart zachary-panel
    wait_for_panel_ready "${PORT}" || true
    ;;

  local)
    build_binaries_and_web
    mkdir -p "${REPO_ROOT}/data"
    chmod 0700 "${REPO_ROOT}/data"

    ENV_FILE="${REPO_ROOT}/.panel.env"
    cat > "${ENV_FILE}" <<EOF
NEXUS_LISTEN=${BIND_HOST}:${PORT}
NEXUS_DB_DRIVER=${DB_DRIVER}
NEXUS_DB_DSN=${DB_DSN}
NEXUS_DATA_DIR=${REPO_ROOT}/data
NEXUS_STATIC_DIR=${REPO_ROOT}/deploy
NEXUS_WEB_DIR=${REPO_ROOT}/web/dist
NEXUS_PUBLIC_URL=${PUBLIC_URL}
NEXUS_TRUSTED_PROXIES=${TRUSTED_PROXIES}
NEXUS_ADMIN_EMAIL=${ADMIN_EMAIL}
NEXUS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
NEXUS_ALLOW_PRIVATE_TARGETS=${ALLOW_PRIVATE_TARGETS}
NEXUS_SEED_DEMO=${SEED_DEMO}
EOF
    chmod 0600 "${ENV_FILE}"

    if [[ -f "${REPO_ROOT}/panel.pid" ]]; then
      kill "$(cat "${REPO_ROOT}/panel.pid")" 2>/dev/null || true
      sleep 1
    fi
    load_env_file "${ENV_FILE}"
    nohup "${REPO_ROOT}/bin/nexus-master" >"${REPO_ROOT}/panel.log" 2>&1 &
    echo $! > "${REPO_ROOT}/panel.pid"
    chmod 0600 "${REPO_ROOT}/panel.log" "${REPO_ROOT}/panel.pid" 2>/dev/null || true
    wait_for_panel_ready "${PORT}" || true
    ;;
esac

DISPLAY_URL="${PUBLIC_URL:-http://${BIND_HOST}:${PORT}}"
if [[ "${BIND_HOST}" == "0.0.0.0" && -z "${PUBLIC_URL}" ]]; then
  DISPLAY_URL="http://<服务器IP>:${PORT} (本机: http://127.0.0.1:${PORT})"
fi

echo ""
echo "${C_GREEN}${C_BOLD}======================================================================${C_RESET}"
echo "${C_GREEN}${C_BOLD}   🎉 Zachary Panel 部署完成！${C_RESET}"
echo "${C_GREEN}${C_BOLD}======================================================================${C_RESET}"
echo "  部署模式       : ${MODE}"
echo "  访问地址       : ${DISPLAY_URL}"
echo "  管理员账号     : ${ADMIN_EMAIL}"
echo "  管理员初始密码 : ${ADMIN_PASSWORD}"
echo "  (请登录后点击右上角「修改密码」妥善更新密码；若数据库已存在管理员账号，则保持原密码不变)"
echo ""
echo "  常用一键运维命令:"
echo "    查看状态 : ./install.sh --status"
echo "    查看日志 : ./install.sh --logs"
echo "    重启面板 : ./install.sh --restart"
echo "    停止面板 : ./install.sh --stop"
echo "    升级面板 : ./install.sh --upgrade"
echo "    卸载面板 : ./install.sh --uninstall"
echo "${C_GREEN}${C_BOLD}======================================================================${C_RESET}"
