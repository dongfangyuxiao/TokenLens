#!/usr/bin/env bash
# TokenLens 一键部署脚本
# 在目标服务器上运行：bash deploy.sh
# 要求：Ubuntu 20.04+/CentOS 7+ / Python 3.10+

set -e

INSTALL_DIR="/opt/tokenlens"
SERVICE_USER="tokenlens"
SERVICE_NAME="tokenlens-audit"
PYTHON_MIN="3.10"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 权限检查 ──────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && error "请使用 root 权限运行：sudo bash deploy.sh"

# ── 获取脚本所在目录（即解压后的 tokenlens/ 目录）──────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"   # deploy/ 的上一层

# ── Python 版本检查 ───────────────────────────────────────────────
info "检查 Python 版本..."
PYTHON=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if python3 -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" &>/dev/null; then
            PYTHON="$cmd"; break
        fi
    fi
done
[ -z "$PYTHON" ] && error "未找到 Python ${PYTHON_MIN}+，请先安装：apt install python3.11 或 yum install python3.11"
info "使用 Python：$PYTHON ($("$PYTHON" --version))"

# ── 安装系统依赖 ──────────────────────────────────────────────────
info "安装系统依赖..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-pip python3-venv git curl
elif command -v yum &>/dev/null; then
    yum install -y -q python3-pip git curl
fi

# ── 创建系统用户 ──────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    info "创建系统用户 $SERVICE_USER..."
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
fi

# ── 部署文件 ──────────────────────────────────────────────────────
info "部署文件到 $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rsync -a --exclude='venv/' --exclude='*.db' --exclude='data/' "$SRC_DIR/" "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/data/reports" "$INSTALL_DIR/data/synced_repos"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/keys" 2>/dev/null || true

# ── 创建虚拟环境并安装依赖 ────────────────────────────────────────
info "创建 Python 虚拟环境..."
"$PYTHON" -m venv "$INSTALL_DIR/venv"
info "安装依赖（可能需要几分钟）..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
info "依赖安装完成"

# ── 生成 systemd 服务 ─────────────────────────────────────────────
info "配置 systemd 服务..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=TokenLens Code Audit Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=DB_PATH=${INSTALL_DIR}/data/audit.db
Environment=REPORTS_DIR=${INSTALL_DIR}/data/reports
Environment=SYNC_ROOT=${INSTALL_DIR}/data/synced_repos
Environment=SESSION_TTL_MINUTES=720
Environment=SESSION_IDLE_MINUTES=120
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
Restart=always
RestartSec=5
User=${SERVICE_USER}
Group=${SERVICE_USER}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "服务启动成功 ✅"
else
    warn "服务启动异常，请查看日志：journalctl -u $SERVICE_NAME -n 50"
fi

# ── Nginx 提示 ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  TokenLens 部署完成！${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
echo ""
echo "  服务地址（内网直接访问）: http://$(hostname -I | awk '{print $1}'):8000"
echo ""
echo "  如需配置域名+Nginx，参考："
echo "    deploy/nginx/tokenlens.conf"
echo ""
echo "  下一步：在系统设置页面上传 license.json 授权文件"
echo ""
