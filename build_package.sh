#!/usr/bin/env bash
# TokenLens 部署包构建脚本（Cython 编译保护）
# 用法：bash build_package.sh [版本号]
# 在有源码的机器上运行，将核心 .py 编译为 .so 二进制后打包

set -e
VERSION="${1:-$(date +%Y%m%d)}"
BUILD_DIR="/tmp/tokenlens_build_$$"
OUTPUT="tokenlens-${VERSION}.tar.gz"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> 构建 TokenLens v${VERSION} 部署包（Cython 编译）"
cd "$SCRIPT_DIR"

# ── 检查依赖 ──────────────────────────────────────────────────────
for cmd in python3 gcc; do
    command -v "$cmd" &>/dev/null || { echo "❌ 缺少依赖：$cmd，请先安装"; exit 1; }
done

# 准备构建 Python 环境
BUILD_PYTHON="python3"
BUILD_VENV=""
if ! python3 -c "import Cython" 2>/dev/null; then
    echo "==> 创建临时构建虚拟环境并安装 Cython..."
    BUILD_VENV="/tmp/tokenlens_build_venv_$$"
    python3 -m venv "$BUILD_VENV"
    "$BUILD_VENV/bin/pip" install --quiet --upgrade pip setuptools Cython
    BUILD_PYTHON="$BUILD_VENV/bin/python"
fi

# ── 需要编译的核心文件 ────────────────────────────────────────────
CORE_FILES=(
    app.py
    database.py
    license_manager.py
    scanner.py
    reporter.py
    notifier.py
    syslog_sender.py
    repo_sync.py
    default_prompts.py
)

# ── 生成 setup.py ─────────────────────────────────────────────────
echo "==> 生成编译配置..."
EXISTING=()
for f in "${CORE_FILES[@]}"; do
    [ -f "$f" ] && EXISTING+=("$f")
done

"$BUILD_PYTHON" - <<PYEOF
files = [f for f in """${EXISTING[*]}""".split() if f]
lines = [
    "from setuptools import setup",
    "from Cython.Build import cythonize",
    "setup(ext_modules=cythonize(",
    "    " + repr(files) + ",",
    "    compiler_directives={'language_level': '3'}",
    "))",
]
open('/tmp/tokenlens_cython_setup_$$.py', 'w').write('\n'.join(lines))
PYEOF

# ── 编译 ─────────────────────────────────────────────────────────
echo "==> 编译核心文件（Cython → C → .so）..."
COMPILE_DIR="/tmp/tokenlens_compile_$$"
mkdir -p "$COMPILE_DIR"

# 复制源文件到编译目录
for f in "${EXISTING[@]}"; do cp "$f" "$COMPILE_DIR/"; done
cp /tmp/tokenlens_cython_setup_$$.py "$COMPILE_DIR/setup.py"

cd "$COMPILE_DIR"
"$BUILD_PYTHON" setup.py build_ext --inplace --quiet

# 检查编译结果
SO_COUNT=$(find "$COMPILE_DIR" -name "*.so" | wc -l)
[ "$SO_COUNT" -eq 0 ] && { echo "❌ 编译失败，未生成 .so 文件"; exit 1; }
echo "   编译成功：${SO_COUNT} 个 .so 文件"

cd "$SCRIPT_DIR"

# ── 组装部署包 ────────────────────────────────────────────────────
echo "==> 组装部署包..."
mkdir -p "$BUILD_DIR/tokenlens"

# 复制编译产物（.so），不复制源码
find "$COMPILE_DIR" -name "*.so" -exec cp {} "$BUILD_DIR/tokenlens/" \;

# clients 目录原样复制（运行时依赖这些 Python 模块）
[ -d "clients" ] && cp -r clients "$BUILD_DIR/tokenlens/"

# 复制非 Python 资源
cp -r static         "$BUILD_DIR/tokenlens/"
cp -r deploy         "$BUILD_DIR/tokenlens/"
cp    requirements.txt "$BUILD_DIR/tokenlens/"

# 公钥（不含私钥）
mkdir -p "$BUILD_DIR/tokenlens/keys"
[ -f "keys/license_public.pem" ] && cp keys/license_public.pem "$BUILD_DIR/tokenlens/keys/"

# 数据目录占位
mkdir -p "$BUILD_DIR/tokenlens/data/reports"
mkdir -p "$BUILD_DIR/tokenlens/data/synced_repos"

# 版本文件
echo "$VERSION" > "$BUILD_DIR/tokenlens/VERSION"

# ── 打包 ─────────────────────────────────────────────────────────
echo "==> 打包..."
tar -czf "$SCRIPT_DIR/$OUTPUT" -C "$BUILD_DIR" tokenlens

# 清理
rm -rf "$BUILD_DIR" "$COMPILE_DIR" "$BUILD_VENV" /tmp/tokenlens_cython_setup_$$.py

echo ""
echo "✅ 部署包已生成：$SCRIPT_DIR/$OUTPUT"
echo "   大小：$(du -sh "$SCRIPT_DIR/$OUTPUT" | cut -f1)"
echo "   核心文件已编译为 .so 二进制，源码不可读"
echo ""
echo "交付给客户后，客户运行：bash deploy/deploy.sh"
