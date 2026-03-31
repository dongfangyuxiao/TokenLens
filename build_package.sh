#!/usr/bin/env bash
# TokenLens 部署包构建脚本
# 用法：bash build_package.sh [版本号]
# 在有源码的机器上运行，生成混淆后的部署包

set -e
VERSION="${1:-$(date +%Y%m%d)}"
BUILD_DIR="/tmp/tokenlens_build_$$"
OUTPUT="tokenlens-${VERSION}.tar.gz"

echo "==> 构建 TokenLens v${VERSION} 部署包"

# 检查 pyarmor
if ! command -v pyarmor &>/dev/null; then
    echo "==> 安装 PyArmor..."
    pip3 install pyarmor --quiet
fi

# 准备构建目录
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/tokenlens"

echo "==> 混淆核心 Python 文件..."
# 需要混淆的核心文件
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

# 混淆存在的核心文件
EXISTING=()
for f in "${CORE_FILES[@]}"; do
    [ -f "$f" ] && EXISTING+=("$f")
done

pyarmor gen --output "$BUILD_DIR/tokenlens" "${EXISTING[@]}"

# 复制客户端模块目录（如果有）
if [ -d "clients" ]; then
    pyarmor gen --output "$BUILD_DIR/tokenlens/clients" clients/*.py 2>/dev/null || cp -r clients "$BUILD_DIR/tokenlens/"
fi

# 复制非 Python 文件
echo "==> 复制静态资源和配置..."
cp -r static "$BUILD_DIR/tokenlens/"
cp requirements.txt "$BUILD_DIR/tokenlens/"
cp .gitignore "$BUILD_DIR/tokenlens/" 2>/dev/null || true

# 复制 deploy 目录
cp -r deploy "$BUILD_DIR/tokenlens/"

# 复制公钥（不复制私钥）
mkdir -p "$BUILD_DIR/tokenlens/keys"
cp keys/license_public.pem "$BUILD_DIR/tokenlens/keys/" 2>/dev/null || true

# 创建数据目录占位
mkdir -p "$BUILD_DIR/tokenlens/data/reports"
mkdir -p "$BUILD_DIR/tokenlens/data/synced_repos"

# 写入版本文件
echo "$VERSION" > "$BUILD_DIR/tokenlens/VERSION"

# 打包
echo "==> 打包..."
tar -czf "$OUTPUT" -C "$BUILD_DIR" tokenlens

# 清理
rm -rf "$BUILD_DIR"

echo ""
echo "✅ 部署包已生成：$OUTPUT"
echo "   大小：$(du -sh "$OUTPUT" | cut -f1)"
echo "   交付给客户后，客户运行：bash deploy/deploy.sh"
