#!/bin/bash
# Perfetto 安装和配置脚本

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_ROOT/tools"
PERFETTO_DIR="$TOOLS_DIR/perfetto"
CONFIG_DIR="$PROJECT_ROOT/configs"
CONFIG_FILE="$CONFIG_DIR/perfetto_config.pbtx"

echo "========================================"
echo "Perfetto 安装和配置"
echo "========================================"

# 创建工具目录
mkdir -p "$TOOLS_DIR"
mkdir -p "$PERFETTO_DIR"

# 检测架构
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ASSET_SUFFIX="linux-amd64.zip"
elif [ "$ARCH" = "aarch64" ]; then
    ASSET_SUFFIX="linux-arm64.zip"
else
    echo "错误：不支持的架构 $ARCH"
    exit 1
fi

echo ""
echo "[1/4] 下载 Perfetto 工具..."
cd "$PERFETTO_DIR"

# 使用 GitHub releases 下载最新的 Perfetto
if [ ! -x "tracebox" ] || [ ! -x "traceconv" ] || [ ! -x "trace_processor_shell" ]; then
    if ! command -v curl >/dev/null 2>&1; then
        echo "  ✗ 需要 curl 来下载 Perfetto"
        exit 1
    fi
    echo "  - 获取最新版本信息..."
    LATEST_URL=$(curl -sL https://api.github.com/repos/google/perfetto/releases/latest | \
                 grep "browser_download_url.*${ASSET_SUFFIX}" | \
                 cut -d '"' -f 4)

    if [ -z "$LATEST_URL" ]; then
        echo "  ✗ 无法获取下载链接"
        exit 1
    fi

    echo "  - 下载 Perfetto ($LATEST_URL)..."
    curl -L "$LATEST_URL" -o perfetto.zip

    # 验证下载
    if [ ! -f "perfetto.zip" ] || [ $(stat -c%s "perfetto.zip") -lt 100000 ]; then
        echo "  ✗ 下载失败"
        rm -f perfetto.zip
        exit 1
    fi

    echo "  - 解压文件..."
    # 优先使用 unzip，如果没有则使用 Python
    if command -v unzip &> /dev/null; then
        unzip -q perfetto.zip
    elif command -v python3 &> /dev/null; then
        python3 << 'PYEOF'
import zipfile
with zipfile.ZipFile('perfetto.zip', 'r') as zip_ref:
    zip_ref.extractall('.')
PYEOF
    else
        echo "  ✗ 需要 unzip 或 python3 来解压文件"
        echo "  请运行: sudo apt-get install unzip"
        rm -f perfetto.zip
        exit 1
    fi

    rm perfetto.zip

    # 移动文件到当前目录
    if [ -d "linux-amd64" ]; then
        mv linux-amd64/* .
        rmdir linux-amd64
    fi

    # 设置执行权限
    chmod +x perfetto traced traced_probes tracebox traceconv trace_processor_shell 2>/dev/null || true

    if [ -f "perfetto" ]; then
        SIZE=$(stat -c%s "perfetto")
        echo "  ✓ Perfetto 安装完成 ($(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo \"${SIZE}B\"))"
    else
        echo "  ✗ 解压后未找到 perfetto 文件"
        exit 1
    fi
else
    echo "  ✓ Perfetto 工具已存在"
fi

echo ""
echo "[2/4] 验证工具..."
./perfetto --version || echo "  ⚠ perfetto 版本检查失败"

echo ""
echo "[3/4] 验证配置文件..."

mkdir -p "$CONFIG_DIR"
if [ -f "$CONFIG_FILE" ]; then
    echo "  ✓ 配置文件存在: $CONFIG_FILE"
else
    echo "  ✗ 未找到配置文件: $CONFIG_FILE"
    exit 1
fi

echo ""
echo "[4/4] 完成"

echo ""
echo "========================================"
echo "安装完成！"
echo "========================================"
echo ""
echo "工具位置:"
echo "  - Tracebox: $PERFETTO_DIR/tracebox"
echo "  - 配置文件: $CONFIG_FILE"
echo ""
echo "使用方法:"
echo "  1. 运行 Perfetto 测试:"
echo "     sudo ./scripts/test_perfetto.sh"
echo ""
echo "  2. 查看 trace 文件:"
echo "     上传到 https://ui.perfetto.dev"
echo "     或使用本地工具查看"
echo "========================================"
