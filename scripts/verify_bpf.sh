#!/bin/bash
# 验证 BPF 程序的 kfunc 调用

set -e

# 切换到项目根目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

BUILD_DIR="build"
TEST_OBJ="$BUILD_DIR/test_eevdf_new.bpf.o"

echo "╔════════════════════════════════════════════════╗"
echo "║     BPF 程序验证                                ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# 检查编译后的文件
if [ ! -f "$TEST_OBJ" ]; then
    echo "✗ $TEST_OBJ 不存在"
    echo "请先编译: make test"
    exit 1
fi

echo "✓ 找到 $TEST_OBJ"
echo ""

# 显示文件信息
echo "[1] 文件信息:"
ls -lh "$TEST_OBJ"
echo ""

# 检查 ELF 格式
echo "[2] ELF 格式检查:"
file "$TEST_OBJ"
echo ""

# 显示反汇编代码
echo "[3] 反汇编代码 (kfunc 调用):"
echo ""
llvm-objdump -d --no-show-raw-insn "$TEST_OBJ" | grep -A3 "call -1"
echo ""

# 统计 kfunc 调用
KFUNC_COUNT=$(llvm-objdump -d "$TEST_OBJ" | grep "call -1" | wc -l)
echo "总计 $KFUNC_COUNT 个 kfunc 调用"
echo ""

# 检查 BTF 信息
echo "[4] BTF 信息:"
bpftool btf dump file "$TEST_OBJ" 2>/dev/null | grep -E "SEC|FUNC" | head -20
echo ""

# 检查段信息
echo "[5] 段信息:"
readelf -S "$TEST_OBJ" 2>/dev/null | grep -E "Name|syscall"
echo ""

echo "╔════════════════════════════════════════════════╗"
echo "║              验证完成！                         ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "BPF 程序编译成功，包含 $KFUNC_COUNT 个 kfunc 调用"
echo ""
echo "在新内核上加载并运行:"
echo "  sudo bash scripts/install_and_test.sh  # 安装新内核"
echo "  sudo reboot                            # 重启"
echo "  bash scripts/test_on_new_kernel.sh     # 在新内核上测试"
