#!/bin/bash
# 在新内核上运行 EEVDF kfunc 测试

set -e

# 切换到项目根目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

BUILD_DIR="build"
TEST_SRC="tests/test_eevdf_new.bpf.c"
TEST_OBJ="$BUILD_DIR/test_eevdf_new.bpf.o"
INCLUDE_DIR="include"

echo "╔════════════════════════════════════════════════╗"
echo "║     EEVDF kfunc 功能测试 (新内核)             ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# 检查内核版本
KERNEL_VERSION=$(uname -r)
echo "当前内核: $KERNEL_VERSION"

if [[ ! "$KERNEL_VERSION" =~ "6.12.57" ]]; then
    echo "⚠️  警告: 未运行新编译的内核 (6.12.57+)"
    echo "请先安装并重启到新内核"
    echo ""
    exit 1
fi

echo "✓ 运行在新内核上"
echo ""

# 检查 BTF
echo "[1/5] 检查 BTF 信息..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "✗ BTF 不可用"
    exit 1
fi
echo "✓ BTF 可用"
echo ""

# 生成 vmlinux.h
echo "[2/5] 生成 vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$INCLUDE_DIR/vmlinux.h"
echo "✓ vmlinux.h 生成完成"
echo ""

# 检查新的 kfunc 签名
echo "[3/5] 检查新的 kfunc 签名..."
echo "bpf_eevdf_add 签名:"
bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A8 "bpf_eevdf_add.*type_id=" | head -10
echo ""

# 编译测试程序
echo "[4/5] 编译测试程序..."
mkdir -p "$BUILD_DIR"
ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
clang -O2 -g -target bpf -D__TARGET_ARCH_${ARCH} \
    -I"$INCLUDE_DIR" \
    -c "$TEST_SRC" -o "$TEST_OBJ" 2>&1

if [ $? -eq 0 ]; then
    echo "✓ BPF 程序编译成功"
    ls -lh "$TEST_OBJ"
else
    echo "✗ BPF 程序编译失败"
    exit 1
fi
echo ""

# 显示 kfunc 引用
echo "[5/5] kfunc 引用信息..."
echo "程序中使用的 kfunc:"
llvm-objdump -d --no-show-raw-insn "$TEST_OBJ" | grep "call -1" | wc -l
echo "个 kfunc 调用"
echo ""

echo "╔════════════════════════════════════════════════╗"
echo "║              测试完成！                         ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "下一步: 加载并运行 BPF 程序"
echo "  bpftool prog load $TEST_OBJ /sys/fs/bpf/test_eevdf"
echo "  bpftool prog list"
