#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

OUTPUT_DIR="$PROJECT_ROOT/output"
mkdir -p "$OUTPUT_DIR"

KERNEL_SRC_DEFAULT="$(awk -F ':=' '/^KERNEL_SRC/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2; exit}' "$PROJECT_ROOT/Makefile")"
KERNEL_SRC="${KERNEL_SRC_DEFAULT:-/home/hustlhy/linux-6.12.57}"
JOBS="$(nproc)"
TARGET=""
RUNS=2
OUTPUT_FILE="$OUTPUT_DIR/bench_kernel_build_dual_tree.txt"
BUILD=false
CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --kernel-src)
            KERNEL_SRC="$2"
            shift 2
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --build)
            BUILD=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --kernel-src DIR  内核源码目录（默认读取 Makefile 的 KERNEL_SRC）"
            echo "  --jobs N          make 并行数（默认 nproc）"
            echo "  --target T        make 目标（默认空，等同于直接 make）"
            echo "  --runs N          运行次数（默认2）"
            echo "  --output FILE     结果输出文件（默认 output/bench_kernel_build_dual_tree.txt）"
            echo "  --build           先执行 make dual-tree"
            echo "  --clean           每次运行前执行 make clean"
            echo "  -h, --help        显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  sudo $0 --runs 3 --jobs 16"
            echo "  sudo $0 --kernel-src /path/to/linux --target vmlinux"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            echo "使用 -h 查看帮助"
            exit 1
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo "错误：需要root权限"
    echo "请使用: sudo $0"
    exit 1
fi

if [ ! -d "$KERNEL_SRC" ] || [ ! -f "$KERNEL_SRC/Makefile" ]; then
    echo "错误：内核源码目录无效: $KERNEL_SRC"
    exit 1
fi

if [ ! -f "$KERNEL_SRC/.config" ]; then
    echo "错误：未找到 $KERNEL_SRC/.config，请先配置并编译过内核"
    exit 1
fi

if [ "$BUILD" = true ]; then
    make
fi

if [ ! -x "./build/loader_clutch" ]; then
    echo "错误：未找到 ./build/loader_clutch"
    echo "请先运行: make"
    exit 1
fi

if command -v pgrep >/dev/null 2>&1; then
    if pgrep -f "./build/loader_clutch" >/dev/null 2>&1; then
        echo "错误：检测到 loader_clutch 正在运行，请先停止"
        exit 1
    fi
fi

ulimit -l unlimited 2>/dev/null || true

run_make_once() {
    local tmp_file
    local real_time
    tmp_file="$(mktemp)"
    if [ "$CLEAN" = true ]; then
        make -C "$KERNEL_SRC" clean >/dev/null 2>&1
    fi
    # 确保 time 输出到 tmp_file，且忽略 make 的 stdout/stderr
    if /usr/bin/time -p bash -c "make -C \"$KERNEL_SRC\" -j\"$JOBS\" $TARGET >/dev/null 2>&1" 2>"$tmp_file"; then
        # 提取 real 时间（兼容不同 time 版本输出格式，通常是 real 123.45）
        real_time="$(grep -oP '^real \K[0-9.]+' "$tmp_file" || awk '/^real/ {print $2}' "$tmp_file")"
        rm -f "$tmp_file"
        if [ -z "$real_time" ]; then
            echo "错误：未获取到编译耗时，请检查 /usr/bin/time 是否可用"
            return 1
        fi
        echo "$real_time"
        return 0
    fi
    rm -f "$tmp_file"
    return 1
}

start_dual_tree() {
    ./build/loader_clutch &
    LOADER_PID=$!
    sleep 3
    if [ -f /sys/kernel/sched_ext/state ]; then
        local state
        state=$(cat /sys/kernel/sched_ext/state)
        if [ "$state" != "enabled" ]; then
            kill "$LOADER_PID" 2>/dev/null || true
            wait "$LOADER_PID" 2>/dev/null || true
            echo "错误：调度器未启用（state=$state）"
            exit 1
        fi
    fi
}

stop_dual_tree() {
    if [ -n "${LOADER_PID:-}" ]; then
        kill -TERM "$LOADER_PID" 2>/dev/null || true
        for _ in {1..5}; do
            if ! kill -0 "$LOADER_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        kill -KILL "$LOADER_PID" 2>/dev/null || true
        wait "$LOADER_PID" 2>/dev/null || true
    fi
}

RESULTS_TMP="$(mktemp)"
LOADER_PID=""

echo "========================================" | tee "$OUTPUT_FILE"
echo "内核编译耗时（双树调度器）" | tee -a "$OUTPUT_FILE"
echo "内核目录: $KERNEL_SRC" | tee -a "$OUTPUT_FILE"
echo "jobs: $JOBS" | tee -a "$OUTPUT_FILE"
echo "target: ${TARGET:-<default>}" | tee -a "$OUTPUT_FILE"
echo "运行次数: $RUNS" | tee -a "$OUTPUT_FILE"
echo "clean: $CLEAN" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"

start_dual_tree
for i in $(seq 1 "$RUNS"); do
    echo "  双树调度器 轮次 $i" | tee -a "$OUTPUT_FILE"
    t=$(run_make_once)
    echo "dual-tree $i $t" >> "$RESULTS_TMP"
done
stop_dual_tree

avg_dual=$(awk '$1=="dual-tree"{sum+=$3; n++} END{if(n>0) printf "%.3f", sum/n; else print "NA"}' "$RESULTS_TMP")

echo "" | tee -a "$OUTPUT_FILE"
echo "结果摘要（单位：秒，越小越好）" | tee -a "$OUTPUT_FILE"
echo "dual-tree 平均: $avg_dual" | tee -a "$OUTPUT_FILE"

rm -f "$RESULTS_TMP"
