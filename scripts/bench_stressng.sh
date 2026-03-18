#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

OUTPUT_DIR="$PROJECT_ROOT/output"
mkdir -p "$OUTPUT_DIR"

TEST_MODE="cpu"
BPF_VERSION="dual-tree"
DURATION=10
RUNS=3
WORKERS=4
OUTPUT_FILE="$OUTPUT_DIR/bench_stressng.txt"
BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --cpu-only)
            TEST_MODE="cpu"
            shift
            ;;
        --mixed)
            TEST_MODE="mixed"
            shift
            ;;
        --io-only)
            TEST_MODE="io"
            shift
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --workers)
            WORKERS="$2"
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
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --cpu-only       仅测试CPU密集型负载（默认）"
            echo "  --mixed          测试混合负载（CPU + I/O）"
            echo "  --io-only        测试 I/O 密集型负载（频繁睡眠/唤醒）"
            echo "  --duration N     每次运行时长（秒，默认10）"
            echo "  --runs N         每种调度器运行次数（默认3）"
            echo "  --workers N      stress-ng 工作线程数（默认4）"
            echo "  --output FILE    结果输出文件（默认 output/bench_stressng.txt）"
            echo "  --build          先执行 make dual-tree"
            echo "  -h, --help       显示此帮助信息"
            echo ""
            echo "示例:"
            echo "  sudo $0 --cpu-only --duration 10 --runs 5"
            echo "  sudo $0 --mixed --duration 20 --workers 6"
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

if ! command -v stress-ng >/dev/null 2>&1; then
    echo "错误：未找到 stress-ng，请先安装 stress-ng"
    exit 1
fi

if [ "$BUILD" = true ]; then
    make
fi

if [ ! -x "./build/loader_global_eevdf" ]; then
    echo "错误：未找到 ./build/loader_global_eevdf"
    echo "请先运行: make"
    exit 1
fi

if command -v pgrep >/dev/null 2>&1; then
    if pgrep -f "./build/loader_global_eevdf" >/dev/null 2>&1; then
        echo "错误：检测到 loader_global_eevdf 正在运行，请先停止"
        exit 1
    fi
fi

ulimit -l unlimited 2>/dev/null || true

run_stress_once() {
    local tmp_file
    tmp_file="$(mktemp)"
    if [ "$TEST_MODE" = "cpu" ]; then
        /usr/bin/time -p stress-ng --cpu "$WORKERS" --timeout "${DURATION}s" --metrics-brief 2>"$tmp_file"
    elif [ "$TEST_MODE" = "mixed" ]; then
        local cpu_workers="$WORKERS"
        local io_workers="$WORKERS"
        if [ "$WORKERS" -ge 2 ]; then
            cpu_workers=$((WORKERS / 2))
            io_workers=$((WORKERS / 2))
            if [ "$cpu_workers" -lt 1 ]; then cpu_workers=1; fi
            if [ "$io_workers" -lt 1 ]; then io_workers=1; fi
        fi
        /usr/bin/time -p stress-ng --cpu "$cpu_workers" --io "$io_workers" --timeout "${DURATION}s" --metrics-brief 2>"$tmp_file"
    else
        /usr/bin/time -p stress-ng --hdd "$WORKERS" --timeout "${DURATION}s" --metrics-brief 2>"$tmp_file"
    fi
    awk '/^real /{print $2}' "$tmp_file"
    rm -f "$tmp_file"
}

set_sched_ext_state() {
    if [ -f /sys/kernel/sched_ext/state ]; then
        echo "$1" > /sys/kernel/sched_ext/state 2>/dev/null || true
    fi
}

start_dual_tree() {
    ./build/loader_global_eevdf &
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
    set_sched_ext_state 0
}

RESULTS_TMP="$(mktemp)"
LOADER_PID=""

echo "========================================" | tee "$OUTPUT_FILE"
echo "stress-ng 完成时间对比" | tee -a "$OUTPUT_FILE"
echo "模式: $TEST_MODE" | tee -a "$OUTPUT_FILE"
echo "时长: ${DURATION}s" | tee -a "$OUTPUT_FILE"
echo "运行次数: $RUNS" | tee -a "$OUTPUT_FILE"
echo "工作线程: $WORKERS" | tee -a "$OUTPUT_FILE"
echo "========================================" | tee -a "$OUTPUT_FILE"

set_sched_ext_state 0

echo "运行默认调度器基线..." | tee -a "$OUTPUT_FILE"
for i in $(seq 1 "$RUNS"); do
    echo "  默认调度器 轮次 $i" | tee -a "$OUTPUT_FILE"
    t=$(run_stress_once)
    echo "default $i $t" >> "$RESULTS_TMP"
done

echo "运行双树调度器..." | tee -a "$OUTPUT_FILE"
start_dual_tree
for i in $(seq 1 "$RUNS"); do
    echo "  双树调度器 轮次 $i" | tee -a "$OUTPUT_FILE"
    t=$(run_stress_once)
    echo "dual-tree $i $t" >> "$RESULTS_TMP"
done
stop_dual_tree

avg_default=$(awk '$1=="default"{sum+=$3; n++} END{if(n>0) printf "%.3f", sum/n; else print "NA"}' "$RESULTS_TMP")
avg_dual=$(awk '$1=="dual-tree"{sum+=$3; n++} END{if(n>0) printf "%.3f", sum/n; else print "NA"}' "$RESULTS_TMP")

echo "" | tee -a "$OUTPUT_FILE"
echo "结果摘要（单位：秒，越小越好）" | tee -a "$OUTPUT_FILE"
echo "default 平均: $avg_default" | tee -a "$OUTPUT_FILE"
echo "dual-tree 平均: $avg_dual" | tee -a "$OUTPUT_FILE"

rm -f "$RESULTS_TMP"
