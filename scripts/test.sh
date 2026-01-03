#!/bin/bash
# EEVDF 调度器主测试脚本
# 支持 CPU / 混合负载 / I/O 密集负载测试

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [ -d "/sys/kernel/tracing" ]; then
    TRACE_DIR="/sys/kernel/tracing"
elif [ -d "/sys/kernel/debug/tracing" ]; then
    TRACE_DIR="/sys/kernel/debug/tracing"
else
    echo "错误：未找到 ftrace 目录（/sys/kernel/tracing 或 /sys/kernel/debug/tracing）"
    exit 1
fi
OUTPUT_DIR="$PROJECT_ROOT/output"
TEXT_TRACE="$OUTPUT_DIR/scheduler_trace.txt"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

LOADER_PID=""
STRESS_PID=""

cleanup() {
    echo 0 > "$TRACE_DIR/tracing_on" 2>/dev/null || true
    echo 0 > "$TRACE_DIR/events/sched/sched_switch/enable" 2>/dev/null || true
    echo 0 > "$TRACE_DIR/events/sched/sched_wakeup/enable" 2>/dev/null || true
    echo nop > "$TRACE_DIR/current_tracer" 2>/dev/null || true

    if [ -n "${STRESS_PID:-}" ] && kill -0 "$STRESS_PID" 2>/dev/null; then
        kill -TERM "$STRESS_PID" 2>/dev/null || true
        for _ in {1..5}; do
            if ! kill -0 "$STRESS_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        kill -KILL "$STRESS_PID" 2>/dev/null || true
    fi

    if [ -n "${LOADER_PID:-}" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
        kill -TERM "$LOADER_PID" 2>/dev/null || true
        for _ in {1..5}; do
            if ! kill -0 "$LOADER_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        kill -KILL "$LOADER_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

# 默认参数
TEST_MODE="cpu"  # cpu | mixed | io
DURATION=10

# 解析命令行参数
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
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --cpu-only       仅测试CPU密集型负载（默认）"
            echo "  --mixed          测试混合负载（CPU + I/O）"
            echo "  --io-only        测试 I/O 密集型负载（频繁睡眠/唤醒）"
            echo "  --duration N     测试时长（秒，默认10）"
            echo "  -h, --help       显示此帮助信息"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            echo "使用 -h 查看帮助"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "EEVDF 调度器测试"
echo "========================================"
echo "测试模式: $TEST_MODE"
echo "测试时长: ${DURATION}秒"
echo ""

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "错误：需要root权限"
    echo "请使用: sudo $0"
    exit 1
fi

if [ ! -x "./build/loader" ]; then
    echo "错误：未找到 ./build/loader，请先运行 make"
    exit 1
fi

if ! command -v stress-ng >/dev/null 2>&1; then
    echo "错误：未找到 stress-ng，请先安装 stress-ng"
    exit 1
fi

# 清理旧文件
rm -f "$TEXT_TRACE"

echo "[1/5] 配置 ftrace..."
echo 0 > "$TRACE_DIR/tracing_on"
echo > "$TRACE_DIR/trace"
echo 8192 > "$TRACE_DIR/buffer_size_kb"
echo 1 > "$TRACE_DIR/events/sched/sched_switch/enable"
echo 1 > "$TRACE_DIR/events/sched/sched_wakeup/enable"
echo nop > "$TRACE_DIR/current_tracer"

echo ""
echo "[2/5] 启动 ftrace..."
echo 1 > "$TRACE_DIR/tracing_on"

echo ""
echo "[3/5] 启动 EEVDF 调度器..."
./build/loader &
LOADER_PID=$!
echo "  - Loader PID: $LOADER_PID"
sleep 3

if [ -f /sys/kernel/sched_ext/state ]; then
    STATE=$(cat /sys/kernel/sched_ext/state)
    echo "  - 调度器状态: $STATE"
    if [ "$STATE" != "enabled" ]; then
        echo "  ⚠ 警告：调度器未启用！"
        kill $LOADER_PID 2>/dev/null || true
        exit 1
    fi
fi

echo ""
echo "[4/5] 运行测试..."
echo "  ⏱ 开始时间: $(date '+%H:%M:%S')"

# 在后台运行 stress-ng，避免阻塞
if [ "$TEST_MODE" = "cpu" ]; then
    echo "  模式: CPU密集型"
    stress-ng --cpu 4 --timeout ${DURATION}s --metrics-brief &
    STRESS_PID=$!
elif [ "$TEST_MODE" = "mixed" ]; then
    echo "  模式: 混合负载（CPU + I/O）"
    stress-ng --cpu 2 --io 2 --timeout ${DURATION}s --metrics-brief &
    STRESS_PID=$!
elif [ "$TEST_MODE" = "io" ]; then
    echo "  模式: I/O密集型（hdd，频繁睡眠/唤醒）"
    stress-ng --hdd 4 --timeout ${DURATION}s --metrics-brief &
    STRESS_PID=$!
fi

echo "  - stress-ng PID: $STRESS_PID"

# 等待 stress-ng 完成（最多等待 DURATION + 5 秒）
WAIT_COUNT=0
while kill -0 $STRESS_PID 2>/dev/null; do
    if [ $WAIT_COUNT -gt $((DURATION + 5)) ]; then
        echo "  ⚠ stress-ng 超时，强制终止"
        kill -9 $STRESS_PID 2>/dev/null || true
        break
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

# 确保 stress-ng 已停止
wait $STRESS_PID 2>/dev/null || true

echo "  ⏱ 结束时间: $(date '+%H:%M:%S')"

echo ""
echo "[5/5] 停止收集..."
echo 0 > "$TRACE_DIR/tracing_on"

# 导出trace
cat "$TRACE_DIR/trace" > "$TEXT_TRACE"

# 禁用事件
echo 0 > "$TRACE_DIR/events/sched/sched_switch/enable"
echo 0 > "$TRACE_DIR/events/sched/sched_wakeup/enable"

TRACE_LINES=$(wc -l < "$TEXT_TRACE")

echo ""
echo "========================================"
echo "测试完成！"
echo "========================================"
echo "Trace 文件: $TEXT_TRACE"
echo "事件数量: $TRACE_LINES 行"
echo ""
echo "快速分析:"
echo "  ./scripts/analyze.sh $TEXT_TRACE"
echo "========================================"
