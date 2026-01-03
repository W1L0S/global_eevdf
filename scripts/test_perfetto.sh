#!/bin/bash
# EEVDF 调度器 Perfetto 测试脚本
# 使用 Perfetto 捕获高质量的调度器 trace

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# 创建输出目录
OUTPUT_DIR="$PROJECT_ROOT/output"
mkdir -p "$OUTPUT_DIR"

# 使用 tracebox（独立模式，不需要后台服务）
PERFETTO_BIN="$PROJECT_ROOT/tools/perfetto/tracebox"
CONFIG_FILE="$PROJECT_ROOT/configs/perfetto_config.pbtx"
TRACE_FILE="$OUTPUT_DIR/eevdf_trace.perfetto-trace"

# 默认参数
TEST_MODE="cpu"  # cpu | mixed | io
DURATION=10

LOADER_PID=""
PERFETTO_PID=""
STRESS_PID=""
TEMP_CONFIG=""

cleanup() {
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

    if [ -n "${PERFETTO_PID:-}" ] && kill -0 "$PERFETTO_PID" 2>/dev/null; then
        kill -TERM "$PERFETTO_PID" 2>/dev/null || true
        for _ in {1..5}; do
            if ! kill -0 "$PERFETTO_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        kill -KILL "$PERFETTO_PID" 2>/dev/null || true
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

    if [ -n "${TEMP_CONFIG:-}" ]; then
        rm -f "$TEMP_CONFIG" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

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
echo "EEVDF 调度器 Perfetto 测试"
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

# 检查 Tracebox
if [ ! -x "$PERFETTO_BIN" ]; then
    echo "错误：未找到 Tracebox 工具"
    echo "请先运行: ./scripts/setup_perfetto.sh"
    exit 1
fi

# 检查配置文件
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误：未找到配置文件 $CONFIG_FILE"
    exit 1
fi

# 清理旧文件
rm -f "$TRACE_FILE"

# 创建临时配置文件，使用用户指定的持续时间
DURATION_MS=$((DURATION * 1000))
TEMP_CONFIG="$(mktemp -p "$PROJECT_ROOT" .perfetto_config.XXXXXX.pbtx)"

# 复制配置文件并替换持续时间
sed "0,/duration_ms: [0-9]*/s//duration_ms: $DURATION_MS/" "$CONFIG_FILE" > "$TEMP_CONFIG"

echo "[1/5] 启动 EEVDF 调度器..."
if [ ! -x "./build/loader" ]; then
    echo "错误：未找到 ./build/loader，请先运行 make"
    exit 1
fi
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
echo "[2/5] 启动 Perfetto trace (使用 tracebox)..."
echo "  - 配置: $TEMP_CONFIG (持续时间: ${DURATION}s)"
echo "  - 输出: $TRACE_FILE"

# 在后台启动 Tracebox（不需要后台服务）
$PERFETTO_BIN -c "$TEMP_CONFIG" -o "$TRACE_FILE" --txt &
PERFETTO_PID=$!
echo "  - Tracebox PID: $PERFETTO_PID"
sleep 2

echo ""
echo "[3/5] 运行测试负载..."
echo "  ⏱ 开始时间: $(date '+%H:%M:%S')"

# 在后台运行 stress-ng，避免阻塞
if ! command -v stress-ng >/dev/null 2>&1; then
    echo "错误：未找到 stress-ng，请先安装 stress-ng"
    exit 1
fi
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

echo ""
echo "[4/5] 等待测试完成..."
# 等待 Perfetto 完成（它控制测试时长）
WAIT_COUNT=0
while kill -0 $PERFETTO_PID 2>/dev/null; do
    if [ $WAIT_COUNT -gt $((DURATION + 10)) ]; then
        echo "  ⚠ Perfetto 超时，强制终止"
        kill -TERM $PERFETTO_PID 2>/dev/null || true
        break
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

# 等待 Perfetto 进程完全结束
wait $PERFETTO_PID 2>/dev/null || true

echo "  ✓ Perfetto 已完成"

# 停止 stress-ng（如果还在运行）
if kill -0 $STRESS_PID 2>/dev/null; then
    echo "  - 停止 stress-ng..."
    kill -TERM $STRESS_PID 2>/dev/null || true
    # 等待最多 5 秒
    for i in {1..5}; do
        if ! kill -0 $STRESS_PID 2>/dev/null; then
            break
        fi
        sleep 1
    done
    # 如果还没退出，强制杀死
    if kill -0 $STRESS_PID 2>/dev/null; then
        kill -9 $STRESS_PID 2>/dev/null || true
    fi
fi

echo "  ⏱ 结束时间: $(date '+%H:%M:%S')"

echo ""
echo "[5/5] 停止调度器..."
sleep 1
if [ -n "${LOADER_PID:-}" ] && kill -0 "$LOADER_PID" 2>/dev/null; then
    kill -TERM "$LOADER_PID" 2>/dev/null || true
    wait "$LOADER_PID" 2>/dev/null || true
fi

# 验证 trace 文件
if [ -f "$TRACE_FILE" ]; then
    SIZE=$(stat -c%s "$TRACE_FILE")
    if command -v bc >/dev/null 2>&1; then
        SIZE_MB=$(echo "scale=2; $SIZE / 1048576" | bc)
    else
        SIZE_MB=$(awk -v s="$SIZE" 'BEGIN { printf("%.2f", s / 1048576) }')
    fi

    # 修改文件权限，让普通用户可以读取
    # 获取真实用户（即使通过 sudo 运行）
    REAL_USER="${SUDO_USER:-$USER}"
    if [ "$REAL_USER" != "root" ]; then
        chown "$REAL_USER:$REAL_USER" "$TRACE_FILE" 2>/dev/null || true
        chmod 644 "$TRACE_FILE" 2>/dev/null || true
        echo "  ✓ 已修改文件权限为 $REAL_USER 可读"
    fi

    echo ""
    echo "========================================"
    echo "测试完成！"
    echo "========================================"
    echo "Trace 文件: $TRACE_FILE"
    echo "文件大小: ${SIZE_MB} MB"
    echo ""
    echo "分析选项："
    echo "  1. 在线查看（推荐）:"
    echo "     上传到 https://ui.perfetto.dev"
    echo ""
    echo "  2. 转换为文本格式:"
    echo "     $PROJECT_ROOT/tools/perfetto/traceconv text $TRACE_FILE > trace.txt"
    echo ""
    echo "  3. 使用 trace_processor_shell:"
    echo "     $PROJECT_ROOT/tools/perfetto/trace_processor_shell $TRACE_FILE"
    echo "========================================"
else
    echo ""
    echo "========================================"
    echo "错误：未生成 trace 文件！"
    echo "========================================"
    echo "请检查 Perfetto 日志"
    exit 1
fi
