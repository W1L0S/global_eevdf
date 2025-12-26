#!/bin/bash
# EEVDF 调度器清理和诊断工具

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 检查是否需要诊断模式
if [ "$1" = "--diag" ] || [ "$1" = "-d" ]; then
    DIAG_MODE=true
else
    DIAG_MODE=false
fi

echo "======================================"
if [ "$DIAG_MODE" = true ]; then
    echo "EEVDF 调度器诊断"
else
    echo "EEVDF 调度器清理"
fi
echo "======================================"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "错误：需要root权限"
    echo "请使用: sudo $0"
    exit 1
fi

# 诊断模式：显示详细信息但不清理
if [ "$DIAG_MODE" = true ]; then
    echo "[诊断] 检查调度器状态..."
    if [ -f /sys/kernel/sched_ext/state ]; then
        STATE=$(cat /sys/kernel/sched_ext/state 2>/dev/null)
        echo "  调度器状态: $STATE"
    else
        echo "  ⚠ 无法读取调度器状态"
    fi

    echo ""
    echo "[诊断] 检查进程状态..."
    echo "  Loader进程:"
    ps aux | grep -E "[l]oader" | head -5 || echo "    (无)"

    echo ""
    echo "  stress-ng进程:"
    ps aux | grep -E "[s]tress-ng" | head -10 || echo "    (无)"

    echo ""
    echo "  D状态（不可中断睡眠）进程:"
    ps aux | awk '$8 ~ /D/ {print "   ", $0}' | head -10 || echo "    (无)"

    echo ""
    echo "[诊断] 检查内核日志（最后20行）..."
    dmesg | tail -20

    echo ""
    echo "[诊断] 检查BPF程序..."
    bpftool prog list 2>/dev/null | grep -E "eevdf|sched" || echo "  (无BPF程序或bpftool不可用)"

    echo ""
    echo "======================================"
    echo "诊断完成"
    echo "======================================"
    echo ""
    echo "如需清理，请运行: sudo $0"
    exit 0
fi

# 清理模式
echo "[1/5] 强制停止所有stress-ng进程..."
pkill -9 stress-ng 2>/dev/null || echo "  (没有stress-ng进程)"
sleep 1

echo ""
echo "[2/5] 强制停止所有loader进程..."
pkill -9 loader 2>/dev/null || echo "  (没有loader进程)"
sleep 1

echo ""
echo "[3/5] 禁用调度器..."
if [ -f /sys/kernel/sched_ext/state ]; then
    echo 0 > /sys/kernel/sched_ext/state 2>/dev/null || echo "  (已禁用或无法访问)"
    STATE=$(cat /sys/kernel/sched_ext/state 2>/dev/null)
    echo "  当前状态: $STATE"
else
    echo "  (sched_ext不可用)"
fi

echo ""
echo "[4/5] 检查残留进程..."
STRESS_COUNT=$(ps aux | grep -c "[s]tress-ng")
LOADER_COUNT=$(ps aux | grep -c "[l]oader")
D_STATE_COUNT=$(ps aux | awk '$8 ~ /D/ && ($11 ~ /stress-ng/ || $11 ~ /loader/)' | wc -l)

echo "  stress-ng进程: $STRESS_COUNT"
echo "  loader进程: $LOADER_COUNT"
echo "  D状态进程: $D_STATE_COUNT"

if [ $STRESS_COUNT -gt 0 ] || [ $LOADER_COUNT -gt 0 ]; then
    echo ""
    echo "  ⚠ 仍有残留进程，显示详情:"
    ps aux | grep -E "[s]tress-ng|[l]oader" | head -10
    echo ""
    if [ $D_STATE_COUNT -gt 0 ]; then
        echo "  ⚠ 警告: 有 $D_STATE_COUNT 个D状态进程"
        echo "  D状态进程无法kill，可能需要重启系统"
    fi
fi

echo ""
echo "[5/5] 清理ftrace..."
TRACE_DIR="/sys/kernel/tracing"
if [ -d "$TRACE_DIR" ]; then
    echo 0 > $TRACE_DIR/tracing_on 2>/dev/null
    echo 0 > $TRACE_DIR/events/sched/sched_switch/enable 2>/dev/null
    echo 0 > $TRACE_DIR/events/sched/sched_wakeup/enable 2>/dev/null
    echo 0 > $TRACE_DIR/events/sched/sched_wakeup_new/enable 2>/dev/null
    echo 0 > $TRACE_DIR/events/sched/sched_process_fork/enable 2>/dev/null
    echo 0 > $TRACE_DIR/events/sched/sched_process_exit/enable 2>/dev/null
    echo > $TRACE_DIR/trace 2>/dev/null
    echo "  ftrace已清理"
fi

echo ""
echo "======================================"
echo "清理完成！"
echo "======================================"
echo ""
echo "下一步:"
if [ $D_STATE_COUNT -eq 0 ]; then
    echo "  1. 重新编译:"
    echo "     cd $PROJECT_ROOT && make clean && make"
    echo ""
    echo "  2. 运行测试:"
    echo "     sudo ./scripts/test.sh --cpu-only"
else
    echo "  ⚠ 系统仍有D状态进程"
    echo "  1. 尝试等待1分钟后再次运行此脚本"
    echo "  2. 如果无效，需要重启系统:"
    echo "     sudo reboot"
fi
echo ""
echo "======================================"
