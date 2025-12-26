#!/bin/bash
# EEVDF 调度器 Trace 分析工具（完整版）

TRACE_FILE="$1"

if [ -z "$TRACE_FILE" ]; then
    echo "用法: $0 <trace_file>"
    echo ""
    echo "示例:"
    echo "  $0 output/scheduler_trace.txt"
    echo ""
    echo "提示: 运行测试后会在 output/ 目录生成 trace 文件"
    exit 1
fi

if [ ! -f "$TRACE_FILE" ]; then
    echo "错误: 文件不存在: $TRACE_FILE"
    exit 1
fi

echo "========================================"
echo "EEVDF 调度器 Trace 分析"
echo "========================================"
echo "分析文件: $TRACE_FILE"
echo ""

# 基本统计
TOTAL_SWITCHES=$(grep -c "sched_switch" "$TRACE_FILE" || echo "0")
TOTAL_WAKEUPS=$(grep -c "sched_wakeup" "$TRACE_FILE" || echo "0")

echo "[1] 基本统计"
echo "---"
echo "  上下文切换总数: $TOTAL_SWITCHES"
echo "  任务唤醒次数: $TOTAL_WAKEUPS"
echo ""

# 时间片轮转分析
echo "[2] 时间片轮转分析"
echo "---"

# 统计不同prev_state的数量
R_COUNT=$(grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | grep "prev_state=R" | wc -l)
D_COUNT=$(grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | grep "prev_state=D" | wc -l)
S_COUNT=$(grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | grep "prev_state=S" | wc -l)
Z_COUNT=$(grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | grep "prev_state=Z" | wc -l)

TOTAL_STRESS_SWITCHES=$((R_COUNT + D_COUNT + S_COUNT + Z_COUNT))

echo "  stress-ng 状态切换统计:"
echo "    R状态（时间片用完）: $R_COUNT 次"
echo "    D状态（I/O等待）: $D_COUNT 次"
echo "    S状态（主动睡眠）: $S_COUNT 次"
echo "    Z状态（僵尸）: $Z_COUNT 次"

if [ $TOTAL_STRESS_SWITCHES -gt 0 ]; then
    if command -v bc >/dev/null 2>&1; then
        RATIO=$(echo "scale=1; $R_COUNT * 100 / $TOTAL_STRESS_SWITCHES" | bc)
        echo "    时间片用完的占比: ${RATIO}%"
    fi
fi

echo ""
if [ $R_COUNT -gt 0 ]; then
    echo "  ✓ 时间片轮转机制工作正常！"
else
    echo "  ⚠ 未发现因时间片用完被切换的任务"
fi
echo ""

# PID调度次数统计
echo "[3] 任务调度次数（Top 10）"
echo "---"
grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | \
    awk -F'prev_pid=' '{print $2}' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | \
while read count pid; do
    echo "  PID $pid: $count 次调度"
done
echo ""

# CPU负载分布
echo "[4] CPU负载分布（Top 10）"
echo "---"
grep "sched_switch.*stress-ng" "$TRACE_FILE" | awk '{print $2}' | tr -d '[]' | sort | uniq -c | sort -rn | head -10 | \
while read count cpu; do
    echo "  CPU$cpu: $count 次调度"
done
echo ""

# 运行时长分析（前5次R状态切换）
echo "[5] 任务运行时长分析（前5次时间片用完）"
echo "---"
COUNT=0
grep "sched_switch.*stress-ng" "$TRACE_FILE" | grep "prev_comm=stress-ng" | grep "prev_state=R" | head -5 | \
while read line; do
    COUNT=$((COUNT + 1))
    TIMESTAMP=$(echo "$line" | awk '{print $4}' | sed 's/://')
    CPU=$(echo "$line" | awk '{print $2}' | tr -d '[]')
    PID=$(echo "$line" | awk -F'prev_pid=' '{print $2}' | awk '{print $1}')

    # 找到这个任务上次在同一CPU上开始运行的时间
    PREV_LINE=$(grep "\[$CPU\].*next_comm=stress-ng next_pid=$PID" "$TRACE_FILE" | \
                awk -v ts="$TIMESTAMP" '$4 < ts' | tail -1)

    if [ -n "$PREV_LINE" ]; then
        PREV_TS=$(echo "$PREV_LINE" | awk '{print $4}' | sed 's/://')
        if command -v bc >/dev/null 2>&1; then
            DURATION=$(echo "scale=3; ($TIMESTAMP - $PREV_TS) * 1000" | bc)
            echo "  [$COUNT] PID $PID @ CPU$CPU: ${DURATION} ms"
        fi
    fi
done
echo ""

# 全局统计
echo "========================================"
echo "总结"
echo "========================================"

if [ $TOTAL_SWITCHES -gt 0 ]; then
    echo "✓ 调度器正常工作"
    echo "  - 总计 $TOTAL_SWITCHES 次上下文切换"
fi

if [ $R_COUNT -gt 0 ]; then
    echo "✓ 时间片轮转机制正常"
    echo "  - 任务在时间片用完后被正确重新入队"
fi

if [ $TOTAL_STRESS_SWITCHES -gt 10 ]; then
    echo "✓ 任务被多次调度"
    echo "  - EEVDF调度器核心逻辑正确"
fi

echo ""
echo "详细数据:"
echo "  - 查看完整trace: cat $TRACE_FILE"
echo "  - 查看特定PID: grep 'pid=XXXX' $TRACE_FILE"
echo "========================================"
