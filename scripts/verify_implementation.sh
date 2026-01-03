#!/bin/bash
# EEVDF (sched_ext) - 实现一致性验证脚本（与当前代码对齐）

set -e

echo "========================================="
echo "EEVDF 调度器实现一致性验证"
echo "========================================="
echo ""

echo "1. 检查编译产物..."
if [ -f "build/eevdf.bpf.o" ]; then
    echo "   ✓ BPF 对象: build/eevdf.bpf.o ($(stat -c%s build/eevdf.bpf.o) bytes)"
else
    echo "   ✗ 缺少 BPF 对象 (build/eevdf.bpf.o)"
    exit 1
fi

if [ -f "build/loader" ]; then
    echo "   ✓ Loader: build/loader ($(stat -c%s build/loader) bytes)"
else
    echo "   ✗ 缺少 Loader (build/loader)"
    exit 1
fi

echo ""
echo "2. 验证关键常量/参数定义..."
grep -q "#define BASE_SLICE_NS" src/eevdf.bpf.c && echo "   ✓ BASE_SLICE_NS 已定义" || echo "   ✗ 缺少 BASE_SLICE_NS"
grep -q "#define MIN_SLICE_NS" src/eevdf.bpf.c && echo "   ✓ MIN_SLICE_NS 已定义" || echo "   ✗ 缺少 MIN_SLICE_NS"
grep -q "#define MAX_RT_PRIO" src/eevdf.bpf.c && echo "   ✓ MAX_RT_PRIO 已定义" || echo "   ✗ 缺少 MAX_RT_PRIO"

echo ""
echo "3. 验证 V 的加权平均计算路径（eevdf_calc_V）..."
grep -q "static __always_inline u64 eevdf_calc_V" src/eevdf.bpf.c && echo "   ✓ eevdf_calc_V 函数存在" || echo "   ✗ 缺少 eevdf_calc_V"
grep -q "avg_vruntime_sum \+ sctx->run_avg_vruntime_sum" src/eevdf.bpf.c && echo "   ✓ V 使用 avg_* + run_avg_*" || echo "   ✗ V 未按等待+运行合并统计"
grep -q "avg_load \+ sctx->run_avg_load" src/eevdf.bpf.c && echo "   ✓ V 使用 avg_load + run_avg_load" || echo "   ✗ V 未按等待+运行合并负载"

echo ""
echo "4. 验证 per-task 上下文字段（vlag/vruntime/last_weight）..."
grep -q "s64 vlag;" src/eevdf.bpf.c && echo "   ✓ task_ctx.vlag 存在" || echo "   ✗ 缺少 task_ctx.vlag"
grep -q "u64 vruntime;" src/eevdf.bpf.c && echo "   ✓ task_ctx.vruntime 存在" || echo "   ✗ 缺少 task_ctx.vruntime"
grep -q "u64 last_weight;" src/eevdf.bpf.c && echo "   ✓ task_ctx.last_weight 存在" || echo "   ✗ 缺少 task_ctx.last_weight"

echo ""
echo "5. 验证 vlag 保存/恢复（stopping/enqueue）..."
grep -q "tctx->vlag = (s64)(sctx->V - tctx->vruntime);" src/eevdf.bpf.c && echo "   ✓ stopping 保存 vlag = V - vruntime" || echo "   ✗ stopping 未保存 vlag"
grep -q "vruntime_new = V_new - vlag" src/eevdf.bpf.c && echo "   ✓ enqueue 使用 vlag 恢复逻辑（文本说明）" || echo "   ⚠ enqueue 未找到恢复逻辑说明文字（不影响功能）"

echo ""
echo "6. 验证 eligible 判定与双红黑树排序..."
grep -q "if (n->ve <= sctx->V)" src/eevdf.bpf.c && echo "   ✓ eligible 判定 (ve <= V) 存在" || echo "   ✗ 缺少 eligible 判定"
grep -q "if (na->vd == nb->vd) return na->pid < nb->pid;" src/eevdf.bpf.c && echo "   ✓ ready: vd 相等时 pid tiebreaker" || echo "   ✗ ready tiebreaker 缺失"
grep -q "if (na->ve == nb->ve) return na->pid < nb->pid;" src/eevdf.bpf.c && echo "   ✓ future: ve 相等时 pid tiebreaker" || echo "   ✗ future tiebreaker 缺失"

echo ""
echo "7. 验证时间片策略（当前为固定 3ms）..."
grep -q "return 3000000ULL;" src/eevdf.bpf.c && echo "   ✓ eevdf_calculate_slice: 固定 3000000ns" || echo "   ⚠ 未找到固定 3ms（可能已改为动态算法）"

echo ""
echo "8. 检查系统 sched_ext 支持..."
if [ -d "/sys/kernel/sched_ext" ]; then
    echo "   ✓ 系统支持 sched_ext"
    STATE=$(cat /sys/kernel/sched_ext/state 2>/dev/null || echo "unknown")
    echo "   当前状态: $STATE"
else
    echo "   ✗ 系统不支持 sched_ext"
fi

echo ""
echo "========================================="
echo "验证完成"
echo "========================================="
echo ""
echo "当前实现的关键特性（以代码为准）："
echo "  ✓ V 通过等待+运行任务的加权平均重算 (eevdf_calc_V)"
echo "  ✓ vlag = V - vruntime 保存/恢复（用于唤醒补偿）"
echo "  ✓ ready/future 双红黑树与 ve<=V eligible 判定"
echo "  ✓ 固定 3ms 时间片（如需动态时间片可在 eevdf_calculate_slice 扩展）"
echo ""
echo "要运行功能测试（需要 root 权限）："
echo "  sudo bash scripts/test.sh --cpu-only --duration 10"
