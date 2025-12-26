# EEVDF 调度器架构与实现

## 项目概述

本项目是一个基于 Linux 6.12.57 sched_ext 框架的 **全局队列 EEVDF (Earliest Eligible Virtual Deadline First) 调度器**，使用 eBPF 技术实现，专为移动端场景优化。

## 核心设计原则

1. **简洁高效**：移除复杂的抢占和唤醒补偿逻辑，专注核心EEVDF算法
2. **全局公平**：使用全局队列，确保所有任务公平调度
3. **防止饥饿**：通过EEVDF算法的deadline机制，保证任务不会被长期饿死

---

## 架构设计

### 1. 数据结构

#### 1.1 核心调度器上下文 (`eevdf_ctx_t`)

```c
struct eevdf_ctx_t {
    struct bpf_rb_root ready;   // 合格树（ve ≤ V）：按vd排序
    struct bpf_rb_root future;  // 不合格树（ve > V）：按ve排序
    struct bpf_spin_lock lock;  // 全局锁保护
    u64 V;                      // 系统虚拟时间
    u64 base_v;                 // 基准虚拟时间
    s64 avg_vruntime_sum;       // 等待任务的加权vruntime总和
    u64 avg_load;               // 等待任务的权重总和
    s64 run_avg_vruntime_sum;   // 运行任务的加权vruntime总和
    u64 run_avg_load;           // 运行任务的权重总和
};
```

#### 1.2 任务节点 (`eevdf_node`)

```c
struct eevdf_node {
    struct bpf_rb_node node;    // 红黑树节点
    s32 pid;                    // 进程ID
    u64 ve;                     // 虚拟就绪时间（virtual eligible time）
    u64 vd;                     // 虚拟截止时间（virtual deadline）
    u64 weight;                 // 任务权重
    u64 wmult;                  // 权重乘数（用于快速计算）
    u64 slice_ns;               // 时间片长度（纳秒）
};
```

**关键公式**：
- `ve = vruntime`（任务的虚拟运行时间）
- `vd = ve + vslice`（EEVDF核心公式）
- `vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32`

#### 1.3 任务上下文 (`task_ctx`)

```c
struct task_ctx {
    u64 vruntime;       // 任务的虚拟运行时间
    u64 last_run_ns;    // 上次开始运行的时间戳
    u64 saved_vd;       // 保存的虚拟截止时间
    u64 last_weight;    // 上次计算的权重
    bool is_running;    // 是否正在运行
};
```

---

### 2. 双红黑树系统

#### 2.1 合格树 (Ready Tree)

**作用**：存放已合格的任务（`ve ≤ V`）

**排序规则**：按虚拟截止时间 `vd` 从小到大排序
- 最左边的节点 = 最早deadline的任务 = 下一个被调度的任务
- 如果 `vd` 相等，使用 `pid` 作为 tiebreaker

**插入条件**：任务的 `ve ≤ 系统虚拟时间V`

#### 2.2 不合格树 (Future Tree)

**作用**：存放未合格的任务（`ve > V`）

**排序规则**：按虚拟就绪时间 `ve` 从小到大排序
- 最左边的节点 = 最早合格的任务
- 如果 `ve` 相等，使用 `pid` 作为 tiebreaker

**插入条件**：任务的 `ve > 系统虚拟时间V`

#### 2.3 树间转移

**时机**：在 `dispatch` 函数中

**逻辑**：
```c
while (loops < MAX_DISPATCH_LOOPS) {
    node = bpf_rbtree_first(&future);
    if (node->ve > V) break;  // 未合格，停止转移
    remove from future;
    add to ready;
}
```

**限制**：最多转移 8 个节点，防止持锁时间过长

---

### 3. 虚拟时间系统

#### 3.1 系统虚拟时间 V

**计算公式**：
```c
V = base_v + (avg_vruntime_sum + run_avg_vruntime_sum) / (avg_load + run_avg_load)
```

**物理意义**：系统中所有任务的平均虚拟运行时间

**作用**：
- 决定任务是否合格（ve ≤ V → 合格）
- 新任务初始化时，vruntime 从 V 开始，确保公平

#### 3.2 任务虚拟运行时间 (vruntime)

**计算公式**：
```c
delta_v = (实际运行时间 * NICE_0_LOAD * wmult) >> 32
vruntime += delta_v
```

**物理意义**：权重归一化后的"虚拟"运行时间
- 高优先级任务（weight大）：vruntime增长慢
- 低优先级任务（weight小）：vruntime增长快

---

### 4. 调度器生命周期

#### 4.1 任务入队 (`enqueue`)

```
新任务到达
    ↓
计算权重 (weight, wmult)
    ↓
计算时间片 (slice_ns)
    ↓
计算虚拟时间片 (vslice)
    ↓
设置 ve = vruntime
设置 vd = ve + vslice
    ↓
加入统计 (avg_vruntime_sum, avg_load)
    ↓
更新系统虚拟时间 V
    ↓
ve ≤ V? ───yes→ 插入 ready 树
    │
   no
    ↓
插入 future 树
```

**关键点**：
- 新任务的 vruntime 从系统 V 开始（如果为0）
- 限制 vruntime 在 `V ± V_WINDOW_NS` 范围内，防止极端值

#### 4.2 任务调度 (`dispatch`)

```
从 ready 树取最左节点
    ↓
检查任务是否存活 (bpf_task_from_pid)
    ↓
检查 CPU 亲和性
    ↓
本地调度? ───yes→ 分发到当前CPU
    │              ↓
   no           更新统计
    ↓              ↓
分发到目标CPU    记录运行账户
    ↓              ↓
踢醒目标CPU     返回
    ↓
继续循环（最多8次）
```

**关键点**：
- 循环最多 8 次，找到可在当前CPU运行的任务
- 处理 CPU 亲和性绑定的任务
- 从 `avg_*` 统计转移到 `run_avg_*` 统计

#### 4.3 任务停止 (`stopping`)

```
任务停止运行
    ↓
更新 vruntime
    ↓
从 run_avg_* 统计中移除
    ↓
更新系统虚拟时间 V
    ↓
任务还可运行? ───no→ 完成（进程退出或睡眠）
    │
   yes
    ↓
重新计算权重和时间片
    ↓
设置 ve = vruntime
设置 vd = ve + vslice
    ↓
加入 avg_* 统计
    ↓
ve ≤ V? ───yes→ 重新插入 ready 树
    │
   no
    ↓
重新插入 future 树
```

**关键点**：
- `runnable` 参数区分：时间片用完（true）vs 主动睡眠（false）
- **时间片轮转机制的核心**：任务用完时间片后重新入队
- 不在 stopping 中做树间转移（减少持锁时间）

---

### 5. 时间片计算

#### 5.1 动态时间片算法

```c
slice_ns = EEVDF_PERIOD_NS / total_load
slice_ns = (slice_ns * factor) >> 10
```

**参数**：
- `EEVDF_PERIOD_NS = 12ms`：调度周期
- `total_load`：系统总负载（等待 + 运行）
- `factor`：基于 latency_nice 的调整因子

**latency_nice 计算**：
```c
latency_nice = (static_prio - 120)  // 范围: -20 ~ +19
factor = 1024 + latency_nice * 64  // 范围: 256 ~ 4096
```

**边界保护**：
```c
if (slice_ns < MIN_SLICE_NS) slice_ns = MIN_SLICE_NS;  // 最小1ms
```

#### 5.2 权重系统

**Nice值到权重的映射**：使用 Linux 内核标准权重表（40个元素）

**有效权重计算**：
```c
effective_weight = (base_weight * cgroup_weight) / NICE_0_LOAD
wmult = (1 << 32) / effective_weight
```

---

### 6. 防饥饿机制

#### 6.1 EEVDF 算法保证

**核心思想**：按deadline调度，最早deadline的任务优先

**防饥饿原理**：
- 任务的 deadline = ve + vslice
- ve 随着等待时间不变，而系统 V 不断增长
- 即使 ve > V（不合格），最终 V 会追上 ve
- 一旦合格，任务的 deadline 固定，不会被无限推迟

#### 6.2 虚拟时间窗口

**限制**：任务的 vruntime 被限制在 `V ± V_WINDOW_NS` 范围内

**作用**：
- 防止长时间睡眠的任务醒来后 vruntime 过小，占用过多CPU
- 防止新任务 vruntime 过大，被长期饥饿

**参数**：`V_WINDOW_NS = BASE_SLICE_NS * 4 = 12ms`

#### 6.3 V 基准点重置

**条件**：当 `V - base_v` 超过 `4 * V_WINDOW_NS` 时

**操作**：
```c
delta = V - base_v
base_v = V
avg_vruntime_sum -= delta * avg_load
run_avg_vruntime_sum -= delta * run_avg_load
```

**作用**：防止虚拟时间溢出，保持数值稳定性

---

### 7. 并发控制

#### 7.1 全局自旋锁

**保护对象**：
- 两棵红黑树 (ready, future)
- V 统计数据 (avg_*, run_avg_*)

**持锁时间优化**：
- `enqueue`：树间转移 + 插入节点
- `dispatch`：树间转移 + 取节点（循环最多8次，每次短暂持锁）
- `stopping`：**不做**树间转移，仅直接插入

#### 7.2 CPU 运行账户

**作用**：记录当前CPU上运行任务的统计信息

**数据**：
```c
struct run_accounting {
    u64 weight_val;  // 缩放后的权重
    s64 key_val;     // (ve - base_v) * weight
    u64 curr_vd;     // 当前deadline
    u64 wmult;       // 权重乘数
    u32 valid;       // 账户是否有效
};
```

**用途**：在 stopping 时快速恢复任务的统计信息

---

### 8. 关键性能参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `BASE_SLICE_NS` | 3ms | 基础时间片 |
| `MIN_SLICE_NS` | 1ms | 最小时间片 |
| `EEVDF_PERIOD_NS` | 12ms | 调度周期 |
| `V_WINDOW_NS` | 12ms | 虚拟时间窗口 |
| `MAX_DISPATCH_LOOPS` | 8 | 最大循环次数 |
| `MAX_PEEK_LOOPS` | 8 | 最大查找次数 |

**调优建议**：
- 移动端场景：可适当增加 `BASE_SLICE_NS`，减少上下文切换
- 交互式场景：可适当减小 `EEVDF_PERIOD_NS`，提高响应性

---

### 9. 已知限制

1. **全局锁设计**：所有CPU共享一个队列和一把锁
   - 适用场景：中等并发（< 16核）
   - 高并发场景：可能成为瓶颈

2. **CPU 亲和性处理**：循环查找策略
   - 限制：最多查找8次
   - 极端情况：大量CPU绑定任务可能导致某些CPU空闲

3. **I/O 密集型负载**：频繁睡眠唤醒会增加锁竞争
   - 优化：停止中不做树间转移
   - 仍可能在极高I/O压力下出现性能下降

---

### 10. 代码结构

```
my-eevdf-scheduler/
├── src/
│   ├── eevdf.bpf.c       # eBPF调度器核心（632行）
│   └── loader.c          # 用户态加载器（80行）
├── scripts/
│   ├── test.sh           # 主测试脚本
│   ├── cleanup.sh        # 清理脚本
│   └── analyze.sh        # Trace分析脚本
├── docs/
│   └── ARCHITECTURE.md   # 本文档
├── README.md             # 使用指南
└── Makefile              # 编译配置
```

---

## 总结

本EEVDF调度器实现了一个**简洁、高效、公平**的全局队列调度系统：

- ✅ **核心EEVDF算法**：基于deadline的公平调度
- ✅ **双红黑树设计**：合格/不合格树分离，高效选择
- ✅ **时间片轮转**：任务用完时间片后正确重新入队
- ✅ **防饥饿机制**：虚拟时间窗口 + EEVDF保证
- ✅ **并发优化**：限制循环次数，减少持锁时间
- ✅ **移动端优化**：移除复杂抢占逻辑，专注核心功能

**验证结果**（基于ftrace测试）：
- 时间片轮转工作正常（25.8%的切换因时间片用完）
- 多CPU负载均衡良好
- 无任务饥饿现象
- 通过 stress-ng CPU 压力测试
