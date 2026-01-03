# EEVDF 调度器架构与实现

## 项目概述

本项目是一个基于 Linux 6.12.57 sched_ext 框架的 **全局队列 EEVDF (Earliest Eligible Virtual Deadline First) 调度器**，使用 eBPF 技术实现。完整实现了 Linux 内核 EEVDF 规范的 lag 补偿机制、权重动态变更处理和虚拟时间管理系统。

## 核心设计原则

1. **符合内核规范**：完整实现 EEVDF 论文的公式 (4), (5), (6)，lag 补偿机制与 Linux 内核一致
2. **简洁高效**：使用乘倒数代替除法，优化 BPF 性能，避免复杂的抢占逻辑
3. **全局公平**：使用全局队列，确保所有任务公平调度
4. **防止饥饿**：通过 EEVDF 算法的 deadline 机制和 lag clamp，保证任务不会被长期饿死

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
    u64 base_v;                 // 基准虚拟时间（用于数值稳定性）
    s64 avg_vruntime_sum;       // 等待任务的加权vruntime总和
    u64 avg_load;               // 等待任务的权重总和
    s64 run_avg_vruntime_sum;   // 运行任务的加权vruntime总和
    u64 run_avg_load;           // 运行任务的权重总和
};
```

**V 的计算公式**：
```c
V = base_v + (avg_vruntime_sum + run_avg_vruntime_sum) / (avg_load + run_avg_load)
```

**物理意义**：V 表示系统中所有任务的平均虚拟运行时间，是 lag 补偿机制的核心参照点。

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
- `vd = ve + vslice`（**EEVDF核心公式**）
- `vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32`

#### 1.3 任务上下文 (`task_ctx`)

```c
struct task_ctx {
    u64 vruntime;       // 任务的虚拟运行时间
    s64 vlag;           // vlag = V - vruntime（正值=落后，负值=超前）
    u64 last_run_ns;    // 上次开始运行的时间戳
    u64 saved_vd;       // 保存的虚拟截止时间
    u64 last_weight;    // 上次计算的权重（用于检测权重变更）
    bool is_running;    // 是否正在运行
};
```

**vlag 字段作用**：
- 在任务 stopping 时保存 `vlag = V - vruntime`
- 在任务 enqueue 时按 `vruntime = V - vlag` 恢复（并做上/下限裁剪）
- 让长时间睡眠/交互任务恢复时不至于“丢份额”

---

### 2. vlag 保存/恢复（唤醒补偿）

当前实现使用 `vlag = V - vruntime` 做“唤醒补偿”的跨睡眠状态保存/恢复；同时用 `eevdf_calc_V()` 统一重算系统虚拟时间 `V`（而不是在 BPF 中直接做 `lag/Σw` 的显式更新）。

#### 2.1 vlag 定义

```
vlag = V - vruntime
```

- **vlag > 0**：任务落后于系统平均（应该给予一定补偿）
- **vlag < 0**：任务超前于系统平均（应该给予一定惩罚）
- **vlag = 0**：任务与系统虚拟时间同步

#### 2.2 保存位置（stopping）

- stopping 中先基于运行时长更新 `vruntime`，再把该任务从 `run_avg_*` 统计移除并调用 `eevdf_calc_V()` 重算 `V`
- 随后保存 `tctx->vlag = V - vruntime`，供下次 enqueue 恢复

#### 2.3 恢复位置（enqueue）

- enqueue 中按内核风格公式恢复：`vruntime = V - vlag`
- 为避免极端补偿/惩罚，当前实现做了基于 `slice_ns` 的裁剪：
  - 最大补偿：`vlag <= slice_ns`
  - 最大惩罚：`vlag >= -(slice_ns/2)`

#### 2.4 Clamp 与数值稳定性

- `LAG_CLAMP_NS` 仍用于虚拟时间系统的数值稳定性控制（例如 `base_v` rebasing 的阈值）
- `eevdf_clamp_lag()` / `eevdf_lag_div_weight()` 作为工具函数保留，但当前主路径以 `eevdf_calc_V()` 为准

---

### 3. 双红黑树系统

#### 3.1 合格树 (Ready Tree)

**作用**：存放已合格的任务（`ve ≤ V`）

**排序规则**：按虚拟截止时间 `vd` 从小到大排序
- 最左边的节点 = 最早 deadline 的任务 = 下一个被调度的任务
- 如果 `vd` 相等，使用 `pid` 作为 tiebreaker

**插入条件**：任务的 `ve ≤ 系统虚拟时间V`

**比较函数**：
```c
static bool less_ready(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct eevdf_node *na = container_of(a, struct eevdf_node, node);
    struct eevdf_node *nb = container_of(b, struct eevdf_node, node);
    if (na->vd == nb->vd) return na->pid < nb->pid;  // Tiebreaker
    return na->vd < nb->vd;
}
```

#### 3.2 不合格树 (Future Tree)

**作用**：存放未合格的任务（`ve > V`）

**排序规则**：按虚拟就绪时间 `ve` 从小到大排序
- 最左边的节点 = 最早合格的任务
- 如果 `ve` 相等，使用 `pid` 作为 tiebreaker

**插入条件**：任务的 `ve > 系统虚拟时间V`

**比较函数**：
```c
static bool less_future(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct eevdf_node *na = container_of(a, struct eevdf_node, node);
    struct eevdf_node *nb = container_of(b, struct eevdf_node, node);
    if (na->ve == nb->ve) return na->pid < nb->pid;  // Tiebreaker
    return na->ve < nb->ve;
}
```

#### 3.3 树间转移

**时机**：在 `dispatch` 函数中

**逻辑**：
```c
while (loops < MAX_DISPATCH_LOOPS) {
    node = bpf_rbtree_first(&future);
    if (!node) break;
    if (node->ve > V) break;  // 未合格，停止转移

    remove from future;
    add to ready;
    loops++;
}
```

**限制**：最多转移 4 个节点，防止持锁时间过长

**性能考量**：
- 在 `enqueue` 中：转移 + 插入
- 在 `dispatch` 中：转移 + 取节点（循环）
- 在 `stopping` 中：**不做**转移，仅直接插入（减少持锁时间）

---

### 4. 虚拟时间系统

#### 4.1 系统虚拟时间 V

**计算公式**：
```c
V = base_v + (avg_vruntime_sum + run_avg_vruntime_sum) / (avg_load + run_avg_load)
```

**组成部分**：
- `avg_vruntime_sum`：等待任务的加权 vruntime 总和 = Σ(ve_i - base_v) * weight_i
- `run_avg_vruntime_sum`：运行任务的加权 vruntime 总和
- `avg_load`：等待任务的权重总和 = Σweight_i
- `run_avg_load`：运行任务的权重总和

**物理意义**：V 代表系统中所有任务（等待 + 运行）的平均虚拟运行时间

**作用**：
1. 决定任务是否合格（`ve ≤ V` → 合格）
2. 新任务初始化时，`vruntime` 从 V 开始，确保公平
3. 唤醒补偿的参照点：`vlag = V - vruntime`

#### 4.2 任务虚拟运行时间 (vruntime)

**更新公式**：
```c
delta_v = (实际运行时间 * NICE_0_LOAD * wmult) >> 32
vruntime += delta_v
```

**物理意义**：权重归一化后的"虚拟"运行时间
- 高权重任务（weight 大）：wmult 小，vruntime 增长慢
- 低权重任务（weight 小）：wmult 大，vruntime 增长快

**公平性保证**：所有任务的 vruntime 增长速度与其权重成反比，实现 CPU 时间的公平分配

#### 4.3 基准点重置（V Rebasing）

**触发条件**：当 `V - base_v` 超过 `4 * LAG_CLAMP_NS` 时

**操作**：
```c
delta = V - base_v
base_v = V
avg_vruntime_sum -= delta * avg_load
run_avg_vruntime_sum -= delta * run_avg_load
```

**作用**：
- 防止虚拟时间溢出（u64 范围）
- 保持数值稳定性，避免精度丢失
- 不影响任务间的相对虚拟时间关系

---

### 5. 调度器生命周期

#### 5.1 任务入队 (`enqueue`)

```
任务入队
    ↓
分配 eevdf_node / 获取 task_ctx
    ↓
计算 weight, wmult（含 cgroup weight 修正）
    ↓
slice_ns = eevdf_calculate_slice()（当前固定 3ms）
vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32
    ↓
恢复 vruntime（得到 ve）
    - 首次启用/首个任务：初始化 V/base_v/统计
    - 新任务：vruntime = V，vlag = 0
    - 旧任务：vruntime = V - vlag（vlag 做基于 slice_ns 的裁剪）
    ↓
vd = ve + vslice
    ↓
加入 avg_* 统计并重算 V（eevdf_calc_V）
    ↓
将 future 中 ve <= V_old 的节点搬到 ready（最多 4 个）
    ↓
ve <= V ? → ready : future
```

**关键点**：
- eligible 判定严格使用 `ve <= V`
- 当前实现以 `eevdf_calc_V()` 统一重算 V，而非显式执行“公式(4)(5)(6)”路径

#### 5.2 任务调度 (`dispatch`)

```
转移 future→ready（最多4个）
    ↓
循环查找（最多8次）
    ↓
从 ready 树取最左节点
    ↓
检查任务是否存活 (bpf_task_from_pid)
    ↓
检查 CPU 亲和性
    ↓
本地调度? ───yes→ 分发到当前CPU
    │              ↓
   no           从 avg_* 转移到 run_avg_*
    ↓              ↓
分发到目标CPU    记录运行账户
    ↓              ↓
踢醒目标CPU     返回
    ↓
继续循环
```

**关键点**：
- 循环最多 8 次，找到可在当前 CPU 运行的任务
- 处理 CPU 亲和性绑定的任务
- 从 `avg_*` 统计转移到 `run_avg_*` 统计

#### 5.3 任务停止 (`stopping`)

```
任务停止运行
    ↓
基于 last_run_ns 更新 vruntime（delta_v）
    ↓
从 run_avg_* 统计中移除并重算 V（eevdf_calc_V）
    ↓
保存 vlag = V - vruntime
    ↓
runnable?
  ├─no → 完成（睡眠/退出）
  └─yes（时间片用完）
        ↓
        重新计算 weight/wmult 与 slice/vslice
        ↓
        ve = vruntime
        vd = ve + vslice
        ↓
        加入 avg_* 统计并重算 V
        ↓
        ve <= V ? → ready : future
```

**关键点**：
- `runnable` 为 true 时负责“时间片轮转”：构造新节点重新入队
- stopping 中不做 future→ready 转移（减少持锁时间），转移集中在 enqueue/dispatch

---

### 6. 时间片与权重

#### 6.1 时间片（当前实现）

当前实现将物理时间片简化为固定值：

- `slice_ns = 3000000ns`（3ms，见 `eevdf_calculate_slice()`）

调度差异主要通过权重影响“虚拟时间增量”（`delta_v`）与 `vslice` 来体现。

#### 6.2 权重系统

- Nice 值到权重：使用内核标准权重表（40个元素）
- cgroup 权重修正：`effective_weight = base_weight * cg_weight / NICE_0_LOAD`
- 计算 `wmult`：`wmult = (1<<32) / effective_weight`

权重用途：
1. `delta_v = (delta_ns * NICE_0_LOAD * wmult) >> 32`
2. `vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32`

---

### 7. 防饥饿机制

#### 7.1 EEVDF 算法保证

**核心思想**：按 deadline 调度，最早 deadline 的任务优先

**防饥饿原理**：
- 任务的 `deadline = ve + vslice`
- `ve` 随着等待时间不变，而系统 V 不断增长
- 即使 `ve > V`（不合格），最终 V 会追上 ve
- 一旦合格，任务的 deadline 固定，不会被无限推迟

#### 7.2 vlag 裁剪与数值稳定性

**作用**：
- 限制唤醒补偿/惩罚幅度：enqueue 中对 `vlag` 做基于 `slice_ns` 的裁剪，避免极端行为
- 保持数值稳定性：`LAG_CLAMP_NS` 主要用于 `V/base_v` 的数值稳定性控制（例如 rebasing 阈值）

**效果**：
- 交互式任务：不会因为长时间睡眠而完全失去“相对份额”
- CPU 密集型任务：不会被一次性过度补偿抢占

#### 7.3 V 基准点重置

**条件**：当 `V - base_v` 超过 `4 * LAG_CLAMP_NS`（默认 36ms）时

**操作**：重置 `base_v`，调整所有 vruntime 相对值

**作用**：防止虚拟时间溢出，保持数值稳定性

---

### 8. 并发控制

#### 8.1 全局自旋锁

**保护对象**：
- 两棵红黑树 (ready, future)
- V 统计数据 (avg_*, run_avg_*)
- 系统虚拟时间 V 和 base_v

**持锁时间优化**：
- `enqueue`：vlag 恢复 + 树间转移（<=4）+ 插入节点
- `dispatch`：树间转移（<=4）+ 取节点（查找循环<=8，每次短暂持锁）
- `stopping`：vlag 保存 + **不做**树间转移，仅直接插入

#### 8.2 CPU 运行账户

**作用**：记录当前 CPU 上运行任务的统计信息

**数据**：
```c
struct run_accounting {
    u64 weight_val;  // 缩放后的权重
    s64 key_val;     // (ve - base_v) * weight
    u64 curr_vd;     // 当前 deadline
    u64 wmult;       // 权重乘数
    u32 valid;       // 账户是否有效
};
```

**用途**：在 stopping 时快速恢复任务的统计信息，无需重新计算

---

### 9. 关键性能参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `BASE_SLICE_NS` | 3ms | 基础时间片常量（当前 slice 固定 3ms） |
| `MIN_SLICE_NS` | 1ms | 最小时间片常量（当前未用于 slice 计算） |
| `EEVDF_PERIOD_NS` | 12ms | 周期常量（当前未用于 slice 计算） |
| `LAG_CLAMP_NS` | 9ms (3x) | 数值稳定性阈值相关常量（配合 base_v rebasing） |
| `MAX_DISPATCH_LOOPS` | 4 | future→ready 转移循环上界 |
| `MAX_PEEK_LOOPS` | 8 | dispatch 查找循环上界 |

**调优建议**：
- 若要启用动态时间片：在 `eevdf_calculate_slice()` 引入 `EEVDF_PERIOD_NS/MIN_SLICE_NS` 的策略
- 若要强化/弱化唤醒补偿：调整 enqueue 中 `vlag` 的裁剪范围（当前：补偿<=1个 slice，惩罚<=0.5个 slice）

---

### 10. 实现要点

#### 10.1 与 Linux 内核的一致性

| 特性 | Linux 内核 EEVDF | 本实现 | 备注 |
|------|----------------|--------|------|
| 唤醒补偿状态保存/恢复 | ✓ | ✓ | 使用 `vlag = V - vruntime` 保存/恢复 |
| Lag clamp (3x base_slice) | ✓ | 部分 | 提供 `LAG_CLAMP_NS/eevdf_clamp_lag()`，主路径当前以 slice 级裁剪为准 |
| 显式公式 (4)(5)(6) 更新 V | ✓ | ✗ | 本实现通过 `eevdf_calc_V()` 加权平均统一重算 V |
| 乘倒数工具函数 | ✓ | ✓ | `eevdf_lag_div_weight()` 保留（当前主路径未使用） |
| 双红黑树 | ✓ | ✓ | ready 按 vd；future 按 ve |
| 防饥饿机制 | ✓ | ✓ | deadline 机制 + V 追赶 future.ve |

#### 10.2 BPF 特定优化

1. **避免有符号除法依赖**：主路径通过 `eevdf_calc_V()` 重算 `V`；同时保留 `eevdf_lag_div_weight()` 作为可选工具函数。

2. **循环次数限制**：
   - 防止 BPF verifier 拒绝无界循环
   - 防止持锁时间过长导致 Hard Lockup
   - future→ready 转移循环上界：4 次（MAX_DISPATCH_LOOPS）
  - dispatch 查找循环上界：8 次（MAX_PEEK_LOOPS）

3. **内存分配**：
   - 使用 `bpf_obj_new/drop` 管理 eevdf_node
   - 每次入队分配新节点，出队时释放
   - 避免内存泄漏

#### 10.3 已知限制

1. **全局锁设计**：所有 CPU 共享一个队列和一把锁
   - 适用场景：中等并发（< 16核）
   - 高并发场景：可能成为瓶颈

2. **CPU 亲和性处理**：循环查找策略
   - 限制：最多查找 8 次
   - 极端情况：大量 CPU 绑定任务可能导致某些 CPU 空闲

3. **I/O 密集型负载**：频繁睡眠唤醒会增加锁竞争
   - 优化：stopping 中不做树间转移
   - 仍可能在极高 I/O 压力下出现性能下降

---

### 11. 代码结构

```
my-eevdf-scheduler/
├── src/
│   ├── eevdf.bpf.c       # eBPF 调度器核心
│   │   ├── 常量/权重表/辅助函数（含 eevdf_calc_V / eevdf_compute_weight 等）
│   │   ├── eevdf_enqueue(): 计算 weight/vslice，恢复 vruntime，按 ve<=V 入 ready/future
│   │   ├── eevdf_dispatch(): future→ready 转移(<=4) + 选择最小 vd + affinity 处理
│   │   └── eevdf_stopping(): 记账更新 vruntime，保存 vlag，runnable 时重新入队
│   └── loader.c          # 用户态加载器（80行）
├── scripts/
│   ├── test.sh           # 主测试脚本
│   ├── cleanup.sh        # 清理脚本
│   ├── analyze.sh        # Trace 分析脚本
│   └── verify_implementation.sh  # 代码验证脚本
├── docs/
│   └── ARCHITECTURE.md   # 本文档
├── README.md             # 使用指南
└── Makefile              # 编译配置
```

---

## 算法流程图

### vlag 保存/恢复流程（唤醒补偿）

```
任务运行中
    ↓
stopping: 记录运行时长 → vruntime 增长（delta_v）
    ↓
stopping: 从 run_avg_* 移除并 eevdf_calc_V() 重算 V
    ↓
stopping: 保存 vlag = V - vruntime
    ↓
任务进入睡眠状态
    ↓
... 时间流逝 ...
    ↓
任务被唤醒
    ↓
enqueue: 读取 vlag
    ↓
enqueue: 裁剪 vlag（补偿<=1个 slice，惩罚<=0.5个 slice）
    ↓
enqueue: 恢复 vruntime = V - vlag
    ↓
ve = vruntime
vd = ve + vslice
    ↓
插入 ready/future（以 ve<=V 判断 eligible）
    ↓
dispatch: 优先选择 ready 中最小 vd 的任务运行
```

---

## 总结

本 EEVDF 调度器实现了一个以 `ready/future` 双红黑树为核心的数据结构，并通过 `eevdf_calc_V()` 维护系统虚拟时间 `V` 的 sched_ext 调度器。

### 核心特性

- ✅ **双红黑树设计**：ready（按 vd）+ future（按 ve），严格以 `ve<=V` 判断 eligible
- ✅ **vlag 保存/恢复**：使用 `vlag = V - vruntime` 在睡眠/唤醒之间提供适度补偿
- ✅ **V 加权平均重算**：等待+运行统一统计，周期性通过 `eevdf_calc_V()` 重算 `V`
- ✅ **防饥饿机制**：deadline 机制 + ready 为空时推进 `V` 追赶 future.ve
- ✅ **BPF 约束友好**：所有循环有明确上界（转移<=4，查找<=8），持锁时间受控

### 验证与测试

- 代码一致性验证：运行 `scripts/verify_implementation.sh`（已与当前实现对齐）
- 行为测试：运行 `scripts/test.sh` 或 `scripts/test_perfetto.sh` 采集 trace 做分析
