# Global EEVDF 架构说明

本文档说明 `global_eevdf` 在 `sched_ext` 下的实现方式，重点回答三个问题：

1. 任务状态如何存储。
2. 调度决策按什么顺序发生。
3. 为什么这个实现能保持 EEVDF 的公平性与可抢占性。

## 1. 设计目标

- 全局视角选择任务，而不是每 CPU 独立排队。
- 严格遵循 EEVDF 的 eligible 条件：$ve \le V$。
- 维持 Linux 风格 lag 语义：$vlag = V - vruntime$。
- 在 BPF 约束下控制复杂度和锁持有时间，避免长循环。

## 2. 关键状态与数据结构

### 2.1 全局状态：`eevdf_ctx` (ARRAY map, 仅 1 项)

对应 `struct eevdf_ctx_t`，由 `bpf_spin_lock` 保护，包含：

- `ready`：可调度任务树，按 `vd` 升序排序（同 `vd` 按 `pid` 打破平局）。
- `future`：暂不可调度任务树，按 `ve` 升序排序（同 `ve` 按 `pid` 打破平局）。
- `V`：系统当前虚拟时间基准。
- `base_v`、`avg_vruntime_sum`、`avg_load`：就绪任务的加权统计。
- `run_avg_vruntime_sum`、`run_avg_load`：正在运行任务的加权统计。

这组统计量共同决定 $V$ 的推进，而不是靠固定步长累加。

### 2.2 任务节点：`eevdf_node`

节点存放在 BPF rbtree 中，生命周期短，主要字段：

- `ve`：虚拟可运行时间，等于任务当前 `vruntime`。
- `vd`：虚拟截止时间，$vd = ve + vslice$。
- `weight`、`wmult`：权重与其倒数乘子缓存。
- `slice_ns`：本次分配的物理时间片（当前实现固定 3ms）。

### 2.3 任务长期状态：`task_ctx_stor` (TASK_STORAGE)

对应 `struct task_ctx`，用于跨事件保留任务上下文：

- `vruntime`：任务累计虚拟运行时间。
- `vlag`：任务相对系统基准的偏差，定义为 $V - vruntime$。
- `saved_vd`、`last_weight`、`last_run_ns`、`is_running`：运行期辅助信息。

因为 rbtree 节点会被释放，长期状态必须放到 task storage 才能稳定恢复。

### 2.4 每 CPU 运行态：`cpu_run_account` (ARRAY map)

对应 `struct run_accounting`，记录当前 CPU 正在跑的任务统计：

- `weight_val`、`key_val`：从就绪集合迁移到运行集合时用到的统计值。
- `curr_vd`：当前任务 `vd`，供唤醒抢占比较。
- `wmult`、`valid`：结算和有效性标记。

## 3. 调度主流程（按时间顺序）

### 3.1 入队：`eevdf_enqueue`

触发时机：任务变为 runnable。

执行步骤：

1. 根据 `nice` 与 cgroup 权重计算 `weight/wmult`。
2. 计算 `slice_ns` 与 `vslice`。
3. 恢复任务 `vruntime`：
   - 新任务：直接贴齐当前 $V$。
   - 老任务：使用保存的 `vlag` 按 $vruntime = V - vlag$ 恢复，并做上下界限制。
4. 得到 `ve` 与 `vd`，将节点纳入全局统计。
5. 重新计算 $V$。
6. 根据 $ve \le V$ 放入 `ready` 或 `future`。
7. 如新任务明显更“紧急”，触发 `kick` 促进抢占。

结果：任务被放入正确队列，且全局时钟与负载统计同步更新。

### 3.2 派发：`eevdf_dispatch`

触发时机：CPU 需要新任务。

执行步骤：

1. 若 `ready` 为空且 `future` 非空，必要时推进 $V$ 到 `future` 最小 `ve`。
2. 将已满足 $ve \le V$ 的 `future` 节点搬运到 `ready`（有循环上限）。
3. 从 `ready` 取最小 `vd` 节点。
4. 做 CPU 亲和性检查：
   - 本地可运行：走 `SCX_DSQ_LOCAL`。
   - 本地不可运行：走 `SCX_DSQ_LOCAL_ON | target_cpu` 远程派发。
5. 将任务统计从 ready 集迁移到 running 集，并更新 `cpu_run_account`。

结果：系统优先执行“已 eligible 且截止时间最早”的任务，同时兼顾亲和性。

### 3.3 停止运行：`eevdf_stopping`

触发时机：任务被切走（时间片用尽、阻塞、主动让出）。

执行步骤：

1. 依据 `delta_ns` 计算本次虚拟运行增量并累加到 `vruntime`。
2. 将该任务从 running 集统计中移除，重算 $V$。
3. 保存 `vlag = V - vruntime`，用于下次唤醒恢复。
4. 清理当前 CPU 的 `run_accounting` 有效位。
5. 若任务仍 runnable，则立即重新生成节点并回到入队路径。

结果：任务历史公平性被保留，系统时钟在任务离开后自动校正。

## 4. 关键公式与判定条件

### 4.1 eligible 判定

$$
ve \le V
$$

满足时进入 `ready`，否则进入 `future`。

### 4.2 虚拟时间片

$$
vslice = (slice\_ns \times NICE\_0\_LOAD \times wmult) \gg 32
$$

当前 `slice_ns` 固定为 3ms，公平性主要通过 `wmult` 体现。

### 4.3 虚拟截止时间

$$
vd = ve + vslice
$$

`ready` 树始终按最小 `vd` 优先。

### 4.4 lag 保存与恢复

$$
vlag = V - vruntime
$$

恢复时：

$$
vruntime_{new} = V_{now} - vlag
$$

该公式保证睡眠补偿语义与内核实现一致。

## 5. 并发与复杂度控制

- 全局关键区由 `bpf_spin_lock` 保护。
- rbtree 操作复杂度为 $O(logN)$。
- `future -> ready` 搬运与 dispatch peek 均设置循环上限，防止单次 BPF 执行过长。
- 抢占 kick 受最小间隔限制，避免高频唤醒风暴。

## 6. 实现中的不变量

- 不变量 1：`ready` 中任一节点都满足 $ve \le V$。
- 不变量 2：`future` 的树顶是最早可能转入 `ready` 的候选。
- 不变量 3：进入 CPU 运行的任务必须先从 ready 统计移到 running 统计。
- 不变量 4：每次 `stopping` 都会更新 `vlag`，确保后续唤醒公平恢复。

## 7. 与默认调度路径的分工

- `select_cpu` 使用 `scx_bpf_select_cpu_dfl`，负责基础 CPU 选择。
- `dispatch` 负责 EEVDF 的核心优先级决策。
- `kick` 机制补足“已有运行任务但新任务更紧急”的抢占触发。

这种分工让代码保持清晰：CPU 放置策略与全局 EEVDF 决策解耦。
