# Per-Cluster Clutch/CFS 架构说明

当前实现采用 per-cluster 三层结构，并使用统一调度实体 `clutch_se` 表达可参与排序的对象。

- bucket 层维护 group 实体树：`group_cfs_rq`
- group 层维护 thread 实体树：`thread_cfs_rq`
- 两层都按最小 `vruntime` 做 CFS 风格选择

## 1. 设计目标

- 从全局单队列切换到 per-cluster 分层队列。
- 固定 `cluster -> bucket -> group -> thread` 的调度路径。
- 先稳定数据结构与并发模型，再逐步补齐 QoS/迁移/抢占策略。

## 2. 三层结构

### 2.1 第一层：cluster / bucket

- `cluster_ctx_map` 记录 cluster 级轮转状态（`next_bucket`）。
- `bucket_ctx_map` 保存每个 bucket 的上下文。
- 每个 bucket 内部维护 `group_cfs_rq`（group 调度实体红黑树）。

### 2.2 第二层：group

- `group_ctx_map` 以 `(cluster_id, group_id)` 为 key 保存 `group_ctx`。
- `group_ctx` 是组的持久化状态，内部有 `thread_cfs_rq`。
- bucket 中参与排序的是短生命周期 `group_se`（类型为 `clutch_se`）。

### 2.3 第三层：thread

- thread 入队时创建 `thread_se`（类型为 `clutch_se`）。
- thread_se 按 `vruntime` 插入所属 group 的 `thread_cfs_rq`。
- dispatch 消费 thread_se 后释放对象。

## 3. 关键数据结构

### 3.1 `struct clutch_se`

统一调度实体，既可表示 group_se，也可表示 thread_se，核心字段：

- `rb_node`：红黑树节点
- `pid / tgid`：对象标识
- `cluster_id / bucket_id / dispatch_cpu`：拓扑与目标 CPU 信息
- `vruntime`：排序主键
- `wmult / slice_ns`：线程运行折算与时间片信息（group_se 不使用时保持默认值）
- `nr_children / seq`：组实体令牌信息

### 3.2 `struct group_ctx`

组级持久化状态：

- `thread_cfs_rq`：组内线程实体树
- `nr_children / vruntime / dispatch_cpu / seq`：组聚合状态
- `lock`：保护组内树与聚合字段

### 3.3 `struct bucket_ctx`

bucket 级状态：

- `group_cfs_rq`：bucket 内组实体树
- `nr_groups`：当前组实体数量
- `lock`：保护 bucket 树

### 3.4 `struct thread_ctx`

线程长期状态（TASK_STORAGE）：

- `vruntime`
- `last_run_ns`
- `cluster_id / bucket_id / home_cpu`
- `is_running`

### 3.5 `struct cpu_run_state`

每 CPU 运行态记账：

- `wmult`
- `cluster_id / bucket_id`
- `pid / tgid`
- `home_cpu`
- `valid`

## 4. BPF Maps 设计

### 4.1 `cluster_ctx_map`

- 类型：`BPF_MAP_TYPE_ARRAY`
- key：`u32 cluster_id`
- value：`struct cluster_ctx`
- 用途：cluster 级 bucket 轮转状态

### 4.2 `bucket_ctx_map`

- 类型：`BPF_MAP_TYPE_ARRAY`
- key：`u32 bucket_index`
- value：`struct bucket_ctx`
- 用途：保存 `group_cfs_rq` 与 bucket 统计状态

### 4.3 `group_ctx_map`

- 类型：`BPF_MAP_TYPE_HASH`
- key：`struct group_key { u32 cluster_id; u32 group_id; }`
- value：`struct group_ctx`
- 用途：组级持久化上下文与 `thread_cfs_rq`

### 4.4 `thread_ctx_map`

- 类型：`BPF_MAP_TYPE_TASK_STORAGE`
- key：`task_struct *`（由 task storage 机制管理）
- value：`struct thread_ctx`
- 用途：线程长期状态与线程到 cluster/group/bucket 映射

### 4.5 `cpu_run_state_map`

- 类型：`BPF_MAP_TYPE_ARRAY`
- key：`u32 cpu_id`
- value：`struct cpu_run_state`
- 用途：每 CPU 当前运行线程的暂态记账

## 5. 调度路径

### 5.1 enqueue

1. 选择 `home_cpu`，映射得到 `cluster_id`。
2. 计算 `bucket_id`。
3. 取得或创建 `group_ctx`。
4. 创建 thread_se，插入 `thread_cfs_rq`。
5. 同步生成 group_se，插入 bucket 的 `group_cfs_rq`。

### 5.2 dispatch

1. 根据当前 CPU 找到所属 cluster。
2. 在 cluster 内做 bucket 轮转，挑选非空 bucket。
3. 从 `group_cfs_rq` 取最小 `vruntime` 的 group_se。
4. 通过 group_key 找到对应 `group_ctx`。
5. 从 `thread_cfs_rq` 取最小 `vruntime` 的 thread_se。
6. 将 thread_se dispatch 到目标 CPU（非法则回退）。

### 5.3 stopping

1. 根据 `delta_ns * wmult` 折算并累加线程 `vruntime`。
2. 清理 `cpu_run_state_map` 对应槽位。
3. 若仍 runnable，则重新执行 enqueue。

## 6. 并发与锁

- `cluster_ctx.lock`：保护 bucket 轮转游标。
- `bucket_ctx.lock`：保护 `group_cfs_rq`。
- `group_ctx.lock`：保护 `thread_cfs_rq` 及组聚合字段。

实现保持分阶段操作，避免跨层嵌套持锁，提升 verifier 通过率与可维护性。

## 7. 当前未实现项

- QoS 驱动的真实 bucket 分类策略
- 更细粒度的 cluster 内选核策略
- cluster 间迁移策略
- 抢占判定与 kick 机制

当前版本目标是稳定层次结构与命名语义，为后续策略扩展提供基座。
