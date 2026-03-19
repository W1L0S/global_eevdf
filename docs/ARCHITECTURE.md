# Per-Cluster Clutch/CFS 架构说明

当前版本不再使用单一全局 `ready/future` 双树，而是先落一个借鉴 Clutch 思路的三层骨架。当前二层和三层都先按 CFS 风格的 `vruntime` 排序，重点是把层次、节点关系和 `per-cluster` 状态固定下来，后续再逐步补 bucket 分类、选核和抢占。

## 1. 设计目标

- 从“全局单队列”切到“per-cluster 分层队列”。
- 先用最小 `vruntime` 驱动二层和三层排序。
- 第一阶段先把整体容器关系和调度路径固定下来。
- `select_cpu`、复杂 cluster 放置、抢占逻辑暂时继续保持最简路径。

## 2. 三层结构

### 2.1 第一层：cluster 顶层 bucket

`cluster_ctxs` 是一个 ARRAY map，每个 cluster 对应一个轻量的 `struct cluster_ctx`，当前只保存 bucket 轮转游标。

真正的 bucket 容器放在独立的 `bucket_ctxs` ARRAY map 里。每个 cluster 里仍然有两个顶层 bucket：

- `buckets[0]`
- `buckets[1]`

目前 bucket 只是承载线程组的容器，还没有真实的 Clutch bucket 分类策略。当前实现先用 `tgid & 1` 把线程组稳定地映射到两个桶里，后续可以替换成交互性、负载等级、QoS 或其他策略。

### 2.2 第二层：线程组节点

第二层现在拆成两个对象：

- `struct group_ref`
  作为 bucket 内线程组红黑树节点，是线程组状态的排序快照。
- `struct group_slot`
  作为 `(cluster_id, tgid)` 对应的持久化状态，内部保存该线程组下的线程红黑树。

`group_nodes` 这个 HASH map 按 `(cluster_id, tgid)` 保存 `group_slot`。bucket 内真正参与二层排序的是 `group_ref` 快照，而第三层线程树放在对应的 `group_slot` 里。

### 2.3 第三层：线程节点

第三层节点使用 `struct thread_node`，语义是“线程节点”：

- `pid` / `tgid` 表示线程身份
- `dispatch_cpu` 记录当前这个线程的暂定 home CPU

线程节点是短生命周期对象：enqueue 时创建，dispatch 取出后释放。

## 3. 关键数据结构

### 3.1 `struct group_ref`

二层 bucket 内线程组节点包含：

- `rb_node`
  作为 bucket 内线程组红黑树节点。
- `tgid / cluster_id / bucket_id`
  标记所属线程组与当前 bucket。
- `nr_children / dispatch_cpu / vruntime / seq`
  缓存当前线程组的关键调度字段和快照版本。

### 3.2 `struct group_slot`

线程组持久化状态包含：

- `children`
  线程组内部线程树，元素类型为 `thread_node`。
- `lock`
  保护组内线程红黑树。
- `tgid / cluster_id / bucket_id`
  标记所属线程组与 cluster / bucket。
- `nr_children / dispatch_cpu / vruntime / seq`
  记录当前线程组的聚合调度状态和当前版本。

### 3.3 `struct thread_node`

三层线程节点包含：

- `rb_node`
  作为 group 内线程红黑树节点。
- `pid / tgid`
  标记线程身份。
- `cluster_id / bucket_id / dispatch_cpu`
  标记所属 cluster / bucket 与暂定目标 CPU。
- `vruntime / wmult / slice_ns`
  当前排序直接使用 `vruntime`，`wmult` 用于运行后折算时间，`slice_ns` 用于 dispatch 时给时间片。

### 3.4 `struct cluster_ctx`

每个 cluster 拥有：

- `next_bucket`
  dispatch 时用于在两个 bucket 之间轮转起点。

### 3.5 `struct clutch_bucket`

每个 bucket 单独作为 `bucket_ctxs` 的 value，包含：

- `groups`
  顶层线程组快照红黑树。
- `lock`
  保护 bucket 红黑树。
- `nr_groups`
  当前 bucket 内线程组快照数量。

### 3.6 `task_ctx_stor`

任务长期状态仍然放在 TASK_STORAGE：

- `vruntime`
- `last_run_ns`
- `cluster_id / bucket_id / home_cpu`

### 3.7 `cpu_run_account`

当前版本保留了每 CPU 的运行态记录，但语义简化为：

- 当前任务的 `wmult`
- 所属 cluster / bucket
- `home_cpu`

它只用于 `stopping` 时把运行时间折算回 `vruntime`。

## 4. 当前调度路径

### 4.1 enqueue

入队时执行：

1. 根据任务允许 CPU 集和当前 CPU，挑一个临时 `home_cpu`。
2. 由 `home_cpu` 映射出 `cluster_id`。
3. 由 `tgid & 1` 得到 `bucket_id`。
4. 创建三层线程节点。
5. 取出或创建对应的线程组节点。
6. 把线程节点按 `vruntime` 插入线程组内部的红黑树。
7. 线程组节点按当前最小线程的 `vruntime` 挂到所属 bucket 的红黑树。

因此，入队路径现在遵循：

`cluster -> bucket -> thread-group -> thread`

### 4.2 dispatch

派发时执行：

1. 根据当前 CPU 找到所属 cluster。
2. 从两个顶层 bucket 中轮流挑一个非空 bucket。
3. 从该 bucket 的红黑树取出 `vruntime` 最小的线程组节点。
4. 从线程组节点内部的红黑树取出 `vruntime` 最小的线程节点。
5. 若线程组还有剩余线程，则按新的最小线程 `vruntime` 重新挂回 bucket 红黑树。
6. 将线程派发到它记录的 `home_cpu`，若不合法则回退到当前 CPU。

这一版 dispatch 的顶层仍然只是“两桶轮转”，但二层和三层已经改成单棵红黑树的 CFS 风格选择：

- bucket 之间做简单轮转
- bucket 内线程组按最小 `vruntime` 选择
- 线程组内线程按最小 `vruntime` 选择

### 4.3 stopping

任务停止运行时：

1. 用 `delta_ns * wmult` 更新 `vruntime`。
2. 清理当前 CPU 的运行态记录。
3. 如果任务仍 runnable，则重新走一次 enqueue，把它重新挂回三层结构。

## 5. 当前没有实现的部分

这次重构明确没有实现下面这些策略：

- 第一层 bucket 的真实分类逻辑
- cluster 内更精细的 CPU 选择
- cluster 间迁移策略
- 抢占判断和 kick 逻辑

换句话说，这个版本的目标是先让结构稳定，而不是让策略完整。

## 6. 并发策略

为了满足 BPF `rbtree` 的锁约束，当前用了三类锁：

- `cluster_ctx.lock`
  保护 cluster 级别的 cursor 和 group stash 安装过程。
- `clutch_bucket.lock`
  保护顶层 bucket 红黑树。
- `group_slot.lock`
  保护单个线程组节点内部的线程红黑树。

实现上避免了嵌套持锁，所有跨层操作都拆成分阶段处理：

- 先改 group 内部线程树
- 再按需要把 group 挂回 bucket 树

这样虽然现在不是最强一致的实现，但更容易通过 BPF verifier，也更适合做第一阶段架构重构。

## 7. 后续扩展点

后面如果继续往更完整的 Clutch 策略推进，建议按这个顺序补：

1. 把 `bucket_id` 从 `tgid & 1` 替换成真实 bucket 分类。
2. 在二层和三层分别补上你最终想要的 group/thread 选择逻辑。
3. 再决定 group key 是直接用最小 thread `vruntime`，还是用更完整的 group 聚合指标。
4. 用真实拓扑替换当前 `cpus_per_cluster` 的静态 cluster 划分。
5. 再补 cluster 内选核和抢占。

这样可以保证每一步都只改一层策略，不需要再动三层骨架本身。
