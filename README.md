# Per-Cluster Clutch Scheduler

基于 Linux `sched_ext` (eBPF) 的 per-cluster 分层调度器实现。

当前版本先落一个借鉴 Clutch 思路的三层骨架：

- 每个 cluster 有可配置数量的顶层 bucket
- 顶层 bucket 按配置的 DDL 做 EDF 选桶
- 默认值仿照 XNU clutch 顶层 root buckets：`FG/IN/DF/UT/BG`
- bucket 里放线程组
- 线程组里放线程
- 统一调度实体为 `clutch_se`
- bucket 维护 `group_cfs_rq`，group 维护 `thread_cfs_rq`
- 二层和三层目前都按最小 `vruntime` 做 CFS 风格排序

## 项目做了什么

1. 从“全局单队列”切到“per-cluster 分层队列”。
2. 固定 `cluster -> bucket -> group -> thread` 这条调度路径。
3. 用红黑树维护 bucket 内线程组、group 内线程。
4. 保留最简 `select_cpu`、dispatch 和 stopping 路径，保证程序可加载运行。

## 代码结构

- `src/clutch.bpf.c`：调度核心（enqueue、dispatch、stopping、抢占触发）。
- `src/loader.c`：用户态加载器，负责 open/load/attach/detach。
- `include/`：头文件和 `vmlinux.h`。
- `docs/ARCHITECTURE.md`：完整架构说明与关键公式。

## 环境要求

- Linux 内核支持 `sched_ext`（建议 6.12+，并启用 `CONFIG_SCHED_CLASS_EXT=y`）。
- `clang-17+`、`bpftool`、`libbpf` 相关开发依赖。
- 需要 root 权限加载调度器。

## 快速开始

```bash
# 1) 生成 vmlinux.h
make install-vmlinux

# 2) 编译
make

# 3) 运行调度器（前台）
sudo ./build/loader_clutch

# 默认 bucket 配置：
# 5 buckets, ddl = 0ns, 37.5ms, 75ms, 150ms, 250ms

# 4) 指定 bucket 数和每桶 DDL（ns）
sudo ./build/loader_clutch --nr-buckets=4 --bucket-ddl=1000000,2000000,4000000,8000000
```

停止方式：`Ctrl+C`。

## 调度流程速览

1. 线程入队时根据 `preferred_cpu` 找到所属 cluster，再由 `pid` 计算 bucket。
2. 线程实体 `thread_se` 先插入所属组的 `thread_cfs_rq`，再同步生成组实体 `group_se` 挂入 bucket 的 `group_cfs_rq`。
3. dispatch 时先在 cluster 的活跃 buckets 之间按 DDL 做 EDF 选桶，再从 `group_cfs_rq` 和 `thread_cfs_rq` 各做一次最小 `vruntime` 选择。
4. 线程停机时按运行时间更新 `vruntime`，若仍 runnable 则重新入队。

## 文档入口

- 架构说明：`docs/ARCHITECTURE.md`
- 输出示例：`output/`
