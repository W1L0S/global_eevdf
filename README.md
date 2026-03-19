# Per-Cluster Clutch Scheduler

基于 Linux `sched_ext` (eBPF) 的 per-cluster 分层调度器实现。

当前版本先落一个借鉴 Clutch 思路的三层骨架：

- 每个 cluster 有 2 个顶层 bucket
- bucket 里放线程组
- 线程组里放线程
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
- `tests/`：BPF 与 kfunc 相关测试代码。
- `scripts/`：验证、压测、跟踪脚本。
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
```

停止方式：`Ctrl+C`。

## 常用命令

```bash
# 编译测试程序
make test

# 构建 kfunc 测试
make test-kfuncs

# 执行基础验证脚本
make test-verify
```

## 调度流程速览

1. 任务入队时根据 `home_cpu` 找到所属 cluster，再由 `tgid & 1` 进入其中一个 bucket。
2. 线程先插入所属线程组的红黑树，线程组再按当前最小 `vruntime` 挂进 bucket 红黑树。
3. dispatch 时先在 cluster 的两个 bucket 之间轮转，再逐层取最小 `vruntime` 的 group 和 thread。
4. 任务停机时按运行时间更新 `vruntime`，若仍 runnable 则重新入队。

## 文档入口

- 架构说明：`docs/ARCHITECTURE.md`
- 基准与分析脚本：`scripts/`
- 输出示例：`output/`
