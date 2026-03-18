# Global EEVDF Scheduler

基于 Linux `sched_ext` (eBPF) 的全局 EEVDF 调度器实现。

项目目标是把 EEVDF 的核心语义在 BPF 环境里落地：

- eligible 判定：$ve \le V$
- 虚拟截止时间优先：最小 `vd` 先运行
- lag 保存与恢复：$vlag = V - vruntime$

## 项目做了什么

1. 用两棵全局红黑树管理任务。
2. 用加权统计实时推进系统虚拟时间 $V$。
3. 保留任务 `vlag`，保证睡眠/唤醒后的公平恢复。
4. 支持本地派发和跨 CPU 远程派发。

对应队列含义：

- `ready`：满足 $ve \le V$，可直接参与调度。
- `future`：暂不满足 eligible，等待 $V$ 推进后转入 `ready`。

## 代码结构

- `src/global_eevdf.bpf.c`：调度核心（enqueue、dispatch、stopping、抢占触发）。
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
sudo ./build/loader_global_eevdf
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

1. 任务入队时计算 `weight/wmult`、`ve/vd`，并按 $ve \le V$ 入 `ready/future`。
2. CPU 需要任务时，从 `ready` 取最小 `vd`；必要时先把 `future` 中已 eligible 的任务搬到 `ready`。
3. 任务停机时结算 `vruntime`，保存 `vlag`，若仍 runnable 则重新入队。

## 文档入口

- 架构与公式：`docs/ARCHITECTURE.md`
- 基准与分析脚本：`scripts/`
- 输出示例：`output/`
