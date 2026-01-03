# EEVDF 调度器（sched_ext）

基于 Linux 6.12+ 的 sched_ext 框架，实现 EEVDF (Earliest Eligible Virtual Deadline First) 调度器的 eBPF 版本，包含唤醒补偿（vlag）与唤醒抢占（带粒度/限频）。

算法与实现细节见 [ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 快速开始

### 0) 依赖与前置条件

- Linux 6.12+ 且启用 `CONFIG_SCHED_CLASS_EXT`
- clang/LLVM、gcc、libelf、zlib、libbpf（来自你的内核源码树）
- stress-ng（用于压测）

注意：默认 Makefile 将 `KERNEL_SRC` 指向本机内核源码路径，必要时先修改 [Makefile](Makefile) 的 `KERNEL_SRC`。

### 1) 编译

```bash
make
```

### 2) 运行

```bash
sudo ./build/loader
```

停止：按 `Ctrl+C`

### 3) 一键测试

Ftrace（文本 trace，快速验证）：

```bash
sudo ./scripts/test.sh --cpu-only --duration 10
sudo ./scripts/test.sh --mixed --duration 10
sudo ./scripts/test.sh --io-only --duration 10
```

输出：`output/scheduler_trace.txt`，分析：

```bash
./scripts/analyze.sh output/scheduler_trace.txt
```

Perfetto（可视化，推荐；使用 tracebox 采集）：

```bash
./scripts/setup_perfetto.sh
sudo ./scripts/test_perfetto.sh --io-only --duration 10
```

输出：`output/eevdf_trace.perfetto-trace`，打开 https://ui.perfetto.dev 上传查看。

## 目录结构

```
my-eevdf-scheduler/
├── src/                       # eBPF 与用户态 loader
├── scripts/                   # 测试/分析/清理脚本
├── configs/perfetto_config.pbtx
├── tools/perfetto/            # perfetto/tracebox 等工具
├── build/                     # 编译产物
└── output/                    # trace 输出
```

## 常用命令

```bash
cat /sys/kernel/sched_ext/state
sudo dmesg | tail -20
sudo ./scripts/cleanup.sh
./scripts/verify_implementation.sh
```

## 常见问题

- 调度器未启用：检查 `/sys/kernel/sched_ext/state` 与内核配置。
- Perfetto trace 无法打开：通常是权限问题，脚本会尝试修复；也可手动 `chown/chmod output/eevdf_trace.perfetto-trace`。

## 许可证

GPL v2
