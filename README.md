# EEVDF 调度器

基于 Linux 6.12+ sched_ext 框架的 **EEVDF (Earliest Eligible Virtual Deadline First)** 调度器 eBPF 实现。

实现了基于 sched_ext 的 EEVDF 选择逻辑、`vlag = V - vruntime` 唤醒补偿与唤醒抢占检查，并对 I/O 密集场景做了 kick 风暴抑制。

## 快速开始

### 1. 编译

```bash
make
```

### 2. 运行调度器

```bash
sudo ./build/loader
```

停止：按 `Ctrl+C`

### 3. 测试

**基础测试（ftrace）**：
```bash
sudo ./scripts/test.sh
```

**Perfetto 测试（推荐，可视化分析）**：
```bash
# 首次运行需要安装 Perfetto
./scripts/setup_perfetto.sh

# 运行测试
sudo ./scripts/test_perfetto.sh
```

**分析**：
```bash
./scripts/analyze.sh output/scheduler_trace.txt
```

分析脚本会输出“唤醒到运行延迟（近似）”指标，用于观察 I/O 唤醒响应；同时会统计 `prev_state=R` 的占比（这是“可运行态切出”占比，包含抢占/时间片到/让出等，不等同于纯粹的时间片用完）。

所有输出文件位于 `output/` 目录。

---

## 核心特性

- ✅ **完整的 EEVDF 算法**：基于 deadline 的公平调度
- ✅ **唤醒补偿机制**：使用 `vlag = V - vruntime` 恢复交互任务进度
- ✅ **权重动态变更**：自动处理 nice 值和 cgroup 权重变化
- ✅ **双红黑树设计**：合格/不合格树分离，高效任务选择
- ✅ **防饥饿保证**：lag clamp 机制确保公平性
- ✅ **唤醒抢占检查**：eligible 且更早 vd 时触发抢占（带粒度/限频）

详细算法说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 测试工具

### Ftrace 测试（快速验证）

```bash
sudo ./scripts/test.sh [选项]

选项:
  --cpu-only       CPU 密集型测试（默认）
  --mixed          混合负载（CPU + I/O）
  --io-only        I/O 密集型测试（频繁睡眠/唤醒）
  --duration N     测试时长（秒，默认10）
```

**输出**：`output/scheduler_trace.txt`

**分析**：
```bash
./scripts/analyze.sh output/scheduler_trace.txt
```

### Perfetto 测试（深度分析）

Perfetto 提供强大的可视化时间线和 SQL 查询功能。

**安装**：
```bash
./scripts/setup_perfetto.sh
```

**运行**：
```bash
sudo ./scripts/test_perfetto.sh [选项]

选项:
  --cpu-only       CPU 密集型测试（默认）
  --mixed          混合负载（CPU + I/O）
  --io-only        I/O 密集型测试（频繁睡眠/唤醒）
  --duration N     测试时长（秒，默认10）
```

**输出**：`output/eevdf_trace.perfetto-trace`

**分析**：
1. 访问 https://ui.perfetto.dev
2. 上传 `output/eevdf_trace.perfetto-trace`
3. 在时间线视图中分析调度行为

**命令行工具**：
```bash
# 转换为文本
./tools/perfetto/traceconv text output/eevdf_trace.perfetto-trace > output/trace.txt

# SQL 查询
./tools/perfetto/trace_processor_shell output/eevdf_trace.perfetto-trace
```

### 代码验证

验证调度器实现是否符合 EEVDF 规范：
```bash
./scripts/verify_implementation.sh
```

### 清理

紧急停止所有测试进程并清理系统：
```bash
sudo ./scripts/cleanup.sh
```

---

## 项目结构

```
my-eevdf-scheduler/
├── src/
│   ├── eevdf.bpf.c          # eBPF 调度器实现
│   └── loader.c             # 用户态加载器
├── scripts/
│   ├── test.sh              # Ftrace 测试
│   ├── test_perfetto.sh     # Perfetto 测试
│   ├── setup_perfetto.sh    # Perfetto 安装
│   ├── analyze.sh           # Trace 分析
│   ├── cleanup.sh           # 系统清理
│   └── verify_implementation.sh  # 代码验证
├── output/                  # 输出文件目录
│   ├── scheduler_trace.txt  # Ftrace 输出
│   └── eevdf_trace.perfetto-trace  # Perfetto 输出
├── docs/
│   └── ARCHITECTURE.md      # 详细架构文档
├── README.md                # 本文档
└── Makefile                 # 编译配置
```

---

## 核心算法

### 唤醒补偿（vlag）

本实现使用 `vlag` 在睡眠/唤醒之间保存任务相对进度，并在 `enqueue` 时恢复：

```
vlag = V - vruntime
```

- `vlag > 0`：任务落后于系统平均，唤醒时获得一定补偿
- `vlag < 0`：任务超前于系统平均，唤醒时受到一定惩罚
- `vlag = 0`：任务与系统同步

### 唤醒抢占检查（wakeup preempt）

新任务入队后，如果满足 `ve <= V` 且 `new_vd` 明显早于当前运行任务的 `curr_vd`，则向目标 CPU 发送 `SCX_KICK_PREEMPT` 触发重调度；为避免 I/O 密集场景 kick 风暴，增加了抢占粒度与每 CPU 限频。

### 双红黑树

- **Ready Tree**：存放 `ve ≤ V` 的任务，按 deadline 排序
- **Future Tree**：存放 `ve > V` 的任务，按就绪时间排序

详细说明见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 调试

**查看调度器状态**：
```bash
cat /sys/kernel/sched_ext/state
```

**查看内核日志**：
```bash
sudo dmesg | tail -20
```

**查看 BPF 日志**：
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## 性能调优

编辑 `src/eevdf.bpf.c` 中的参数：

```c
#define BASE_SLICE_NS   3000000ULL   // 基础时间片（3ms）
#define EEVDF_PERIOD_NS 12000000ULL  // 调度周期（12ms）
#define LAG_CLAMP_NS    (BASE_SLICE_NS * 3ULL)  // Lag clamp（9ms）
#define WAKEUP_PREEMPT_GRAN_NS       200000ULL  // 唤醒抢占粒度
#define WAKEUP_KICK_MIN_INTERVAL_NS  200000ULL  // 每 CPU kick 最小间隔
```

- **提高响应性**：减小 `BASE_SLICE_NS`（如 2ms）
- **减少切换开销**：增大 `BASE_SLICE_NS`（如 5ms）
- **调整 lag 容忍度**：修改 `LAG_CLAMP_NS` 倍数（1-5倍）

---

## 常见问题

### Q: 调度器无法启动

检查内核是否支持 sched_ext：
```bash
cat /sys/kernel/sched_ext/state
```

需要 Linux 6.12+ 且启用 `CONFIG_SCHED_CLASS_EXT`。

### Q: 测试卡住

紧急清理：
```bash
sudo ./scripts/cleanup.sh
```

### Q: Perfetto trace 文件无法在浏览器打开

文件权限问题。测试脚本会自动修复，或手动执行：
```bash
sudo chown $USER:$USER output/eevdf_trace.perfetto-trace
sudo chmod 644 output/eevdf_trace.perfetto-trace
```

---

## 系统要求

- Linux 6.12+ 内核（支持 sched_ext）
- clang/LLVM 工具链
- libbpf 开发库
- stress-ng（测试用）
- Python 3（Perfetto 解压用）

---

## 许可证

GPL v2

---

## 致谢

基于 Linux 内核的 sched_ext 框架和 EEVDF 调度算法。
