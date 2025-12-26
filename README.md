# EEVDF 全局队列调度器

基于 Linux 6.12.57 sched_ext 框架的 **EEVDF (Earliest Eligible Virtual Deadline First)** 调度器，使用 eBPF 技术实现。完整实现了 Linux 内核 EEVDF 规范的 lag 补偿机制和虚拟时间管理系统。

## 核心特性

- ✅ **完整的 EEVDF 算法**：基于 deadline 的公平调度，符合 Linux 内核规范
- ✅ **Lag 补偿机制**：保存任务的 lag 状态，为交互式任务提供延迟补偿
- ✅ **权重动态变更**：自动检测并处理 nice 值和 cgroup 权重变化
- ✅ **高效虚拟时间计算**：使用乘倒数代替除法，优化 BPF 性能
- ✅ **双红黑树设计**：合格/不合格树分离，高效任务选择
- ✅ **防饥饿保证**：lag clamp 机制确保任务公平性

---

## 快速开始

### 1. 系统要求

- Linux 6.12+ 内核（支持 sched_ext）
- clang/LLVM 工具链
- libbpf 开发库
- stress-ng（可选，用于测试）

### 2. 编译

```bash
make
```

编译输出：
- `build/eevdf.bpf.o` - eBPF 字节码 (~880KB)
- `build/eevdf.skel.h` - 生成的骨架头文件
- `build/loader` - 用户态加载器

### 3. 运行调度器

```bash
sudo ./build/loader
```

**停止调度器**：按 `Ctrl+C` 或在另一终端运行：
```bash
sudo pkill loader
```

### 4. 检查状态

```bash
# 查看调度器状态
cat /sys/kernel/sched_ext/state

# 查看内核日志
sudo dmesg | tail -20
```

---

## 测试与验证

### 代码验证脚本

验证调度器实现是否符合 EEVDF 规范：

```bash
bash scripts/verify_implementation.sh
```

**验证项目**：
- ✓ 编译产物检查（BPF 对象、Loader）
- ✓ Lag clamp 配置（±3 倍 base_slice）
- ✓ 乘倒数计算实现
- ✓ EEVDF 公式 (4), (5), (6) 实现
- ✓ task_ctx 结构完整性
- ✓ 权重变更检测机制
- ✓ 系统 sched_ext 支持

**示例输出**：
```
=========================================
EEVDF Lag 补偿机制 - 代码验证
=========================================

1. 检查编译产物...
   ✓ BPF 对象: build/eevdf.bpf.o (883792 bytes)
   ✓ Loader: build/loader (2714232 bytes)

2. 验证关键常量定义...
   ✓ LAG_CLAMP_NS 已定义
   ✓ Clamp 为 3 倍 base_slice

...

所有核心功能已实现：
  ✓ Lag 保存和恢复机制
  ✓ 3 倍 base_slice 的 lag clamp
  ✓ 乘倒数计算 (避免有符号除法)
  ✓ EEVDF 公式 (4), (5), (6) 实现
  ✓ 权重变更自动处理
=========================================
```

### 主测试脚本

运行完整的调度器压力测试：

```bash
sudo ./scripts/test.sh
```

**功能**：
- 启动调度器
- 使用 ftrace 收集调度事件
- 运行 CPU 压力测试（stress-ng）
- 自动分析调度行为

**选项**：
```bash
# 仅运行 CPU 测试（推荐）
sudo ./scripts/test.sh --cpu-only

# 运行混合负载测试（CPU + I/O）
sudo ./scripts/test.sh --mixed

# 自定义测试时长（秒）
sudo ./scripts/test.sh --duration 20
```

**输出文件**：
- `scheduler_trace.txt` - ftrace 原始数据
- 控制台输出测试统计信息

### 分析脚本

分析调度器行为和性能指标：

```bash
./scripts/analyze.sh scheduler_trace.txt
```

**输出指标**：
- 上下文切换统计
- 时间片轮转验证
- 任务调度次数
- CPU 负载分布
- 运行时长分析

**示例输出**：
```
======================================
时间片轮转分析
======================================
R状态切换（时间片用完）: 22 次
D状态切换（I/O等待）: 56 次
时间片用完的占比: 25.8%

✓ 时间片轮转机制工作正常！
```

### 清理脚本

紧急清理系统状态：

```bash
sudo ./scripts/cleanup.sh
```

**功能**：
- 强制停止所有 stress-ng 和 loader 进程
- 禁用调度器
- 清理 ftrace 设置
- 检查残留进程

**使用场景**：
- 测试卡住时紧急清理
- 调度器异常时恢复系统

---

## 项目结构

```
my-eevdf-scheduler/
├── src/
│   ├── eevdf.bpf.c           # eBPF 调度器核心实现
│   └── loader.c              # 用户态加载器
├── build/                    # 编译输出（自动生成）
│   ├── eevdf.bpf.o          # BPF 字节码
│   ├── eevdf.skel.h         # 骨架头文件
│   └── loader               # 加载器可执行文件
├── scripts/                  # 测试和工具脚本
│   ├── test.sh              # 主测试脚本
│   ├── analyze.sh           # Trace 分析脚本
│   ├── cleanup.sh           # 清理脚本
│   └── verify_implementation.sh  # 代码验证脚本
├── docs/
│   └── ARCHITECTURE.md      # 架构与实现详细文档
├── README.md                # 本文档
├── Makefile                 # 编译配置
└── .gitignore
```

---

## 核心算法详解

### Lag 补偿机制

调度器实现了完整的 lag 补偿系统，符合 Linux 内核 EEVDF 规范：

#### 1. Lag 定义
```
lag = vruntime - V
```
- `lag < 0`：任务落后，应获得补偿（更高优先级）
- `lag > 0`：任务超前，应降低优先级
- `lag = 0`：任务与系统虚拟时间同步

#### 2. EEVDF 公式实现

**公式 (4) - 任务离开竞争**：
```
V(t) = V(t) + lag_j(t) / Σw_i
```
在 `stopping` 回调中计算并保存 lag，更新系统虚拟时间 V。

**公式 (5) - 任务加入竞争**：
```
V(t) = V(t) - lag_j(t) / (Σw_i + w_j)
```
在 `enqueue` 回调中恢复 lag，调整 V，让落后任务获得补偿。

**公式 (6) - 权重变更**：
```
V(t) = V(t) + lag_j/(Σw_i - w_j) - lag_j/(Σw_i - w_j + w_j')
```
自动检测权重变更（nice 值或 cgroup 权重变化），平滑调整虚拟时间。

#### 3. Lag Clamp

限制 lag 到 `±3 * base_slice`（默认 ±9ms）：
- 防止极端 lag 值破坏调度公平性
- 平衡交互式任务的响应性和 CPU 密集型任务的公平性
- 符合 Linux 内核默认配置

#### 4. 乘倒数优化

使用乘倒数代替除法计算 `lag / weight`：
```c
inv_weight = (1ULL << 32) / total_weight
delta = (abs_lag * inv_weight) >> 32
```
- 避免 BPF 不支持的有符号除法
- 提高计算效率
- 更接近 Linux 内核实现

### 虚拟时间系统

**系统虚拟时间 V**：
```
V = base_v + (avg_vruntime_sum + run_avg_vruntime_sum) / (avg_load + run_avg_load)
```
表示系统中所有任务的平均虚拟运行时间。

**任务虚拟运行时间**：
```
delta_v = (实际运行时间 * NICE_0_LOAD * wmult) >> 32
vruntime += delta_v
```
高权重任务 vruntime 增长慢，低权重任务增长快，实现公平性。

### 双红黑树设计

**合格树 (Ready Tree)**：
- 存放 `ve ≤ V` 的任务
- 按 `vd`（deadline）排序
- 最左节点 = 最早 deadline = 下一个被调度的任务

**不合格树 (Future Tree)**：
- 存放 `ve > V` 的任务
- 按 `ve`（就绪时间）排序
- 最左节点 = 最早合格的任务

---

## 开发指南

### 修改代码

1. 编辑 `src/eevdf.bpf.c` 或 `src/loader.c`
2. 重新编译：
   ```bash
   make clean && make
   ```
3. 验证实现：
   ```bash
   bash scripts/verify_implementation.sh
   ```
4. 测试：
   ```bash
   sudo ./scripts/test.sh --cpu-only
   ```

### 调试

**查看 BPF 日志**：
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**查看调度器信息**：
```bash
sudo bpftool prog list | grep sched
```

**检查 Lag 补偿工作状态**：
调度器在 `enqueue` 和 `stopping` 中使用 `bpf_printk` 输出关键信息。

### 性能调优

编辑 `src/eevdf.bpf.c` 中的参数：

```c
#define BASE_SLICE_NS   3000000ULL   // 基础时间片（3ms）
#define MIN_SLICE_NS    1000000ULL   // 最小时间片（1ms）
#define EEVDF_PERIOD_NS 12000000ULL  // 调度周期（12ms）
#define LAG_CLAMP_NS    (BASE_SLICE_NS * 3ULL)  // Lag clamp（9ms）
```

**调优建议**：
- **提高响应性**：减小 `BASE_SLICE_NS`（如 2ms）
- **减少切换开销**：增大 `BASE_SLICE_NS`（如 5ms）
- **调整 lag 容忍度**：修改 `LAG_CLAMP_NS` 倍数（1-5倍）
- **调整调度周期**：修改 `EEVDF_PERIOD_NS`（推荐 10-20ms）

---

## 常见问题

### Q1: 调度器无法启动

**检查**：
```bash
# 检查内核是否支持 sched_ext
cat /sys/kernel/sched_ext/state

# 如果文件不存在，说明内核不支持
```

**解决**：需要 Linux 6.12+ 内核并启用 CONFIG_SCHED_CLASS_EXT

### Q2: 测试卡住不动

**紧急处理**：
```bash
# 新开终端
sudo ./scripts/cleanup.sh

# 如果仍卡住，强制停止
sudo pkill -9 loader stress-ng
```

**预防措施**：
- 使用 `--cpu-only` 模式测试（更稳定）
- 避免在生产环境运行

### Q3: 看到 "D state" 进程

**说明**：D状态（不可中断睡眠）是正常的，表示进程在等待I/O

**判断是否异常**：
- 如果进程能继续运行 → 正常
- 如果长时间卡住（>30秒）→ 可能异常

**处理**：
```bash
# 查看 D 状态进程
ps aux | awk '$8 ~ /D/'

# 如果是 loader 或 stress-ng，运行清理脚本
sudo ./scripts/cleanup.sh
```

### Q4: 验证脚本报错

**检查编译状态**：
```bash
make clean && make
bash scripts/verify_implementation.sh
```

**常见问题**：
- 缺少编译产物 → 运行 `make`
- LAG_CLAMP_NS 未定义 → 检查代码版本
- sched_ext 不支持 → 检查内核版本

---

## 技术细节

详细的架构设计、算法原理、数据结构、lag 补偿机制实现等技术文档，请参阅：

📖 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## 与 Linux 内核的对比

| 特性 | Linux 内核 EEVDF | 本实现 | 状态 |
|------|----------------|--------|------|
| Lag 保存/恢复 | ✓ | ✓ | 完全符合 |
| Lag clamp (3x base_slice) | ✓ | ✓ | 完全符合 |
| 乘倒数计算 | ✓ | ✓ | 完全符合 |
| 权重变更处理（公式6） | ✓ | ✓ | 完全符合 |
| V 更新公式 (4, 5) | ✓ | ✓ | 完全符合 |
| 双红黑树 | ✓ | ✓ | 完全符合 |
| 防饥饿机制 | ✓ | ✓ | 完全符合 |

---

## Git 工作流

### 本地开发

```bash
# 查看更改
git status

# 提交更改
git add .
git commit -m "描述你的更改"

# 查看提交历史
git log --oneline
```

### 推送到 GitHub

```bash
# 添加远程仓库（首次）
git remote add origin <your-github-repo-url>

# 推送
git push -u origin main
```

---

## 许可证

GPL v2

---

## 致谢

基于 Linux 内核的 sched_ext 框架和 EEVDF 调度算法实现。完整实现了 EEVDF 论文中的 lag 补偿机制和虚拟时间管理系统。
