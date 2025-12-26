#!/bin/bash
# Perfetto 安装和配置脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_ROOT/tools"
PERFETTO_DIR="$TOOLS_DIR/perfetto"

echo "========================================"
echo "Perfetto 安装和配置"
echo "========================================"

# 创建工具目录
mkdir -p "$TOOLS_DIR"
mkdir -p "$PERFETTO_DIR"

# 检测架构
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    PERFETTO_ARCH="x86_64"
elif [ "$ARCH" = "aarch64" ]; then
    PERFETTO_ARCH="aarch64"
else
    echo "错误：不支持的架构 $ARCH"
    exit 1
fi

echo ""
echo "[1/4] 下载 Perfetto 工具..."
cd "$PERFETTO_DIR"

# 使用 GitHub releases 下载最新的 Perfetto
if [ ! -f "perfetto" ]; then
    echo "  - 获取最新版本信息..."
    LATEST_URL=$(curl -sL https://api.github.com/repos/google/perfetto/releases/latest | \
                 grep "browser_download_url.*linux-amd64.zip" | \
                 cut -d '"' -f 4)

    if [ -z "$LATEST_URL" ]; then
        echo "  ✗ 无法获取下载链接"
        exit 1
    fi

    echo "  - 下载 Perfetto ($LATEST_URL)..."
    curl -L "$LATEST_URL" -o perfetto.zip

    # 验证下载
    if [ ! -f "perfetto.zip" ] || [ $(stat -c%s "perfetto.zip") -lt 100000 ]; then
        echo "  ✗ 下载失败"
        rm -f perfetto.zip
        exit 1
    fi

    echo "  - 解压文件..."
    # 优先使用 unzip，如果没有则使用 Python
    if command -v unzip &> /dev/null; then
        unzip -q perfetto.zip
    elif command -v python3 &> /dev/null; then
        python3 << 'PYEOF'
import zipfile
with zipfile.ZipFile('perfetto.zip', 'r') as zip_ref:
    zip_ref.extractall('.')
PYEOF
    else
        echo "  ✗ 需要 unzip 或 python3 来解压文件"
        echo "  请运行: sudo apt-get install unzip"
        rm -f perfetto.zip
        exit 1
    fi

    rm perfetto.zip

    # 移动文件到当前目录
    if [ -d "linux-amd64" ]; then
        mv linux-amd64/* .
        rmdir linux-amd64
    fi

    # 设置执行权限
    chmod +x perfetto traced traced_probes tracebox traceconv trace_processor_shell 2>/dev/null || true

    if [ -f "perfetto" ]; then
        SIZE=$(stat -c%s "perfetto")
        echo "  ✓ Perfetto 安装完成 ($(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo \"${SIZE}B\"))"
    else
        echo "  ✗ 解压后未找到 perfetto 文件"
        ls -la
        exit 1
    fi
else
    echo "  ✓ perfetto 已存在"
fi

echo ""
echo "[2/4] 验证工具..."
./perfetto --version || echo "  ⚠ perfetto 版本检查失败"

echo ""
echo "[3/4] 创建配置文件..."

# 创建 Perfetto 配置文件（用于调度器跟踪）
cat > "$PROJECT_ROOT/perfetto_config.pbtx" << 'EOF'
# Perfetto 配置文件 - EEVDF 调度器跟踪
#
# 功能说明：
# 1. 捕获调度事件（sched_switch, sched_wakeup 等）
# 2. 捕获 CPU 频率和空闲状态
# 3. 捕获进程统计信息
# 4. 捕获 BPF 程序的 printk 输出

buffers {
  size_kb: 65536
  fill_policy: RING_BUFFER
}

buffers {
  size_kb: 2048
  fill_policy: RING_BUFFER
}

# 调度事件数据源
data_sources {
  config {
    name: "linux.ftrace"
    target_buffer: 0
    ftrace_config {
      # 核心调度事件
      ftrace_events: "sched/sched_switch"
      ftrace_events: "sched/sched_wakeup"
      ftrace_events: "sched/sched_wakeup_new"
      ftrace_events: "sched/sched_process_exit"
      ftrace_events: "sched/sched_process_fork"

      # CPU 空闲和频率
      ftrace_events: "power/cpu_idle"
      ftrace_events: "power/cpu_frequency"

      # sched_ext 相关事件
      ftrace_events: "sched_ext/sched_ext_dump"

      # 增大缓冲区
      buffer_size_kb: 16384
      drain_period_ms: 250
    }
  }
}

# 进程信息数据源
data_sources {
  config {
    name: "linux.process_stats"
    target_buffer: 1
    process_stats_config {
      scan_all_processes_on_start: true
      proc_stats_poll_ms: 1000
    }
  }
}

# 系统信息
data_sources {
  config {
    name: "linux.sys_stats"
    target_buffer: 1
    sys_stats_config {
      stat_period_ms: 1000
      stat_counters: STAT_CPU_TIMES
      stat_counters: STAT_FORK_COUNT
    }
  }
}

# 持续时间（默认30秒，可通过 -t 参数覆盖）
duration_ms: 30000

# 写入文件模式
write_into_file: true
file_write_period_ms: 2000
flush_period_ms: 5000
EOF

echo "  ✓ 配置文件已创建: $PROJECT_ROOT/perfetto_config.pbtx"

echo ""
echo "========================================"
echo "安装完成！"
echo "========================================"
echo ""
echo "工具位置:"
echo "  - Tracebox: $PERFETTO_DIR/tracebox"
echo "  - 配置文件: $PROJECT_ROOT/perfetto_config.pbtx"
echo ""
echo "使用方法:"
echo "  1. 运行 Perfetto 测试:"
echo "     sudo ./scripts/test_perfetto.sh"
echo ""
echo "  2. 查看 trace 文件:"
echo "     上传到 https://ui.perfetto.dev"
echo "     或使用本地工具查看"
echo "========================================"
