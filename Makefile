# Clutch Scheduler Makefile
CLANG ?= clang-17
CC ?= gcc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 路径设置
KERNEL_SRC := /home/hustlhy/linux-6.12.57
LIBBPF_DIR := $(KERNEL_SRC)/tools/lib/bpf
LIBBPF_A := $(LIBBPF_DIR)/libbpf.a
VMLINUX := /sys/kernel/btf/vmlinux

# 目录结构
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
CONFIGS_DIR := configs

# 主程序目标文件（Per-cluster clutch 调度器）
BPF_SRC := $(SRC_DIR)/clutch.bpf.c
BPF_OBJ := $(BUILD_DIR)/clutch.bpf.o
SKEL_H := $(BUILD_DIR)/clutch.skel.h
USER_APP := $(BUILD_DIR)/loader_clutch
SCHED_NAME := clutch

USER_SRC := $(SRC_DIR)/loader.c

# BPF 编译选项
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 \
              -I./$(INCLUDE_DIR)

# 用户态编译选项
USER_CFLAGS := -g -O2 -I./$(INCLUDE_DIR) -I./$(BUILD_DIR) \
               -DSKEL_PREFIX=$(SCHED_NAME) \
               -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include/uapi \
               -I$(LIBBPF_DIR)/include -I$(KERNEL_SRC)/tools/include/uapi

ifeq ($(wildcard $(LIBBPF_A)),)
USER_LDFLAGS := -L$(LIBBPF_DIR) -Wl,-rpath,$(LIBBPF_DIR) -lbpf -lelf -lz
else
USER_LDFLAGS := $(LIBBPF_A) -lelf -lz
endif

.PHONY: all clean dirs help install-vmlinux

# 默认目标（Per-cluster clutch 调度器）
all: dirs $(USER_APP)

# 帮助信息
help:
	@echo "Clutch Scheduler Makefile"
	@echo ""
	@echo "可用目标:"
	@echo "  all              - 编译 per-cluster clutch 调度器（默认）"
	@echo "  install-vmlinux  - 生成 vmlinux.h 头文件"
	@echo "  clean            - 清理构建文件"
	@echo "  help             - 显示此帮助信息"

# 创建构建目录
dirs:
	@mkdir -p $(BUILD_DIR)

# 生成 vmlinux.h
install-vmlinux: dirs
	@echo "生成 vmlinux.h..."
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $(INCLUDE_DIR)/vmlinux.h

# 1. 编译主 BPF 程序
$(BPF_OBJ): $(BPF_SRC) | dirs
	@echo "编译 BPF 程序 (clutch)..."
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# 2. 生成 Skeleton
$(SKEL_H): $(BPF_OBJ)
	@echo "生成 Skeleton..."
	$(KERNEL_SRC)/tools/bpf/bpftool/bpftool gen skeleton $(BPF_OBJ) > $(SKEL_H)

# 3. 编译用户态 Loader
$(USER_APP): $(USER_SRC) $(SKEL_H)
	@echo "编译用户态程序..."
	$(CC) $(USER_CFLAGS) -DSKEL_H=\"$(notdir $(SKEL_H))\" \
		$(USER_SRC) -o $(USER_APP) $(USER_LDFLAGS)

# 清理
clean:
	rm -rf $(BUILD_DIR)
