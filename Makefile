# EEVDF Scheduler Makefile
CLANG ?= clang-17
CC ?= gcc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 路径设置
KERNEL_SRC := /home/hustlhy/linux-6.12.57
LIBBPF_DIR := $(KERNEL_SRC)/tools/lib/bpf
VMLINUX := /sys/kernel/btf/vmlinux

# 目录结构
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include
TESTS_DIR := tests
SCRIPTS_DIR := scripts
CONFIGS_DIR := configs

# 主程序目标文件（Global EEVDF 调度器）
BPF_SRC := $(SRC_DIR)/global_eevdf.bpf.c
BPF_OBJ := $(BUILD_DIR)/global_eevdf.bpf.o
SKEL_H := $(BUILD_DIR)/global_eevdf.skel.h
USER_APP := $(BUILD_DIR)/loader_global_eevdf
SCHED_NAME := global_eevdf

USER_SRC := $(SRC_DIR)/loader.c

# 测试程序目标文件
TEST_BPF_OBJS := $(BUILD_DIR)/test_eevdf.bpf.o \
                 $(BUILD_DIR)/test_eevdf_new.bpf.o \
                 $(BUILD_DIR)/test_eevdf_simple.bpf.o

# kfunc 测试程序
TEST_KFUNCS_BPF := $(BUILD_DIR)/test_kfuncs.bpf.o
TEST_KFUNCS_SKEL := $(BUILD_DIR)/test_kfuncs.skel.h
TEST_KFUNCS_APP := $(BUILD_DIR)/test_kfuncs

# BPF 编译选项
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 \
              -I./$(INCLUDE_DIR)

# 用户态编译选项
USER_CFLAGS := -g -O2 -I./$(INCLUDE_DIR) -I./$(BUILD_DIR) \
               -DSKEL_PREFIX=$(SCHED_NAME) \
               -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include/uapi \
               -I$(LIBBPF_DIR)/include -I$(KERNEL_SRC)/tools/include/uapi
USER_LDFLAGS := $(LIBBPF_DIR)/libbpf.a -lelf -lz

.PHONY: all clean dirs test test-verify help install-vmlinux

# 默认目标（Global EEVDF 调度器）
all: dirs $(USER_APP)

# 帮助信息
help:
	@echo "EEVDF Scheduler Makefile"
	@echo ""
	@echo "可用目标:"
	@echo "  all              - 编译 Global EEVDF 调度器（默认）"
	@echo "  test             - 编译测试程序"
	@echo "  test-kfuncs      - 编译并生成 kfunc 测试程序"
	@echo "  test-verify      - 编译并验证测试程序"
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
	@echo "编译 BPF 程序 (global_eevdf)..."
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

# 测试程序编译规则
$(BUILD_DIR)/test_eevdf.bpf.o: $(TESTS_DIR)/test_eevdf.bpf.c | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_eevdf_new.bpf.o: $(TESTS_DIR)/test_eevdf_new.bpf.c | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_eevdf_simple.bpf.o: $(TESTS_DIR)/test_eevdf_simple.bpf.c | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# kfunc 测试程序编译规则
$(TEST_KFUNCS_BPF): $(TESTS_DIR)/test_kfuncs.bpf.c | dirs
	@echo "编译 kfunc 测试 BPF 程序..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(TEST_KFUNCS_SKEL): $(TEST_KFUNCS_BPF)
	@echo "生成 kfunc 测试 Skeleton..."
	$(KERNEL_SRC)/tools/bpf/bpftool/bpftool gen skeleton $(TEST_KFUNCS_BPF) > $(TEST_KFUNCS_SKEL)

$(TEST_KFUNCS_APP): $(TESTS_DIR)/test_kfuncs_loader.c $(TEST_KFUNCS_SKEL)
	@echo "编译 kfunc 测试用户态程序..."
	$(CC) -g -O2 -I./$(INCLUDE_DIR) -I./$(BUILD_DIR) \
		-I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include/uapi \
		-I$(LIBBPF_DIR)/include -I$(KERNEL_SRC)/tools/include/uapi \
		$(TESTS_DIR)/test_kfuncs_loader.c -o $(TEST_KFUNCS_APP) \
		$(USER_LDFLAGS)

# 编译测试程序
test: dirs $(TEST_BPF_OBJS)
	@echo "测试程序编译完成"

# 编译 kfunc 测试
test-kfuncs: dirs $(TEST_KFUNCS_APP)
	@echo "kfunc 测试程序编译完成"
	@echo "运行: sudo $(TEST_KFUNCS_APP)"

# 验证测试程序
test-verify: test
	@echo ""
	@echo "运行 BPF 程序验证..."
	bash $(SCRIPTS_DIR)/verify_bpf.sh

# 清理
clean:
	rm -rf $(BUILD_DIR)
