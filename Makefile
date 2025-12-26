CLANG ?= clang
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 路径设置
KERNEL_SRC := /home/hustlhy/linux-6.12.57
LIBBPF_DIR := $(KERNEL_SRC)/tools/lib/bpf

# 目录结构
SRC_DIR := src
BUILD_DIR := build
INCLUDE_DIR := include

# 目标文件
BPF_SRC := $(SRC_DIR)/eevdf.bpf.c
USER_SRC := $(SRC_DIR)/loader.c
BPF_OBJ := $(BUILD_DIR)/eevdf.bpf.o
SKEL_H := $(BUILD_DIR)/eevdf.skel.h
USER_APP := $(BUILD_DIR)/loader

# BPF 编译选项
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -I./$(INCLUDE_DIR)

# 用户态编译选项
USER_CFLAGS := -g -O2 -I./$(INCLUDE_DIR) -I./$(BUILD_DIR) -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include/uapi -I$(LIBBPF_DIR)/include -I$(KERNEL_SRC)/tools/include/uapi
USER_LDFLAGS := $(LIBBPF_DIR)/libbpf.a -lelf -lz

.PHONY: all clean dirs

all: dirs $(USER_APP)

# 创建构建目录
dirs:
	@mkdir -p $(BUILD_DIR)

# 1. 编译 BPF 程序
$(BPF_OBJ): $(BPF_SRC) | dirs
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# 2. 生成 Skeleton
$(SKEL_H): $(BPF_OBJ)
	$(KERNEL_SRC)/tools/bpf/bpftool/bpftool gen skeleton $(BPF_OBJ) > $(SKEL_H)

# 3. 编译用户态 Loader
$(USER_APP): $(USER_SRC) $(SKEL_H)
	$(CC) $(USER_CFLAGS) $(USER_SRC) -o $(USER_APP) $(USER_LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)