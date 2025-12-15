CLANG ?= clang
CC ?= gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# 路径设置 (指向你的内核源码)
KERNEL_SRC := /home/hustlhy/linux-6.12.57
LIBBPF_DIR := $(KERNEL_SRC)/tools/lib/bpf

# 目标文件
BPF_OBJ := eevdf.bpf.o
USER_APP := loader

# BPF 编译选项
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -mcpu=v3 -I./include

# 用户态编译选项
# -L 指定库路径, -l 指定库名, -z noexecstack 是安全选项
# 把内核树里的 libbpf 头文件放在最前，避免误用系统的 /usr/include/bpf/libbpf.h
USER_CFLAGS := -g -O2 -I./include -I$(LIBBPF_DIR) -I$(LIBBPF_DIR)/include/uapi -I$(LIBBPF_DIR)/include -I$(KERNEL_SRC)/tools/include/uapi
USER_LDFLAGS := $(LIBBPF_DIR)/libbpf.a -lelf -lz

all: $(BPF_OBJ) $(USER_APP)

# 1. 编译 BPF 程序
$(BPF_OBJ): eevdf.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c eevdf.bpf.c -o $(BPF_OBJ)

# 2. 生成 Skeleton (如果 .o 变了，重新生成 .h)
eevdf.skel.h: $(BPF_OBJ)
	$(KERNEL_SRC)/tools/bpf/bpftool/bpftool gen skeleton $(BPF_OBJ) > eevdf.skel.h

# 3. 编译用户态 Loader
# loader.c 依赖 eevdf.skel.h
$(USER_APP): loader.c eevdf.skel.h
	$(CC) $(USER_CFLAGS) loader.c -o $(USER_APP) $(USER_LDFLAGS)

clean:
	rm -f *.o *.skel.h $(USER_APP)