#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>      /* [新增] 引入标准整数类型 */
#include <bpf/libbpf.h>

/* [关键修复] 为骨架文件和 loader 定义内核风格的类型别名 */
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

/* 必须在定义了 u32 之后再包含骨架文件 */
#include "eevdf.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv)
{
    struct eevdf_bpf *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase rlimit: %d\n", err);
        return 1;
    }

    skel = eevdf_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = eevdf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    if (skel->struct_ops.eevdf_ops) {
        skel->struct_ops.eevdf_ops->timeout_ms = 5000;
    }

    err = eevdf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully loaded Global EEVDF scheduler.\n");
    printf("  - Watchdog: 5000ms\n");
    printf("Press Ctrl+C to stop and detach.\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    eevdf_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}