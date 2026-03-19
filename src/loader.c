#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
#include <bpf/libbpf.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

#ifdef SKEL_H
#include SKEL_H
#else
#include "clutch.skel.h"
#endif

/* 根据 SKEL_PREFIX 定义正确的 skeleton 名称 */
/* 需要两层宏展开来正确处理 SKEL_PREFIX，因为 ## 会阻止参数展开 */
#define _SKEL_CONCAT_(x, y) x##y
#define _SKEL_CONCAT(x, y) _SKEL_CONCAT_(x, y)

/* 第一层：使用带参数的宏来强制 SKEL_PREFIX 展开后再连接 */
/* 注意：需要加 struct 关键字 */
#define SKEL_TYPE_X(x) struct _SKEL_CONCAT_(x, _bpf)
/* 第二层：传入 SKEL_PREFIX，使其先被展开 */
#define SKEL_TYPE SKEL_TYPE_X(SKEL_PREFIX)

/* 函数宏同理 */
#define SKEL_OPEN_X(x) _SKEL_CONCAT_(x, _bpf__open)()
#define SKEL_OPEN SKEL_OPEN_X(SKEL_PREFIX)

#define SKEL_LOAD_X(x, skel) _SKEL_CONCAT_(x, _bpf__load)(skel)
#define SKEL_LOAD(skel) SKEL_LOAD_X(SKEL_PREFIX, skel)

#define SKEL_ATTACH_X(x, skel) _SKEL_CONCAT_(x, _bpf__attach)(skel)
#define SKEL_ATTACH(skel) SKEL_ATTACH_X(SKEL_PREFIX, skel)

#define SKEL_DESTROY_X(x, skel) _SKEL_CONCAT_(x, _bpf__destroy)(skel)
#define SKEL_DESTROY(skel) SKEL_DESTROY_X(SKEL_PREFIX, skel)

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {};
    struct rlimit rlim_new = {};

    if (getrlimit(RLIMIT_MEMLOCK, &rlim))
        return 0;

    if (rlim.rlim_cur == RLIM_INFINITY)
        return 0;

    rlim_new.rlim_cur = rlim.rlim_max == RLIM_INFINITY ? RLIM_INFINITY : rlim.rlim_max;
    rlim_new.rlim_max = rlim.rlim_max;

    if (!setrlimit(RLIMIT_MEMLOCK, &rlim_new))
        return 0;

    return 0;
}

int main(int argc, char **argv)
{
    SKEL_TYPE *skel;
    int err;
    int nr_possible_cpus;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase rlimit: %d\n", err);
        return 1;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "This loader must be run as root (for example: sudo %s)\n",
                argv[0]);
        return 1;
    }

    skel = SKEL_OPEN;
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    nr_possible_cpus = libbpf_num_possible_cpus();
    if (nr_possible_cpus < 1)
        nr_possible_cpus = 1;

    if (skel->rodata) {
        skel->rodata->nr_cpu_ids = (u32)nr_possible_cpus;
        skel->rodata->cpus_per_cluster = 4;
    }

    err = SKEL_LOAD(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    if (skel->struct_ops.clutch_ops) {
        skel->struct_ops.clutch_ops->timeout_ms = 5000;
    }

    err = SKEL_ATTACH(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully loaded per-cluster clutch scheduler.\n");
    printf("  - Watchdog: 5000ms\n");
    printf("Press Ctrl+C to stop and detach.\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    SKEL_DESTROY(skel);
    return err < 0 ? -err : 0;
}
