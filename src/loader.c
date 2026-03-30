#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <bpf/libbpf.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

#define MAX_CPUS 256
#define CORES_PER_CLUSTER 5

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

struct cluster_topology {
    u32 cpu_to_cluster[MAX_CPUS];
    u32 cluster_sizes[MAX_CPUS];
    s32 raw_cluster_ids[MAX_CPUS];
    u32 nr_clusters;
    bool ready;
    const char *source_name;
};

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

static int read_topology_id(u32 cpu, const char *name, s32 *value)
{
    char path[128];
    FILE *fp;

    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%u/topology/%s", cpu, name);

    fp = fopen(path, "r");
    if (!fp)
        return -errno;

    if (fscanf(fp, "%d", value) != 1) {
        fclose(fp);
        return -EINVAL;
    }

    fclose(fp);
    return 0;
}

static int build_cluster_topology(struct cluster_topology *topo,
                                  const s32 *ids, u32 nr_cpus,
                                  const char *source_name)
{
    u32 cpu;

    *topo = (struct cluster_topology){};

    for (cpu = 0; cpu < nr_cpus; cpu++) {
        u32 cluster;

        for (cluster = 0; cluster < topo->nr_clusters; cluster++) {
            if (topo->raw_cluster_ids[cluster] == ids[cpu])
                break;
        }

        if (cluster == topo->nr_clusters) {
            if (topo->nr_clusters >= MAX_CPUS)
                return -E2BIG;

            topo->raw_cluster_ids[topo->nr_clusters] = ids[cpu];
            cluster = topo->nr_clusters++;
        }

        topo->cpu_to_cluster[cpu] = cluster;
        topo->cluster_sizes[cluster]++;
    }

    topo->ready = topo->nr_clusters > 0;
    topo->source_name = source_name;
    return topo->ready ? 0 : -ENOENT;
}

static int detect_cluster_topology(struct cluster_topology *topo, int nr_possible_cpus)
{
    u32 nr_cpus = nr_possible_cpus > MAX_CPUS ? MAX_CPUS : (u32)nr_possible_cpus;
    s32 core_ids[MAX_CPUS];
    s32 grouped_core_ids[MAX_CPUS];
    s32 uniq_core_ids[MAX_CPUS];
    u32 nr_uniq_cores = 0;
    u32 cpu;

    for (cpu = 0; cpu < nr_cpus; cpu++) {
        if (read_topology_id(cpu, "core_id", &core_ids[cpu]) < 0 ||
            core_ids[cpu] < 0)
            core_ids[cpu] = (s32)cpu;
    }

    for (cpu = 0; cpu < nr_cpus; cpu++) {
        u32 core_idx;

        for (core_idx = 0; core_idx < nr_uniq_cores; core_idx++) {
            if (uniq_core_ids[core_idx] == core_ids[cpu])
                break;
        }

        if (core_idx == nr_uniq_cores) {
            if (nr_uniq_cores >= MAX_CPUS)
                return -E2BIG;

            uniq_core_ids[nr_uniq_cores++] = core_ids[cpu];
        }

        grouped_core_ids[cpu] = (s32)(core_idx / CORES_PER_CLUSTER);
    }

    return build_cluster_topology(topo, grouped_core_ids, nr_cpus,
                                  "vm core groups (5 cores per cluster)");
}

static void print_cluster_topology(const struct cluster_topology *topo, int nr_possible_cpus)
{
    u32 nr_cpus = nr_possible_cpus > MAX_CPUS ? MAX_CPUS : (u32)nr_possible_cpus;
    u32 cluster, cpu;

    if (!topo->ready)
        return;

    printf("Detected CPU topology from sysfs:\n");
    printf("  - source: %s\n", topo->source_name ?: "unknown");
    printf("  - clusters: %u\n", topo->nr_clusters);

    for (cluster = 0; cluster < topo->nr_clusters; cluster++) {
        bool first = true;

        printf("  - cluster %u (sysfs id %d, cpus %u): ",
               cluster, topo->raw_cluster_ids[cluster], topo->cluster_sizes[cluster]);

        for (cpu = 0; cpu < nr_cpus; cpu++) {
            if (topo->cpu_to_cluster[cpu] != cluster)
                continue;

            printf("%s%u", first ? "" : ",", cpu);
            first = false;
        }

        printf("\n");
    }
}

int main(int argc, char **argv)
{
    SKEL_TYPE *skel;
    struct cluster_topology topo;
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

    err = detect_cluster_topology(&topo, nr_possible_cpus);
    if (err)
        topo = (struct cluster_topology){};

    if (skel->rodata) {
        u32 cpu;

        skel->rodata->nr_cpu_ids = (u32)nr_possible_cpus;
        skel->rodata->cpus_per_cluster =
            topo.ready && topo.nr_clusters ? (u32)nr_possible_cpus / topo.nr_clusters : 4;
        skel->rodata->cpu_cluster_map_ready = topo.ready ? 1 : 0;

        for (cpu = 0; cpu < (u32)nr_possible_cpus && cpu < MAX_CPUS; cpu++)
            skel->rodata->cpu_cluster_map[cpu] = topo.cpu_to_cluster[cpu];
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
    if (topo.ready)
        print_cluster_topology(&topo, nr_possible_cpus);
    else
        printf("  - cluster topology: sysfs unavailable, fallback to fixed-width mapping\n");
    printf("  - Watchdog: 5000ms\n");
    printf("Press Ctrl+C to stop and detach.\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    SKEL_DESTROY(skel);
    return err < 0 ? -err : 0;
}
