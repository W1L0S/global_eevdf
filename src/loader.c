#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

struct eevdf_stats {
    u64 dispatch_attempts;
    u64 dispatch_empty;
    u64 dispatch_aborts;
    u64 local_dispatches;
    u64 remote_dispatches;
    u64 running_transitions;
    u64 quiescent_dispatch_resets;
    u64 wakeup_idle_kicks;
    u64 wakeup_preempt_kicks;
    u64 task_lookup_misses;
    u64 affinity_penalty_hits;
    u64 recent_migration_penalty_hits;
    u64 wait_bonus_hits;
    u64 interactive_boost_hits;
};

#ifdef SKEL_H
#include SKEL_H
#else
#include "eevdf.skel.h"
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
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static bool parse_env_u32(const char *name, u32 *out)
{
    char *end = NULL;
    const char *val = getenv(name);
    unsigned long parsed;

    if (!val || !*val)
        return false;

    errno = 0;
    parsed = strtoul(val, &end, 10);
    if (errno || !end || *end != '\0')
        return false;

    *out = (u32)parsed;
    return true;
}

static bool parse_env_u64(const char *name, u64 *out)
{
    char *end = NULL;
    const char *val = getenv(name);
    unsigned long long parsed;

    if (!val || !*val)
        return false;

    errno = 0;
    parsed = strtoull(val, &end, 10);
    if (errno || !end || *end != '\0')
        return false;

    *out = (u64)parsed;
    return true;
}

static void apply_tunables(SKEL_TYPE *skel)
{
    u32 v32;
    u64 v64;

    if (!skel || !skel->rodata)
        return;

    if (parse_env_u32("GEEVDF_TOPK", &v32))
        skel->rodata->cfg_dispatch_candidates = v32;
    if (parse_env_u64("GEEVDF_WAKE_PREEMPT_GRAN_NS", &v64))
        skel->rodata->cfg_wakeup_preempt_gran_ns = v64;
    if (parse_env_u64("GEEVDF_WAKE_KICK_MIN_NS", &v64))
        skel->rodata->cfg_wakeup_kick_min_interval_ns = v64;
    if (parse_env_u64("GEEVDF_AFFINITY_PENALTY_NS", &v64))
        skel->rodata->cfg_affinity_penalty_ns = v64;
    if (parse_env_u64("GEEVDF_RECENT_MIGRATION_PENALTY_NS", &v64))
        skel->rodata->cfg_recent_migration_penalty_ns = v64;
    if (parse_env_u64("GEEVDF_WAIT_BONUS_CAP_NS", &v64))
        skel->rodata->cfg_wait_bonus_cap_ns = v64;
    if (parse_env_u64("GEEVDF_INTERACTIVE_SHORT_SLEEP_NS", &v64))
        skel->rodata->cfg_interactive_short_sleep_ns = v64;
    if (parse_env_u64("GEEVDF_INTERACTIVE_MID_SLEEP_NS", &v64))
        skel->rodata->cfg_interactive_mid_sleep_ns = v64;
    if (parse_env_u64("GEEVDF_PREFERRED_CPU_TTL_NS", &v64))
        skel->rodata->cfg_preferred_cpu_ttl_ns = v64;
    if (parse_env_u32("GEEVDF_LOAD_LIGHT_PCT", &v32))
        skel->rodata->cfg_load_light_pct = v32;
    if (parse_env_u32("GEEVDF_LOAD_NORMAL_PCT", &v32))
        skel->rodata->cfg_load_normal_pct = v32;
    if (parse_env_u32("GEEVDF_LOAD_BUSY_PCT", &v32))
        skel->rodata->cfg_load_busy_pct = v32;
    if (parse_env_u32("GEEVDF_LOAD_HEAVY_PCT", &v32))
        skel->rodata->cfg_load_heavy_pct = v32;
    if (parse_env_u32("GEEVDF_INTERACTIVE_HIGH_PCT", &v32))
        skel->rodata->cfg_interactive_high_pct = v32;
    if (parse_env_u32("GEEVDF_INTERACTIVE_MID_PCT", &v32))
        skel->rodata->cfg_interactive_mid_pct = v32;
    if (parse_env_u32("GEEVDF_AFFINITY_MATCH_PCT", &v32))
        skel->rodata->cfg_affinity_match_pct = v32;
    if (parse_env_u32("GEEVDF_AFFINITY_MISS_PCT", &v32))
        skel->rodata->cfg_affinity_miss_pct = v32;
}

static void aggregate_stats(struct eevdf_stats *dst, const struct eevdf_stats *src)
{
    dst->dispatch_attempts += src->dispatch_attempts;
    dst->dispatch_empty += src->dispatch_empty;
    dst->dispatch_aborts += src->dispatch_aborts;
    dst->local_dispatches += src->local_dispatches;
    dst->remote_dispatches += src->remote_dispatches;
    dst->running_transitions += src->running_transitions;
    dst->quiescent_dispatch_resets += src->quiescent_dispatch_resets;
    dst->wakeup_idle_kicks += src->wakeup_idle_kicks;
    dst->wakeup_preempt_kicks += src->wakeup_preempt_kicks;
    dst->task_lookup_misses += src->task_lookup_misses;
    dst->affinity_penalty_hits += src->affinity_penalty_hits;
    dst->recent_migration_penalty_hits += src->recent_migration_penalty_hits;
    dst->wait_bonus_hits += src->wait_bonus_hits;
    dst->interactive_boost_hits += src->interactive_boost_hits;
}

static void print_stats(SKEL_TYPE *skel)
{
    struct eevdf_stats total = {};
    struct eevdf_stats *percpu = NULL;
    int map_fd, ncpus, key = 0;
    size_t values_sz;
    int i;

    if (!skel || !skel->maps.eevdf_stats_map)
        return;

    map_fd = bpf_map__fd(skel->maps.eevdf_stats_map);
    if (map_fd < 0)
        return;

    ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return;

    values_sz = sizeof(*percpu) * (size_t)ncpus;
    percpu = calloc((size_t)ncpus, sizeof(*percpu));
    if (!percpu)
        return;

    if (bpf_map_lookup_elem(map_fd, &key, percpu)) {
        free(percpu);
        return;
    }

    for (i = 0; i < ncpus; i++)
        aggregate_stats(&total, &percpu[i]);

    printf("\nEEVDF stats:\n");
    printf("  dispatch_attempts      : %llu\n", (unsigned long long)total.dispatch_attempts);
    printf("  dispatch_empty         : %llu\n", (unsigned long long)total.dispatch_empty);
    printf("  dispatch_aborts        : %llu\n", (unsigned long long)total.dispatch_aborts);
    printf("  local_dispatches       : %llu\n", (unsigned long long)total.local_dispatches);
    printf("  remote_dispatches      : %llu\n", (unsigned long long)total.remote_dispatches);
    printf("  running_transitions    : %llu\n", (unsigned long long)total.running_transitions);
    printf("  quiescent_resets       : %llu\n", (unsigned long long)total.quiescent_dispatch_resets);
    printf("  wakeup_idle_kicks      : %llu\n", (unsigned long long)total.wakeup_idle_kicks);
    printf("  wakeup_preempt_kicks   : %llu\n", (unsigned long long)total.wakeup_preempt_kicks);
    printf("  task_lookup_misses     : %llu\n", (unsigned long long)total.task_lookup_misses);
    printf("  affinity_penalty_hits  : %llu\n", (unsigned long long)total.affinity_penalty_hits);
    printf("  recent_migration_hits  : %llu\n", (unsigned long long)total.recent_migration_penalty_hits);
    printf("  wait_bonus_hits        : %llu\n", (unsigned long long)total.wait_bonus_hits);
    printf("  interactive_boost_hits : %llu\n", (unsigned long long)total.interactive_boost_hits);

    free(percpu);
}

int main(int argc, char **argv)
{
    SKEL_TYPE *skel;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase rlimit: %d\n", err);
        return 1;
    }

    skel = SKEL_OPEN;
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    apply_tunables(skel);

    err = SKEL_LOAD(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    if (skel->struct_ops.eevdf_ops) {
        skel->struct_ops.eevdf_ops->timeout_ms = 5000;
    }

    err = SKEL_ATTACH(skel);
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
    if (!err)
        print_stats(skel);
    SKEL_DESTROY(skel);
    return err < 0 ? -err : 0;
}
