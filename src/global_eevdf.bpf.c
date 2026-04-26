#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_experimental.h>

/* 调度参数 */
#define NICE_0_LOAD     1024ULL
#define BASE_SLICE_NS   3000000ULL
#define MIN_SLICE_NS    1000000ULL
#define MAX_SLICE_NS    6000000ULL
#define EEVDF_PERIOD_NS 12000000ULL
#define MAX_RT_PRIO     100
#define LAG_CLAMP_NS    (BASE_SLICE_NS * 3ULL)  /* Lag clamped to ±3 * base_slice */
#define MAX_CPUS        256

#define MAX_DISPATCH_LOOPS 4
#define MAX_PEEK_LOOPS     8
#define MAX_DISPATCH_CANDIDATES 4

#define WAKEUP_PREEMPT_GRAN_NS       200000ULL
#define WAKEUP_KICK_MIN_INTERVAL_NS  200000ULL
#define AFFINITY_PENALTY_NS          250000ULL
#define RECENT_MIGRATION_PENALTY_NS  100000ULL
#define WAIT_BONUS_CAP_NS            300000ULL
#define INTERACTIVE_SHORT_SLEEP_NS   2000000ULL
#define INTERACTIVE_MID_SLEEP_NS     10000000ULL
#define PREFERRED_CPU_TTL_NS         6000000ULL

#include "../../tools/sched_ext/include/scx/common.bpf.h"

/* 权重表，从 nice 值到权重 */
static const int eevdf_prio_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
     9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
     1024,  820,  655,  526,  423,   335,  272,  215,  172,  137,
      110,   87,   70,   56,   45,    36,   29,   23,   18,   15,
};

static const u32 eevdf_prio_to_wmult[40] = {
     48388,   59856,   76040,   92818,  118348,
    147320,  184698,  229616,  287308,  360437,
    449829,  563644,  704093,  875809, 1099582,
   1376151, 1717300, 2157191, 2708050, 3363326,
   4194304, 5237765, 6557202, 8165337,10153587,
  12820798,15790321,19976592,24970740,31350126,
  39045157,49367440,61356676,76695844,95443717,
 119304647,148102320,186737708,238609294,286331153,
};

extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;

char _license[] SEC("license") = "GPL";

const volatile u32 cfg_dispatch_candidates = MAX_DISPATCH_CANDIDATES;
const volatile u64 cfg_wakeup_preempt_gran_ns = WAKEUP_PREEMPT_GRAN_NS;
const volatile u64 cfg_wakeup_kick_min_interval_ns = WAKEUP_KICK_MIN_INTERVAL_NS;
const volatile u64 cfg_affinity_penalty_ns = AFFINITY_PENALTY_NS;
const volatile u64 cfg_recent_migration_penalty_ns = RECENT_MIGRATION_PENALTY_NS;
const volatile u64 cfg_wait_bonus_cap_ns = WAIT_BONUS_CAP_NS;
const volatile u64 cfg_interactive_short_sleep_ns = INTERACTIVE_SHORT_SLEEP_NS;
const volatile u64 cfg_interactive_mid_sleep_ns = INTERACTIVE_MID_SLEEP_NS;
const volatile u64 cfg_preferred_cpu_ttl_ns = PREFERRED_CPU_TTL_NS;
const volatile u32 cfg_load_light_pct = 125;
const volatile u32 cfg_load_normal_pct = 100;
const volatile u32 cfg_load_busy_pct = 75;
const volatile u32 cfg_load_heavy_pct = 50;
const volatile u32 cfg_interactive_high_pct = 70;
const volatile u32 cfg_interactive_mid_pct = 85;
const volatile u32 cfg_affinity_match_pct = 110;
const volatile u32 cfg_affinity_miss_pct = 90;

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

struct eevdf_node {
    struct bpf_rb_node node;
    s32 pid; 
    u64 ve;      
    u64 vd;      
    u64 weight;  
    u64 wmult;   
    u64 seq;
    u64 slice_ns;
    u64 enqueue_ns;
    u64 last_cpu_ts;
    u64 preferred_cpu_ts;
    u32 last_cpu;
    u32 preferred_cpu;
    u32 interactive_score;
};

struct task_ctx {
    u64 vruntime;
    s64 vlag;         /* vlag = V - vruntime */
    u64 last_run_ns;
    u64 sleep_start_ns;
    u64 last_sleep_ns;
    u64 saved_vd;
    u64 last_weight;
    u64 last_slice_ns;
    u64 last_cpu_ts;
    u64 preferred_cpu_ts;
    u64 run_weight_val;
    u64 run_wmult;
    u64 queue_seq_gen;
    u64 active_node_seq;
    u64 queued_ve;
    u64 queued_weight_scaled;
    u32 last_cpu;
    u32 preferred_cpu;
    u32 interactive_score;
    u8 queued_tree;
    u8 run_state;
    u8 slept_before_wakeup;
    u8 defaults_initialized;
    u8 sched_state_valid;
    u8 pad[2];
};

struct run_accounting {
    u64 curr_vd;
    u32 valid;
    u8  pad[36];
};

struct eevdf_ctx_t {
    struct bpf_rb_root ready __contains(eevdf_node, node);  
    struct bpf_rb_root future __contains(eevdf_node, node); 
    struct bpf_spin_lock lock;
    u64 V;                     
    u64 base_v;                
    s64 avg_vruntime_sum;      
    u64 avg_load;              
    s64 run_avg_vruntime_sum;  
    u64 run_avg_load;          
    u32 nr_ready;
    u32 nr_future;
    u32 nr_running;
    u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct eevdf_ctx_t);
} eevdf_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct task_ctx);
    __uint(map_flags, BPF_F_NO_PREALLOC); 
} task_ctx_stor SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, struct run_accounting);
} cpu_run_account SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} cpu_last_kick_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct eevdf_stats);
} eevdf_stats_map SEC(".maps");

#define EEVDF_TASK_IDLE       0
#define EEVDF_TASK_DISPATCHED 1
#define EEVDF_TASK_RUNNING    2
#define EEVDF_QUEUE_NONE      0
#define EEVDF_QUEUE_READY     1
#define EEVDF_QUEUE_FUTURE    2

/* --- Internal Helpers --- */

static __always_inline void eevdf_avg_add(struct eevdf_ctx_t *sctx, struct eevdf_node *n);
static __always_inline void eevdf_task_ctx_init(struct task_ctx *tctx);
static __always_inline void eevdf_update_sleep_state(struct task_ctx *tctx, u64 now_ns);
static __always_inline struct eevdf_stats *eevdf_stats_get(void);
static __always_inline void eevdf_clear_run_snapshot(struct task_ctx *tctx);
static __always_inline void eevdf_clear_queued_snapshot(struct task_ctx *tctx);
static __always_inline void eevdf_mark_queued_snapshot(struct task_ctx *tctx,
                                                       struct eevdf_node *n,
                                                       u8 queued_tree);
static __always_inline u64 eevdf_next_node_seq(struct task_ctx *tctx);
static __always_inline u32 eevdf_cfg_u32(u32 value, u32 fallback);
static __always_inline u64 eevdf_cfg_u64(u64 value, u64 fallback);
static __always_inline u32 eevdf_dispatch_candidate_limit(void);
static __always_inline u32 eevdf_effective_preferred_cpu_task(struct task_ctx *tctx, u64 now_ns);
static __always_inline u32 eevdf_effective_preferred_cpu_node(struct eevdf_node *n, u64 now_ns);

/* Clamp lag to ±3 * base_slice */
static __always_inline s64 eevdf_clamp_lag(s64 lag)
{
    s64 limit = (s64)LAG_CLAMP_NS;
    if (lag > limit) return limit;
    if (lag < -limit) return -limit;
    return lag;
}

/*
 * Calculate lag / total_weight using multiplication by inverse
 * This is more kernel-like than direct division
 * Returns the delta to apply to V
 */
static __always_inline u64 eevdf_lag_div_weight(s64 lag, u64 total_weight)
{
    if (total_weight == 0) return 0;

    // Calculate inverse weight: inv_weight = (1ULL << 32) / total_weight
    u64 inv_weight = ((u64)1 << 32) / total_weight;

    // Get absolute value of lag
    u64 abs_lag = lag < 0 ? (u64)(-lag) : (u64)lag;

    // delta = (abs_lag * inv_weight) >> 32
    u64 delta = (abs_lag * inv_weight) >> 32;

    return delta;
}

static __always_inline void eevdf_kick_preempt_if_needed(struct task_struct *p,
                                                         u64 new_ve, u64 new_vd,
                                                         u64 V_now)
{
    struct eevdf_stats *stats = eevdf_stats_get();

    if (new_ve > V_now) return;

    s32 cpu = scx_bpf_task_cpu(p);
    if (cpu < 0 || cpu >= MAX_CPUS) return;
    u32 cpu_idx = (u32)cpu;

    u64 now_ns = bpf_ktime_get_ns();
    u64 *last_kick = bpf_map_lookup_elem(&cpu_last_kick_ns, &cpu_idx);
    if (last_kick && now_ns - *last_kick <
        eevdf_cfg_u64(cfg_wakeup_kick_min_interval_ns, WAKEUP_KICK_MIN_INTERVAL_NS))
        return;

    if (scx_bpf_test_and_clear_cpu_idle(cpu)) {
        if (last_kick)
            *last_kick = now_ns;
        if (stats)
            stats->wakeup_idle_kicks++;
        scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
        return;
    }

    struct run_accounting *acct = bpf_map_lookup_elem(&cpu_run_account, &cpu_idx);
    if (!acct || !acct->valid) return;

    u64 curr_vd = acct->curr_vd;
    if (!curr_vd) return;

    if (new_vd + eevdf_cfg_u64(cfg_wakeup_preempt_gran_ns, WAKEUP_PREEMPT_GRAN_NS) >= curr_vd)
        return;

    if (last_kick)
        *last_kick = now_ns;

    if (stats)
        stats->wakeup_preempt_kicks++;
    scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

static bool less_ready(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct eevdf_node *na = container_of(a, struct eevdf_node, node);
    struct eevdf_node *nb = container_of(b, struct eevdf_node, node);
    if (na->vd == nb->vd) return na->pid < nb->pid;
    return na->vd < nb->vd;
}

static bool less_future(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct eevdf_node *na = container_of(a, struct eevdf_node, node);
    struct eevdf_node *nb = container_of(b, struct eevdf_node, node);
    // 修复：当ve相等时使用pid作为tiebreaker，避免红黑树插入时的不确定性
    if (na->ve == nb->ve) return na->pid < nb->pid;
    return na->ve < nb->ve;
}

static __always_inline u64 eevdf_scaled_weight(u64 weight)
{
    u64 w = weight >> 10; 
    return w ? w : 1;
}

static __always_inline void eevdf_task_ctx_init(struct task_ctx *tctx)
{
    if (!tctx || tctx->defaults_initialized)
        return;

    tctx->last_cpu = MAX_CPUS;
    tctx->preferred_cpu = MAX_CPUS;
    tctx->run_state = EEVDF_TASK_IDLE;
    tctx->defaults_initialized = 1;
}

static __always_inline struct eevdf_stats *eevdf_stats_get(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&eevdf_stats_map, &key);
}

static __always_inline void eevdf_clear_run_snapshot(struct task_ctx *tctx)
{
    if (!tctx)
        return;

    tctx->run_state = EEVDF_TASK_IDLE;
    tctx->last_run_ns = 0;
    tctx->saved_vd = 0;
    tctx->run_weight_val = 0;
    tctx->run_wmult = 0;
}

static __always_inline void eevdf_clear_queued_snapshot(struct task_ctx *tctx)
{
    if (!tctx)
        return;

    tctx->active_node_seq = 0;
    tctx->queued_ve = 0;
    tctx->queued_weight_scaled = 0;
    tctx->queued_tree = EEVDF_QUEUE_NONE;
}

static __always_inline void eevdf_mark_queued_snapshot(struct task_ctx *tctx,
                                                       struct eevdf_node *n,
                                                       u8 queued_tree)
{
    if (!tctx || !n)
        return;

    tctx->active_node_seq = n->seq;
    tctx->queued_ve = n->ve;
    tctx->queued_weight_scaled = eevdf_scaled_weight(n->weight);
    tctx->queued_tree = queued_tree;
}

static __always_inline u64 eevdf_next_node_seq(struct task_ctx *tctx)
{
    if (!tctx)
        return 1;

    tctx->queue_seq_gen++;
    if (!tctx->queue_seq_gen)
        tctx->queue_seq_gen = 1;
    return tctx->queue_seq_gen;
}

static __always_inline u32 eevdf_cfg_u32(u32 value, u32 fallback)
{
    return value ? value : fallback;
}

static __always_inline u64 eevdf_cfg_u64(u64 value, u64 fallback)
{
    return value ? value : fallback;
}

static __always_inline u32 eevdf_dispatch_candidate_limit(void)
{
    u32 limit = eevdf_cfg_u32(cfg_dispatch_candidates, MAX_DISPATCH_CANDIDATES);

    if (!limit)
        return 1;
    if (limit > MAX_DISPATCH_CANDIDATES)
        return MAX_DISPATCH_CANDIDATES;
    return limit;
}

static __always_inline u32 eevdf_effective_preferred_cpu_task(struct task_ctx *tctx, u64 now_ns)
{
    u64 ttl;

    if (!tctx)
        return MAX_CPUS;

    eevdf_task_ctx_init(tctx);

    if (tctx->preferred_cpu >= MAX_CPUS)
        return MAX_CPUS;

    if (!tctx->preferred_cpu_ts)
        return tctx->preferred_cpu;

    ttl = eevdf_cfg_u64(cfg_preferred_cpu_ttl_ns, PREFERRED_CPU_TTL_NS);
    if (now_ns < tctx->preferred_cpu_ts)
        return MAX_CPUS;
    if (now_ns - tctx->preferred_cpu_ts > ttl)
        return MAX_CPUS;

    return tctx->preferred_cpu;
}

static __always_inline u32 eevdf_effective_preferred_cpu_node(struct eevdf_node *n, u64 now_ns)
{
    u64 ttl;

    if (!n || n->preferred_cpu >= MAX_CPUS)
        return MAX_CPUS;

    if (!n->preferred_cpu_ts)
        return n->preferred_cpu;

    ttl = eevdf_cfg_u64(cfg_preferred_cpu_ttl_ns, PREFERRED_CPU_TTL_NS);
    if (now_ns < n->preferred_cpu_ts)
        return MAX_CPUS;
    if (now_ns - n->preferred_cpu_ts > ttl)
        return MAX_CPUS;

    return n->preferred_cpu;
}

static __always_inline u32 eevdf_nr_cpus(void)
{
    u32 nr = scx_bpf_nr_cpu_ids();
    return nr ? nr : 1;
}

static __always_inline void eevdf_update_sleep_state(struct task_ctx *tctx, u64 now_ns)
{
    if (!tctx)
        return;

    eevdf_task_ctx_init(tctx);

    if (!tctx->slept_before_wakeup || !tctx->sleep_start_ns)
        return;

    if (now_ns <= tctx->sleep_start_ns) {
        tctx->slept_before_wakeup = 0;
        tctx->sleep_start_ns = 0;
        return;
    }

    u64 sleep_ns = now_ns - tctx->sleep_start_ns;
    tctx->last_sleep_ns = sleep_ns;

    if (sleep_ns <= eevdf_cfg_u64(cfg_interactive_short_sleep_ns, INTERACTIVE_SHORT_SLEEP_NS)) {
        if (tctx->interactive_score <= 8)
            tctx->interactive_score += 2;
        else
            tctx->interactive_score = 10;
    } else if (sleep_ns <= eevdf_cfg_u64(cfg_interactive_mid_sleep_ns, INTERACTIVE_MID_SLEEP_NS)) {
        if (tctx->interactive_score < 10)
            tctx->interactive_score += 1;
    } else if (tctx->interactive_score > 0) {
        tctx->interactive_score -= 1;
    }

    tctx->slept_before_wakeup = 0;
    tctx->sleep_start_ns = 0;
}

static __always_inline void eevdf_compute_weight(struct task_struct *p, int idx,
                                                 u64 *weight, u64 *wmult)
{
    u64 base_w = eevdf_prio_to_weight[idx];
    u32 cg_w   = p->scx.weight;

    if (!cg_w || cg_w == NICE_0_LOAD) {
        *weight = base_w;
        *wmult  = eevdf_prio_to_wmult[idx];
        return;
    }

    u64 eff_w = base_w * cg_w;
    eff_w = eff_w / NICE_0_LOAD;
    if (!eff_w) eff_w = 1;

    *weight = eff_w;
    *wmult  = ((u64)1 << 32) / eff_w;
}

static __always_inline u64 eevdf_calculate_slice(struct task_struct *p,
                                                 struct task_ctx *tctx,
                                                 struct eevdf_ctx_t *sctx,
                                                 u32 cpu_hint)
{
    u64 slice = BASE_SLICE_NS;
    u32 load_pct = 100;
    u32 interactive_pct = 100;
    u32 affinity_pct = 100;
    u32 preferred_cpu = MAX_CPUS;

    if (sctx) {
        u32 nr_cpu = eevdf_nr_cpus();
        u32 runnable = sctx->nr_ready + sctx->nr_future + sctx->nr_running;

        if (runnable <= nr_cpu)
            load_pct = eevdf_cfg_u32(cfg_load_light_pct, 125);
        else if (runnable <= nr_cpu * 2)
            load_pct = eevdf_cfg_u32(cfg_load_normal_pct, 100);
        else if (runnable <= nr_cpu * 4)
            load_pct = eevdf_cfg_u32(cfg_load_busy_pct, 75);
        else
            load_pct = eevdf_cfg_u32(cfg_load_heavy_pct, 50);
    }

    if (tctx) {
        u64 now_ns = bpf_ktime_get_ns();

        eevdf_task_ctx_init(tctx);
        preferred_cpu = eevdf_effective_preferred_cpu_task(tctx, now_ns);

        if (tctx->interactive_score >= 6)
            interactive_pct = eevdf_cfg_u32(cfg_interactive_high_pct, 70);
        else if (tctx->interactive_score >= 3)
            interactive_pct = eevdf_cfg_u32(cfg_interactive_mid_pct, 85);

        if (cpu_hint < MAX_CPUS) {
            if (tctx->last_cpu == cpu_hint || preferred_cpu == cpu_hint)
                affinity_pct = eevdf_cfg_u32(cfg_affinity_match_pct, 110);
            else if (tctx->last_cpu < MAX_CPUS && tctx->last_cpu != cpu_hint)
                affinity_pct = eevdf_cfg_u32(cfg_affinity_miss_pct, 90);
        }
    }

    slice = slice * load_pct / 100;
    slice = slice * interactive_pct / 100;
    slice = slice * affinity_pct / 100;

    if (p && p->nr_cpus_allowed == 1 && slice < BASE_SLICE_NS)
        slice = BASE_SLICE_NS;

    if (slice < MIN_SLICE_NS)
        slice = MIN_SLICE_NS;
    if (slice > MAX_SLICE_NS)
        slice = MAX_SLICE_NS;

    return slice;
}

static __always_inline u64 eevdf_candidate_score(struct eevdf_node *n,
                                                 struct task_struct *p,
                                                 s32 cpu, u64 now_ns)
{
    u64 score;
    u64 wait_bonus = 0;
    u32 preferred_cpu;
    u64 affinity_penalty;
    u64 recent_migration_penalty;
    u64 wait_bonus_cap;
    u64 interactive_gran;
    u64 short_sleep_ns;

    if (!n || !p)
        return ~0ULL;

    if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return ~0ULL;

    affinity_penalty = eevdf_cfg_u64(cfg_affinity_penalty_ns, AFFINITY_PENALTY_NS);
    recent_migration_penalty = eevdf_cfg_u64(cfg_recent_migration_penalty_ns,
                                             RECENT_MIGRATION_PENALTY_NS);
    wait_bonus_cap = eevdf_cfg_u64(cfg_wait_bonus_cap_ns, WAIT_BONUS_CAP_NS);
    interactive_gran = eevdf_cfg_u64(cfg_wakeup_preempt_gran_ns,
                                     WAKEUP_PREEMPT_GRAN_NS);
    short_sleep_ns = eevdf_cfg_u64(cfg_interactive_short_sleep_ns,
                                   INTERACTIVE_SHORT_SLEEP_NS);

    score = n->vd;

    preferred_cpu = eevdf_effective_preferred_cpu_node(n, now_ns);
    if (preferred_cpu < MAX_CPUS && preferred_cpu != (u32)cpu)
        score += affinity_penalty;

    if (n->last_cpu < MAX_CPUS && n->last_cpu != (u32)cpu)
        score += affinity_penalty;

    if (n->last_cpu < MAX_CPUS && n->last_cpu != (u32)cpu &&
        n->last_cpu_ts &&
        now_ns > n->last_cpu_ts &&
        now_ns - n->last_cpu_ts < short_sleep_ns)
        score += recent_migration_penalty;

    if (n->enqueue_ns && now_ns > n->enqueue_ns) {
        wait_bonus = (now_ns - n->enqueue_ns) >> 2;
        if (wait_bonus > wait_bonus_cap)
            wait_bonus = wait_bonus_cap;
        if (score > wait_bonus)
            score -= wait_bonus;
        else
            score = 0;
    }

    if (n->interactive_score >= 6 && score > interactive_gran)
        score -= interactive_gran;

    return score;
}

static __always_inline u64 eevdf_calc_V(struct eevdf_ctx_t *sctx)
{
    s64 sum = sctx->avg_vruntime_sum + sctx->run_avg_vruntime_sum;
    u64 load = sctx->avg_load + sctx->run_avg_load;

    if (!load) return sctx->V;

    u64 V_now;
    if (sum >= 0)
        V_now = sctx->base_v + ((u64)sum / load);
    else
        V_now = sctx->base_v - ((u64)(-sum + load - 1) / load);

    s64 dv = (s64)(V_now - sctx->base_v);
    if (dv > (s64)(LAG_CLAMP_NS * 4ULL) || dv < -(s64)(LAG_CLAMP_NS * 4ULL)) {
        u64 base_old = sctx->base_v;
        u64 base_new = V_now;
        s64 delta = (s64)(base_new - base_old);

        sctx->avg_vruntime_sum -= delta * (s64)sctx->avg_load;
        sctx->run_avg_vruntime_sum -= delta * (s64)sctx->run_avg_load;

        sctx->base_v = base_new;

        sum = sctx->avg_vruntime_sum + sctx->run_avg_vruntime_sum;
        if (sum >= 0)
            V_now = sctx->base_v + ((u64)sum / load);
        else
            V_now = sctx->base_v - ((u64)(-sum + load - 1) / load);
    }

    return V_now;
}

/* --- Scheduler Ops --- */

SEC("struct_ops/select_cpu")
s32 BPF_PROG(eevdf_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    struct task_ctx *tctx;
    bool is_idle = false;
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (tctx) {
        eevdf_task_ctx_init(tctx);
        if (cpu >= 0 && cpu < MAX_CPUS) {
            tctx->preferred_cpu = (u32)cpu;
            tctx->preferred_cpu_ts = bpf_ktime_get_ns();
        }
    }

    return cpu;
}

SEC("struct_ops/enqueue")
int BPF_PROG(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct eevdf_node *n;
    struct eevdf_ctx_t *sctx;
    struct task_ctx *tctx;
    struct bpf_rb_node *fnode;
    struct eevdf_node *fn;
    u32 key = 0;
    u64 v, weight, wmult, slice_ns, vslice;
    s64 lag;
    u64 now_ns;
    u32 preferred_cpu;
    int idx;

    // 分配新的EEVDF节点
    n = bpf_obj_new(typeof(*n));
    if (!n) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) { bpf_obj_drop(n); return 0; }

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx) { bpf_obj_drop(n); return 0; }
    eevdf_task_ctx_init(tctx);

    n->pid = p->pid;

    // 计算任务权重
    idx = p->static_prio - MAX_RT_PRIO;
    if (idx < 0) idx = 0;
    if (idx >= 40) idx = 39;
    eevdf_compute_weight(p, idx, &weight, &wmult);
    n->weight = weight;
    n->wmult = wmult;
    n->seq = eevdf_next_node_seq(tctx);
    tctx->last_weight = weight;

    now_ns = bpf_ktime_get_ns();
    eevdf_update_sleep_state(tctx, now_ns);
    preferred_cpu = eevdf_effective_preferred_cpu_task(tctx, now_ns);

    // 计算时间片和虚拟时间片
    slice_ns = eevdf_calculate_slice(p, tctx, sctx, preferred_cpu);
    n->slice_ns = slice_ns;
    n->enqueue_ns = now_ns;
    n->last_cpu_ts = tctx->last_cpu_ts;
    n->last_cpu = tctx->last_cpu;
    n->preferred_cpu = preferred_cpu;
    n->preferred_cpu_ts = preferred_cpu < MAX_CPUS ? tctx->preferred_cpu_ts : 0;
    n->interactive_score = tctx->interactive_score;
    tctx->last_slice_ns = slice_ns;
    vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32;

    bpf_spin_lock(&sctx->lock);

    // 首个任务时初始化虚拟时间系统
    if (!sctx->avg_load && !sctx->run_avg_load) {
        // 初始化时 vlag = 0, vruntime = V
        tctx->vruntime = 0;
        tctx->vlag = 0;
        tctx->sched_state_valid = 1;
        sctx->base_v = 0;
        sctx->avg_vruntime_sum = 0;
        sctx->run_avg_vruntime_sum = 0;
        sctx->V = 0;
        sctx->nr_ready = 0;
        sctx->nr_future = 0;
        sctx->nr_running = 0;
        v = 0;
    } else {
        bool is_new_task = !tctx->sched_state_valid;

        if (is_new_task) {
            // 新任务: 直接设置为当前 V，vlag = 0
            v = sctx->V;
            tctx->vlag = 0;
            tctx->sched_state_valid = 1;
        } else {
            /*
             * [关键修复] 使用Linux内核风格的vlag恢复逻辑
             *
             * Linux内核定义: vlag = V - vruntime
             *   - vlag > 0: 任务落后于系统平均（应该给予补偿）
             *   - vlag < 0: 任务超前于系统平均（应该惩罚）
             *
             * 恢复公式（来自Linux内核place_entity）:
             *   vruntime = V - vlag
             *
             * 这样:
             *   - 如果任务落后(vlag > 0): vruntime = V - vlag < V，进入ready队列
             *   - 如果任务超前(vlag < 0): vruntime = V - vlag = V + |vlag| > V，可能进入future队列
             *
             * 注意: tctx->vlag是在stopping时保存的 V_old - vruntime_old
             * 现在用当前V恢复: vruntime_new = V_new - vlag
             */

            // 获取保存的vlag
            s64 vlag = tctx->vlag;

            // 应用lag衰减/限制（参考Linux内核）
            // 限制最大补偿和惩罚范围
            s64 max_lag = (s64)slice_ns;  // 最多补偿一个slice
            s64 min_lag = -(s64)(slice_ns / 2);  // 最多惩罚半个slice

            if (vlag > max_lag) {
                vlag = max_lag;  // 落后太多，限制补偿
            } else if (vlag < min_lag) {
                vlag = min_lag;  // 超前太多，限制惩罚
            }

            // 恢复vruntime = V - vlag（Linux内核公式）
            v = sctx->V;
            if (vlag >= 0) {
                // 任务落后，vruntime = V - vlag < V，将进入ready队列
                v = v >= (u64)vlag ? v - (u64)vlag : 0;
            } else {
                // 任务超前，vruntime = V - vlag = V + |vlag| > V
                v = v + (u64)(-vlag);
            }

            // 更新vlag
            tctx->vlag = vlag;
        }

        tctx->vruntime = v;
    }

    n->ve = v;  // 虚拟就绪时间 = vruntime

    // 计算虚拟截止时间：vd = ve + vslice（EEVDF核心公式）
    n->vd = n->ve + vslice;
    tctx->saved_vd = 0;

    u64 new_ve = n->ve;
    u64 new_vd = n->vd;

    // 保存当前的V，用于判断任务应该进入哪个队列
    u64 V_old = sctx->V;

    // 将任务加入负载统计
    eevdf_avg_add(sctx, n);

    // 将future队列中已eligible的任务转移到ready队列
    // 严格判断：ve <= V_old
    int move_loops = 0;
    while (move_loops < MAX_DISPATCH_LOOPS) {
        fnode = bpf_rbtree_first(&sctx->future);
        if (!fnode) break;
        fn = container_of(fnode, struct eevdf_node, node);
        if (fn->ve > V_old) break;  // 不eligible

        fnode = bpf_rbtree_remove(&sctx->future, fnode);
        if (!fnode) break;
        bpf_rbtree_add(&sctx->ready, fnode, less_ready);
        if (sctx->nr_future)
            sctx->nr_future--;
        sctx->nr_ready++;
        move_loops++;
    }

    // 重新计算 V（基于所有任务的 vruntime 加权平均值）
    // 这是 V 自然增长的核心机制
    sctx->V = eevdf_calc_V(sctx);
    u64 V_now = sctx->V;

    /*
     * [Eligible 判断调整]
     * 严格按照 EEVDF 定义：ve <= V 即为 eligible。
     * 移除容忍区间，简化逻辑。
     */
    if (n->ve <= sctx->V)
        bpf_rbtree_add(&sctx->ready, &n->node, less_ready);   // eligible，进入ready队列
    else
        bpf_rbtree_add(&sctx->future, &n->node, less_future); // not eligible，进入future队列

    if (n->ve <= sctx->V) {
        sctx->nr_ready++;
        eevdf_mark_queued_snapshot(tctx, n, EEVDF_QUEUE_READY);
    } else {
        sctx->nr_future++;
        eevdf_mark_queued_snapshot(tctx, n, EEVDF_QUEUE_FUTURE);
    }

    bpf_spin_unlock(&sctx->lock);

    eevdf_kick_preempt_if_needed(p, new_ve, new_vd, V_now);

    return 0;
}

SEC("struct_ops/dispatch")
int BPF_PROG(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
    struct bpf_rb_node *node;
    struct eevdf_node *n;
    struct task_struct *p;
    struct eevdf_ctx_t *sctx;
    struct task_ctx *tctx;
    struct eevdf_stats *stats;
    u32 key = 0;
    bool run_local = true;
    s32 target_cpu = cpu;
    bool abort_dispatch = false;
    u64 w_val, ve, vd, slice, V_now;

    if (cpu < 0 || cpu >= MAX_CPUS) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) return 0;
    stats = eevdf_stats_get();
    if (stats)
        stats->dispatch_attempts++;

    bpf_spin_lock(&sctx->lock);

    node = bpf_rbtree_first(&sctx->ready);
    bool ready_empty = !node;

    // 检查 future 队列
    struct bpf_rb_node *future_node = bpf_rbtree_first(&sctx->future);
    if (future_node) {
        struct eevdf_node *future_task = container_of(future_node, struct eevdf_node, node);

        if (ready_empty) {
            // ready 队列为空：强制更新 V，让 future 任务变为 eligible
            // 严格对齐：V = ve，这样 ve <= V 成立
            if (future_task->ve > sctx->V) {
                sctx->V = future_task->ve;
            }
        }
    }

    // Future -> Ready 转移（严格 Eligible 判断）
    int loops = 0;
    while (loops < MAX_DISPATCH_LOOPS) {
        node = bpf_rbtree_first(&sctx->future);
        if (!node) break;
        n = container_of(node, struct eevdf_node, node);
        // 严格判断eligible
        if (n->ve > sctx->V) break;
        
        node = bpf_rbtree_remove(&sctx->future, node);
        if (!node) break;
        bpf_rbtree_add(&sctx->ready, node, less_ready);
        if (sctx->nr_future)
            sctx->nr_future--;
        sctx->nr_ready++;
        loops++;
    }
    node = bpf_rbtree_first(&sctx->ready);
    if (!node) {
        bpf_spin_unlock(&sctx->lock);
        if (stats)
            stats->dispatch_empty++;
        return 0;
    }

    node = bpf_rbtree_remove(&sctx->ready, node);
    if (!node) {
        bpf_spin_unlock(&sctx->lock);
        if (stats)
            stats->dispatch_empty++;
        return 0;
    }
    n = container_of(node, struct eevdf_node, node);
    bpf_spin_unlock(&sctx->lock);

    p = bpf_task_from_pid(n->pid);
    if (!p) {
        if (stats)
            stats->task_lookup_misses++;
        bpf_spin_lock(&sctx->lock);
        sctx->avg_vruntime_sum -= (s64)(n->ve - sctx->base_v) *
                                  (s64)eevdf_scaled_weight(n->weight);
        sctx->avg_load -= eevdf_scaled_weight(n->weight);
        if (sctx->nr_ready)
            sctx->nr_ready--;
        sctx->V = eevdf_calc_V(sctx);
        bpf_spin_unlock(&sctx->lock);
        bpf_obj_drop(n);
        return 0;
    }

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx || tctx->active_node_seq != n->seq) {
        bpf_spin_lock(&sctx->lock);
        sctx->avg_vruntime_sum -= (s64)(n->ve - sctx->base_v) *
                                  (s64)eevdf_scaled_weight(n->weight);
        sctx->avg_load -= eevdf_scaled_weight(n->weight);
        if (sctx->nr_ready)
            sctx->nr_ready--;
        sctx->V = eevdf_calc_V(sctx);
        bpf_spin_unlock(&sctx->lock);
        bpf_task_release(p);
        bpf_obj_drop(n);
        return 0;
    }

    target_cpu = scx_bpf_task_cpu(p);
    if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
        run_local = true;
    } else if (target_cpu >= 0 && target_cpu < MAX_CPUS &&
               bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr)) {
        run_local = false;
    } else {
        abort_dispatch = true;
    }

    bpf_spin_lock(&sctx->lock);
    if (abort_dispatch) {
        bpf_rbtree_add(&sctx->ready, &n->node, less_ready);
        if (stats)
            stats->dispatch_aborts++;
        sctx->V = eevdf_calc_V(sctx);
        bpf_spin_unlock(&sctx->lock);
        bpf_task_release(p);
        return 0;
    }

    w_val = eevdf_scaled_weight(n->weight);
    ve = n->ve;
    vd = n->vd;
    slice = n->slice_ns;
    sctx->V = eevdf_calc_V(sctx);
    V_now = sctx->V;
    bpf_spin_unlock(&sctx->lock);

    eevdf_task_ctx_init(tctx);
    eevdf_clear_queued_snapshot(tctx);
    tctx->run_state = EEVDF_TASK_DISPATCHED;
    tctx->last_run_ns = 0;
    tctx->saved_vd = vd;
    tctx->run_weight_val = w_val;
    tctx->run_wmult = n->wmult;

    if (!run_local) {
        u64 dsq_id = SCX_DSQ_LOCAL_ON | target_cpu;
        if (stats)
            stats->remote_dispatches++;
        scx_bpf_dispatch(p, dsq_id, slice, 0);
        eevdf_kick_preempt_if_needed(p, ve, vd, V_now);
    } else {
        if (stats)
            stats->local_dispatches++;
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice, 0);
    }

    bpf_task_release(p);
    bpf_obj_drop(n);

    return 0;
}

SEC("struct_ops/running")
void BPF_PROG(eevdf_running, struct task_struct *p)
{
    struct eevdf_ctx_t *sctx;
    struct task_ctx *tctx;
    struct run_accounting *acct;
    u32 key = 0;
    s32 cpu = bpf_get_smp_processor_id();
    u32 cpu_idx;
    u64 now_ns;
    u64 w_val;
    u64 vd;

    if (cpu < 0 || cpu >= MAX_CPUS)
        return;
    cpu_idx = (u32)cpu;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx)
        return;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    eevdf_task_ctx_init(tctx);
    if (tctx->run_state != EEVDF_TASK_DISPATCHED)
        return;

    w_val = tctx->run_weight_val;
    vd = tctx->saved_vd;

    bpf_spin_lock(&sctx->lock);
    if (w_val) {
        s64 key_val = (s64)(tctx->vruntime - sctx->base_v) * (s64)w_val;

        sctx->avg_vruntime_sum -= key_val;
        sctx->avg_load -= w_val;
        sctx->run_avg_vruntime_sum += key_val;
        sctx->run_avg_load += w_val;
        if (sctx->nr_ready)
            sctx->nr_ready--;
        sctx->nr_running++;
        sctx->V = eevdf_calc_V(sctx);
    }
    bpf_spin_unlock(&sctx->lock);

    now_ns = bpf_ktime_get_ns();
    tctx->run_state = EEVDF_TASK_RUNNING;
    tctx->last_run_ns = now_ns;
    tctx->last_cpu = cpu_idx;
    tctx->last_cpu_ts = now_ns;
    tctx->preferred_cpu = cpu_idx;
    tctx->preferred_cpu_ts = now_ns;

    acct = bpf_map_lookup_elem(&cpu_run_account, &cpu_idx);
    if (acct) {
        acct->curr_vd = vd;
        acct->valid = 1;
    }

    {
        struct eevdf_stats *stats = eevdf_stats_get();
        if (stats)
            stats->running_transitions++;
    }
}

SEC("struct_ops/dequeue")
void BPF_PROG(eevdf_dequeue, struct task_struct *p, u64 deq_flags)
{
    struct eevdf_ctx_t *sctx;
    struct task_ctx *tctx;
    u32 key = 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx)
        return;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    eevdf_task_ctx_init(tctx);
    if (tctx->run_state != EEVDF_TASK_IDLE ||
        !tctx->active_node_seq ||
        !tctx->queued_weight_scaled ||
        tctx->queued_tree == EEVDF_QUEUE_NONE)
        return;

    eevdf_clear_queued_snapshot(tctx);
}

SEC("struct_ops/stopping")
int BPF_PROG(eevdf_stopping, struct task_struct *p, bool runnable)
{
    struct eevdf_ctx_t *sctx;
    struct run_accounting *acct;
    struct task_ctx *tctx;
    u32 key = 0;

    s32 cpu = bpf_get_smp_processor_id();
    if (cpu < 0 || cpu >= MAX_CPUS) return 0;
    u32 cpu_idx = (u32)cpu;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) return 0;

    acct = bpf_map_lookup_elem(&cpu_run_account, &cpu_idx);

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return 0;
    eevdf_task_ctx_init(tctx);
    if (tctx->run_state != EEVDF_TASK_RUNNING ||
        !tctx->run_weight_val || !tctx->run_wmult)
        return 0;

    u64 old_vruntime = tctx->vruntime;
    u64 w = tctx->run_weight_val;
    u64 wmult = tctx->run_wmult;
    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = tctx->last_run_ns ? now - tctx->last_run_ns : 0;
    u64 delta_v = (delta_ns * NICE_0_LOAD * wmult) >> 32;
    u64 new_vruntime = old_vruntime + delta_v;

    bpf_spin_lock(&sctx->lock);

    s64 key_val = (s64)(old_vruntime - sctx->base_v) * (s64)w;
    sctx->run_avg_vruntime_sum -= key_val;
    sctx->run_avg_load -= w;
    if (sctx->nr_running)
        sctx->nr_running--;

    // 重新计算 V（任务离开后，V 会自然调整）
    sctx->V = eevdf_calc_V(sctx);

    /*
     * [关键修复] 保存vlag = V - vruntime（Linux内核定义）
     *
     * vlag > 0: 任务落后于系统平均，唤醒时应该给予补偿
     * vlag < 0: 任务超前于系统平均，唤醒时应该惩罚
     *
     * 这个vlag会在任务唤醒时被enqueue使用，恢复公式是:
     *   vruntime = V_new - vlag
     */
    tctx->vruntime = new_vruntime;
    tctx->vlag = (s64)(sctx->V - tctx->vruntime);

    bpf_spin_unlock(&sctx->lock);

    if (acct) {
        acct->valid = 0;
        acct->curr_vd = 0;
    }

    eevdf_clear_run_snapshot(tctx);

    // 关键：如果任务还可运行（时间片用完但不睡眠），重新入队
    if (runnable) {
        struct eevdf_node *n = bpf_obj_new(typeof(*n));
        if (!n) return 0;

        n->pid = p->pid;

        // 重新计算权重（任务优先级可能在运行期间改变）
        int idx = p->static_prio - MAX_RT_PRIO;
        if (idx < 0) idx = 0;
        if (idx >= 40) idx = 39;
        u64 new_weight, new_wmult;
        eevdf_compute_weight(p, idx, &new_weight, &new_wmult);
        n->weight = new_weight;
        n->wmult = new_wmult;
        n->seq = eevdf_next_node_seq(tctx);

        // 更新task_ctx中的权重
        tctx->last_weight = new_weight;

        // 计算新的时间片
        if (tctx->interactive_score > 0)
            tctx->interactive_score--;
        tctx->slept_before_wakeup = 0;
        tctx->last_cpu = cpu_idx;
        tctx->last_cpu_ts = now;
        tctx->preferred_cpu = cpu_idx;
        tctx->preferred_cpu_ts = now;

        u64 slice_ns = eevdf_calculate_slice(p, tctx, sctx, cpu_idx);
        n->slice_ns = slice_ns;
        n->enqueue_ns = now;
        n->last_cpu_ts = tctx->last_cpu_ts;
        n->last_cpu = tctx->last_cpu;
        n->preferred_cpu = eevdf_effective_preferred_cpu_task(tctx, now);
        n->preferred_cpu_ts = n->preferred_cpu < MAX_CPUS ? tctx->preferred_cpu_ts : 0;
        n->interactive_score = tctx->interactive_score;
        tctx->last_slice_ns = slice_ns;
        u64 vslice = (slice_ns * NICE_0_LOAD * new_wmult) >> 32;

        // ve = 当前的vruntime
        n->ve = tctx->vruntime;
        // vd = ve + vslice
        n->vd = n->ve + vslice;

        bpf_spin_lock(&sctx->lock);

        // 将任务加入统计
        eevdf_avg_add(sctx, n);

        // 重新计算 V（任务重新加入后，V 会自然调整）
        sctx->V = eevdf_calc_V(sctx);

        // [修复] 移除future→ready转移，减少持锁时间
        // 转移操作只在dispatch中进行，避免stopping中长时间持锁

        // 直接入队，不做转移操作
        if (n->ve <= sctx->V)
            bpf_rbtree_add(&sctx->ready, &n->node, less_ready);
        else
            bpf_rbtree_add(&sctx->future, &n->node, less_future);

        if (n->ve <= sctx->V) {
            sctx->nr_ready++;
            eevdf_mark_queued_snapshot(tctx, n, EEVDF_QUEUE_READY);
        } else {
            sctx->nr_future++;
            eevdf_mark_queued_snapshot(tctx, n, EEVDF_QUEUE_FUTURE);
        }

        bpf_spin_unlock(&sctx->lock);
    } else {
        tctx->sleep_start_ns = now;
        tctx->last_cpu = cpu_idx;
        tctx->last_cpu_ts = now;
        tctx->slept_before_wakeup = 1;
    }

    return 0;
}

SEC("struct_ops/quiescent")
void BPF_PROG(eevdf_quiescent, struct task_struct *p, u64 deq_flags)
{
    struct eevdf_ctx_t *sctx;
    struct task_ctx *tctx;
    struct eevdf_stats *stats;
    u32 key = 0;
    u64 w;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx)
        return;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    eevdf_task_ctx_init(tctx);
    if (tctx->run_state != EEVDF_TASK_DISPATCHED || !tctx->run_weight_val)
        return;

    w = tctx->run_weight_val;
    stats = eevdf_stats_get();

    bpf_spin_lock(&sctx->lock);
    sctx->avg_vruntime_sum -= (s64)(tctx->vruntime - sctx->base_v) * (s64)w;
    if (sctx->avg_load >= w)
        sctx->avg_load -= w;
    else
        sctx->avg_load = 0;
    if (sctx->nr_ready)
        sctx->nr_ready--;
    sctx->V = eevdf_calc_V(sctx);
    bpf_spin_unlock(&sctx->lock);

    eevdf_clear_run_snapshot(tctx);
    if (stats)
        stats->quiescent_dispatch_resets++;
}

SEC("struct_ops/enable")
int BPF_PROG(eevdf_enable)
{
    u32 key = 0;
    struct eevdf_ctx_t *sctx;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) return 0;

    bpf_spin_lock(&sctx->lock);
    sctx->V = 0;
    sctx->base_v = 0;
    sctx->avg_vruntime_sum = 0;
    sctx->avg_load = 0;
    sctx->run_avg_vruntime_sum = 0;
    sctx->run_avg_load = 0;
    sctx->nr_ready = 0;
    sctx->nr_future = 0;
    sctx->nr_running = 0;
    bpf_spin_unlock(&sctx->lock);
    
    bpf_printk("Global EEVDF Scheduler Enabled");
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops eevdf_ops = {
    .select_cpu = (void *)eevdf_select_cpu,
    .enqueue    = (void *)eevdf_enqueue,
    .dequeue    = (void *)eevdf_dequeue,
    .dispatch   = (void *)eevdf_dispatch,
    .running    = (void *)eevdf_running,
    .stopping   = (void *)eevdf_stopping,
    .quiescent  = (void *)eevdf_quiescent,
    .enable     = (void *)eevdf_enable,
    .name       = "global_eevdf",
};

static __always_inline void eevdf_avg_add(struct eevdf_ctx_t *sctx, struct eevdf_node *n)
{
    u64 w = eevdf_scaled_weight(n->weight);
    s64 key = (s64)(n->ve - sctx->base_v);

    sctx->avg_vruntime_sum += key * (s64)w;
    sctx->avg_load += w;
}
