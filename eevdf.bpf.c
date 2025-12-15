#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_experimental.h>

/* --- Configuration Constants --- */
#define NICE_0_LOAD     1024ULL
#define BASE_SLICE_NS   3000000ULL       
#define MIN_SLICE_NS    1000000ULL       
#define EEVDF_PERIOD_NS 12000000ULL      
#define MAX_RT_PRIO     100
#define V_WINDOW_NS     (BASE_SLICE_NS * 4ULL) 
#define MAX_CPUS        256              

/* * [关键调整] 
 * 恢复循环以避免 NOHZ 错误，但限制为 8 次以防止 Hard Lockup。
 * 8次足够跳过一小群绑定任务，又不会让 BPF 运行太久。
 */
#define MAX_DISPATCH_LOOPS 8            
#define MAX_PEEK_LOOPS     8

#include "../tools/sched_ext/include/scx/common.bpf.h"

/* --- Lookup Tables --- */
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

/* --- Data Structures --- */

struct eevdf_node {
    struct bpf_rb_node node;
    s32 pid; 
    u64 ve;      
    u64 vd;      
    u64 weight;  
    u64 wmult;   
    u64 slice_ns;
};

struct task_ctx {
    u64 vruntime;      
    u64 last_run_ns;   
    u64 saved_vd;      
    u64 last_weight;   
    s64 saved_lag;     
    bool is_running;   
    u64 last_boost_ns; 
};

struct run_accounting {
    u64 weight_val;
    s64 key_val;
    u64 curr_vd;
    u64 wmult;
    u32 valid;
    u8  pad[24];
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
};

/* --- Maps --- */
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

/* --- Internal Helpers --- */

static __always_inline void eevdf_avg_add(struct eevdf_ctx_t *sctx, struct eevdf_node *n);

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
    return na->ve < nb->ve;
}

static __always_inline u64 eevdf_scaled_weight(u64 weight)
{
    u64 w = weight >> 10; 
    return w ? w : 1;
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

static __always_inline u64 eevdf_calculate_slice(struct task_struct *p)
{
    int idx = p->static_prio - MAX_RT_PRIO;
    if (idx < 0) idx = 0;
    if (idx >= 40) idx = 39;

    int latency_nice = idx - 20;
    int factor = 1024 + latency_nice * 64;

    if (factor < 256) factor = 256;
    if (factor > 4096) factor = 4096;

    u32 key = 0;
    struct eevdf_ctx_t *sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    u64 total_load = 0;
    if (sctx)
        total_load = sctx->avg_load + sctx->run_avg_load;

    if (total_load == 0) total_load = 1;

    u64 slice_ns = EEVDF_PERIOD_NS / total_load;
    slice_ns = (slice_ns * factor) >> 10;

    if (slice_ns < MIN_SLICE_NS) slice_ns = MIN_SLICE_NS;

    return slice_ns;
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
    if (dv > (s64)(V_WINDOW_NS * 4ULL) || dv < -(s64)(V_WINDOW_NS * 4ULL)) {
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
    bool is_idle = false;
    
    if (prev_cpu >= 0 && prev_cpu < MAX_CPUS) {
        const struct cpumask *idle = scx_bpf_get_idle_cpumask();
        if (idle) {
            if (bpf_cpumask_test_cpu((u32)prev_cpu, idle)) {
                scx_bpf_put_idle_cpumask(idle);
                return prev_cpu;
            }
            scx_bpf_put_idle_cpumask(idle);
        }
    }

    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
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
    int idx;
    s32 kick_cpu = -1;
    bool do_preempt = false;
    u64 target_curr_vd = 0;
    bool is_wakeup = enq_flags & SCX_ENQ_WAKEUP;

    n = bpf_obj_new(typeof(*n));
    if (!n) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) { bpf_obj_drop(n); return 0; }

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx) { bpf_obj_drop(n); return 0; }

    n->pid = p->pid;

    idx = p->static_prio - MAX_RT_PRIO;
    if (idx < 0) idx = 0;
    if (idx >= 40) idx = 39;
    eevdf_compute_weight(p, idx, &weight, &wmult);
    n->weight = weight;
    n->wmult = wmult;

    tctx->last_weight = weight;

    slice_ns = eevdf_calculate_slice(p);
    n->slice_ns = slice_ns;
    vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32;

    v = tctx->vruntime;
    kick_cpu = scx_bpf_task_cpu(p);

    if (kick_cpu >= 0 && kick_cpu < MAX_CPUS) {
        u32 target_cpu_idx = (u32)kick_cpu;
        struct run_accounting *acct = bpf_map_lookup_elem(&cpu_run_account, &target_cpu_idx);
        if (acct && acct->valid)
            target_curr_vd = acct->curr_vd;
    }

    bpf_spin_lock(&sctx->lock);

    if (v == 0 && sctx->V > 0) {
        v = sctx->V;
        tctx->vruntime = v;
    }

    if (is_wakeup) {
        s64 lag = tctx->saved_lag;
        u64 V_now = sctx->V;

        if (lag > 0) {
            s64 v_new = (s64)V_now - lag;
            v = (v_new < 0) ? 0 : (u64)v_new;
        } else {
            v = V_now;
        }

        s64 dv = (s64)(v - V_now);
        if (dv < -(s64)V_WINDOW_NS)
            v = V_now - V_WINDOW_NS;
        else if (dv > (s64)V_WINDOW_NS)
            v = V_now + V_WINDOW_NS;

        tctx->vruntime = v;
        tctx->saved_lag = 0;
    } else {
        u64 V_now = sctx->V;
        s64 dv = (s64)(v - V_now);

        if (dv < -(s64)V_WINDOW_NS)
            v = V_now - V_WINDOW_NS;
        else if (dv > (s64)V_WINDOW_NS)
            v = V_now + V_WINDOW_NS;

        tctx->vruntime = v;
    }
    n->ve = v;

    if (!sctx->avg_load && !sctx->run_avg_load) {
        sctx->base_v = n->ve;
        sctx->avg_vruntime_sum = 0;
        sctx->run_avg_vruntime_sum = 0;
        sctx->V = n->ve;
    }

    if (!is_wakeup && tctx->saved_vd > n->ve) {
        n->vd = tctx->saved_vd;
    } else {
        n->vd = n->ve + vslice;
    }
    tctx->saved_vd = 0;

    u64 preempt_gran = 1000000ULL;
    if (preempt_gran > slice_ns) preempt_gran = slice_ns;

    if (target_curr_vd && (n->vd + preempt_gran) < target_curr_vd)
        do_preempt = true;

    eevdf_avg_add(sctx, n);
    sctx->V = eevdf_calc_V(sctx);

    int move_loops = 0;
    while (move_loops < MAX_DISPATCH_LOOPS) {
        fnode = bpf_rbtree_first(&sctx->future);
        if (!fnode) break;
        fn = container_of(fnode, struct eevdf_node, node);
        if (fn->ve > sctx->V) break;

        fnode = bpf_rbtree_remove(&sctx->future, fnode);
        if (!fnode) break;
        bpf_rbtree_add(&sctx->ready, fnode, less_ready);
        move_loops++;
    }

    if (n->ve <= sctx->V)
        bpf_rbtree_add(&sctx->ready, &n->node, less_ready);
    else
        bpf_rbtree_add(&sctx->future, &n->node, less_future);

    bpf_spin_unlock(&sctx->lock);

    if (do_preempt && kick_cpu >= 0) {
        scx_bpf_kick_cpu(kick_cpu, SCX_KICK_PREEMPT);
    } else {
        const struct cpumask *idle = scx_bpf_get_idle_cpumask();
        if (idle) {
            u32 target = bpf_cpumask_first(idle);
            if (target < MAX_CPUS && bpf_cpumask_test_cpu(target, idle)) {
                scx_bpf_kick_cpu((s32)target, SCX_KICK_IDLE);
            }
            scx_bpf_put_idle_cpumask(idle);
        }
    }
        
    return 0;
}

SEC("struct_ops/dispatch")
int BPF_PROG(eevdf_dispatch, s32 cpu, struct task_struct *prev)
{
    struct bpf_rb_node *node;
    struct eevdf_node *n;
    struct task_struct *p;
    struct eevdf_ctx_t *sctx;
    struct run_accounting *acct;
    struct task_ctx *tctx;
    u32 key = 0;
    u32 cpu_idx = (u32)cpu;

    if (cpu < 0 || cpu >= MAX_CPUS) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) return 0;

    bpf_spin_lock(&sctx->lock);

    u64 total_load = sctx->avg_load + sctx->run_avg_load;
    
    // Future -> Ready Logic
    node = bpf_rbtree_first(&sctx->future);
    if (node && total_load == 0) {
        n = container_of(node, struct eevdf_node, node);
        if (n->ve > sctx->V) {
            sctx->V = n->ve; 
        }
    }

    int loops = 0;
    while (loops < MAX_DISPATCH_LOOPS) {
        node = bpf_rbtree_first(&sctx->future);
        if (!node) break;
        n = container_of(node, struct eevdf_node, node);
        if (n->ve > sctx->V) break; 
        
        node = bpf_rbtree_remove(&sctx->future, node);
        if (!node) break; 
        bpf_rbtree_add(&sctx->ready, node, less_ready);
        loops++;
    }
    
    bpf_spin_unlock(&sctx->lock);

    /*
     * [BALANCE FIX] 恢复循环，但限制次数。
     * MAX_PEEK_LOOPS = 8。这足以处理大多数绑定任务堆积的情况，
     * 同时避免长时间运行 BPF 导致锁死或 NOHZ 错误。
     */
    int peek_loops = 0;
    while (peek_loops < MAX_PEEK_LOOPS) {
        peek_loops++;

        bpf_spin_lock(&sctx->lock);
        node = bpf_rbtree_first(&sctx->ready);
        if (!node) {
            bpf_spin_unlock(&sctx->lock);
            return 0; // 无任务
        }
        node = bpf_rbtree_remove(&sctx->ready, node);
        if (!node) {
            bpf_spin_unlock(&sctx->lock);
            return 0;
        }
        n = container_of(node, struct eevdf_node, node);

        u64 w_val = eevdf_scaled_weight(n->weight);
        s64 key_val = (s64)(n->ve - sctx->base_v) * (s64)w_val;
        s32 pid = n->pid;
        u64 vd = n->vd;
        u64 wmult = n->wmult;
        u64 slice = n->slice_ns;
        bpf_spin_unlock(&sctx->lock);

        p = bpf_task_from_pid(pid);
        if (!p) {
            bpf_spin_lock(&sctx->lock);
            sctx->avg_vruntime_sum -= key_val;
            sctx->avg_load -= w_val;
            sctx->V = eevdf_calc_V(sctx);
            bpf_spin_unlock(&sctx->lock);
            bpf_obj_drop(n);
            continue; 
        }

        /* --- Affinity Check --- */
        bool run_local = true;
        s32 target_cpu = scx_bpf_task_cpu(p);

        if (target_cpu != cpu) {
            if (p->nr_cpus_allowed == 1) {
                run_local = false;
            } else if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
                run_local = false;
            }
        }

        if (!run_local) {
            // Remote dispatch
            u64 dsq_id = SCX_DSQ_LOCAL_ON | target_cpu;

            bpf_spin_lock(&sctx->lock);
            sctx->avg_vruntime_sum -= key_val;
            sctx->avg_load -= w_val;
            sctx->V = eevdf_calc_V(sctx);
            bpf_spin_unlock(&sctx->lock);

            scx_bpf_dispatch(p, dsq_id, slice, 0);
            scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
            
            bpf_task_release(p);
            bpf_obj_drop(n);
            
            // [关键] 继续尝试，直到上限 8 次
            continue;
        }

        /* --- Local Dispatch --- */
        acct = bpf_map_lookup_elem(&cpu_run_account, &cpu_idx);
        tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

        if (acct && tctx) {
            tctx->last_run_ns = bpf_ktime_get_ns();
            tctx->is_running = true;
            tctx->saved_vd = vd;

            bpf_spin_lock(&sctx->lock);
            sctx->avg_vruntime_sum -= key_val;
            sctx->avg_load -= w_val;
            sctx->run_avg_vruntime_sum += key_val;
            sctx->run_avg_load += w_val;
            sctx->V = eevdf_calc_V(sctx);
            bpf_spin_unlock(&sctx->lock);

            acct->weight_val = w_val;
            acct->key_val = key_val;
            acct->curr_vd = vd;
            acct->wmult = wmult;
            acct->valid = 1;
        } else {
            bpf_spin_lock(&sctx->lock);
            sctx->avg_vruntime_sum -= key_val;
            sctx->avg_load -= w_val;
            sctx->V = eevdf_calc_V(sctx);
            bpf_spin_unlock(&sctx->lock);
        }

        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice, 0);
        bpf_task_release(p);
        bpf_obj_drop(n);
        
        return 0; // Found task, done.
    }

    return 0;
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
    if (!acct) return 0;

    u64 w = acct->weight_val;
    s64 k = acct->key_val;
    u64 wmult = acct->wmult;
    u32 valid = acct->valid;

    if (!valid || !w || !wmult) return 0;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    
    if (tctx && tctx->last_run_ns) {
        u64 now = bpf_ktime_get_ns();
        u64 delta_ns = now - tctx->last_run_ns;

        u64 delta_v = (delta_ns * NICE_0_LOAD * wmult) >> 32;
        tctx->vruntime += delta_v;

        tctx->last_run_ns = 0;
        tctx->is_running = false;

        if (!runnable) {
            s64 lag = (s64)sctx->V - (s64)tctx->vruntime;
            tctx->saved_lag = lag;
            tctx->saved_vd = 0;
        }
    }

    bpf_spin_lock(&sctx->lock);

    sctx->run_avg_vruntime_sum -= k;
    sctx->run_avg_load -= w;
    sctx->V = eevdf_calc_V(sctx);

    bpf_spin_unlock(&sctx->lock);

    acct->valid = 0;
    acct->weight_val = 0;
    acct->key_val = 0;
    acct->curr_vd = 0;
    return 0;
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
    bpf_spin_unlock(&sctx->lock);
    
    bpf_printk("Global EEVDF Scheduler Enabled (Balanced Loop Mode)");
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops eevdf_ops = {
    .select_cpu = (void *)eevdf_select_cpu,
    .enqueue    = (void *)eevdf_enqueue,
    .dispatch   = (void *)eevdf_dispatch,
    .stopping   = (void *)eevdf_stopping,
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