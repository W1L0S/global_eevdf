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
#define LAG_CLAMP_NS    (BASE_SLICE_NS * 3ULL)  /* Lag clamped to ±3 * base_slice */
#define MAX_CPUS        256

/*
 * [关键调整]
 * 限制循环次数以避免 NOHZ tick-stop 错误。
 * 增加到 4 次以确保在高负载下 future -> ready 转移能及时完成。
 * 同时避免 BPF 运行过长导致 softirq 积压。
 */
#define MAX_DISPATCH_LOOPS 4
#define MAX_PEEK_LOOPS     4

#include "../../tools/sched_ext/include/scx/common.bpf.h"

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
    s64 lag;          /* Saved lag (vruntime - V) for lag compensation */
    u64 last_run_ns;
    u64 saved_vd;
    u64 last_weight;
    bool is_running;
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
    // 使用默认的CPU选择逻辑
    bool is_idle = false;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
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
    int idx;

    // 分配新的EEVDF节点
    n = bpf_obj_new(typeof(*n));
    if (!n) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) { bpf_obj_drop(n); return 0; }

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx) { bpf_obj_drop(n); return 0; }

    n->pid = p->pid;

    // 计算任务权重
    idx = p->static_prio - MAX_RT_PRIO;
    if (idx < 0) idx = 0;
    if (idx >= 40) idx = 39;
    eevdf_compute_weight(p, idx, &weight, &wmult);
    n->weight = weight;
    n->wmult = wmult;
    tctx->last_weight = weight;

    // 计算时间片和虚拟时间片
    slice_ns = eevdf_calculate_slice(p);
    n->slice_ns = slice_ns;
    vslice = (slice_ns * NICE_0_LOAD * wmult) >> 32;

    bpf_spin_lock(&sctx->lock);

    // 首个任务时初始化虚拟时间系统
    if (!sctx->avg_load && !sctx->run_avg_load) {
        // 初始化时 lag = 0, vruntime = V
        tctx->vruntime = 0;
        tctx->lag = 0;
        sctx->base_v = 0;
        sctx->avg_vruntime_sum = 0;
        sctx->run_avg_vruntime_sum = 0;
        sctx->V = 0;
        v = 0;
    } else {
        // 读取保存的 lag (dequeue 时保存的 lag)
        lag = tctx->lag;
        u64 old_weight = tctx->last_weight;

        // Clamp lag 到 ±3 * base_slice（在使用前 clamp）
        lag = eevdf_clamp_lag(lag);

        // EEVDF 公式 (5) 或 (6): 当 client 加入竞争时
        // 如果权重变更，需要按照公式 (6) 处理
        u64 total_weight = sctx->avg_load + sctx->run_avg_load;

        // 检查权重是否变更
        bool weight_changed = (old_weight != 0 && old_weight != weight);

        if (weight_changed && total_weight > 0) {
            // 公式 (6): 权重变更时
            // V = V + lag/(Σw_i - w_old) - lag/(Σw_i - w_old + w_new)
            // 简化为: V = V + lag/total_weight - lag/(total_weight + w_new)
            // 注意：此时 total_weight 不包含该任务

            // 第一项：+lag / total_weight（以旧权重离开的影响）
            u64 v_delta1 = eevdf_lag_div_weight(lag, total_weight);
            if (lag >= 0) {
                sctx->V = sctx->V + v_delta1;
            } else {
                sctx->V = sctx->V >= v_delta1 ? sctx->V - v_delta1 : 0;
            }

            // 第二项：-lag / (total_weight + new_weight)（以新权重加入的影响）
            u64 v_delta2 = eevdf_lag_div_weight(lag, total_weight + eevdf_scaled_weight(weight));
            if (lag >= 0) {
                sctx->V = sctx->V >= v_delta2 ? sctx->V - v_delta2 : 0;
            } else {
                sctx->V = sctx->V + v_delta2;
            }
        } else if (total_weight > 0) {
            // 公式 (5): 普通加入（权重未变更）
            // V = V - lag / (total_weight + new_weight)
            u64 scaled_w = eevdf_scaled_weight(weight);
            u64 v_delta = eevdf_lag_div_weight(lag, total_weight + scaled_w);

            if (lag >= 0) {
                // lag > 0: V = V - lag/w（任务超前，降低 V）
                sctx->V = sctx->V >= v_delta ? sctx->V - v_delta : 0;
            } else {
                // lag < 0: V = V - (-lag)/w = V + lag/w（任务落后，提升 V）
                sctx->V = sctx->V + v_delta;
            }
        }

        // 恢复 vruntime: vruntime = V + lag
        v = sctx->V;
        if (lag >= 0) {
            v = v + (u64)lag;
        } else {
            u64 abs_lag = (u64)(-lag);
            v = v >= abs_lag ? v - abs_lag : 0;
        }

        // 新任务初始化为当前 V
        if (tctx->vruntime == 0) {
            v = sctx->V;
            lag = 0;
        }

        tctx->vruntime = v;
        tctx->lag = lag;  // 更新保存的 lag（已 clamped）
    }

    n->ve = v;  // 虚拟就绪时间 = vruntime

    // 计算虚拟截止时间：vd = ve + vslice（EEVDF核心公式）
    n->vd = n->ve + vslice;
    tctx->saved_vd = 0;

    // 将任务加入负载统计
    eevdf_avg_add(sctx, n);
    sctx->V = eevdf_calc_V(sctx);

    // 将future队列中已合格的任务（ve <= V）转移到ready队列
    int move_loops = 0;
    while (move_loops < MAX_DISPATCH_LOOPS) {
        fnode = bpf_rbtree_first(&sctx->future);
        if (!fnode) break;
        fn = container_of(fnode, struct eevdf_node, node);
        if (fn->ve > sctx->V) break;  // 未合格，停止转移

        fnode = bpf_rbtree_remove(&sctx->future, fnode);
        if (!fnode) break;
        bpf_rbtree_add(&sctx->ready, fnode, less_ready);
        move_loops++;
    }

    // 根据ve与V的关系决定入队位置
    if (n->ve <= sctx->V)
        bpf_rbtree_add(&sctx->ready, &n->node, less_ready);   // 合格树（按vd排序）
    else
        bpf_rbtree_add(&sctx->future, &n->node, less_future); // 不合格树（按ve排序）

    bpf_spin_unlock(&sctx->lock);

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

    /*
     * [关键修复] 饥饿问题修复
     *
     * 问题：当 ready 队列为空但 future 队列有任务时，
     * 如果有其他 CPU 正在运行任务 (run_avg_load > 0)，
     * V 不会更新，导致 future 队列中的任务永远无法变为"合格"。
     *
     * 解决方案：当 ready 队列为空时，无条件检查 future 队列，
     * 并将 V 更新到最小 ve，确保任务能够被调度。
     */
    node = bpf_rbtree_first(&sctx->ready);
    if (!node) {
        // ready 队列为空，检查 future 队列
        node = bpf_rbtree_first(&sctx->future);
        if (node) {
            n = container_of(node, struct eevdf_node, node);
            // 强制更新 V 到 future 队列首个任务的 ve
            // 这确保 future 中的任务可以立即变为"合格"
            if (n->ve > sctx->V) {
                sctx->V = n->ve;
            }
        }
    }

    // Future -> Ready 转移
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
            // 使用 IDLE kick 而不是 PREEMPT，减少 softirq 压力
            scx_bpf_kick_cpu(target_cpu, 0);

            bpf_task_release(p);
            bpf_obj_drop(n);

            // [优化] remote dispatch 后返回，避免单次调用处理过多任务
            return 0;
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
    }

    bpf_spin_lock(&sctx->lock);

    sctx->run_avg_vruntime_sum -= k;
    sctx->run_avg_load -= w;

    // EEVDF 公式 (4): 当 client 离开竞争时，计算并保存 lag
    if (tctx) {
        // 计算 lag = vruntime - V
        s64 lag = (s64)(tctx->vruntime - sctx->V);

        // 保存 lag 到 task_ctx（在 enqueue 时使用）
        tctx->lag = lag;

        // 更新 V: V = V + lag / Σw_i
        // 注意：这里的 total_weight 是离开后的权重（已经减去了当前任务）
        u64 total_weight = sctx->avg_load + sctx->run_avg_load;
        if (total_weight > 0) {
            // 使用乘倒数计算 lag / total_weight
            u64 v_delta = eevdf_lag_div_weight(lag, total_weight);

            // V = V + lag / total_weight
            if (lag >= 0) {
                sctx->V = sctx->V + v_delta;
            } else {
                sctx->V = sctx->V >= v_delta ? sctx->V - v_delta : 0;
            }
        }
    }

    sctx->V = eevdf_calc_V(sctx);

    bpf_spin_unlock(&sctx->lock);

    acct->valid = 0;
    acct->weight_val = 0;
    acct->key_val = 0;
    acct->curr_vd = 0;

    // 关键：如果任务还可运行（时间片用完但不睡眠），重新入队
    if (runnable && tctx) {
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

        // 保存旧权重用于权重变更检测
        u64 old_weight = tctx->last_weight;

        // 更新task_ctx中的权重
        tctx->last_weight = new_weight;

        // 计算新的时间片
        u64 slice_ns = eevdf_calculate_slice(p);
        n->slice_ns = slice_ns;
        u64 vslice = (slice_ns * NICE_0_LOAD * new_wmult) >> 32;

        // ve = 当前的vruntime
        n->ve = tctx->vruntime;
        // vd = ve + vslice
        n->vd = n->ve + vslice;

        bpf_spin_lock(&sctx->lock);

        // 处理重新加入时的 V 更新（公式 5 或 6）
        // 之前已经执行了 V += lag / total_weight（离开）
        // 现在需要执行 V -= lag / (total_weight + new_weight)（加入）
        s64 lag = tctx->lag;
        u64 total_weight = sctx->avg_load + sctx->run_avg_load;

        if (total_weight > 0) {
            u64 scaled_new_w = eevdf_scaled_weight(new_weight);
            u64 v_delta = eevdf_lag_div_weight(lag, total_weight + scaled_new_w);

            // V = V - lag / (total_weight + new_weight)
            if (lag >= 0) {
                sctx->V = sctx->V >= v_delta ? sctx->V - v_delta : 0;
            } else {
                sctx->V = sctx->V + v_delta;
            }
        }

        // 将任务加入统计
        eevdf_avg_add(sctx, n);
        sctx->V = eevdf_calc_V(sctx);

        // [修复] 移除future→ready转移，减少持锁时间
        // 转移操作只在dispatch中进行，避免stopping中长时间持锁

        // 直接入队，不做转移操作
        if (n->ve <= sctx->V)
            bpf_rbtree_add(&sctx->ready, &n->node, less_ready);
        else
            bpf_rbtree_add(&sctx->future, &n->node, less_future);

        bpf_spin_unlock(&sctx->lock);
    }

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
    
    bpf_printk("Global EEVDF Scheduler Enabled");
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