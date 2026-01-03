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

#define MAX_DISPATCH_LOOPS 4
#define MAX_PEEK_LOOPS     8

#define WAKEUP_PREEMPT_GRAN_NS       200000ULL
#define WAKEUP_KICK_MIN_INTERVAL_NS  200000ULL

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
    s64 vlag;         /* vlag = V - vruntime (正值=落后，负值=超前) */
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, u64);
} cpu_last_kick_ns SEC(".maps");

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

static __always_inline void eevdf_kick_preempt_if_needed(struct task_struct *p,
                                                         u64 new_ve, u64 new_vd,
                                                         u64 V_now)
{
    if (new_ve > V_now) return;

    s32 cpu = scx_bpf_task_cpu(p);
    if (cpu < 0 || cpu >= MAX_CPUS) return;
    u32 cpu_idx = (u32)cpu;

    u64 now_ns = bpf_ktime_get_ns();
    u64 *last_kick = bpf_map_lookup_elem(&cpu_last_kick_ns, &cpu_idx);
    if (last_kick && now_ns - *last_kick < WAKEUP_KICK_MIN_INTERVAL_NS)
        return;

    struct rq *rq = scx_bpf_cpu_rq(cpu);
    if (!rq) return;

    struct task_struct *curr = rq->curr;
    if (!curr) return;

    if (curr->pid == p->pid) return;

    struct task_ctx *ct = bpf_task_storage_get(&task_ctx_stor, curr, 0, 0);
    if (!ct) return;

    u64 curr_vd = ct->saved_vd;
    if (!curr_vd) return;

    if (new_vd + WAKEUP_PREEMPT_GRAN_NS >= curr_vd)
        return;

    if (last_kick)
        *last_kick = now_ns;

    u64 flags = scx_bpf_test_and_clear_cpu_idle(cpu) ? SCX_KICK_IDLE : SCX_KICK_PREEMPT;
    scx_bpf_kick_cpu(cpu, flags);
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
    // 简化设计：所有任务统一使用 3ms 时间片
    // 调度差异主要由权重(weight)决定的虚拟时间片(vslice)来体现
    return 3000000ULL;
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
        // 初始化时 vlag = 0, vruntime = V
        tctx->vruntime = 0;
        tctx->vlag = 0;
        sctx->base_v = 0;
        sctx->avg_vruntime_sum = 0;
        sctx->run_avg_vruntime_sum = 0;
        sctx->V = 0;
        v = 0;
    } else {
        // 检查是否是新任务（vruntime未初始化）
        bool is_new_task = (tctx->vruntime == 0);

        if (is_new_task) {
            // 新任务: 直接设置为当前 V，vlag = 0
            v = sctx->V;
            tctx->vlag = 0;
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
    struct run_accounting *acct;
    struct task_ctx *tctx;
    u32 key = 0;
    u32 cpu_idx = (u32)cpu;

    if (cpu < 0 || cpu >= MAX_CPUS) return 0;

    sctx = bpf_map_lookup_elem(&eevdf_ctx, &key);
    if (!sctx) return 0;

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
            scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);

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
    if (tctx) {
        tctx->vlag = (s64)(sctx->V - tctx->vruntime);
    }

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