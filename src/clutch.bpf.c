#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_experimental.h>

#define NICE_0_LOAD              1024ULL
#define DEFAULT_SLICE_NS         3000000ULL
#define MAX_RT_PRIO              100
#define MAX_CPUS                 256
#define MAX_CLUSTERS             MAX_CPUS
#define MAX_GROUPS               16384
#define NR_CLUTCH_BUCKETS        2
#define DEFAULT_CPUS_PER_CLUSTER 4
#include "../../tools/sched_ext/include/scx/common.bpf.h"

static const int clutch_prio_to_weight[40] = {
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
     9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
     1024,  820,   655,   526,   423,   335,   272,   215,   172,   137,
      110,   87,    70,    56,    45,    36,    29,    23,    18,    15,
};

static const u32 clutch_prio_to_wmult[40] = {
     48388,   59856,   76040,   92818,  118348,
    147320,  184698,  229616,  287308,  360437,
    449829,  563644,  704093,  875809, 1099582,
   1376151, 1717300, 2157191, 2708050, 3363326,
   4194304, 5237765, 6557202, 8165337, 10153587,
  12820798, 15790321, 19976592, 24970740, 31350126,
  39045157, 49367440, 61356676, 76695844, 95443717,
 119304647, 148102320, 186737708, 238609294, 286331153,
};

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

char _license[] SEC("license") = "GPL";

const volatile u32 nr_cpu_ids = MAX_CPUS;
const volatile u32 cpus_per_cluster = DEFAULT_CPUS_PER_CLUSTER;

struct thread_node {
    struct bpf_rb_node rb_node;
    s32 pid;
    s32 tgid;
    s32 dispatch_cpu;
    u32 cluster_id;
    u32 bucket_id;
    u64 vruntime;
    u64 wmult;
    u64 slice_ns;
};

struct group_ref {
    struct bpf_rb_node rb_node;
    s32 tgid;
    s32 dispatch_cpu;
    u32 cluster_id;
    u32 bucket_id;
    u32 nr_children;
    u64 vruntime;
    u64 seq;
};

struct group_slot {
    struct bpf_rb_root children __contains(thread_node, rb_node);
    struct bpf_spin_lock lock;
    s32 tgid;
    s32 dispatch_cpu;
    u32 cluster_id;
    u32 bucket_id;
    u32 nr_children;
    u64 vruntime;
    u64 seq;
};

struct clutch_bucket {
    struct bpf_spin_lock lock;
    struct bpf_rb_root groups __contains(group_ref, rb_node);
    u32 nr_groups;
};

struct cluster_ctx {
    struct bpf_spin_lock lock;
    u32 next_bucket;
};

struct group_key {
    u32 cluster_id;
    s32 tgid;
};

struct group_snapshot {
    struct group_key key;
    u32 bucket_id;
    u32 nr_children;
    s32 dispatch_cpu;
    u64 vruntime;
    u64 seq;
};

struct task_ctx {
    u64 vruntime;
    u64 last_run_ns;
    u32 cluster_id;
    u32 bucket_id;
    s32 home_cpu;
    bool is_running;
};

struct run_accounting {
    u64 wmult;
    u32 cluster_id;
    u32 bucket_id;
    s32 pid;
    s32 tgid;
    s32 home_cpu;
    u32 valid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CLUSTERS);
    __type(key, u32);
    __type(value, struct cluster_ctx);
} cluster_ctxs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CLUSTERS * NR_CLUTCH_BUCKETS);
    __type(key, u32);
    __type(value, struct clutch_bucket);
} bucket_ctxs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_GROUPS);
    __type(key, struct group_key);
    __type(value, struct group_slot);
} group_nodes SEC(".maps");

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

static bool clutch_group_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct group_ref *na = container_of(a, struct group_ref, rb_node);
    struct group_ref *nb = container_of(b, struct group_ref, rb_node);

    if (na->vruntime != nb->vruntime)
        return na->vruntime < nb->vruntime;
    if (na->tgid != nb->tgid)
        return na->tgid < nb->tgid;
    if (na->cluster_id != nb->cluster_id)
        return na->cluster_id < nb->cluster_id;
    return na->seq < nb->seq;
}

static bool clutch_thread_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
    struct thread_node *na = container_of(a, struct thread_node, rb_node);
    struct thread_node *nb = container_of(b, struct thread_node, rb_node);

    if (na->vruntime != nb->vruntime)
        return na->vruntime < nb->vruntime;
    if (na->pid != nb->pid)
        return na->pid < nb->pid;
    return na->tgid < nb->tgid;
}

static __always_inline u32 clutch_nr_cpus(void)
{
    u32 nr = nr_cpu_ids;

    if (!nr || nr > MAX_CPUS)
        nr = MAX_CPUS;

    return nr;
}

static __always_inline u32 clutch_cpus_per_cluster(void)
{
    u32 width = cpus_per_cluster;
    u32 nr = clutch_nr_cpus();

    if (!width)
        width = DEFAULT_CPUS_PER_CLUSTER;
    if (!width)
        width = 1;
    if (width > nr)
        width = nr;

    return width;
}

static __always_inline u32 clutch_cpu_to_cluster(s32 cpu)
{
    u32 nr = clutch_nr_cpus();
    u32 width = clutch_cpus_per_cluster();
    u32 cid;

    if (cpu < 0)
        cpu = 0;
    if ((u32)cpu >= nr)
        cpu = nr - 1;

    cid = (u32)cpu / width;
    if (cid >= MAX_CLUSTERS)
        cid = MAX_CLUSTERS - 1;

    return cid;
}

static __always_inline s32 clutch_pick_home_cpu(struct task_struct *p)
{
    s32 cpu = scx_bpf_task_cpu(p);

    if (cpu >= 0 && cpu < (s32)clutch_nr_cpus() &&
        bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return cpu;

    cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
    if (cpu >= 0 && cpu < (s32)clutch_nr_cpus())
        return cpu;

    return 0;
}

static __always_inline u32 clutch_bucket_id(s32 tgid)
{
    return ((u32)tgid) & (NR_CLUTCH_BUCKETS - 1);
}

static __always_inline struct cluster_ctx *clutch_cluster_ctx(u32 cluster_id)
{
    if (cluster_id >= MAX_CLUSTERS)
        return NULL;

    return bpf_map_lookup_elem(&cluster_ctxs, &cluster_id);
}

static __always_inline struct clutch_bucket *clutch_bucket_ctx(u32 cluster_id, u32 bucket_id)
{
    u32 idx;

    if (cluster_id >= MAX_CLUSTERS || bucket_id >= NR_CLUTCH_BUCKETS)
        return NULL;

    idx = cluster_id * NR_CLUTCH_BUCKETS + bucket_id;
    return bpf_map_lookup_elem(&bucket_ctxs, &idx);
}

static __always_inline struct group_slot *clutch_group_slot(struct group_key *key)
{
    struct group_slot empty = {};
    struct group_slot *slot;

    slot = bpf_map_lookup_elem(&group_nodes, key);
    if (slot)
        return slot;

    bpf_map_update_elem(&group_nodes, key, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&group_nodes, key);
}

static __always_inline u64 clutch_compute_wmult(struct task_struct *p, int idx)
{
    u64 base_w = clutch_prio_to_weight[idx];
    u32 cg_w = p->scx.weight;

    if (!cg_w || cg_w == NICE_0_LOAD)
        return clutch_prio_to_wmult[idx];

    base_w = (base_w * cg_w) / NICE_0_LOAD;
    if (!base_w)
        base_w = 1;

    return ((u64)1 << 32) / base_w;
}

static __always_inline u64 clutch_calculate_slice(struct task_struct *p)
{
    return DEFAULT_SLICE_NS;
}

static __always_inline bool clutch_refresh_group_key_locked(struct group_slot *group)
{
    struct bpf_rb_node *rb;
    struct thread_node *thread;

    rb = bpf_rbtree_first(&group->children);
    if (!rb)
        return false;

    thread = container_of(rb, struct thread_node, rb_node);
    group->vruntime = thread->vruntime;
    group->dispatch_cpu = thread->dispatch_cpu;
    return true;
}

static __always_inline void clutch_sync_group_ref(struct group_ref *group_ref,
                                                  struct group_slot *slot)
{
    group_ref->tgid = slot->tgid;
    group_ref->cluster_id = slot->cluster_id;
    group_ref->bucket_id = slot->bucket_id;
    group_ref->dispatch_cpu = slot->dispatch_cpu;
    group_ref->nr_children = slot->nr_children;
    group_ref->vruntime = slot->vruntime;
    group_ref->seq = slot->seq;
}

static __always_inline struct group_ref *
clutch_alloc_group_ref(const struct group_key *key, u32 bucket_id)
{
    struct group_ref *group_ref;

    group_ref = bpf_obj_new(typeof(*group_ref));
    if (!group_ref)
        return NULL;

    group_ref->tgid = key->tgid;
    group_ref->cluster_id = key->cluster_id;
    group_ref->bucket_id = bucket_id;
    group_ref->dispatch_cpu = -1;

    return group_ref;
}

static __always_inline struct thread_node *
clutch_alloc_thread_node(struct task_struct *p, struct task_ctx *tctx,
                         u32 cluster_id, u32 bucket_id, s32 home_cpu)
{
    struct thread_node *node;
    u64 wmult, slice_ns;
    int idx;

    node = bpf_obj_new(typeof(*node));
    if (!node)
        return NULL;

    idx = p->static_prio - MAX_RT_PRIO;
    if (idx < 0)
        idx = 0;
    if (idx >= 40)
        idx = 39;

    wmult = clutch_compute_wmult(p, idx);
    slice_ns = clutch_calculate_slice(p);

    node->pid = p->pid;
    node->tgid = p->tgid;
    node->cluster_id = cluster_id;
    node->bucket_id = bucket_id;
    node->dispatch_cpu = home_cpu;
    node->wmult = wmult;
    node->slice_ns = slice_ns;
    node->vruntime = tctx->vruntime;

    tctx->cluster_id = cluster_id;
    tctx->bucket_id = bucket_id;
    tctx->home_cpu = home_cpu;

    return node;
}

static __always_inline void clutch_bucket_add_group(struct clutch_bucket *bucket,
                                                    struct group_ref *group)
{
    if (!bucket || !group)
        return;

    bpf_spin_lock(&bucket->lock);
    bpf_rbtree_add(&bucket->groups, &group->rb_node, clutch_group_less);
    bucket->nr_groups++;
    bpf_spin_unlock(&bucket->lock);
}

static __always_inline int clutch_queue_thread(struct group_slot *slot,
                                               const struct group_key *key,
                                               struct thread_node *thread)
{
    struct group_ref *group;
    struct clutch_bucket *bucket;

    group = clutch_alloc_group_ref(key, thread->bucket_id);
    if (!group) {
        bpf_obj_drop(thread);
        return -1;
    }

    bucket = clutch_bucket_ctx(key->cluster_id, thread->bucket_id);
    if (!bucket) {
        bpf_obj_drop(group);
        bpf_obj_drop(thread);
        return -1;
    }

    bpf_spin_lock(&slot->lock);
    if (bpf_rbtree_add(&slot->children, &thread->rb_node, clutch_thread_less)) {
        bpf_spin_unlock(&slot->lock);
        bpf_obj_drop(group);
        return -1;
    }
    slot->nr_children++;
    clutch_refresh_group_key_locked(slot);
    slot->seq++;
    clutch_sync_group_ref(group, slot);
    bpf_spin_unlock(&slot->lock);

    if (!group->nr_children) {
        bpf_obj_drop(group);
        return -1;
    }

    clutch_bucket_add_group(bucket, group);
    return 0;
}

static __always_inline int clutch_enqueue_task(struct task_struct *p)
{
    struct task_ctx *tctx;
    struct thread_node *thread;
    struct group_slot *slot;
    struct group_key key;
    s32 home_cpu;
    u32 cluster_id, bucket_id;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return -1;

    home_cpu = clutch_pick_home_cpu(p);
    cluster_id = clutch_cpu_to_cluster(home_cpu);
    bucket_id = clutch_bucket_id(p->tgid);

    key.cluster_id = cluster_id;
    key.tgid = p->tgid;

    slot = clutch_group_slot(&key);
    if (!slot)
        return -1;

    slot->cluster_id = cluster_id;
    slot->tgid = p->tgid;
    slot->bucket_id = bucket_id;

    thread = clutch_alloc_thread_node(p, tctx, cluster_id, bucket_id, home_cpu);
    if (!thread)
        return -1;

    if (clutch_queue_thread(slot, &key, thread))
        return -1;

    return 0;
}

static __noinline int clutch_dispatch_thread(struct thread_node *thread, s32 cpu)
{
    struct task_struct *p;
    struct run_accounting *acct;
    struct task_ctx *tctx;
    u32 target_idx;
    s32 target_cpu;

    target_cpu = thread->dispatch_cpu;
    if (target_cpu < 0 || target_cpu >= MAX_CPUS)
        target_cpu = cpu;

    p = bpf_task_from_pid(thread->pid);
    if (!p)
        return -1;

    if (!bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr))
        target_cpu = cpu;

    if (!bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr))
        target_cpu = clutch_pick_home_cpu(p);

    if (target_cpu < 0 || target_cpu >= MAX_CPUS ||
        !bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr))
        target_cpu = cpu;

    target_idx = (u32)target_cpu;
    acct = bpf_map_lookup_elem(&cpu_run_account, &target_idx);
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

    if (acct) {
        acct->wmult = thread->wmult;
        acct->cluster_id = thread->cluster_id;
        acct->bucket_id = thread->bucket_id;
        acct->pid = thread->pid;
        acct->tgid = thread->tgid;
        acct->home_cpu = thread->dispatch_cpu;
        acct->valid = 1;
    }

    if (tctx) {
        tctx->last_run_ns = bpf_ktime_get_ns();
        tctx->cluster_id = thread->cluster_id;
        tctx->bucket_id = thread->bucket_id;
        tctx->home_cpu = thread->dispatch_cpu;
        tctx->is_running = true;
    }

    scx_bpf_dispatch(p,
                     target_cpu == cpu ? SCX_DSQ_LOCAL : (SCX_DSQ_LOCAL_ON | target_cpu),
                     thread->slice_ns ?: DEFAULT_SLICE_NS,
                     0);

    bpf_task_release(p);
    bpf_obj_drop(thread);
    return 0;
}

static __noinline void clutch_requeue_group(struct clutch_bucket *bucket,
                                            const struct group_snapshot *snapshot)
{
    struct group_ref *group;

    if (!bucket || !snapshot || !snapshot->nr_children)
        return;

    group = clutch_alloc_group_ref(&snapshot->key, snapshot->bucket_id);
    if (!group)
        return;

    group->nr_children = snapshot->nr_children;
    group->dispatch_cpu = snapshot->dispatch_cpu;
    group->vruntime = snapshot->vruntime;
    group->seq = snapshot->seq;

    clutch_bucket_add_group(bucket, group);
}

static __always_inline struct group_ref *
clutch_pop_group_from_bucket(struct clutch_bucket *bucket)
{
    struct bpf_rb_node *rb;

    if (!bucket)
        return NULL;

    bpf_spin_lock(&bucket->lock);
    rb = bpf_rbtree_first(&bucket->groups);
    if (rb) {
        rb = bpf_rbtree_remove(&bucket->groups, rb);
        if (rb) {
            struct group_ref *group;

            group = container_of(rb, struct group_ref, rb_node);
            if (bucket->nr_groups)
                bucket->nr_groups--;
            bpf_spin_unlock(&bucket->lock);
            return group;
        }
    }
    bpf_spin_unlock(&bucket->lock);

    return NULL;
}

static __always_inline struct group_ref *
clutch_pick_group(struct cluster_ctx *cluster, u32 cluster_id)
{
    struct clutch_bucket *bucket;
    struct group_ref *group;
    u32 start, first_idx, second_idx;

    bpf_spin_lock(&cluster->lock);
    start = cluster->next_bucket & (NR_CLUTCH_BUCKETS - 1);
    cluster->next_bucket = (start + 1) & (NR_CLUTCH_BUCKETS - 1);
    bpf_spin_unlock(&cluster->lock);

    first_idx = start;
    second_idx = start ^ 1;

    bucket = clutch_bucket_ctx(cluster_id, first_idx);
    group = clutch_pop_group_from_bucket(bucket);
    if (group)
        return group;

    bucket = clutch_bucket_ctx(cluster_id, second_idx);
    group = clutch_pop_group_from_bucket(bucket);
    if (group)
        return group;

    return NULL;
}

SEC("struct_ops/select_cpu")
s32 BPF_PROG(clutch_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;

    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

SEC("struct_ops/enqueue")
int BPF_PROG(clutch_enqueue, struct task_struct *p, u64 enq_flags)
{
    if (clutch_enqueue_task(p))
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, clutch_calculate_slice(p), enq_flags);

    return 0;
}

SEC("struct_ops/dispatch")
int BPF_PROG(clutch_dispatch, s32 cpu, struct task_struct *prev)
{
    struct cluster_ctx *cluster;
    struct clutch_bucket *bucket;
    struct group_ref *group;
    struct group_slot *slot;
    struct thread_node *thread;
    struct bpf_rb_node *rb;
    struct group_key key;
    struct group_snapshot next_snapshot;
    u32 cluster_id;
    bool has_more;

    if (cpu < 0 || cpu >= MAX_CPUS) {
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    cluster_id = clutch_cpu_to_cluster(cpu);
    cluster = clutch_cluster_ctx(cluster_id);
    if (!cluster) {
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    group = clutch_pick_group(cluster, cluster_id);
    if (!group) {
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    bucket = clutch_bucket_ctx(group->cluster_id, group->bucket_id);
    if (!bucket) {
        bpf_obj_drop(group);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    key.cluster_id = group->cluster_id;
    key.tgid = group->tgid;
    slot = bpf_map_lookup_elem(&group_nodes, &key);
    if (!slot) {
        bpf_obj_drop(group);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    bpf_spin_lock(&slot->lock);
    if (slot->seq != group->seq || !slot->nr_children) {
        bpf_spin_unlock(&slot->lock);
        bpf_obj_drop(group);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    rb = bpf_rbtree_first(&slot->children);
    if (!rb) {
        slot->nr_children = 0;
        bpf_spin_unlock(&slot->lock);
        bpf_obj_drop(group);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    rb = bpf_rbtree_remove(&slot->children, rb);
    if (!rb) {
        bpf_spin_unlock(&slot->lock);
        bpf_obj_drop(group);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    thread = container_of(rb, struct thread_node, rb_node);
    if (slot->nr_children)
        slot->nr_children--;
    has_more = clutch_refresh_group_key_locked(slot);
    slot->seq++;
    if (has_more) {
        next_snapshot.key.cluster_id = slot->cluster_id;
        next_snapshot.key.tgid = slot->tgid;
        next_snapshot.bucket_id = slot->bucket_id;
        next_snapshot.nr_children = slot->nr_children;
        next_snapshot.dispatch_cpu = slot->dispatch_cpu;
        next_snapshot.vruntime = slot->vruntime;
        next_snapshot.seq = slot->seq;
    }
    bpf_spin_unlock(&slot->lock);

    if (has_more)
        clutch_requeue_group(bucket, &next_snapshot);

    bpf_obj_drop(group);

    if (clutch_dispatch_thread(thread, cpu)) {
        bpf_obj_drop(thread);
        scx_bpf_consume(SCX_DSQ_GLOBAL);
        return 0;
    }

    return 0;
}

SEC("struct_ops/stopping")
int BPF_PROG(clutch_stopping, struct task_struct *p, bool runnable)
{
    struct run_accounting *acct;
    struct task_ctx *tctx;
    u32 cpu_idx;
    s32 cpu;

    cpu = bpf_get_smp_processor_id();
    if (cpu < 0 || cpu >= MAX_CPUS)
        return 0;

    cpu_idx = (u32)cpu;
    acct = bpf_map_lookup_elem(&cpu_run_account, &cpu_idx);
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

    if (acct && acct->valid && tctx && tctx->last_run_ns) {
        u64 now = bpf_ktime_get_ns();
        u64 delta_ns = now - tctx->last_run_ns;
        u64 delta_v = (delta_ns * NICE_0_LOAD * acct->wmult) >> 32;

        tctx->vruntime += delta_v;
        tctx->last_run_ns = 0;
        tctx->is_running = false;
    }

    if (acct) {
        acct->valid = 0;
        acct->pid = 0;
        acct->tgid = 0;
        acct->wmult = 0;
        acct->home_cpu = -1;
    }

    if (runnable)
        clutch_enqueue_task(p);

    return 0;
}

SEC("struct_ops/enable")
int BPF_PROG(clutch_enable)
{
    bpf_printk("Per-cluster bucket/group/thread CFS skeleton enabled");
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops clutch_ops = {
    .select_cpu = (void *)clutch_select_cpu,
    .enqueue    = (void *)clutch_enqueue,
    .dispatch   = (void *)clutch_dispatch,
    .stopping   = (void *)clutch_stopping,
    .enable     = (void *)clutch_enable,
    .name       = "global_clutch",
};
