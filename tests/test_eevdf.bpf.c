/* EEVDF Scheduler Test - BPF Program */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kfuncs.h"

/* 任务结构体 - 包含 EEVDF 所需字段 */
struct task_ctx {
	struct bpf_rb_node rb_node;
	u64 vruntime;
	u64 deadline;
	u64 min_vruntime;
	u64 weight;
};

/* 全局红黑树根 */
struct bpf_rb_root tasks_tree SEC(".data");

/* EEVDF 偏移量结构体 - 新API使用 */
const struct bpf_eevdf_offsets offs = {
	.vruntime_offset = offsetof(struct task_ctx, vruntime),
	.deadline_offset = offsetof(struct task_ctx, deadline),
	.min_vruntime_offset = offsetof(struct task_ctx, min_vruntime),
	.node_offset = offsetof(struct task_ctx, rb_node),
};

/* 当前最小 vruntime (系统平均) */
const volatile u64 avg_vruntime = 0;

/* 任务计数 */
volatile u64 task_count = 0;

/* EEVDF 比较函数 - 按 deadline 排序 */
static bool task_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct task_ctx *ta = container_of(a, struct task_ctx, rb_node);
	struct task_ctx *tb = container_of(b, struct task_ctx, rb_node);

	return ta->deadline < tb->deadline;
}

/* 测试：添加任务到 EEVDF 树 */
SEC("syscall")
int add_task(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 初始化字段 */
	ctx->vruntime = avg_vruntime;
	ctx->deadline = ctx->vruntime + (1000000000 / (ctx->weight ?: 1));
	ctx->min_vruntime = ctx->vruntime;

	/* 使用新的 EEVDF kfunc 添加任务 (4参数API) */
	long ret = bpf_eevdf_add(&tasks_tree, &ctx->rb_node, task_less, &offs);

	if (ret == 0)
		__sync_fetch_and_add(&task_count, 1);

	return ret;
}

/* 测试：从 EEVDF 树移除任务 */
SEC("syscall")
int remove_task(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	struct bpf_rb_node *node = bpf_eevdf_remove(&tasks_tree, &ctx->rb_node, &offs);

	if (node) {
		__sync_fetch_and_sub(&task_count, 1);
		return 0;
	}
	return -1;
}

/* 测试：检查任务是否 eligible */
SEC("syscall")
int check_eligible(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 任务 eligible 当 vruntime <= avg_vruntime */
	return bpf_eevdf_is_eligible(ctx->vruntime, avg_vruntime);
}

/* 测试：选取第一个 eligible 任务 */
SEC("syscall")
int pick_eligible(void)
{
	struct bpf_rb_node *node;

	node = bpf_eevdf_pick_first_eligible(&tasks_tree, avg_vruntime, &offs);

	if (!node)
		return -1; /* 没有 eligible 任务 */

	struct task_ctx *t = container_of(node, struct task_ctx, rb_node);
	return t->weight; /* 返回权重作为测试 */
}

/* 测试：更新任务 deadline */
SEC("syscall")
int update_deadline(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 新的 deadline = vruntime + slice/weight */
	u64 new_deadline = ctx->vruntime + (500000000 / (ctx->weight ?: 1));

	return bpf_eevdf_update_deadline(&ctx->rb_node, new_deadline, &offs);
}

/* 测试：检查子树是否有 eligible 任务 */
SEC("syscall")
int subtree_has_eligible(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	return bpf_eevdf_subtree_has_eligible(&ctx->rb_node, avg_vruntime, &offs);
}

char LICENSE[] SEC("license") = "GPL";
