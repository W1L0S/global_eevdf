/* EEVDF 测试 - 新签名（使用结构体参数） */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "kfuncs.h"

char LICENSE[] SEC("license") = "GPL";

/* 任务结构体 */
struct task_ctx {
	struct bpf_rb_node rb_node;
	u64 vruntime;
	u64 deadline;
	u64 min_vruntime;
	u64 weight;
};

/* 全局红黑树 */
struct bpf_rb_root tasks_tree SEC(".data");

/* 全局偏移量结构体 */
const struct bpf_eevdf_offsets offs = {
	.vruntime_offset = offsetof(struct task_ctx, vruntime),
	.deadline_offset = offsetof(struct task_ctx, deadline),
	.min_vruntime_offset = offsetof(struct task_ctx, min_vruntime),
	.node_offset = offsetof(struct task_ctx, rb_node),
};

/* 当前平均 vruntime */
const volatile u64 avg_vruntime = 0;

/* 比较函数 - 按 deadline 排序 */
static bool task_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct task_ctx *ta = container_of(a, struct task_ctx, rb_node);
	struct task_ctx *tb = container_of(b, struct task_ctx, rb_node);
	return ta->deadline < tb->deadline;
}

/* 测试：添加任务到 EEVDF 树 */
SEC("syscall")
int test_add_task(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 初始化字段 */
	ctx->vruntime = avg_vruntime;
	ctx->deadline = ctx->vruntime + (1000000000 / (ctx->weight ?: 1));
	ctx->min_vruntime = ctx->vruntime;

	/* 使用新的 bpf_eevdf_add (4 参数) */
	return bpf_eevdf_add(&tasks_tree, &ctx->rb_node, task_less, &offs);
}

/* 测试：从 EEVDF 树移除任务 */
SEC("syscall")
int test_remove_task(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 使用新的 bpf_eevdf_remove (3 参数) */
	struct bpf_rb_node *node = bpf_eevdf_remove(&tasks_tree, &ctx->rb_node, &offs);

	return node ? 0 : -1;
}

/* 测试：检查任务是否 eligible */
SEC("syscall")
int test_is_eligible(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 使用 bpf_eevdf_is_eligible (2 参数) */
	return bpf_eevdf_is_eligible(ctx->vruntime, avg_vruntime);
}

/* 测试：选取第一个 eligible 任务 */
SEC("syscall")
int test_pick_first(void)
{
	/* 使用新的 bpf_eevdf_pick_first_eligible (3 参数) */
	struct bpf_rb_node *node = bpf_eevdf_pick_first_eligible(&tasks_tree, avg_vruntime, &offs);

	if (!node)
		return -1;

	struct task_ctx *t = container_of(node, struct task_ctx, rb_node);
	return t->weight;
}

/* 测试：更新任务 deadline */
SEC("syscall")
int test_update_deadline(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 计算新的 deadline */
	u64 new_deadline = ctx->vruntime + (500000000 / (ctx->weight ?: 1));

	/* 使用新的 bpf_eevdf_update_deadline (3 参数) */
	return bpf_eevdf_update_deadline(&ctx->rb_node, new_deadline, &offs);
}

/* 测试：检查子树是否有 eligible 任务 */
SEC("syscall")
int test_subtree_eligible(struct task_ctx *ctx)
{
	if (!ctx)
		return -1;

	/* 使用新的 bpf_eevdf_subtree_has_eligible (3 参数) */
	return bpf_eevdf_subtree_has_eligible(&ctx->rb_node, avg_vruntime, &offs);
}
