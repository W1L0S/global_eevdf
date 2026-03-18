/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KFUNCS_H
#define _KFUNCS_H

/*
 * EEVDF kfunc 声明
 *
 * 这些函数由内核的 ext_eevdf.c 实现，通过 BPF kfunc 机制调用
 */

#include "vmlinux.h"

/* 树创建和销毁 */
extern struct eevdf_tree *bpf_eevdf_tree_create(void) __ksym;
extern void bpf_eevdf_tree_destroy(struct eevdf_tree *tree) __ksym;

/* 节点添加 */
extern int bpf_eevdf_add(struct eevdf_tree *tree,
                        struct bpf_rb_node *node,
                        bool (*less)(struct bpf_rb_node *a,
                                    const struct bpf_rb_node *b),
                        const struct bpf_eevdf_offsets *offs) __ksym;

/* 节点移除 */
extern struct bpf_rb_node *bpf_eevdf_remove(struct eevdf_tree *tree,
                                            struct bpf_rb_node *node,
                                            const struct bpf_eevdf_offsets *offs) __ksym;

/* 查询操作 */
extern struct bpf_rb_node *bpf_eevdf_first(struct eevdf_tree *tree) __ksym;

/* 可运行性检查 */
extern bool bpf_eevdf_is_eligible(u64 vruntime, u64 avg_vruntime) __ksym;

/* 子树是否有可运行任务 */
extern bool bpf_eevdf_subtree_has_eligible(struct bpf_rb_node *node,
                                          u64 avg_vruntime,
                                          const struct bpf_eevdf_offsets *offs) __ksym;

/* 选择第一个可运行的任务 */
extern struct bpf_rb_node *bpf_eevdf_pick_first_eligible(
    struct eevdf_tree *tree,
    u64 avg_vruntime,
    const struct bpf_eevdf_offsets *offs) __ksym;

/* 更新截止时间 */
extern int bpf_eevdf_update_deadline(struct bpf_rb_node *node,
                                    u64 new_deadline,
                                    const struct bpf_eevdf_offsets *offs) __ksym;

#endif /* _KFUNCS_H */
