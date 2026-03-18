/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _EEVDF_TYPES_H
#define _EEVDF_TYPES_H

/*
 * EEVDF 类型定义 - 必须在 vmlinux.h 之前定义
 *
 * 这些类型必须与内核中的定义完全匹配。
 */

#include <bpf/bpf_helper_defs.h>

/* 基础类型定义 */
#ifndef __bpf__

struct rb_node {
    unsigned long __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((preserve_access_index));

struct rb_root {
    struct rb_node *rb_node;
} __attribute__((preserve_access_index));

typedef struct {
    int __val[2];
} spinlock_t __attribute__((preserve_access_index));

/*
 * EEVDF 树结构 - 必须与 kernel/sched/ext_eevdf.c 中的定义完全匹配
 */
struct eevdf_tree {
    struct rb_root root;
    spinlock_t lock;
} __attribute__((preserve_access_index));

#endif /* __bpf__ */

#endif /* _EEVDF_TYPES_H */
