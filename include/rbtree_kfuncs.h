/* rbtree kfunc 声明 */
#ifndef __RBTREE_KFUNCS_H
#define __RBTREE_KFUNCS_H

#include <vmlinux.h>

/* bpf_rbtree_add_augmented 和 bpf_rbtree_remove_augmented 已在 kfuncs.h 中声明 */

extern struct bpf_rb_node *bpf_rbtree_next(struct bpf_rb_node *node);
extern struct bpf_rb_node *bpf_rbtree_prev(struct bpf_rb_node *node);
extern struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root);

#endif
