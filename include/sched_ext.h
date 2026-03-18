#ifndef SCHED_EXT_H
#define SCHED_EXT_H

struct bpf_rb_root {
    struct bpf_rb_node *rb_root;
};

struct bpf_rb_node {
    unsigned long long __rb_node_color;
    struct bpf_rb_node *rb_right;
    struct bpf_rb_node *rb_left;
    struct bpf_rb_node *rb_parent;
};

#endif
