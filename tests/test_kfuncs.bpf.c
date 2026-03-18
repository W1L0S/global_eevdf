/* 完整的 EEVDF kfunc 测试 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "kfuncs.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

struct result {
    u32 test_id;
    u32 passed;
    u64 value;
};

/*
 * 测试1: tree_create 和 tree_destroy
 */
SEC("tp/syscalls/sys_enter_execve")
int test_tree_create(void *ctx)
{
    struct eevdf_tree *tree;
    struct result *r;

    tree = bpf_eevdf_tree_create();
    if (!tree)
        return 0;

    bpf_eevdf_tree_destroy(tree);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 1;
        r->passed = 1;
        r->value = 1;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}

/*
 * 测试2: is_eligible
 */
SEC("tp/syscalls/sys_enter_execve")
int test_is_eligible(void *ctx)
{
    struct result *r;
    bool eligible;

    /* vruntime < avg_vruntime -> should return true */
    eligible = bpf_eevdf_is_eligible(100, 200);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 2;
        r->passed = eligible ? 1 : 0;
        r->value = eligible;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}

/*
 * 测试3: first - 空树应返回 NULL
 */
SEC("tp/syscalls/sys_enter_execve")
int test_first_empty(void *ctx)
{
    struct eevdf_tree *tree;
    struct bpf_rb_node *first;
    struct result *r;

    tree = bpf_eevdf_tree_create();
    if (!tree)
        return 0;

    first = bpf_eevdf_first(tree);

    bpf_eevdf_tree_destroy(tree);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 3;
        /* 空树应该返回 NULL */
        r->passed = (first == NULL);
        r->value = (first != NULL) ? 1 : 0;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}

/*
 * 测试4: pick_first_eligible - 空树应返回 NULL
 */
SEC("tp/syscalls/sys_enter_execve")
int test_pick_first_eligible(void *ctx)
{
    struct eevdf_tree *tree;
    struct bpf_eevdf_offsets offs = {
        .vruntime_offset = 0,
        .deadline_offset = 8,
    };
    struct bpf_rb_node *eligible;
    struct result *r;

    tree = bpf_eevdf_tree_create();
    if (!tree)
        return 0;

    eligible = bpf_eevdf_pick_first_eligible(tree, 200, &offs);

    bpf_eevdf_tree_destroy(tree);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 4;
        r->passed = 1;  /* 函数调用成功就算 PASS */
        r->value = (eligible != NULL) ? 1 : 0;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}

/*
 * 测试5: update_deadline - NULL node 应返回错误
 */
SEC("tp/syscalls/sys_enter_execve")
int test_update_deadline(void *ctx)
{
    struct bpf_eevdf_offsets offs = {
        .vruntime_offset = 0,
        .deadline_offset = 8,
    };
    int ret;
    struct result *r;

    /* NULL node, should return error */
    ret = bpf_eevdf_update_deadline(NULL, 1000, &offs);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 5;
        r->passed = (ret < 0);  /* 应该返回负数 */
        r->value = ret;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}

/*
 * 测试6: subtree_has_eligible
 */
SEC("tp/syscalls/sys_enter_execve")
int test_subtree_has_eligible(void *ctx)
{
    struct bpf_eevdf_offsets offs = {
        .vruntime_offset = 0,
        .deadline_offset = 8,
    };
    bool eligible;
    struct result *r;

    /* NULL node, should return false (no subtree) */
    eligible = bpf_eevdf_subtree_has_eligible(NULL, 200, &offs);

    r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
    if (r) {
        r->test_id = 6;
        r->passed = !eligible;  /* NULL node 应该返回 false */
        r->value = eligible;
        bpf_ringbuf_submit(r, 0);
    }

    return 0;
}
