#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "test_kfuncs.skel.h"

static volatile bool exiting = false;
static int count = 0;
static int total_passed = 0;

struct result {
    uint32_t test_id;
    uint32_t passed;
    uint64_t value;
};

const char *test_names[] = {
    "",  /* 0 */
    "tree_create/destroy",
    "is_eligible",
    "first (empty tree)",
    "pick_first_eligible",
    "update_deadline (NULL)",
    "subtree_has_eligible (NULL)",
};

static int handle_event(void *ctx, void *data, size_t len) {
    struct result *r = data;
    const char *name = (r->test_id < 7) ? test_names[r->test_id] : "unknown";
    printf("Test %d (%s): %s", r->test_id, name,
           r->passed ? "PASS" : "FAIL");
    if (r->value != 0 || r->test_id == 5)
        printf(" (value=%llu)", r->value);
    printf("\n");

    count++;
    if (r->passed) total_passed++;
    return 0;
}

static void sig_handler(int sig) { exiting = true; }

static int bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(void) {
    struct test_kfuncs_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase rlimit: %d\n", err);
        return 1;
    }

    skel = test_kfuncs_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("Loading BPF program...\n");
    err = test_kfuncs_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        test_kfuncs_bpf__destroy(skel);
        return 1;
    }
    printf("BPF program loaded successfully!\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ringbuffer: %d\n", errno);
        test_kfuncs_bpf__destroy(skel);
        return 1;
    }

    struct bpf_program *prog;
    struct bpf_link *link;
    int attached = 0;
    bpf_object__for_each_program(prog, skel->obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "Failed to attach %s: %d\n",
                   bpf_program__name(prog), errno);
        } else {
            attached++;
        }
    }

    if (attached == 0) {
        fprintf(stderr, "No programs attached!\n");
        ring_buffer__free(rb);
        test_kfuncs_bpf__destroy(skel);
        return 1;
    }
    printf("Attached %d programs\n\n", attached);

    printf("Running tests...\n\n");

    while (!exiting && count < 12) {
        system("echo test");
        ring_buffer__poll(rb, 100);
    }

    printf("\n=== Test Summary ===\n");
    printf("Total: %d, Passed: %d, Failed: %d\n",
           count, total_passed, count - total_passed);

    ring_buffer__free(rb);
    test_kfuncs_bpf__destroy(skel);
    return (total_passed == count) ? 0 : 1;
}
