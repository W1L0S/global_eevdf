#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "eevdf.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv)
{
    struct eevdf_bpf *skel;
    int err;

    /* Set up signal handlers for graceful exit */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Bump RLIMIT_MEMLOCK to allow BPF map creation */
    err = bump_memlock_rlimit();
    if (err) {
        fprintf(stderr, "Failed to increase rlimit: %d\n", err);
        return 1;
    }

    /* Open BPF skeleton */
    skel = eevdf_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & Verify BPF programs */
    err = eevdf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* * Configure Safety Timeout (Watchdog).
     * If the BPF scheduler hangs or fails to dispatch tasks for 5 seconds,
     * the kernel will automatically detach it to prevent system freeze.
     */
    if (skel->struct_ops.eevdf_ops) {
        skel->struct_ops.eevdf_ops->timeout_ms = 5000;
    }

    /* Attach scheduler to the kernel */
    err = eevdf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully loaded Global EEVDF scheduler.\n");
    printf("Watchdog protection enabled (5000ms).\n");
    printf("Press Ctrl+C to stop and detach.\n");

    /* Main loop: keep process alive until signal */
    while (!exiting) {
        sleep(1);
    }

cleanup:
    /* Clean up and detach */
    eevdf_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}