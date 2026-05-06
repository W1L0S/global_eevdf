import sys

with open("src/global_eevdf.bpf.c", "r") as f:
    text = f.read()

start_str = "    u64 best_score = ~0ULL;"
end_str = "    return 0;\n}"
start_idx = text.find(start_str)
end_idx = text.find(end_str, start_idx) + len(end_str)

new_code = """    struct bpf_rb_node *cand0 = NULL;
    struct bpf_rb_node *cand1 = NULL;
    struct bpf_rb_node *cand2 = NULL;
    struct bpf_rb_node *cand3 = NULL;

    u64 score0 = ~0ULL, score1 = ~0ULL, score2 = ~0ULL, score3 = ~0ULL;
    u64 min_score = ~0ULL;
    u8 best_idx = 0;

#define EVAL_CANDIDATE(CAND_VAR, SCORE_VAR, CAND_IDX) do { \\
    node = bpf_rbtree_first(&sctx->ready); \\
    if (node) { \\
        n = container_of(node, struct eevdf_node, node); \\
        if (min_score == ~0ULL || n->vd < min_score + wait_bonus_cap) { \\
            CAND_VAR = bpf_rbtree_remove(&sctx->ready, node); \\
            if (CAND_VAR) { \\
                n = container_of(CAND_VAR, struct eevdf_node, node); \\
                u64 wait_time = (now_ns > n->enqueue_ns) ? (now_ns - n->enqueue_ns) : 0; \\
                u64 bonus = (wait_time > wait_bonus_cap) ? wait_bonus_cap : wait_time; \\
                u64 score = n->vd; \\
                u32 pref_cpu = eevdf_effective_preferred_cpu_node(n, now_ns); \\
                if (pref_cpu != (u32)cpu && n->last_cpu != (u32)cpu) { \\
                    score += affinity_penalty; \\
                    if (stats) __sync_fetch_and_add(&stats->affinity_penalty_hits, 1); \\
                } \\
                score -= bonus; \\
                if (bonus > 0 && stats) __sync_fetch_and_add(&stats->wait_bonus_hits, 1); \\
                SCORE_VAR = score; \\
                if (score < min_score) { \\
                    min_score = score; \\
                    best_idx = CAND_IDX; \\
                } \\
            } \\
        } \\
    } \\
} while(0)

    if (k_max > 0) EVAL_CANDIDATE(cand0, score0, 0);
    if (k_max > 1 && cand0) EVAL_CANDIDATE(cand1, score1, 1);
    if (k_max > 2 && cand1) EVAL_CANDIDATE(cand2, score2, 2);
    if (k_max > 3 && cand2) EVAL_CANDIDATE(cand3, score3, 3);

#undef EVAL_CANDIDATE

    if (!cand0 && !cand1 && !cand2 && !cand3) {
        bpf_spin_unlock(&sctx->lock);
        if (stats)
            stats->dispatch_empty++;
        return 0;
    }

#define FINALIZE_DISPATCH(O_BEST) do { \\
    n = container_of(O_BEST, struct eevdf_node, node); \\
    bpf_spin_unlock(&sctx->lock); \\
    p = bpf_task_from_pid(n->pid); \\
    if (!p) { \\
        if (stats) \\
            __sync_fetch_and_add(&stats->task_lookup_misses, 1); \\
        bpf_spin_lock(&sctx->lock); \\
        sctx->avg_vruntime_sum -= (s64)(n->ve - sctx->base_v) * \\
                                  (s64)eevdf_scaled_weight(n->weight); \\
        sctx->avg_load -= eevdf_scaled_weight(n->weight); \\
        if (sctx->nr_ready) \\
            sctx->nr_ready--; \\
        sctx->V = eevdf_calc_V(sctx); \\
        bpf_spin_unlock(&sctx->lock); \\
        bpf_obj_drop(n); \\
        return 0; \\
    } \\
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0); \\
    if (!tctx || tctx->active_node_seq != n->seq) { \\
        bpf_spin_lock(&sctx->lock); \\
        sctx->avg_vruntime_sum -= (s64)(n->ve - sctx->base_v) * \\
                                  (s64)eevdf_scaled_weight(n->weight); \\
        sctx->avg_load -= eevdf_scaled_weight(n->weight); \\
        if (sctx->nr_ready) \\
            sctx->nr_ready--; \\
        sctx->V = eevdf_calc_V(sctx); \\
        bpf_spin_unlock(&sctx->lock); \\
        bpf_task_release(p); \\
        bpf_obj_drop(n); \\
        return 0; \\
    } \\
    target_cpu = scx_bpf_task_cpu(p); \\
    if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) { \\
        run_local = true; \\
    } else if (target_cpu >= 0 && target_cpu < MAX_CPUS && \\
               bpf_cpumask_test_cpu(target_cpu, p->cpus_ptr)) { \\
        run_local = false; \\
    } else { \\
        abort_dispatch = true; \\
    } \\
    bpf_spin_lock(&sctx->lock); \\
    if (abort_dispatch) { \\
        bpf_rbtree_add(&sctx->ready, &n->node, less_ready); \\
        if (stats) \\
            __sync_fetch_and_add(&stats->dispatch_aborts, 1); \\
        sctx->V = eevdf_calc_V(sctx); \\
        bpf_spin_unlock(&sctx->lock); \\
        bpf_task_release(p); \\
        return 0; \\
    } \\
    w_val = eevdf_scaled_weight(n->weight); \\
    ve = n->ve; \\
    vd = n->vd; \\
    slice = n->slice_ns; \\
    sctx->V = eevdf_calc_V(sctx); \\
    V_now = sctx->V; \\
    bpf_spin_unlock(&sctx->lock); \\
    eevdf_task_ctx_init(tctx); \\
    eevdf_clear_queued_snapshot(tctx); \\
    tctx->run_state = EEVDF_TASK_DISPATCHED; \\
    tctx->last_run_ns = 0; \\
    tctx->saved_vd = vd; \\
    tctx->run_weight_val = w_val; \\
    tctx->run_wmult = n->wmult; \\
    if (!run_local) { \\
        u64 dsq_id = SCX_DSQ_LOCAL_ON | target_cpu; \\
        if (stats) \\
            __sync_fetch_and_add(&stats->remote_dispatches, 1); \\
        scx_bpf_dispatch(p, dsq_id, slice, 0); \\
        eevdf_kick_preempt_if_needed(p, ve, vd, V_now); \\
    } else { \\
        if (stats) \\
            __sync_fetch_and_add(&stats->local_dispatches, 1); \\
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice, 0); \\
    } \\
    bpf_task_release(p); \\
    bpf_obj_drop(n); \\
    return 0; \\
} while(0)

    if (best_idx == 0) {
        if (cand1) bpf_rbtree_add(&sctx->ready, cand1, less_ready);
        if (cand2) bpf_rbtree_add(&sctx->ready, cand2, less_ready);
        if (cand3) bpf_rbtree_add(&sctx->ready, cand3, less_ready);
        FINALIZE_DISPATCH(cand0);
    } else if (best_idx == 1) {
        if (cand0) bpf_rbtree_add(&sctx->ready, cand0, less_ready);
        if (cand2) bpf_rbtree_add(&sctx->ready, cand2, less_ready);
        if (cand3) bpf_rbtree_add(&sctx->ready, cand3, less_ready);
        if (stats) __sync_fetch_and_add(&stats->top_k_improvements, 1);
        FINALIZE_DISPATCH(cand1);
    } else if (best_idx == 2) {
        if (cand0) bpf_rbtree_add(&sctx->ready, cand0, less_ready);
        if (cand1) bpf_rbtree_add(&sctx->ready, cand1, less_ready);
        if (cand3) bpf_rbtree_add(&sctx->ready, cand3, less_ready);
        if (stats) __sync_fetch_and_add(&stats->top_k_improvements, 1);
        FINALIZE_DISPATCH(cand2);
    } else if (best_idx == 3) {
        if (cand0) bpf_rbtree_add(&sctx->ready, cand0, less_ready);
        if (cand1) bpf_rbtree_add(&sctx->ready, cand1, less_ready);
        if (cand2) bpf_rbtree_add(&sctx->ready, cand2, less_ready);
        if (stats) __sync_fetch_and_add(&stats->top_k_improvements, 1);
        FINALIZE_DISPATCH(cand3);
    }

    return 0;
}"""

with open("src/global_eevdf.bpf.c", "w") as f:
    f.write(text[:start_idx] + new_code + text[end_idx:])

