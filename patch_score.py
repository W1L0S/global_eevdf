import sys

with open("src/global_eevdf.bpf.c", "r") as f:
    text = f.read()

# 1. Remove eevdf_candidate_score
start_str = "static __always_inline u64 eevdf_candidate_score"
end_str = "static __always_inline u64 eevdf_calc_V"

start_idx = text.find(start_str)
end_idx = text.find(end_str)

if start_idx != -1 and end_idx != -1:
    text = text[:start_idx] + text[end_idx:]

# 2. Update eevdf_dispatch vars
old_vars = """    u64 wait_bonus_cap = eevdf_cfg_u64(cfg_wait_bonus_cap_ns, WAIT_BONUS_CAP_NS);
    u64 affinity_penalty = eevdf_cfg_u64(cfg_affinity_penalty_ns, AFFINITY_PENALTY_NS);
    u32 k_max = eevdf_dispatch_candidate_limit();"""

new_vars = """    u64 wait_bonus_cap = eevdf_cfg_u64(cfg_wait_bonus_cap_ns, WAIT_BONUS_CAP_NS);
    u64 affinity_penalty = eevdf_cfg_u64(cfg_affinity_penalty_ns, AFFINITY_PENALTY_NS);
    u64 recent_migration_penalty = eevdf_cfg_u64(cfg_recent_migration_penalty_ns, RECENT_MIGRATION_PENALTY_NS);
    u64 interactive_gran = eevdf_cfg_u64(cfg_wakeup_preempt_gran_ns, WAKEUP_PREEMPT_GRAN_NS);
    u64 short_sleep_ns = eevdf_cfg_u64(cfg_interactive_short_sleep_ns, INTERACTIVE_SHORT_SLEEP_NS);
    u64 max_deduction = wait_bonus_cap + interactive_gran;
    u32 k_max = eevdf_dispatch_candidate_limit();"""

text = text.replace(old_vars, new_vars)

# 3. Update EVAL_CANDIDATE
old_macro = """#define EVAL_CANDIDATE(CAND_VAR, SCORE_VAR, CAND_IDX) do { \\
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
} while(0)"""

new_macro = """#define EVAL_CANDIDATE(CAND_VAR, SCORE_VAR, CAND_IDX) do { \\
    node = bpf_rbtree_first(&sctx->ready); \\
    if (node) { \\
        n = container_of(node, struct eevdf_node, node); \\
        if (min_score == ~0ULL || n->vd < min_score + max_deduction) { \\
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
                if (n->last_cpu < MAX_CPUS && n->last_cpu != (u32)cpu && \\
                    n->last_cpu_ts && now_ns > n->last_cpu_ts && \\
                    now_ns - n->last_cpu_ts < short_sleep_ns) { \\
                    score += recent_migration_penalty; \\
                    if (stats) __sync_fetch_and_add(&stats->recent_migration_penalty_hits, 1); \\
                } \\
                if (score > bonus) score -= bonus; else score = 0; \\
                if (bonus > 0 && stats) __sync_fetch_and_add(&stats->wait_bonus_hits, 1); \\
                if (n->interactive_score >= 6) { \\
                    if (score > interactive_gran) score -= interactive_gran; else score = 0; \\
                    if (stats) __sync_fetch_and_add(&stats->interactive_boost_hits, 1); \\
                } \\
                SCORE_VAR = score; \\
                if (score < min_score) { \\
                    min_score = score; \\
                    best_idx = CAND_IDX; \\
                } \\
            } \\
        } \\
    } \\
} while(0)"""

text = text.replace(old_macro, new_macro)

with open("src/global_eevdf.bpf.c", "w") as f:
    f.write(text)

