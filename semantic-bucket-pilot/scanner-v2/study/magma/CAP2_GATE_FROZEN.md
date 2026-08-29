# Capability 2 — independent acceptance gate (FROZEN)

Capability 2 is accepted on its OWN recorded evidence, independent of toolchain acceptance.
Runnable gate: `gate_capability_2.py` -> `CAP2_GATE=PASS`. Frontend: joern-c2cpg v4.0.608
(frozen; TOOLCHAIN_FROZEN.md). No model calls, no TChecker.

## Required evidence — each satisfied

1. **Separate delegation-wrapper and counted-writer implementations.**
   Two distinct model files, not one merged model, and each harness asserts the other does
   NOT claim its shape:
   - `cap_wrapper_summary.py` — delegation to a known write sink only.
   - `cap_counted_loop_writer.py` — counted loop through an incremented pointer.

2. **Synthetic positive and adversarial controls.**
   - Delegation positives: `deleg`, `deleg_alias`; adversarial negatives that must NOT be
     summarized: `copy_into` (name-only), `writes_local` (dest not a param), `fixed_len`
     (length not a param), `conflict` (two sinks, different lengths), and `walk` (a loop —
     belongs to the other model).
   - Counted-writer positive: `cw`; adversarial negatives: `no_advance` (single-slot write,
     extent 1 not count), `double_advance` (2 advances/iter), `alien_walk` (unrelated
     local), `two_dests` (two walked params).

3. **Identity, argument-position, conflicting-path, early-exit, zero-count, signedness.**
   - identity: dest bound to a real pointer PARAMETER via one-hop aliasing; name never
     consulted (`deleg_alias`; `copy_into` rejected; `alien_walk` rejected).
   - argument-position: params in NON-standard order bound correctly, not assumed 0/2 —
     `deleg_reordered` (dest arg1, len arg0) and `cw_reordered` (dest arg1, counter arg0).
   - conflicting-path: `conflict` (delegation) and `two_dests` (counted) -> abstain.
   - early-exit: `cw_break` (a `break` in the loop) is still summarized soundly, count as
     the upper bound.
   - zero-count: `cw(big,0)` -> proven safe, never a false overflow.
   - signedness: `cw_signed` (signed counter) -> `count_sign_unresolved` at the call site,
     never proven safe.

4. **Magma development-site recovery on REAL bodies** (frozen scanner recognized 0/2):
   - TIF013 `_TIFFmemcpy` (real delegation body) -> delegation model recognizes, binds
     capacity 512, routes relationship_unresolved on the symbolic length.
   - SSL004 `ascii2ebcdic` (real loop body, OpenSSL crypto/ebcdic.c @ 3bd5319) ->
     counted-writer model recognizes (advance 1, unsigned size_t counter), binds capacity
     1024, routes relationship_unresolved on the symbolic count.

5. **Unchanged frozen outputs outside its new domain.**
   Both models are ADDITIVE (call sites disjoint from the frozen v1 producer ops; 0 ops on
   a bare direct-memcpy file). The frozen `analysis-record-r01` gate still reports
   `ANALYSIS_RECORD_R01=53/53`. capability-1 harness independently re-confirmed ALL PASS
   under 4.0.608.

6. **No SecVulEval / Big-Vul / ARVO held-out results inspected.**
   Enforced by the gate: the model + control sources are grepped and must reference NONE of
   `secvuleval_full`, `study/bigvul`, `study/arvo`, `study/pooled`, `FROZEN_heldout`. The
   controls are synthetic C plus Magma DEVELOPMENT-site real bodies only. The pooled
   held-out corpus (258 sites, 42 families) remains frozen and uninspected; held-out
   measurement is deferred to the confirmatory run under the frozen scanner commit.

## Harness totals (all under 4.0.608)

- `cap_wrapper_summary_test.py`: ALL PASS (delegation controls + arg-position + Magma TIF013
  + separation + additive + no-regression).
- `cap_counted_loop_writer_test.py`: ALL PASS (all six obligation controls + arg-position +
  early-exit + Magma SSL004 + separation + additive + no-regression).
- `gate_analysis_record_r01.py`: 53/53.
- `gate_capability_2.py`: **CAP2_GATE=PASS**.

This gate is FROZEN. Capability 3 (pointer-walk writes) may begin; it must not modify
capability 2's models or move this gate, and its own acceptance is recorded separately.
