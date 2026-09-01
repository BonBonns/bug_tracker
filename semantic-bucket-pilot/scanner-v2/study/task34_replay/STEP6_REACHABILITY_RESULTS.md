# Roadmap step 6: remaining unknown reachability paths -- results

Per direct instruction ("Finish the remaining unknown reachability paths: Validate
callback/worker reachability. Validate module-load execution. Rerun the 97-package
aggregator."). Both heuristics `reachability_tier.py`'s own docstring had explicitly deferred
(task #32's own reopened-but-still-partial scope: "the callback/worker and module-load
heuristics... stay OUT of this module and OUT of staged_enablement.py's allowlist --
explicitly deferred... pending their own dedicated positive/negative/ambiguity controls") are
now built, validated, wired in, and their real corpus consequences manually reviewed.

## What was built

1. **`reachability_tier.resolve_method_ref_targets()`** -- a self-contained port of
   `reachability_deep_dive.py`'s own METHOD_REF-argument resolver.
2. **`reachability_tier.CALLBACK_OR_WORKER_REGISTRATION_APIS`** -- a real, narrow, cited
   allowlist (`pthread_create`, `thrd_create`, `uv_queue_work`, `napi_create_async_work`,
   `napi_create_threadsafe_function`, `sqlite3_create_function[_v2]`,
   `sqlite3_create_window_function`, `sqlite3_exec`, `CreateThread`), built from a real
   per-candidate audit (`callback_worker_classifier_audit.py`) that found 118 of the original
   heuristic's own 124 real matches (95%) were pure structural noise (a function pointer
   appearing as an operand of `<operator>.arrayInitializer`/`.cast`/`.assignment`/`.addressOf`,
   never a real registration) -- the new tier (`TIER_CALLBACK_OR_WORKER_PROVEN`) only fires for
   the allowlisted shape.
3. **Module-load execution, reusing `find_clean_transitive_path` with `Init` as the root set**
   (`TIER_MODULE_LOAD_EXECUTION_PROVEN`) -- a real per-candidate audit
   (`module_load_classifier_audit.py`) confirmed all 7 of the original heuristic's own real
   occurrences (concentrated in one function, `@elchetz/cld@2.8.5`'s `GetLanguageFromName`) have
   a real, clean (single-target-resolved at every hop), hop-by-hop-verified 5-hop path from the
   addon's own `Init`: `Init -> Constants::getInstance() -> Constants::Constants() -> init() ->
   initLanguages() -> CLD2::GetLanguageFromName`.
4. **`check_reachability_tier.py`**: 34/34 (was 25/25) -- added positive/negative/ambiguity
   synthetic controls for both new tiers plus 2 real smoke tests (`@appthreat/sqlite3`'s real
   `sha1QueryFunc`/`sqlite3_create_function`, `@elchetz/cld`'s real `GetLanguageFromName`) --
   caught and fixed a real bug in the process: an earlier draft of `classify_record_reachability`
   never actually computed/passed `init_ids` through, so the module-load tier would never have
   fired in the live pipeline despite the synthetic unit tests passing -- the real smoke test is
   what caught it, exactly the kind of gap a synthetic-only test suite misses.
5. **`staged_enablement._EXTERNALLY_REACHABLE_TIERS`**: both new tiers added by exact name (now
   5 tiers total), per this module's own established discipline (never broadened via loosened
   "any non-internal tier" logic).
6. **`rerun_aggregator_step6.py`**: reran the full aggregator (reachability_tier ->
   applicability_gate -> adjudication_registry -> staged_enablement -> vendored_attribution ->
   six_property_aggregator) over the same 97 preserved bundles, no Joern rebuild. Caught and
   fixed a second real bug: an initial draft omitted the `applicability_gate.apply_applicability()`
   step entirely (the documented real pipeline order, per `rerun_aggregator_applicability.py`'s
   own docstring), which silently left every newly-promoted candidate's own
   `applicability_status` at `NOT_YET_DETERMINED` -- caught by checking `reportable` directly
   against the real per-candidate detail, not assumed correct from the tier transition counts
   alone.

## Real result: 13 real reachability tier transitions, all corpus-wide

```
TIER_INTERNAL_UNREGISTERED -> TIER_MODULE_LOAD_EXECUTION_PROVEN: 7
TIER_INTERNAL_UNREGISTERED -> TIER_CALLBACK_OR_WORKER_PROVEN: 6
```

Exactly matching each audit's own real, pre-computed count -- no surprises, no additional
promotions from anywhere else in the 97-package sample. This produced 13 newly `reportable=True`
findings (2 `lock_balance_findings`, 4 `oob_write_candidates`, 7 `oob_index_write_candidates`)
across 6 real function-level sites in 4 packages.

## Manual review: all 13 are false positives (`STEP6_PROMOTIONS_MANUAL_REVIEW.md`)

Per the same precedent `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md` set for task #32's earlier
reopened tier, these 13 were manually reviewed against the real, pinned, hash-verified source
BEFORE this round could be considered complete -- never left as an unreviewed surprise. Two
real, distinct root causes, both disclosed and both directly relevant to roadmap step 7's own
scope:

- **`ggml_graph_compute_secondary_thread`** (2 packages, `lock_balance_findings`) -- a real
  CFG-precision gap: the flagged lock is genuinely matched by an unlock within the same nested
  loop, before any path reaches the function's own return. Not the earlier "primitive-wrapper"
  shape (task #32's own 5 promotions) -- a new, distinct false-positive class.
- **`GetLanguageFromName`** (`@elchetz/cld`, `oob_write_candidates`) and **3 vendored SQLite
  functions** (`@appthreat/sqlite3`, `oob_index_write_candidates`) -- a real bound-propagation
  gap: an earlier guard (`if(len>=16) return;`) or a small, provably-constant loop bound
  (`i<3`, `i<nCol`) is not propagated to a later indexed write/offset, even though the write is
  real, in-bounds, and provably safe by direct hand-verification.

6 of the 13 (both `lock_balance_findings`, all 4 `oob_write_candidates` -- the ones carrying a
real, unique `site_id`/`lock_call_id`) are now suppressed via 6 new, cited
`adjudication_registry.py` entries. The remaining 7 (`oob_index_write_candidates`) stay
`reportable=True`, correctly documented as false positives but not yet mechanically
suppressible -- `oob_index_write_candidates` has no populated `site_id` field (a real, disclosed,
separate gap; entering an adjudication on a shared `None` key would silently veto every future
finding for that property on these packages, which this registry's own discipline forbids).

## Final, real funnel (`results/replay_records_v7.jsonl`, after adjudication)

```
lock_balance_findings:       raw=12  reportable=0  (was 0, briefly 2, now 0 again -- correctly suppressed)
oob_write_candidates:        raw=252 reportable=0  (was 0, briefly 4, now 0 again -- correctly suppressed)
oob_index_write_candidates:  raw=3290 reportable=7 (was 0, now 7 -- real, disclosed, unsuppressible false positives)
nan_findings:                raw=22  reportable=3  (unchanged -- task 4's own result)
```

**Net real effect of this round: the 97-package funnel's only reportable=True findings remain
node-snap7's own 3 Nan candidates, PLUS 7 real, individually-reviewed-and-disclosed
`oob_index_write_candidates` false positives that cannot yet be mechanically suppressed.** This
is a smaller, cleaner, fully-explained set than the raw tier-promotion count (13) suggested --
exactly the outcome the manual-review discipline exists to produce.

## What this leaves open, disclosed

- `oob_index_write_candidates`'s own missing `site_id` field is real follow-up work (not fixed
  here, out of this step's own scope) -- needed before its own false positives can be
  individually suppressed the same way `oob_write_candidates`'s can.
- The two real false-positive root causes found here (`lock_balance_verdict.py`'s nested-loop
  CFG imprecision; `CPP_FIXED_ARRAY_INDEX_UNBOUNDED`/`CPP_PARAM_LENGTH_PAIR_INDEX_UNBOUNDED`'s
  own bound-propagation gap) are real, concrete evidence for roadmap step 7's own listed
  "structural false-positive families" -- not the SAME shapes task #32's own 5 promotions
  found (primitive-wrapper functions, cross-variable `sizeof()` equivalence), but closely
  related precision gaps in the same two analyzers, now documented with real, reproducible
  examples for that step's own fix.
