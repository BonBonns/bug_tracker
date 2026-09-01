# Task #32 reopened, and task #34's aggregator rerun over the same 97 bundles

Per direct instruction, in order: (1) review the 5 R06 `GUARD_MISSING` candidates -- see
`R06_GUARD_MISSING_REVIEW.md`; (2) reopen #32 for the missing reachability tiers, validate the
transitive-call path, keep callback/worker and module-load heuristic-only, feed the validated
tier into `staged_enablement.py` by exact name; (3) rerun task #34's aggregator over the existing
97 bundles, still no Joern rebuild; (4) audit OOB Index precision after reachability is
corrected. This document covers (3) and (4); (1)/(2) are covered in their own commits/documents
(`R06_GUARD_MISSING_REVIEW.md`, `adjudication_registry.py`, `reachability_tier.py`'s own
`TIER_TRANSITIVELY_CALLED_FROM_REGISTERED`, `check_reachability_tier.py`).

## What changed in this rerun, and what did not

Still no Joern rebuild, no new download, no re-running R06 -- only the reachability-dependent
stages were recomputed (`reachability_tier.classify_record_reachability` ->
`adjudication_registry.apply_known_adjudications` -> `staged_enablement.enforce_staged_enablement`
-> `vendored_attribution.attribute_record` -> `six_property_aggregator.aggregate_record`), reusing
each package's own already-preserved `cpp_facts.json`/`js_facts.json` and every raw finding
verbatim from the original replay. `results/replay_records_v2.jsonl` is the full updated output
(same 97 replayed + 3 inherited, same 100/100 accounting); `results/task32_rerun_delta.json` is
the real, computed before/after comparison this document summarizes.

## Real tier transitions (before -> after, real counts)

| Transition | Count |
|---|---|
| TIER_INTERNAL_UNREGISTERED -> TIER_INTERNAL_UNREGISTERED (unchanged) | 3,761 |
| REACHABILITY_UNRESOLVED -> REACHABILITY_UNRESOLVED (unchanged) | 136 |
| **TIER_INTERNAL_UNREGISTERED -> TIER_TRANSITIVELY_CALLED_FROM_REGISTERED** | **5** |

Exactly the 5 findings (4 distinct function sites) independently validated in
`validate_transitive_paths.py` before this tier was wired in -- no surprises, no additional
promotions beyond what was structurally confirmed.

## Adjudication

2 real adjudications newly applied this rerun (node-libcurl's own real Easy::ReadFunction finding
exists in both `r05_findings` and `r06_findings` -- 1 real site, 2 lineage copies, both matched
by exact site identity). Both already `reportable=False` before and after -- the adjudication now
correctly RECORDS the reason (`CONFIRMED_FALSE_POSITIVE`, cited) rather than leaving it an open
precondition.

## Per-property funnel, v1 vs v2 -- real numbers, not asserted

| Property | v1 raw | v1 reportable | v2 raw | v2 reportable | Changed? |
|---|---|---|---|---|---|
| R04 | 2 | 0 | 2 | 0 | no |
| R05 | 7 | 0 | 7 | 0 | no |
| R06 | 7 | 0 | 7 | 0 | no |
| LOCK_BALANCE | 12 | 0 | 12 | 0 | no |
| PROTECTED_FIELD | 233 | 0 | 233 | 0 | no |
| OOB_WRITE | 252 | 0 | 252 | 0 | no |
| **OOB_INDEX_WRITE** | **3290** | **0** | **3290** | **0** | **no** |
| OOB_READ | 115 | 0 | 115 | 0 | no |
| OOB_COMPARE | 0 | 0 | 0 | 0 | no |

**Zero newly-reportable findings anywhere**, including the 5 real, structurally-validated
transitive-call promotions -- they clear the (now-corrected) reachability gate, but `reportable`
still requires `applicability_status == "APPLICABLE"`, which nothing in this pipeline has ever
affirmatively set for a real staged-property finding (the same disclosed gap `R06_GUARD_MISSING_
REVIEW.md` documents for R06's own candidates). Reachability was A bottleneck, never the ONLY
one -- confirmed directly, not assumed, by this real rerun.

Every fail-closed invariant re-verified directly against `replay_records_v2.jsonl` (12/12,
including two new ones specific to this rerun: exactly 5 real transitive-tier promotions
occurred, and none of them are reportable): all PASS. Full combined gate suite (unchanged since
the previous commit, re-confirmed): ALL PASS.

## Step 4: OOB Index precision audit after reachability is corrected

**OOB_INDEX_WRITE's own reachability distribution is IDENTICAL before and after this real
correction: 3,290/3,290 raw candidates, 0 promoted, 0 reportable.** None of the 5 real
transitive-call promotions this rerun found belong to OOB_INDEX_WRITE -- all 5 are LOCK_BALANCE
(3) and OOB_WRITE (2).

This is itself a real, meaningful result for the precision question `REJECTION_FUNNEL_ANALYSIS.
md` raised: a genuine, structurally-validated call-graph walk -- not a heuristic, not a
shortcut, gated on single-target-resolved edges only -- was applied across all 3,290 real
OOB_INDEX_WRITE candidates in this 97-package sample, and found **not one** real, clean path from
any registered export to any of them. Combined with the earlier stratified audit's own findings
(volume concentrated in a small number of vendored dispatch-table-shaped functions; derivation
rule `CPP_FIXED_ARRAY_INDEX_UNBOUNDED`/`CPP_PARAM_LENGTH_PAIR_INDEX_UNBOUNDED` firing on
syntactically-unbounded fixed-array indexing regardless of reachability), this further
strengthens -- does not merely fail to contradict -- the broad-matching-pattern interpretation:
the reachability gap for OOB_INDEX_WRITE specifically is not an artifact of
`reachability_tier.py`'s own previously-narrower scope. A real transitive walk was run against
exactly this property's own real candidates and confirmed the same picture.

**Recommendation, unchanged from `REJECTION_FUNNEL_ANALYSIS.md`, now on stronger evidence:**
OOB_INDEX_WRITE remains the correct precision-audit target before any further scanning, but the
audit should focus on the DETECTOR's own matching breadth (per-function/per-array-name volume
concentration, the top vendored-dispatch-table sites already identified) rather than on
reachability classification -- reachability has now been checked as thoroughly as this corpus
allows (registration, direct JS call, AND a real, validated transitive call-graph walk), and the
result is unchanged.

## What remains deferred, per direct instruction

- `CALLBACK_OR_WORKER_HEURISTIC` (124 real candidates) and `MODULE_LOAD_EXECUTION_HEURISTIC` (7)
  stay diagnostic-only -- explicitly NOT added to `staged_enablement.py`'s allowlist, pending
  their own dedicated positive/negative/ambiguity controls (not built in this round).
- The 4 pqclean candidates (`R06_GUARD_MISSING_REVIEW.md`) stay un-adjudicated -- genuinely new,
  first-seen sites, never individually reviewed with the rigor node-libcurl's own case had.
- The remaining 394 packages stay paused.
- OOB_COMPARE (task #40) stays disabled.

---
*Rerun over the SAME 97 preserved bundles, no Joern rebuild. `results/replay_records_v2.jsonl`
and `results/task32_rerun_delta.json` carry the full real detail behind every number above.*
