# v1 → v2 route transition matrix — complete three-producer population

How much does the frozen v1 88.8% additional-evidence distribution actually change
when the runtime stack-capacity capability (v2) is added — measured over the
**complete three-producer population**, deduplicated to distinct physical
operations by the **frozen** operation fingerprint?

## Method (`transition_matrix_v1_v2.py`)

- Population: `RUNTIME_CAPACITY + CURSOR + INTERPROCEDURAL` over the 10 expansion
  scans — the same "broader population" the audit reported at 88.8%.
- Deduplicated with the **frozen fingerprint imported from
  `build_frozen_corpus._fingerprint`** (not reimplemented) and the frozen
  evidence-monotone canonical rule (most evidence established wins; all producer
  verdicts retained; genuine disagreement flagged `dedup_conflict`).
- Two populations, **identical except the runtime producer**: v1 uses frozen
  `oob_runtime_capacity_verdict`, v2 uses `oob_runtime_capacity_v2`. Cursor and
  interproc are byte-identical in both, so every route change is attributable to
  the runtime stack-capacity capability alone.
- The fingerprint universe is asserted identical between v1 and v2 (v2 changes
  routes of existing operations; it never adds or removes an operation).

## Population — 2,532 fingerprint-distinct operations

**3,246 raw producer records → 2,532 fingerprint-distinct operations** — identical
to the frozen v1 audit baseline, confirming the same population.

"Fingerprint-distinct" means keyed by the frozen fingerprint over
`(_source_label, file, function, line, dest)`: one physical destination-operation
is one case, and repeated raw records at the same site (macro/repeat expansion)
collapse into it. This is a stable aggregation key — it is **not** a claim that
source-level uniqueness was independently established (two truly different writes
that happen to share all five fields would collapse; none such were separately
verified here). All counts below are over this fingerprint-distinct population.

## v1 vs v2 route distribution (2,532 fingerprint-distinct operations)

| route | v1 | v1 % | v2 | v2 % |
|-------|---:|-----:|---:|-----:|
| additional_evidence_required | 2,248 | **88.8%** | 1,628 | **64.3%** |
| semantic_relationship_review | 198 | 7.8% | 696 | 27.5% |
| range_arithmetic_review | 0 | 0.0% | 68 | 2.7% |
| semantic_contract_review | 62 | 2.4% | 62 | 2.4% |
| deterministic_complete | 24 | 0.9% | 78 | 3.1% |

## Transition matrix (v1 route → v2 route)

Only three cells are off-diagonal; **every change originates from
`additional_evidence_required`** and nothing else moves — the expected result,
since v2 augments only runtime records that v1 left `abstained /
required_evidence_absent`:

| v1 route | → v2 route | operations |
|----------|-----------|-----------:|
| additional_evidence_required | semantic_relationship_review | **498** |
| additional_evidence_required | range_arithmetic_review | **68** |
| additional_evidence_required | deterministic_complete | **54** |
| *(all other cells)* | *(unchanged)* | diagonal |

**620 fingerprint-distinct operations change route.** The additional-evidence route falls by
**24.5 points, from 88.8% to 64.3%** — a real, bounded reduction of the frozen
distribution, not a headline estimate.

## Conflict sensitivity — the improvement is not an aggregation artifact

The evidence-monotone canonical rule resolves cross-producer disagreements by
keeping the most-evidence record. Could the 24.5-point drop be an artifact of that
policy? No — the two are **completely disjoint**:

| | value |
|--|------|
| cross-producer conflict groups (v2 population) | 124 |
| of the 620 changed operations, how many are in a conflict group | **0** |
| changed operations outside all conflict groups | **620** |

Re-running the matrix with **all 124 conflict groups excluded**:

| | ops | v1 AE | v2 AE | changed |
|--|----:|------:|------:|--------:|
| excluding conflicts | 2,408 | **93.4%** | **67.6%** | 620 |

Every one of the 2,248 v1 additional-evidence operations lies outside the conflict
groups (conflict groups are ops multiple producers already carried past
abstention), so excluding conflicts removes none of the changes and the drop
persists — a **25.8-point** reduction on the conflict-free population. The
aggregation policy touches none of the 620; the improvement is entirely on
operations where the producers did not disagree.

## Generalization — 148 functions, 49 files, not a few big crypto routines

Is the 24.5-point improvement broad or concentrated in a handful of large crypto
functions? Broad:

| | value |
|--|------|
| distinct functions among the 620 | **148** |
| distinct source files | **49** |
| case families (of E1–E5) touched | 3 — E1, E2, E4 |
| (family, function) pairs | 192 |
| changes concentrated in the top-1 function | 5.8% (`CTS_DecryptUpdate`, 36) |
| changes concentrated in the top-3 functions | 12.6% |

By case family: **E1 = 50, E2 = 204, E4 = 366.** E3 (UTF8) and E5 (AVA) contribute
**0** — they have no stack-fixed-array write pattern, so the capability correctly
does nothing there. Within the three crypto-heavy scans the effect is spread
across 148 functions with no single function above ~6% and the top three under
13%, so the reduction is a general integration improvement, not a few big
functions inflating the headline.

*(The `deterministic_complete` subset alone remains narrow — 54 ops, one comba
pattern plus byte-array key/hash copies — as reported in `EVIDENCE_TRACE.md`. It
is the full 620, dominated by the 566 relationship moves, that generalizes.)*

## Honesty checks

- **Nothing but additional-evidence moved.** The `semantic_contract_review` (62)
  and pre-existing `semantic_relationship_review` / `deterministic_complete`
  operations are untouched; no non-abstained operation changed route.
- **0 runtime promotions masked by another producer.** Every one of the 620
  runtime route changes surfaces as a distinct-operation route change; none is
  hidden because cursor or interproc already dominated that fingerprint with
  equal-or-greater evidence. (Reported field
  `runtime_promotions_masked_by_other_producer = 0`.)
- **124 cross-producer conflicts preserved** in the v2 population
  (`dedup_conflict`), retained under `producer_verdicts` — the merge hides no
  disagreement.
- **Routes are reason-specific, not collapsed to "LLM review."** The 498 semantic
  and 68 range/arithmetic operations keep distinct routes (only the 498 are
  `llm_eligible`); the 54 deterministic prove only
  `write_length_within_destination_capacity`.

## What the 24.5-point reduction does and does not claim

It shows how far the frozen v1 route distribution moves once the runtime producer
consumes stack fixed-array capacity it already had in the normalized facts. It is
measured over the expansion population, with cursor and interproc frozen, so the
movement is attributable to that one capability. It does **not** claim any of the
620 operations is safe: 54 establish the destination-capacity property only, and
566 move to a reviewable route (relationship bound, count/relationship still to be
resolved). The remaining 64.3% additional-evidence population is out of this
capability's reach (normalizer loss, local pointers, name collisions, genuine
multi-identity, heap) and remains future work.

Full matrix, per-operation changes, masked/conflict counts:
`transition_matrix_v1_v2.json`.
