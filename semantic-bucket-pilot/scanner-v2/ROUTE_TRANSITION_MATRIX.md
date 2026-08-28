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

## Distinct-operation population

**3,246 raw producer records → 2,532 distinct operations** — identical to the
frozen v1 audit baseline, confirming the same population.

## v1 vs v2 route distribution (2,532 distinct operations)

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

**620 distinct operations change route.** The additional-evidence route falls by
**24.5 points, from 88.8% to 64.3%** — a real, bounded reduction of the frozen
distribution, not a headline estimate.

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
