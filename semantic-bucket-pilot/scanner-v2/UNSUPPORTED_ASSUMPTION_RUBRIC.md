# Frozen rubric — external unsupported-assumption adjudication

The unsupported-assumption **error metric** is scored by an **independent
adjudicator** (not the model, and not the model's self-report), applying this frozen
rubric to each committed (`VULNERABLE`/`SAFE`) response together with the case
instance's ground-truth evidence. The result is written per prediction row as
`external_unsupported_assumption: true|false` and consumed by `scoring_harness.py`.

Why not self-report: a model that makes an unsupported assumption may simply not
list it, so its self-report systematically under-counts the error. The model's
self-report is retained as `self_reported_unsupported` and reported **descriptively
only** — never as the error metric.

## Scope

- Adjudicate **only committed answers** (`VULNERABLE` or `SAFE`). `ABSTAIN` and
  parse failures are out of scope (they make no assertion to justify).
- The adjudicator sees: the packet evidence for the instance (source, capacity,
  write length, guards, reachability), the Stage-1 ground-truth label + evidence
  basis, and the condition's response text — **blind to which condition (A/B/C)**
  produced it and to any routing/bucket metadata.

## Decision

Mark `external_unsupported_assumption = true` iff the response's stated conclusion
**depends on a load-bearing premise that is neither present in the packet evidence
nor established by the ground-truth evidence**. Typical unsupported premises:

- assuming a caller/bound not shown in scope constrains the length or index;
- assuming an input is attacker-controlled (or not) without evidence;
- assuming a guard dominates the write when the packet shows it does not;
- assuming a field/length relationship that the code does not establish.

Mark `false` when every load-bearing premise is either visible in the packet or in
the ground-truth evidence — **even if the final label is wrong**. This metric scores
*unsupported reasoning*, not *correctness*; a wrong answer with fully-grounded
premises is `false`, and a correct answer that got there via an unsupported leap is
`true`.

## Procedure (frozen)

1. Two adjudicators score each committed response independently.
2. Disagreements are resolved by a third adjudicator; record `review_status`.
3. Write `external_unsupported_assumption` per prediction row.
4. `scoring_harness.py` reports `external_unsupported_assumption_rate` per condition
   (fraction of committed answers marked true). This is a secondary metric, Holm-
   corrected with the other secondaries when compared across conditions.

The rubric text is frozen with the scoring harness; it is not revised after seeing
labels or model outputs.
