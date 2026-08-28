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
- **This metric is CONDITION-RELATIVE** — unlike the accuracy target, which is the
  fixed `evidence_reference_conclusion`. A premise may be *supported* in B/C by an
  established scanner fact yet *unsupported* in A, which never received that fact. So
  each response is adjudicated against the **evidence actually supplied to its
  condition** (A: code only; B/C: code + the established facts, in B's bucket form or
  C's focused-question form), **not** the reference packet. The adjudicator is told
  which evidence set the condition received, but stays **blind to the A/B/C
  identity** and to any routing/bucket names.
- The adjudicator also sees the Stage-1 ground-truth evidence basis for the instance.

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
