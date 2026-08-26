# JS-REAL-R01 — Phase 5: Residual Characterization

## Residual table

| | count |
|---|---|
| Total findings (raw erasure candidates) | 1 |
| True candidates | 0 |
| Demonstrated false positives | 1 |
| Unresolved | 0 |

100% of findings were fully adjudicated; nothing was left in a `NEEDS_REVIEW`
state. n=1 on this corpus, so this table is not itself statistically
meaningful -- it is reported honestly as n=1, not dressed up as a rate.

## False positives by root cause

| Root cause | count |
|---|---|
| PATH_SENSITIVITY | 0 |
| REACHING_DEFINITION | 0 |
| RETURN_CONTRACT | 1 |
| SINK_MODEL | 0 |
| PROPERTY_FLOW | 0 |
| EXTERNAL_CALL | 0 |
| FRAMEWORK_SEMANTICS | 0 |
| OTHER | 0 |

## What is the largest measured blocker on real code?

Based on this single data point, **RETURN_CONTRACT** (the erasure classifier
firing without first establishing that the guarded value's origin actually
has a distinguishable success/failure return contract) is the only root
cause observed. It is also the only root cause *possible* to observe at n=1,
so this is a weak basis for a strong claim -- stated explicitly rather than
overreaching from one example.

**The more informative and more robust finding from this phase is structural,
not statistical: on 77,966 LOC / 50,638 calls / 2,098 control structures of
real authentication-server code, the erasure classifier fired exactly once.**
This is a much stronger signal about the pipeline's current *precision
ceiling* than about any one root cause's dominance:

- R04 (then-branch exclusion) and R05 (reassignment exclusion) had **zero
  opportunities to fire** on this corpus -- not because they don't work
  (JS-STATE-R03..R05's fixtures already prove they do, on synthetic cases
  built specifically to need them), but because the base erasure detector
  essentially never matches real code in the first place. Real code very
  rarely writes `guard(coerce(riskyResult))` in the narrow shape R02 detects
  (a small closed set of coercion builtins/operators feeding directly into a
  comparison inside a guard condition). This suggests the current fact
  family's RECALL, not its precision, may be the larger open question -- a
  question this scan cannot answer (a single false positive says nothing
  about false negatives), but one the near-zero raw-candidate count makes
  newly visible.
- The one candidate that did fire failed for a reason (RETURN_CONTRACT) that
  is upstream of and independent from R04/R05's known line/AST
  approximations entirely. **The "known limitation" carried into this scan
  (path/CFG approximation) was not the thing that produced this scan's one
  false positive.** That's a meaningful, disconfirming data point against
  assuming the documented limitation is automatically the most important one
  in practice -- it wasn't, here.

## Explicit caution against overreaching from one example

Per instructions, this phase does not choose a next milestone from one
interesting example. A single false positive, however cleanly explained,
does not establish that RETURN_CONTRACT dominates false positives on JS/TS
code in general -- it only establishes that it happened once, here, and that
the two already-known approximations (R04/R05) were not implicated. Phase 6
weighs this together with the near-zero-recall observation above, not the
false-positive count alone.
