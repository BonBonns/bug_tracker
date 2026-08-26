# JS-REAL-R01 — Phase 6: Next Milestone, From Evidence

No engine changes are made in this phase. This nominates, does not implement.

## Applying the decision rule from the brief

> If path/reassignment errors dominate, nominate JS-STATE-R06 — CFG +
> Reaching-Definitions Unification. If sink modeling dominates, nominate a
> framework/security-sink characterization milestone. If return-contract
> visibility dominates, characterize that instead. If another existing fact
> family is the dominant blocker, say so.

Phase 5's root-cause table has exactly one nonzero entry: **RETURN_CONTRACT
(1/1)**. `PATH_SENSITIVITY` and `REACHING_DEFINITION` are both **0** --
despite path/CFG approximation being the limitation explicitly flagged before
this scan started. That is the evidence speaking against a preconception, not
for one: the a-priori "obvious" next step (unify R04/R05 into real CFG
reasoning) is **not** what this corpus's evidence supports as the immediate
next milestone, because R04/R05 never got the chance to be wrong here -- the
base detector fired too rarely for their approximations to matter yet.

`SINK_MODEL` is also 0, but for a different reason than a clean pass: zero
`SENSITIVE` classifications were produced at all, so the sink-matching logic
was never meaningfully exercised (one candidate, no profile match, nothing to
falsely match). This is an absence of data, not a demonstrated success --
stated explicitly so it isn't mistaken for "the sink model works fine."

## Nomination

**Characterize RETURN_CONTRACT visibility.** Proposed name, following the
existing naming convention: **JS-STATE-R06 — Return-Contract Establishment
Characterization.**

Scope (characterization only, matching JS-STATE-R01's original discipline --
no implementation until the characterization supports it):

1. Before the erasure classifier considers a guarded value a candidate,
   characterize whether real Joern facts can establish that the value's
   origin actually carries a distinguishable success/failure return contract
   (a `ReturnStateFact`, in JS-STATE-R01's original vocabulary -- proposed
   but never wired into R02 as a precondition). This is exactly the R01 Q1
   question, revisited with real-code evidence instead of only fixture
   evidence.
2. Characterize the specific failure mode this scan surfaced: a plain,
   non-union-typed object field (`bounce.email`) feeding a closed-set
   coercion operator inside *any* control-structure condition currently
   satisfies R02's pattern. Determine what minimal additional fact (e.g. "is
   the guarded local's ultimate origin's declared/inferred type a union
   containing more than one shape, or explicitly `Error`/`null`/
   `undefined`-typed") would have suppressed this specific false positive
   without suppressing true candidates like the R01 fixture's `case2`.
3. Given the corpus's very low raw-candidate count (1 in 50,638 calls),
   explicitly characterize whether tightening the RETURN_CONTRACT
   requirement further reduces recall on real code -- run against a second,
   independent slice of the corpus (or a second real repository) once a
   return-contract check exists, to see whether it produces zero findings
   entirely, which would itself be a meaningful (if disappointing) result to
   report rather than silently accept.

## Secondary observation, explicitly not promoted to a nomination

The near-zero raw-candidate rate (1 finding across 50,638 calls) is flagged
here as worth future attention, but is **not** nominated as the next
milestone on its own, because:

- It is a recall question, and this scan has no way to measure recall
  (no known-vulnerable ground truth in this corpus was checked against).
- Per instructions, the next milestone must come from the measured dominant
  blocker (RETURN_CONTRACT), not from a separate impression formed alongside
  it. Recording it here keeps it visible without violating that discipline.

## What this nomination is NOT

- Not a claim that CFG/reaching-definitions unification (the originally-
  anticipated "known limitation") is unimportant -- only that it is not what
  THIS corpus's evidence names as the next step. It remains open, undisputed,
  and worth returning to once RETURN_CONTRACT visibility is characterized and
  the base detector's precision/recall profile is better understood on real
  code (a CFG unification pass is more valuable once the base detector fires
  often enough for CFG approximation errors to actually matter).
- Not an implementation. Per Phase 4/6 discipline throughout, no engine code
  changes were made in this pass.
