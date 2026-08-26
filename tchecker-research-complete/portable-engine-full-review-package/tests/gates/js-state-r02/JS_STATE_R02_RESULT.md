# JS-STATE-R02 — Failure-State Erasure: ERASES-only implementation

## Status: IMPLEMENTED, real run, PASS

```text
JS_STATE_R02=28/28
```

(Was `24/24` at first implementation; grew to `26/26` after `case13` was added,
then `28/28` after `case14` was added — both as part of the JS-STATE-R04/R05
branch- and reassignment-awareness follow-ups. case13 and case14 both have the
same Number()-before-instanceof-Error erasure shape as case2, so R02 correctly
flags both regardless of where their sink calls sit or whether the guarded
local is later reassigned; branch/reassignment reasoning is JS-STATE-R04/R05's
concern, not R02's. See
`tests/gates/js-state-r03/JS_STATE_R03_RESULT.md`.)

Run against a real Joern install (joern-cli, `codepropertygraph-domain-classes
1.7.70`), real `jssrc2cpg` output, no stored/pre-computed fixtures. Wired into
`tests/run_all.py` (id 117, blocked cleanly if `JSSRC2CPG`/`JOERN` are unset, same
pattern as JSTS-R05). Verified with zero regressions to Gate 24-TS (`27/27`) or
JSTS-R05 (`8/8`), both of which share the modified `export_ts_facts.sc`.

## Scope

Implements **only** the narrowest sound invariant JS-STATE-R01 identified as
ready to promote:

> A guard on instanceof/equality/relational comparison protects the exact value
> it structurally checks (via REF), and only that value. If the checked value's
> producing CALL is a member of a closed set of builtins/operators with
> spec-fixed, argument-shape-sensitive coercion semantics that are known to
> destroy a prior value's failure discriminator, the guard must not be credited
> as protecting the original callee result.

Deliberately **not** implemented (per JS-STATE-R01 Q4/Q5, both explicitly out of
scope for this milestone):

- PRESERVES detection (structural passthrough proof, e.g. `identity()`) —
  case5 correctly stays silent, but not because Fable proved preservation; the
  transformation just isn't in the closed erasing set. This is a correct
  non-claim, not a proof of safety.
- UNKNOWN/abstain bookkeeping for arbitrary external calls — case6
  (`externalNormalize`) correctly stays silent for the same reason. Silence here
  means "not flagged as this specific bug shape," never "proven safe."
- Security-sensitive-sink classification — every emitted fact is a
  `FailureStateErasureCandidateFact`, never a verdict. case7/10/11/12 are all
  flagged even though they reach `unrelatedSink`, not `authenticate`, because
  reachability-to-a-sensitive-sink is explicitly out of scope; a downstream
  profile (mirroring `SINK-R01`/`SOURCE-R02`'s pattern) would need to consume
  these facts and add that judgment separately.

## What was added

- `frontends/javascript-typescript/joern-ts/export_ts_facts.sc` — two new
  exports, promoted from JS-STATE-R01's ad-hoc characterization queries into the
  real, shared pipeline: `control_structures.tsv` (condition subtree root per
  `if`/etc.) and `condition_identifiers.tsv` (every identifier in a condition's
  **full** AST subtree — not just direct children, fixing the shallow-walk bug
  JS-STATE-R01 found via case3 — resolved to its LOCAL/PARAMETER via `REF`).
- `frontends/javascript-typescript/joern-ts/failure_state_facts.py` — the
  `FailureStateErasureCandidateFact` normalizer. Classification is table-driven
  against a closed, spec-fixed set (`Number`/`String`/`Boolean`/`parseInt`/
  `parseFloat` as global builtins identified structurally via `is_external` +
  `<global>` namespace parent, not by bare name match; unary `<operator>.plus`
  checked by arity; bitwise `<operator>.or`/`and`/`xor` checked by arity;
  `<operator>.formatString` for template coercion). `<operator>.cast` (TS `as`)
  is explicitly and deliberately excluded — it's compile-time-only with no
  runtime coercion effect, and JS-STATE-R01's case8/case9 fixtures used it only
  to satisfy the compiler before a real runtime operator; treating the cast
  itself as erasing would have been unsound.
- `tests/gates/js-state-r02/` — fixture (JS-STATE-R01's `state_erasure.ts`,
  reused as-is), `run.sh`, `check_js_state_r02.py` (24 checks: 8 expected
  candidates fire exactly once each, 5 expected non-candidates stay silent, plus
  structural invariants — no fact ever carries a verdict field, every resolution
  is `ERASES`, no double-counting).
- `tests/run_all.py` — wired in as gate 117, added to `EXPECTED_GATES` so a
  silently-skipped run fails the harness health check.

## Why this is sound, not just passing its own test

The check script's expectations were derived directly from JS-STATE-R01's
independently-written per-case `RESULT` lines (written before any R02 code
existed), not adjusted after the fact to match whatever the implementation
produced. The one adjustment made along the way was fixing a bug (case3's
shallow AST walk) that JS-STATE-R01 had already documented as a known gap in the
*characterization* query, not something discovered by and fitted to the R02
implementation.

## Suggested next steps (not started)

1. A security-sensitive-sink profile for JS/TS (mirrors `SINK-R01`/`SOURCE-R02`)
   to turn `FailureStateErasureCandidateFact` + sink-reachability into an actual
   candidate-vulnerability signal — this is the piece needed to distinguish
   case2/8/9 (reaches `authenticate`) from case7/10/11/12 (reaches
   `unrelatedSink`) downstream of this module.
2. The structural-passthrough PRESERVES check (JS-STATE-R01 Q4 reason 2) — would
   let case5-shaped code be positively cleared instead of merely un-flagged.
3. `parseFloat()` — one fixture case away from being empirically exercised
   rather than only structurally included in the closed set.
4. Broader-corpus validation — this fixture is still hand-written; the false-
   positive risks JS-STATE-R01 listed (alias-name return types, the malformed
   `createN`-style return type, `<operator>.plus` arity collisions) haven't been
   stress-tested against real-world code yet.
