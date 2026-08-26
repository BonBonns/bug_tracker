# JS-STATE-R03 / R04 / R05 — Security-sensitive-sink reachability

## Status: IMPLEMENTED, real run, PASS

```text
JS_STATE_R03=30/30
```

Real Joern run, no stored fixtures. No regressions: JS-STATE-R02 is `26/26`
(case13 added), Gate 24-TS is still `27/27`, JSTS-R05 is still `8/8`. This
completes the target bug shape from JS-STATE-R01 end-to-end:

```text
create() returns success/failure
  -> Number()/String()/Boolean()/parseInt()/+/| destroys the discriminator
  -> guard checks the TRANSFORMED value
  -> the erased value reaches authenticate() ON THE CONTINUE PATH,
     not merely "somewhere in the same function"
```

is now a real, machine-produced chain of facts, not just a hand-verified
observation.

## What this is, precisely

`security_sensitive_reachability.py` takes every JS-STATE-R02
`FailureStateErasureCandidateFact` and asks one more question, via the same
REF-graph mechanism (never identifier names): does the guarded local, or any
expression wrapping it, flow into an argument of some call in the same
function -- and if so, is that call actually reachable on the guard's continue
path, or only inside the guard's own "condition fired" branch?

If the call's name matches an **explicit, external, human-curated profile**
(`security_sink_profile.py`), the fact is annotated `SENSITIVE`. Otherwise it's
`UNKNOWN` — never `NOT_SENSITIVE`, because absence from a small example profile
is not proof of safety.

## The JS-STATE-R04 branch-awareness fix

The original R03 write-up flagged an explicit gap: reachability was computed
as "appears as an argument anywhere in the same function," with no awareness
of *which branch* a call sits in. That means a call inside the guard's own
`if (checkFailed) { ...; sinkCall(x); return; }` branch -- which only runs
when the check believed something had failed, not on the path where it
continues normally -- would be wrongly credited as "reaching" the guarded
value on the safe path.

Fixed by exporting `guard_then_branch_members.tsv` (every node id inside a
control structure's condition-true branch) and excluding any reaching call
whose id falls in the erasure candidate's own guard's then-branch. Excluded
calls are reported separately in `excluded_then_branch_calls`, not silently
dropped, so the exclusion is auditable.

**A second, deeper bug surfaced while building the fixture case to prove this:**
the demonstration case (`case13`, `authenticate(id13 as number)`) has its
argument wrapped in a TypeScript `as` cast, not a bare identifier. The original
R03 reachability code only matched arguments that WERE identifiers, so it
missed the `authenticate` call entirely — not because of the branch issue, but
because of a shallower, unrelated bug: the same "matched only direct AST
children, not the full subtree" mistake JS-STATE-R01 already found once for
guard conditions, recurring here for call arguments. Fixed the same way: a new
export, `call_argument_identifiers.tsv`, walks the FULL AST subtree of every
call's arguments (not just bare-identifier arguments) for REF-resolvable
identifiers. This was **found empirically, mid-implementation, not
anticipated** — the fixture case was built to test branch-exclusion, and
exposed a different, real gap instead. Both are now fixed and both are
verified by `check_js_state_r03.py`'s case13 checks (zero `sink_matches`, zero
`reaching_calls`, and the `authenticate` call specifically present in
`excluded_then_branch_calls` — proving the exclusion mechanism actually fired,
not that the case coincidentally landed on UNKNOWN some other way).

Also cleaned up along the way: the reachability computation was including each
guarded local's own defining `<operator>.assignment` and the guard's own
`<operator>.instanceOf`/comparison call as "reaching calls" (trivially true via
REF, but meaningless for sink-matching, since no real sink profile will ever
list an operator name). These are now filtered out of `reaching_calls`
entirely as structural noise.

## The JS-STATE-R05 reassignment-awareness fix

The original R03/R04 write-up flagged this explicitly as the next concrete
gap: a call could see the guarded local only AFTER it was reassigned to a
different, unrelated value, and the module would still credit the (long-gone)
erased value as reaching that call, since a `LOCAL` node in the CPG represents
the variable's identity across its whole lifetime, not a specific value at a
specific point.

Fixed by tracking every `<operator>.assignment` to a given local (not just the
one erasure-producing assignment JS-STATE-R02 already tracks), and excluding
any reaching call whose line number comes after an intervening reassignment's
line number. Excluded calls are reported in `excluded_reassigned_calls`,
distinct from `excluded_then_branch_calls`, so the two exclusion reasons stay
auditable and distinguishable rather than collapsing into one undifferentiated
"excluded" bucket.

**This is explicitly a line-number approximation, not a real CFG/dominance
check** — stated in the module docstring, not just here. It catches the
straightforward, common shape demonstrated by fixture case14
(`id = Number(r); if (...) return; id = 42; authenticate(id);`) and
deliberately does not attempt to reason about reassignments inside loops,
reassignments on conditionally-executed branches, or same-line
reassign-and-use. Both `check_js_state_r03.py`'s case14 checks and case13's
were written to confirm the *specific* exclusion mechanism fired (not just
that the case happened to land on `UNKNOWN`), and to confirm case14's
`authenticate` call lands in `excluded_reassigned_calls` and NOT in
`excluded_then_branch_calls` — proving the two fixes are actually distinct
code paths, not one fix accidentally covering for the other.

## What this deliberately is still NOT

- **Not a general JS/TS authentication-code detector.** Unchanged from the
  original R03 write-up — the profile is example-only, documented as such in
  `security_sink_profile.py`'s docstring.
- **Not fully path-sensitive, even after R04/R05.** Both fixes are targeted,
  narrow patches for the two most obvious failure modes, not a general CFG
  reachability engine. Still open: a call could be behind an unrelated,
  unconnected `if` that never executes on any real path (general CFG
  dominance, not just "is this the guard's own then-branch"); a reassignment
  inside a loop or a conditionally-executed reassignment isn't reasoned about;
  two reassignments on the same source line as a read aren't ordered
  correctly by the line-number approximation. All called out explicitly here
  rather than assumed solved.
- **Not a vulnerability verdict.** `SENSITIVE` means "this erasure candidate's
  guarded value also reaches a profiled sink on a path this module could not
  rule out via its two exclusion checks" — still a candidate requiring human
  judgment.

## Verified against independently-written expectations

`check_js_state_r03.py`'s expectations for case2/4b/7/8/9/10/11/12 come
directly from JS-STATE-R01's original per-case `RESULT` lines, written before
this module existed. case13's and case14's expectations (UNKNOWN, with the
specific exclusion-mechanism checks) were written as part of designing each
fix itself, targeting the exact behavior each fix was meant to produce, then
verified against the real implementation rather than tuned to match whatever
it happened to output.

## Suggested next steps

1. **General CFG-dominance reachability** — would subsume both the
   then-branch-only exclusion (R04) and the line-number reassignment
   approximation (R05) with a single, proper "is this call actually reachable
   from the guard's continue edge, and does a definition of the local reach
   this use" check, using Joern's already-computed CFG/reaching-definitions
   (nothing here uses them yet; only AST-branch-membership and line-number
   ordering are used). This is the natural unification of both current fixes,
   not a third bolt-on.
2. A real project/framework profile to replace `EXAMPLE_SENSITIVE_SINKS` (e.g.
   `passport.js` `req.login`, `jsonwebtoken` `jwt.sign`/`jwt.verify`, session
   assignment patterns) — scoped as its own follow-up, framework research, not
   more CPG-fact engineering.
3. The PRESERVES structural-passthrough check from JS-STATE-R01 Q4 reason 2,
   still not implemented (unchanged from the JS-STATE-R02 result doc).

