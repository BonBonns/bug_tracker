# JS-REAL-R01 — Phase 4: Candidate Adjudication

One candidate was produced by Phase 3. Adjudicated in full below.

---

## Candidate 1

```text
CALLSITE: routes/account.ts:1759-1764, inside AccountHandler.emailBounceStatus,
          in the filter callback passed to
          `[...normalizedBounces, ...wildcardBounces].filter(...)`

ORIGINAL RESULT: `bounce`, the filter callback's parameter, typed inline as
          `{ email: string; createdAt: number }`. Traced upstream: `bounce`
          ranges over `normalizedBounces`/`wildcardBounces`, which come from
          `await this.db.emailBounces(...)`, and the enclosing `bounces`
          variable is explicitly typed `Array<{ bounceType: number }>`.
          Nowhere in this chain is there a union return type, a
          discriminated-union return, an Error-object return, or a
          null/undefined-sentinel return. This is an ordinary array of
          plain data records.

FAILURE STATE: NONE ESTABLISHED. There is no success/failure discriminator
          anywhere in this value's provenance. The premise the erasure
          classifier requires (JS-STATE-R01's ReturnStateFact /
          RETURN_STATE_VISIBLE question) does not hold here at all.

ERASING TRANSFORMATION: `` `${bounce.email}:${bounce.createdAt}` `` --
          correctly classified as `<operator>.formatString` /
          TEMPLATE_STRING_COERCION by the closed builtin/operator table.
          The classifier is CORRECT about the transformation's identity and
          its general erasure semantics (template coercion does call
          ToString, and would destroy an Error-shaped value's discriminator
          IF one were present). It is simply being applied to a value that
          was never carrying a failure discriminator to begin with.

GUARD SUBJECT: `key`, the local the template string was assigned into --
          correctly resolved via REF, matching JS-STATE-R02's own
          (correct) mechanism. `if (seen.has(key))` checks `key` directly,
          the same local the transformation produced -- so GUARD_SUBJECT is
          technically "the transformed value," exactly as designed.

SINK: `seen.has(key)` and `seen.add(key)` -- a `Set<string>` used for
          intra-request deduplication. Not `authenticate`, not any
          identity/session/token operation. `seen` is a local `new
          Set<string>()` created two lines above, entirely local to this
          request handler's dedup logic.

SINK PROFILE: NO MATCH. `has`/`add` are not in `EXAMPLE_SENSITIVE_SINKS`.
          Correctly landed on `security_sensitive_use: UNKNOWN`.

REASSIGNMENT BEFORE SINK: NONE. `key` is `const`, never reassigned.
          `excluded_reassigned_calls` is empty, correctly.

CONTROL-FLOW OBSERVATION: `if (seen.has(key)) return false;` is itself the
          guard's ENTIRE body (an early-return filter, structurally similar
          in shape to the fixture's guard pattern) -- but the *condition
          itself* is the sink call (`seen.has(key)`), not a downstream call
          reached after the guard. This is a structurally different pattern
          from every JS-STATE fixture case (which all had
          `if (guard(transformed)) return; ...; sink(transformed);` --
          guard and sink as two separate calls). Here the "guard" and the
          only meaningfully related call ARE the same call. R02's condition-
          identifier walk doesn't distinguish "guard condition IS the only
          related call" from "guard condition is followed by a separate
          call downstream" -- both get the identifier resolved the same way,
          which is why this fired at all.

ATTACKER/EXTERNAL CONTROL: `bounce.email`/`bounce.createdAt` originate from
          this account's own bounce records in the database (queried by
          `email`, which IS externally supplied via `request.payload`).
          So the VALUE is partially external-influenced -- but that is
          irrelevant here, since there is no failure-state question in play
          at all; external control of a dedup key has no security
          consequence for this code path.

SECURITY CONSEQUENCE: NONE. Worst case if this were somehow "wrong": a
          bounce record could be deduplicated incorrectly (a functional/
          correctness bug at most, not a security one) -- and even that
          isn't actually at risk, since the template-string coercion here
          is applied to two already-plain values (a string and a number),
          not to anything that could have carried a failure state.
```

**Classification: `RETURN_CONTRACT_NOT_ESTABLISHED`**

This is the most precise available label from the required taxonomy. It is
not `TRANSFORMATION_NOT_PROVEN_ERASING` (the transformation classification
itself is correct in isolation). It is not `SINK_PROFILE_FALSE_MATCH` (there
was no match to begin with, so nothing to be false about). It is not
`PATH_APPROXIMATION_FALSE_POSITIVE` (R04/R05's specific approximations played
no role here -- no branch exclusion, no reassignment exclusion; this fact
never got that far in reasoning terms). The root cause is structural and
upstream of everything R04/R05 touch: **the erasure classifier never checks
that the guarded value's origin actually establishes a distinguishable
success/failure return contract before firing** -- it only checks "guard
condition contains an identifier whose producing call is in the closed
erasure-operator set," which is necessary but not sufficient for the target
bug shape. `bounce.email`/`bounce.createdAt` are plain fields with no failure
semantics whatsoever, so the erasure "detection" was true about the
*transformation* and meaningless about the *value*.

Not called a vulnerability: this is a single, structurally benign
false-positive, fully explained end to end.
