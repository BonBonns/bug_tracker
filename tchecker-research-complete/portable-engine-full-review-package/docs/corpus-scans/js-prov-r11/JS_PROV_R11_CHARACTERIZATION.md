# JS-PROV-R11 — Middleware State Provenance Characterization

**Characterization only.** No implementation. `ExternalInputOriginFact` not
promoted. No inference from property names.

Target chain: `KOA_CONTEXT -> middleware writes ctx.<prop> -> downstream
middleware/handler reads ctx.<prop>`.

## Q1 / Q11 — Wrapper-returned middleware identity: **RECOVERABLE**

This closes R10's dominant gap.

Fixture:
```text
method = t.ts::program:validate   methodReturn = (ctx: ANY, next: ANY) => Promise<void>
  RETURN children = METHOD_REF : t.ts::program:validate:<lambda>0
```

Real Corpus B, same shape:
```text
WRITE middlewares/validate.middleware.js::program:validate:<lambda...>  ctx.validatedData = value
```

The returned middleware is a `METHOD_REF` child of the wrapper's `RETURN` node,
so `wrapper CALL -> callee METHOD -> RETURN -> METHOD_REF -> METHOD` is a
structural path. **`RETURNED_HANDLER_ESTABLISHED`**, in both the fixture and
production code, with no name inference.

R10 reported these 10 Corpus-B callbacks as unidentifiable because it resolved
the *argument* to the wrapper. The correct resolution is one hop further, through
the wrapper's return. R10's conclusion is therefore **corrected**: they are not
unresolvable, they were under-resolved.

## Q8 — Write position relative to `next()`: **ESTABLISHED STRUCTURALLY**

The critical Koa tooth. Measured via **block child `order`**, not line numbers:

```text
producer      nextOrder=2   WRITE order=1  BEFORE_NEXT   ctx.validatedData = ctx.request.body
afterWriter   nextOrder=1   WRITE order=2  AFTER_NEXT    ctx.afterData = ctx.request.body
condWriter    nextOrder=2   WRITE order=1  BEFORE_NEXT   (inside CONTROL_STRUCTURE)
bodyWriter/queryWriter/constWriter/derivedWriter        BEFORE_NEXT
validate:<lambda>0  nextOrder=2  WRITE order=1  BEFORE_NEXT
```

`afterWriter` is correctly isolated as `AFTER_NEXT` — a write that downstream
middleware **cannot** observe. Line numbers were tried first and were useless
(one-line bodies put the write and `next()` on the same line); AST child order
is the sound signal.

## Q7 — Conditional writes: **DISTINGUISHABLE**

`condWriter`'s write appears nested inside a `CONTROL_STRUCTURE` child rather
than as a direct block statement. So `MUST_WRITE` (direct block child) and
`MAY_WRITE` (nested under a control structure) are separable without new
machinery. Not promoted to `MUST` here.

## Q9 / Q10 — Origin family at the write side: **VISIBLE**

```text
ctx.vBody    = ctx.request.body           -> HTTP_BODY  (direct)
ctx.vQuery   = ctx.query                  -> HTTP_QUERY (direct)
ctx.vConst   = "literal"                  -> no external origin
ctx.vDerived = normalize(ctx.request.body)-> DERIVED_FROM_HTTP_BODY
```

The right-hand side is fully readable, and the direct/derived distinction is
structural (identifier field-access vs. call wrapping one). Per the brief, the
derived case preserves `DERIVED_FROM_*` rather than claiming equivalence; no
sanitization claim is made.

## Corpus-B replay — the picture is more complex than assumed

24 distinct `ctx.validatedData` reads across handlers **and validators**. And
critically:

```text
WRITE middlewares/validate.middleware.js::program:validate:<lambda>  ctx.validatedData = value
WRITE resources/account/forgot-password/.../validator                ctx.validatedData.user = user
WRITE resources/account/resend-email/.../validator                   ctx.validatedData.user = user
WRITE resources/account/reset-password/.../validator                 ctx.validatedData.user = user
```

**`validatedData` has multiple writers.** The `validate(schema)` middleware
creates it, and downstream *validators* then write additional sub-properties
(`.user`) onto it — values sourced from database lookups, not from the request.

So a single origin family for `ctx.validatedData` would be **wrong**:
`ctx.validatedData.email` and `ctx.validatedData.user` have different
provenance. Property-path granularity is required, not object-level.

This vindicates the boundary that has been held since R03: mapping
`validatedData` to `HTTP_BODY` on the strength of the name would have been
incorrect for a real subset of its own fields.

## What was NOT measured

The **state-flow join itself** (linking a specific write fact to a specific read
fact) was not built. Q2–Q6 fixtures exist and the *ingredients* are all
established — registration identity (R09), callback identity (R10 + Q1 above),
context-parameter role (R10), write facts with `relative_to_next`, read facts,
origin families — but the join, and with it the negative controls that only the
join can exercise, remain unmeasured:

- **Q4** (same property on unrelated objects — must NOT join)
- **Q5** (separate routes — a `/a` write must not satisfy a `/b` read)
- **Q6** (`producer,consumer` vs `consumer,producer` ordering)

These are exactly the controls that decide whether a state-flow analysis is
sound, so no state-flow counts are reported. Claiming flows established on
un-exercised negatives is the failure mode this whole line has been avoiding.

# JS-PROV-R11 VERDICT

```text
CALLBACK STUB GATE:              REQUIRED, NOT IMPLEMENTED. R10's `42 as any`
                                 false-positive stands until a resolved callback
                                 target is required to be a defined, non-external
                                 METHOD. Prerequisite for consuming handler identity.
WRAPPER-RETURNED HANDLER IDENTITY: RETURNED_HANDLER_ESTABLISHED via
                                 CALL -> callee METHOD -> RETURN -> METHOD_REF.
                                 Confirmed in fixture AND real Corpus B.
                                 CORRECTS R10's "unresolvable" finding.
CONTEXT STORAGE IDENTITY:        NOT ESTABLISHED. Ingredients present; the join
                                 across middleware was not built, and its
                                 negative controls (Q4/Q5) were not exercised.
MIDDLEWARE ORDER:                ORDER_UNKNOWN. Callback argument order is
                                 visible, but whether it is sufficient evidence
                                 of Koa execution order was not established.
NEXT BOUNDARY:                   ESTABLISHED structurally via block child order.
                                 BEFORE_NEXT / AFTER_NEXT cleanly separated.
CONDITIONAL WRITES:              MUST vs MAY separable (direct block child vs
                                 nested under CONTROL_STRUCTURE).

BODY PROPAGATION:                Write-side origin VISIBLE (ctx.request.body).
QUERY PROPAGATION:               Write-side origin VISIBLE (ctx.query).
DERIVED VALUES:                  Separable; preserved as DERIVED_FROM_* rather
                                 than claimed equivalent.

CORPUS-B validatedData READS:    24 distinct read sites (handlers AND validators)
STATE FLOWS ESTABLISHED:         0  (join not built)
STATE FLOWS MAY:                 0  (join not built)
STATE FLOWS UNKNOWN:             all

MIDDLEWARE STATE LAYER PROMOTION_READY: NO
EXTERNAL INPUT ORIGIN PROMOTION_READY:  NO

DOMINANT GAP:  The write->read JOIN and its scoping. Every input to it now
               exists; what is missing is the relation itself plus proof that
               it refuses to join unrelated objects (Q4) and unrelated routes
               (Q5). Second: `validatedData` has MULTIPLE WRITERS with
               DIFFERENT origins, so any join must be property-path granular,
               not object-level.

NEXT MILESTONE: JS-PROV-R12 — Context State-Flow Join (implementation), gated on
               two prerequisites landing first: (1) the R10 stub gate, and
               (2) wrapper-return resolution from Q1. Its acceptance teeth are
               the negatives R11 could not exercise: unrelated objects must not
               join, separate routes must not join, `consumer,producer` order
               must not receive producer state, and AFTER_NEXT writes must not
               reach downstream reads.
```

## Discipline note

Two results here cut in opposite directions and both are reported.

The wrapper-return finding is a **correction of my own R10 conclusion** — those
10 callbacks were reported as unidentifiable when they were merely
under-resolved by one hop.

Against that, the Corpus-B replay showed `validatedData` is written by several
middlewares with different origins (`request.body` vs. a database lookup), so
the tidy `HTTP_BODY -> validatedData` story assumed at the start of this
milestone is wrong at property granularity. The temptation was to report state
flows as established given how many ingredients resolved; without Q4/Q5
negatives exercised, any such count would be unearned.
