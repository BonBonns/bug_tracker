# JS-PROV-R10 — Handler Identity + Context-Parameter Role Characterization

**Characterization only.** No implementation, no `ExternalInputOriginFact`
promotion, no generic "last callback = handler" rule, and **no parameter names
used as evidence**. `FrameworkRegistrationFact` (R09) is an input, not
rediscovered.

## Phase 1 — The four real Corpus-B argument shapes

Enumerated from production, not modelled a priori. Over R09's 14 established
registrations:

```text
n=8   (IDENTIFIER, LITERAL, CALL, IDENTIFIER, IDENTIFIER)   recv, path, validate(schema), validator, handler
n=3   (IDENTIFIER, LITERAL, IDENTIFIER)                     recv, path, handler
n=2   (IDENTIFIER, LITERAL, CALL, IDENTIFIER)               recv, path, validate(schema), validator
n=1   (IDENTIFIER, LITERAL, IDENTIFIER, IDENTIFIER)         recv, path, validator, handler
```

Exactly four, matching R07's independently-derived count. Argument 0 is the
receiver and argument 1 is the route literal in **all** shapes; callback
candidates are arguments >= 2. Callback count varies 1..3.

## Phase 2/3 — Callback identity (Corpus B)

```text
callback arguments total :  33
identities ESTABLISHED   :  21
identities UNKNOWN       :  12
```

Broken down by node kind, which is where the real finding is:

```text
IDENTIFIER : 23  ->  21 ESTABLISHED via REF -> METHOD, 2 UNKNOWN
CALL       : 10  ->   0 ESTABLISHED  (ALL wrapper-returned)
```

**Wrapper-returned handlers cannot be identified.** `validate(schema)` and
`upload.single(...)` are *calls whose return value* is the middleware. Resolving
the argument yields the **wrapper module** (`middlewares/validate.middleware`),
not the returned function. The observable tell is a generic stub parameter
signature `(p0, p1, p2)` rather than a real `(ctx)` / `(ctx, next)` signature.

These 10 must abstain as `HANDLER_IDENTITY_UNKNOWN`. Recovering them by name
was not attempted.

The 2 remaining UNKNOWNs are inline lambdas assigned to a local, carrying a
function *type* (`(ctx: ANY) => Promise<void>`) but no resolvable METHOD.

**Role model preserved, not invented:** Koa Router treats every callback in the
chain as middleware. The `/m1` control (`post(path, mwA, mwB, namedHandler)`)
established **all three** callables with identical role structure. No
`MAIN_HANDLER` distinction was introduced.

## Phase 4/5 — Parameter roles, and the name-independence proof

Established-callback formal-parameter signatures in Corpus B:

```text
n=12  (ctx,)
n=9   (ctx, next)        -> 21 total, matching the 21 established identities
```

Roles are assigned by **position after Joern's implicit `this`** (parameter
index 1 = CONTEXT, index 2 = NEXT). Names are never consulted. Demonstrated:

```text
/n1  (ctx, next)                  ctx->CONTEXT,     next->NEXT
/n2  (context, continuation)      context->CONTEXT, continuation->NEXT
/n3  (banana, orange)             banana->CONTEXT,  orange->NEXT
```

Identical role results across three unrelated naming schemes.

Positional and arity controls:

```text
/p1  (a, b)      a->CONTEXT, b->NEXT
/p2  (a, b)      a->CONTEXT, b->NEXT     <- second parameter NEVER gets CONTEXT,
                                            regardless of which one the body uses
/p3  (only)      only->CONTEXT
/p4  ()          no parameters -> NO ROLE ASSIGNED
/p5  (x, y, z)   x->CONTEXT, y->NEXT, z->NO_ROLE   <- no role invented beyond
                                                      the framework arity model
/n6  namedHandler(a, b)   ESTABLISHED via REF -> METHOD -> METHOD_PARAMETER
```

Phase 6's required chain holds: `FrameworkRegistrationFact -> callback argument
-> REF/METHOD identity -> exact METHOD_PARAMETER`, with **no type propagation
needed to identify the context parameter**.

## Phase 10 — Negative controls, including one FAILURE

```text
notRegistered(a, b)      never appears                          PASS (silent)
fake.get("/x", handler)  receiver not the established parameter PASS (excluded)
router.get("/nc", 42)    non-callable argument                  *** FAIL ***
```

**`/nc` produced a false ESTABLISHED** with roles `p1->CONTEXT, p2->NEXT`. The
`42 as any` cast lowered to a CALL that resolved to a generic external stub
whose signature is `(p0, p1, p2)` — the *same* tell as the wrapper-returned
case above.

This is a genuine negative-control failure and is reported rather than tuned
away. It identifies a **required additional gate** before any implementation:

> A callback's resolved target must be a method with a real body (non-external),
> not a stub. The generic `(p0, p1, p2)` signature is the observable marker of
> a stub resolution in both the wrapper case and this non-callable case.

That gate is structural (external/stub vs. defined method), not name-based. It
was **not** implemented here, per the no-implementation constraint.

## R09 limitation found while building this fixture

The first R10 fixture registered a `router` **local** directly and produced
**zero** registrations: `framework_registration.py` only handles receivers that
are *parameters* (`if not param_method: continue`). Corpus B is entirely of
that shape, so R09 never exercised the direct-local case. The fixture was
reshaped to Corpus-B form; the limitation is recorded as an R09 scope boundary,
not patched during a characterization milestone.

## The `validatedData` boundary — explicitly preserved

Reaching `parameter = KOA_CONTEXT` does **not** establish an origin family.

```text
ctx.validatedData.username   ->   ORIGIN_FAMILY = UNKNOWN
```

It must not be mapped to `HTTP_BODY` merely because validation middleware
commonly reads request bodies. Notably, 10 of Corpus B's 33 callback arguments
are exactly those `validate(...)` middlewares — and their identity is
*unresolvable* (above), so the middleware that populates `validatedData` is
currently opaque. That strengthens rather than weakens the boundary.

# JS-PROV-R10 VERDICT

```text
ARGUMENT SHAPES:        4 distinct, enumerated from production (8/3/2/1).
                        arg0=receiver, arg1=route literal in ALL shapes;
                        callbacks are args >= 2; callback count 1..3.
CALLBACK IDENTITY:      21/33 ESTABLISHED via REF -> METHOD. 12 UNKNOWN.
NAMED HANDLERS:         ESTABLISHED (REF -> METHOD -> METHOD_PARAMETER).
ANONYMOUS HANDLERS:     ESTABLISHED as METHOD_REF lambdas; 2 Corpus-B cases
                        assigned to a local carry a function TYPE but no
                        resolvable METHOD -> UNKNOWN.
IMPORTED HANDLERS:      Corpus B imports handlers via `require('./x').register`,
                        already resolved at the registration layer (R09).
                        Renamed-import / one-hop re-export NOT separately
                        exercised -> UNMEASURED, not claimed.
REEXPORTS/ALIASES:      UNMEASURED in R10 (R01/R02 showed alias boundaries lose
                        TYPE evidence; whether METHOD identity survives them was
                        not tested here).
MIDDLEWARE CHAINS:      ESTABLISHED — all 3 callables in post(path,mwA,mwB,h)
                        identified, identical role structure. Koa's
                        "every callback is middleware" semantics PRESERVED;
                        no MAIN_HANDLER distinction invented.

CONTEXT ROLE:           ESTABLISHED positionally (param index 1 after implicit
                        `this`). PROVEN name-independent across
                        (ctx,next)/(context,continuation)/(banana,orange).
NEXT ROLE:              ESTABLISHED at index 2. 0-param -> no role; 3rd param
                        -> NO_ROLE (nothing invented beyond framework arity).
NEGATIVE CONTROLS:      2 of 3 PASS. `router.get("/nc", 42 as any)` FAILS —
                        a non-callable argument produced a false ESTABLISHED
                        via a generic (p0,p1,p2) stub resolution.

CORPUS-B REGISTRATIONS:      14
CORPUS-B CALLBACKS:          33
CALLBACKS ESTABLISHED:       21
PARAMETER ROLES ESTABLISHED: 21 CONTEXT, 9 NEXT

HANDLER LAYER PROMOTION_READY: NO. Four of six gate conditions met (shapes
                        characterized, identity survives real code, roles from
                        position/framework semantics, names unnecessary). FAILS
                        on "fake/non-registered controls remain silent" — the
                        /nc false ESTABLISHED is promotion-blocking — and
                        partially on "unresolved identities abstain", since the
                        wrapper-returned case currently resolves to a stub
                        rather than abstaining.
EXTERNAL-INPUT ORIGIN PROMOTION_READY: NO.

DOMINANT GAP:           Stub-resolution admittance. One structural gate
                        (resolved target must be a defined, non-external method)
                        would fix BOTH the /nc false positive AND convert the 10
                        wrapper-returned callbacks from wrong-identity to honest
                        abstention. Second gap: wrapper-returned middleware
                        identity itself (10/33 of Corpus B) is genuinely
                        unresolvable without modelling the returned closure.

NEXT MILESTONE:         JS-PROV-R11 — Middleware State Provenance
                        (KOA_CONTEXT -> middleware writes -> ctx.validatedData
                        -> handler reads). This is the edge that turns handler
                        identity into input-origin provenance, and it is a
                        state-flow problem across middleware rather than a
                        recognition problem. R10's finding that the
                        validate(...) middlewares are exactly the unresolvable
                        callbacks makes this the correct next target.
                        A small stub-resolution gate should be folded in as a
                        prerequisite fix, not as its own milestone.
```

## Discipline note

The `/nc` control was the point of the milestone. Everything else passed
cleanly — four shapes enumerated, 21/33 identities established, roles proven
name-independent across three naming schemes, middleware chains fully
identified, Koa's semantics preserved without inventing a MAIN_HANDLER role.
It would have been easy to report that as success and treat one odd control as
noise.

It is not noise: it shares a root cause with the 10 unidentifiable
wrapper-returned callbacks. Both are stub resolutions admitted as if they were
real methods. Reporting the handler layer as promotion-ready would have shipped
a rule that assigns CONTEXT role to the integer `42`.

---

> ## SUPERSEDED (annotated by JS-PROV-R28)
>
> **Both of R10's promotion blockers are resolved.** This verdict should not be
> read as current.
>
> 1. **`42 as any` false ESTABLISHED** — resolved by JS-PROV-R12's stub gate
>    (`is_defined_method`, rejecting generic `(p0,p1,p2)` stub signatures).
>    Permanently asserted: `JS_PROV_R12` teeth *"NEG-5 stub callback (42 as any)
>    establishes nothing"* and *"NEG-5 stub recorded as an abstention"*.
> 2. **10 wrapper-returned callbacks unidentifiable** — resolved by JS-PROV-R11,
>    which found they were UNDER-resolved by one hop
>    (`CALL -> callee METHOD -> RETURN -> METHOD_REF`). Asserted by
>    `JS_PROV_R12` tooth *"NEG-6 wrapper-returned validate(schema) DOES join"*.
>
> R10's measurements stand; its `HANDLER LAYER PROMOTION_READY: NO` does not.
> The handler layer is exercised in production through R12/R19.
