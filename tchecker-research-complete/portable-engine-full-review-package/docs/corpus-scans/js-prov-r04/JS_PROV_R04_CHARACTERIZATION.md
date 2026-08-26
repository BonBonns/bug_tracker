# JS-PROV-R04 — Argument→Parameter Type Propagation Characterization

**Characterization only. No propagation implemented.** R07 unchanged. No
engine modification.

R03 isolated the semantic edge: caller argument type PRESENT, call edge
RESOLVED, callee parameter PRESENT, callee parameter type `ANY`. R04
determines the narrowest sound rule and — critically — its **join semantics**.

Fixture: `src/prop.ts`, 10 required teeth, real Joern run.

---

## Q1 — Single-callsite propagation (R04-1)

```text
r1_register  callees=[prop.ts::program:r1_register]     <-- exactly one
    ARGS   0:this:prop.ts::program  1:r1:prop.ts::program:Router:<init>
    PARAMS 0:this:prop.ts::program  1:router:ANY
```

All four preconditions hold: call edge resolves to exactly one callee,
argument index maps directly to parameter index, argument type is established,
parameter carries no stronger declared type. **Propagatable.**

**Immediate normalization finding, not anticipated:** the same conceptual type
has *two spellings* depending on how the value was produced —
`prop.ts::program:Router:<init>` (from `new Router()`) versus `Router` (from
`makeRouter()`'s declared return). A join over raw type strings would treat
these as **distinct types** and manufacture a false conflict. Any propagation
rule needs a type-identity normalization step before joining; this was not
visible before R04.

## Q2 — Conflicting callsites (R04-2/3/4) — the load-bearing tooth

```text
R04-2  same type, 3 callsites
  r2_register  arg1: Router:<init>   (x3, identical)          -> {Router}

R04-3  two distinct concrete types                            <-- CONFLICT
  r3_register  arg1: prop.ts::program:Router:<init>
  r3_register  arg1: prop.ts::program:Db:<init>                -> {Router, Db}

R04-4  concrete + ANY + unknown + null
  r4_register  arg1: prop.ts::program:Router:<init>
  r4_register  arg1: ANY            (from `any`)
  r4_register  arg1: ANY            (from `unknown`)  <-- COLLAPSED
  r4_register  arg1: __ecma.Null
```

The conflict **is observable** — both types survive to their call sites, so
last-writer-wins is not merely wrong, it is unnecessary.

**Recommended representation: a SET of observed types with provenance, not a
lattice join.** Reasoning:

- `{Router, Db}` preserves what downstream consumers actually need (R12 asks
  "can this value be an OBJECT outside its declared domain?"; R11 asks "are
  two operands in different domains?"). Both are answerable from a set;
  neither is answerable from a collapsed `JOIN(Router,Db)` supertype.
- Collapsing to a common supertype would discard exactly the information that
  makes the fact useful, and in JS the supertype is almost always `Object`.

**Concrete + ANY must NOT reduce to the concrete type.** Per R11's permanent
invariant (`ANY` is not a domain, it is the absence of one), a callsite
passing `any` means the parameter's runtime domain is **unconstrained**. The
correct result for R04-4 is therefore:

```text
observed_types = {Router, Null}
unconstrained_callsite_present = TRUE     -> downstream must treat the
                                             parameter's domain as UNKNOWN
```

Reporting `{Router}` and silently dropping the `ANY` callsites would be the
same class of error R11 identified: evidence that looks like a domain proof
but is not.

**Also measured:** TypeScript `any` and `unknown` both export as `ANY` and are
**indistinguishable**. `unknown` is the safe, deliberately-opaque annotation
and `any` is the unsafe escape hatch; the frontend erases that distinction. A
propagation layer cannot tell "author explicitly opted out of typing" from
"author explicitly demanded narrowing before use." Recorded as a limitation.

## Q3 — Declared vs propagated (R04-9)

```text
r9_declared  ARGS   1:r9d:prop.ts::program:Derived
             PARAMS 1:x:prop.ts::program:Base:<init>    <-- real declared type
```

The declared parameter type survives and is not `ANY`. A rule gated on
"propagate only where the parameter type is `ANY`" therefore **abstains here
automatically** — the stronger declared contract is preserved without needing
a special case.

Reported separately, as required:

```text
DECLARED_DOMAIN:          Base
OBSERVED_ARGUMENT_DOMAINS: {Derived}
```

**Candidate invariant adopted** (consistent with R11's corrected thesis):

> Propagated argument types are positive evidence about *observed callsite
> values*, not proof of the parameter's exhaustive runtime domain.

A parameter observed only with `Derived` may still receive any other `Base`
from a callsite not in the analyzed scope.

### Q3 (second sub-case) — cast-erased argument vs stronger declared contract

**Added in a follow-up pass.** The first R04 pass covered `f(x: Base); f(derived)`
but omitted the prompt's second Q3 test, `g(x: ConcreteA); g(concreteB as any)`.
Closed here, and it produced a finding the first sub-case could not:

```text
CALL g   ARGS   1:concreteB as any : ANY
         PARAMS 1:x : q3b.ts::program:ConcreteA:<init>     <-- declared, stronger

CALL g2  ARGS   1:concreteA        : q3b.ts::program:ConcreteA      (control)
         PARAMS 1:x : q3b.ts::program:ConcreteA:<init>

CALL g3  ARGS   1:concreteB as any : ANY
         PARAMS 1:x : ANY                                   (propagation applies)
```

The `ANY`-gate behaves correctly: `g`'s declared `ConcreteA` is not `ANY`, so the
rule abstains and the stronger contract is preserved without a special case —
consistent with the first sub-case.

**But the more important finding is what propagation cannot see.** The value
actually reaching `g` at runtime is a `ConcreteB`, a genuine violation of the
declared `ConcreteA` contract. The `as any` cast **erased the argument type at
the callsite**, so the propagation layer observes only `ANY`. Propagation is
therefore *blind precisely in the cases where a declared contract is being
violated* — which is the exact situation R11 and R12 identified as
security-relevant (runtime values escaping their declared domain).

This does not change the rule (abstention is still correct), but it bounds the
capability honestly: argument→parameter propagation strengthens evidence about
**well-typed** call sites and contributes nothing on **deliberately erased**
ones. It must not be described as improving runtime-domain knowledge in
general.

`g3` additionally confirms the Q2 flag behaves as specified: `ANY` into an
`ANY` parameter propagates nothing of value but must set
`unconstrained_callsite = TRUE`, not be silently dropped.

The `g2` control also **re-confirms the normalization finding**: the argument
types as `ConcreteA` while the parameter declares
`ConcreteA:<init>` — same concept, different spellings, on the same
type in the same file.

## Q4 — Positional correctness (R04-5)

```text
r5_two  ARGS   0:this  1:r5r:Router:<init>  2:r5d:Db:<init>
        PARAMS 0:this  1:a:ANY              2:b:ANY
```

**No crossover.** Joern's implicit `this` occupies index 0 on **both** sides
consistently, so argument index maps directly to parameter index with no
offset correction. Verified on every multi-argument callsite in the fixture.

## Q5 — Default / rest / optional parameters (R04-5b)

```text
r5c_default(a = 1)      PARAMS 1:a:__ecma.Number      <-- typed FROM the default
r5c_rest(...args)       PARAMS 1:args:__ecma.Array    <-- arg maps to an ELEMENT
r5c_mixed(a, b = 2)     PARAMS 1:a:ANY  2:b:__ecma.Number
```

Two of three abstain **for free**: defaulted parameters already carry a type
inferred from the default value, so the `ANY`-gate excludes them.

**Rest parameters are the genuine hazard.** `r5c_rest(makeRouter())` passes a
`Router` at argument index 1, but parameter `args` is the whole
`__ecma.Array`. The index mapping is **not exact** — argument *i* corresponds
to an array *element*, not the parameter. Here the `ANY`-gate happens to
abstain (`__ecma.Array` ≠ `ANY`), but that is **incidental, not principled**.
A rule must explicitly detect and exclude rest parameters rather than relying
on that coincidence.

## Q6 — Higher-order callbacks (R04-6b)

```text
r6b_reg((ctx) => …)     ARGS 1:<lambda>0:prop.ts::program:<lambda>0
r6b_reg(r6b_handler)    ARGS 1:r6b_handler:prop.ts::program:r6b_handler
                        PARAMS 1:cb:ANY
```

Both inline arrows and named function references carry a resolvable **method
fullName** as their argument type, and the CPG represents them identically at
this level. So propagation into `cb` would yield *callable identity*, which is
a different kind of evidence from an object type.

Crossing further — from `cb`'s identity into the callback's **own**
parameters (`ctx`) — is a **separate hop** not addressed by this rule and not
measured here. Keeping these distinct matters: conflating "which function is
passed" with "what type its parameters receive" would be a second, unearned
inference.

## Q7 — Transitive propagation (R04-7)

```text
r7_a(makeRouter())   ARGS 1:makeRouter():Router      PARAMS 1:x:ANY
  r7_b(x)            ARGS 1:x:prop:ts::program:Base  PARAMS 1:y:ANY
    r7_c(y)          ARGS 1:y:ANY                    PARAMS 1:z:ANY
```

Reaching `z` requires re-evaluating each call after the previous hop updates a
parameter — i.e. **iteration to a fixpoint**, not a single pass.

```text
monotonic:            YES  (observed-type sets only grow; nothing is removed)
finite domain:        YES  (types drawn from the finite set present in the CPG)
fixpoint required:    YES  (single pass reaches x only; z needs 3 iterations)
termination obvious:  YES  (monotone growth over a finite lattice of subsets
                            of a finite type set => bounded ascending chain)
```

**Serious hazard found in this same case.** Inside `r7_a`, the identifier `x`
types as `prop:ts::program:Base` — a value with no relationship to `Router`,
and note the **malformed separator** (`prop:ts:` with a colon rather than
`prop.ts.`). This is a pre-existing type-recovery mis-resolution, and it
appears on the `r8_*` cases too. Propagation would **spread this error
transitively** rather than contain it. Combined with the R02 `methodFullName`
mis-resolution (`router.get` → `ctx:cookies:…:get`), this is now the second
independent instance of unreliable type recovery in this pipeline, and it
argues that any propagated fact must carry its derivation chain so a wrong
type can be traced back rather than silently inherited.

## Q8 — Recursion (R04-8)

```text
r8_self(x) { if (…) r8_self(x); }   -- direct recursion
r8_m1(x) -> r8_m2(x) -> r8_m1(x)    -- mutual recursion
```

Both admit a terminating fixpoint under the monotone set-union formulation:
once `x`'s observed set contains `Router`, the recursive callsite contributes
`Router` again, the set does not change, and iteration halts. No recursive
expansion occurs **because the formulation accumulates into a set rather than
substituting types**. This is a direct argument for the set-based
representation over any substitution-based one.

## Q9 — Unresolved / ambiguous call edges (R04-6)

Every callsite in the fixture resolved to **exactly one** callee
(`callees=[…]` singleton throughout), so the precondition is mechanically
checkable: `|callee| == 1`.

`dynTarget(makeRouter())` (dynamic, unresolvable) produced no resolved callee
and therefore no propagation opportunity — correct abstention. Multiple
candidate callees, external/stub callees, and missing callees must likewise
remain `UNKNOWN`; none should propagate, since the argument may reach only one
of several possible parameters.

## Q10 — Corpus-B replay (R04-10)

Re-examined R03's 12 `register(router)` callsites in
`paralect/koa-api-starter` @ `19b1a265`, engine unchanged:

```text
CALLSITE:                   12x register(router) across
                            resources/{account,health,user}/**
CALLEE:                     resolved, exactly one each
                            (e.g. resources/account/sign-in/index.js::program:<lambda>0)
PARAMETER:                  index 1, name `router`
ARGUMENT_TYPE:              @koa/router   (all 12, identical)
DECLARED_PARAM_TYPE:        ANY           (all 12)
ALL_CALLSITE_TYPES_FOR_PARAM: each parameter has exactly ONE callsite
                            (one register() per resource module)
JOIN_RESULT:                {@koa/router} — singleton, no conflict
PROPAGATION_STATUS:         WOULD PROPAGATE (all 12 preconditions satisfied)
```

Confirmed: all 12 genuinely yield the same `@koa/router` evidence, with no
conflicting callsites and no `ANY` contamination. Notably this is the *easy*
shape — one callsite per parameter — so Corpus B would **not** exercise the
join semantics that Q2 shows are the actual risk.

### This is explicitly NOT provenance success

Per R03's second finding, preserved verbatim here: Corpus B's handlers read
`ctx.validatedData.*` — a **middleware-written property** — not
`ctx.request.body.*`. Restoring framework identity would restore *handler
recognition*; it would **not** establish the correct external-input origin
family for most of that corpus.

```text
router argument type missing at parameter  ->  interprocedural TYPE-EVIDENCE problem
ctx.validatedData.*                        ->  middleware-derived PROVENANCE problem
```

Two separate problems. Closing the first must not be reported as closing the
second.

---

## Architectural home

```text
A. upstream in jssrc2cpg / type recovery
B. Fable's neutral normalization layer
C. provenance-specific derived fact
```

| Criterion | A (frontend) | B (neutral layer) | C (provenance-specific) |
|---|---|---|---|
| Generality across analyses | highest — every consumer benefits | high — all Fable readers benefit | lowest — one reader |
| Strength of evidence | would be indistinguishable from declared types (**bad**) | can carry a distinct resolution | can carry a distinct resolution |
| Maintenance burden | none for Fable (upstream owns it) | ongoing pass in Fable | duplicated per consumer |
| Duplicates frontend semantics | no | yes, partially | yes |
| Preserves provenance | **no** — would mutate `parameter.typeFullName` | yes | yes |

**Recommendation: B**, with A as a longer-term preference *only if* upstream
would emit it as a separately-labelled property.

The decisive criterion is evidence preservation, not convenience. Option A as
normally implemented would write the propagated type into
`parameter.typeFullName`, making callsite-derived evidence
**indistinguishable from a declared contract** — which is precisely the
conflation R11 showed to be dangerous (declared types describe intent;
propagated types describe observed calls). Option C fragments a genuinely
general capability into one bug family, repeating the mistake JS-PROV-R01 was
created to correct.

## Candidate fact (not promoted)

```text
ObservedParameterTypeFact
  callee_method_id
  parameter_index
  parameter_value_id
  observed_types[]            <-- SET, not a single type (Q2)
  unconstrained_callsite      <-- TRUE if any callsite passed ANY (Q2/R11)
  source_call_ids[]           <-- derivation chain (Q7 mis-resolution hazard)
  declared_type               <-- retained ALONGSIDE, never overwritten (Q3)
  resolution = CALLSITE_PROPAGATED
```

Never mutate `parameter.type`.

---

# JS-PROV-R04 VERDICT

```text
SINGLE-CALL PROPAGATION:  FEASIBLE — all four preconditions verified (R04-1).
                          New requirement found: type-identity normalization
                          (`Router:<init>` vs `Router` are the same concept
                          with different spellings; naive joins would
                          manufacture false conflicts).

POSITIONAL MAPPING:       EXACT — implicit `this` occupies index 0 on BOTH
                          sides, so arg index == param index with no offset.
                          No crossover on multi-arg calls (R04-5).

MULTI-CALL JOIN:          SET OF OBSERVED TYPES, with an explicit
                          `unconstrained_callsite` flag. NOT last-wins, NOT a
                          collapsed supertype. Concrete + ANY must NOT reduce
                          to the concrete type — `ANY` means the domain is
                          unconstrained (R11 invariant). Conflicts are
                          genuinely observable (R04-3: {Router, Db}).
                          LIMITATION: TS `any` and `unknown` both export as
                          `ANY` and are indistinguishable.

DECLARED-vs-PROPAGATED:   CLEANLY SEPARABLE (both Q3 sub-cases).
                          NEW BOUND: an `as any` cast ERASES the argument type
                          at the callsite, so propagation is BLIND exactly where
                          a declared contract is being violated — the situation
                          R11/R12 flagged as security-relevant. Propagation
                          strengthens evidence about well-typed callsites and
                          contributes nothing on deliberately erased ones. Gating on "parameter type == ANY"
                          preserves stronger declared contracts automatically
                          (R04-9). Invariant adopted: propagated types are
                          positive evidence about observed callsites, NOT
                          proof of exhaustive runtime domain.

TRANSITIVE FIXPOINT:      monotonic YES / finite domain YES / fixpoint
                          REQUIRED / termination provable (monotone growth
                          over a finite subset lattice). HAZARD: a
                          pre-existing type-recovery mis-resolution
                          (`prop:ts::program:Base`, malformed separator) would
                          be SPREAD transitively — second independent instance
                          of unreliable type recovery in this pipeline.

RECURSION:                TERMINATES under the set-union formulation (direct
                          and mutual). This is a direct argument FOR the
                          set-based representation over substitution.

AMBIGUOUS CALLS:          Precondition mechanically checkable (|callee| == 1).
                          Dynamic/external/multi-candidate callees produced no
                          propagation opportunity — correct abstention.

REST PARAMETERS:          MUST BE EXPLICITLY EXCLUDED. Argument index maps to
                          an array ELEMENT, not the parameter. The ANY-gate
                          abstains only incidentally, not on principle.

CORPUS-B REPLAY:          12/12 confirmed — all yield {@koa/router}, singleton,
                          no conflict, no ANY contamination, all preconditions
                          met. But this is the EASY shape (one callsite per
                          parameter) and does NOT exercise the join semantics
                          that are the real risk.

ARCHITECTURAL HOME:       B — Fable's neutral normalization layer. Decisive
                          criterion is evidence preservation: option A as
                          normally implemented would overwrite
                          `parameter.typeFullName`, making propagated evidence
                          indistinguishable from declared contracts (the exact
                          R11 conflation). Option C re-fragments a general
                          capability. A remains preferable long-term ONLY if
                          upstream emits it as a separately-labelled property.

PROMOTION_READY:          NO. The rule is now well-specified and its teeth are
                          characterized, but three items are unresolved:
                          (1) type-identity normalization is undesigned;
                          (2) the transitive mis-resolution hazard has no
                              containment strategy;
                          (3) any/unknown collapse is unfixable at this layer.
                          Additionally, Corpus B would not exercise the join
                          semantics, so passing it would prove little.

DOMINANT GAP:             Type-recovery RELIABILITY, not propagation
                          mechanics. Propagation is now understood; what is
                          not understood is how often the types being
                          propagated are themselves wrong. Two independent
                          mis-resolutions are now on record (R02
                          `router.get` -> `ctx:cookies:…:get`; R04
                          `prop:ts::program:Base`), and propagation would
                          amplify rather than contain them.

NEXT MILESTONE:           JS-PROV-R05 — Type-Recovery Reliability
                          Characterization. Measure, on the existing real
                          corpora, how frequently jssrc2cpg type recovery
                          produces wrong or malformed types (malformed
                          separators, receiver mis-binding, spurious class
                          attribution). Establish an error rate BEFORE
                          building anything that propagates types
                          transitively. If the base error rate is material,
                          propagation is unsafe regardless of how correct its
                          join semantics are.
```

## Discipline note

The tempting move was to implement the rule — Corpus B is 12/12 clean, the
preconditions are mechanically checkable, and positional mapping is exact.
Two findings argued against it, and both emerged only from the adversarial
teeth rather than from the Corpus-B replay:

- Corpus B is the *easy* shape and would not exercise join semantics at all,
  so passing it would have been weak evidence dressed as validation.
- The transitive case surfaced a spurious `Base` type on a value that never
  touches `Base`. Propagation is an *amplifier*: it takes whatever type
  recovery produced and spreads it across call boundaries. Building an
  amplifier before measuring the signal's error rate is the wrong order, and
  R05 is nominated specifically to fix that ordering.
