# JS-PROV-R03 — Cross-Module Framework-Identity Propagation Characterization

**Characterization only. Nothing implemented.** No engine changes; R07
unchanged (`b18bc7aa…`); no name heuristics; no framework-specific patches.

Question inherited from JS-PROV-R02's single dominant residual:

> Can framework-object identity be propagated across module boundaries from
> existing facts, or is this a `FRONTEND_GAP` requiring interprocedural type
> propagation `jssrc2cpg` does not perform?

Measured against JS-PROV-R02's Corpus B (`paralect/koa-api-starter`
@ `19b1a2657854be79f8eb10904e7ba28013643d2a`), where registration provenance
scored 0/14.

---

## Result: NOT a frontend gap. Every required fact exists. Exactly ONE hop is missing.

### Link 1 — Constructor identity in the defining module: **PRESENT**

```text
ASSIGN  const Router = require('@koa/router')
ASSIGN  const router = new Router()
LOCAL   router  type=@koa/router
```

The framework identity is fully resolved where the router is constructed.
JS-PROV-R02 reported `router: ANY`, which was correct — but that observation
was taken *inside the receiving module*. In the **defining** module the type
is `@koa/router`. This distinction was not visible in R02 and materially
changes the diagnosis.

### Link 2 — Argument type at the call site: **PRESENT**

Every one of the 12 `register(router)` call sites carries the framework type
on the argument:

```text
register mfn=resources/account/sign-in/index.js::program:<lambda>0
    arg0 IDENT _tmp_2 type=resources/account/sign-in/index.js::program
    arg1 IDENT router type=@koa/router          <-- identity intact at caller
```

### Link 3 — Call edge caller→callee: **RESOLVED**

```text
register  callee=resources/account/sign-up/index.js::program:<lambda>0   argType=@koa/router
register  callee=resources/account/sign-in/index.js::program:<lambda>0   argType=@koa/router
register  callee=resources/account/sign-out/index.js::program:<lambda>1  argType=@koa/router
```

`cpg.call.callee` resolves each cross-module `register(...)` to the **exact**
target method. The import/export wiring
(`require('./sign-in').register(router)` → `module.exports = { register }`)
is fully traversed by the frontend.

### Link 4 — Callee parameter type: **THE MISSING HOP**

```text
resources/account/sign-in/index.js::program:<lambda>0
    param0 this   type=resources/account/sign-in/index.js::program  hints=[…]
    param1 router type=ANY                                          hints=[]   <-- LOST
    REG post mfn=<unknownFullName> recv_type=ANY
```

The caller says the argument is `@koa/router`. The call edge is resolved. The
callee's corresponding parameter is `ANY`, with **empty** dynamic type hints.

```text
caller arg1 : @koa/router  ──(resolved CALL edge)──▶  callee param1 : ANY
                                                      ↑
                                          argument→parameter type binding
                                          NOT PERFORMED
```

Note the contrast within the same node: `param0` (`this`) *does* carry both a
type and a dynamic hint, so the parameter-typing machinery works — it simply
is not fed by cross-module argument types.

---

## Classification

```text
FRONTEND_GAP:                   NO
MISSING_INTERPROCEDURAL_INFERENCE: YES — argument→parameter type propagation
                                   across an already-resolved call edge
DERIVABLE_FROM_EXISTING_FACTS:     YES
```

This is a materially better outcome than R02's residual suggested. R02
concluded "framework-object type does not survive being passed as a parameter
across module boundaries," which was accurate as an observation but ambiguous
as a diagnosis — it could have meant the frontend loses the import wiring
entirely. It does not. The wiring, the argument type, and the call edge are
all present and correct; only the one-hop binding between them is absent.

Every fact required to compute it is already exported:

| Requirement | Existing fact |
|---|---|
| argument type at caller | `arguments.tsv` / identifier `typeFullName` |
| resolved call target | `calls.tsv` `candidate_target_ids` (`cpg.call.callee`) |
| callee parameter identity | `parameters.tsv` (index, name) |

A propagation would be: *for each resolved call, bind argument type at index
`i` to callee parameter at index `i` where the parameter's type is `ANY`.*

---

## What this does NOT establish (guarding against over-claiming)

This milestone measured **feasibility of the missing hop**, not soundness of
performing it. Before any implementation, the following are unmeasured and
each could invalidate the approach:

1. **Multiple call sites, conflicting argument types.** Corpus B happens to
   pass the same `@koa/router` object to every `register`. A parameter called
   with two different types must resolve to a join (or abstain), not
   last-writer-wins. Untested.
2. **Recursive / transitive propagation.** If a parameter's newly-inferred
   type must itself flow onward through a further call, this becomes a
   fixpoint computation with termination and ordering concerns. Untested.
3. **Soundness direction.** Overwriting `ANY` with a caller-derived type is an
   *assumption* that the parameter is only ever called that way. Under
   Fable's standing discipline (`ANY` is not a domain; UNKNOWN is not SAFE),
   a propagated type is weaker evidence than a declared one and must be
   labelled as such — a distinct `resolution` value, not silently merged with
   directly-declared types.
4. **Whether this is Fable's job at all.** The cleanest fix is upstream: if
   `jssrc2cpg` performed this binding, every downstream consumer benefits and
   Fable adds no inference of its own. Doing it in Fable means maintaining a
   type-propagation pass that duplicates frontend responsibility. This is an
   architectural decision, not a technical one, and R03 does not settle it.

Also unresolved, and **independent** of this hop: even with framework identity
restored, JS-PROV-R02 found Corpus B's handlers read `ctx.validatedData.*` — a
**middleware-written property**, not `ctx.request.body`. So closing this hop
would restore handler recognition but would **not** by itself yield correct
origin families for most of that corpus. Two separate problems; only one is
addressed here.

And the `methodFullName` mis-resolution R02 found
(`router.get` → `ctx:cookies:<returnValue>:<member>(cookies):get`) remains
unexplained. It is visible again here as `mfn=<unknownFullName>` on the
registration calls — consistent with a receiver typed `ANY`, but it means
`mfn` cannot be trusted as framework evidence without receiver corroboration,
regardless of this hop.

---

## Acceptance anchor for any future implementation

Already defined by R02 and unchanged:

```text
Corpus B (paralect/koa-api-starter @ 19b1a265):
    14 registrations must gain framework identity
    WITHOUT any name heuristic
Corpus A (gobeam/truthy @ 9b9a61be):
    must remain EXACTLY unchanged (33 recognized, 16/6/12/0 origin families)
Both corpora:
    false origins must remain 0
```

Corpus A is the critical control: annotation provenance does not depend on
this hop at all, so any change that perturbs Corpus A's results is doing
something other than what it claims.

---

# JS-PROV-R03 VERDICT

```text
CONSTRUCTOR IDENTITY (defining module):   PRESENT (@koa/router)
ARGUMENT TYPE AT CALL SITE:               PRESENT (12/12 register sites)
CALL EDGE caller -> callee:               RESOLVED (exact method fullNames)
CALLEE PARAMETER TYPE:                    ANY  <-- THE SINGLE MISSING HOP
IMPORT/EXPORT WIRING:                     FULLY TRAVERSED by the frontend

CLASSIFICATION:  NOT a FRONTEND_GAP.
                 Missing interprocedural argument->parameter type binding
                 across an already-resolved call edge.
                 DERIVABLE from facts already exported.

DOMINANT RESIDUAL: unchanged in substance, sharpened in diagnosis. The blocker
                 is one inference, not missing data. But three soundness
                 questions (conflicting call sites, transitive/fixpoint
                 propagation, evidence-strength labelling) and one
                 architectural question (frontend vs. Fable ownership) are
                 UNMEASURED and must precede implementation.

                 Independently: middleware-written properties
                 (ctx.validatedData.*) would still block correct origin
                 families for most of Corpus B even after this hop closes.

NEXT MILESTONE:  JS-PROV-R04 — Argument→Parameter Type Propagation
                 Characterization (characterization only). Scope:
                 (1) measure conflicting-argument-type frequency across both
                     corpora and at least one larger repo;
                 (2) determine whether propagation must be transitive and if
                     so whether it terminates;
                 (3) define the distinct resolution value for propagated
                     (vs. declared) types, preserving the ANY-is-not-a-domain
                     invariant;
                 (4) decide frontend-vs-Fable ownership explicitly.
                 Only then reconsider ExternalInputOriginFact promotion.

PROMOTION_JUSTIFIED: NO (unchanged from R02; nothing here changes the gate
                 outcome — Gate 1 still requires two mechanisms surviving real
                 code, and registration provenance still does not).
```

## Discipline note

The temptation here was to implement the hop — it is genuinely small, the
facts are all present, and it would take Corpus B from 0/14 to plausibly
14/14 in one pass. Three things argued against doing it inside a
characterization milestone: the soundness questions above are real and
untested, the fix may belong upstream in `jssrc2cpg` rather than in Fable at
all, and closing this hop would still leave Corpus B's origin families wrong
because of the separate middleware-property problem. A 0→14 recognition jump
would have looked like a decisive win while leaving the actual provenance
output no more correct than before.
