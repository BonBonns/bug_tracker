# JS-PROV-R12 — Context State-Flow Join (implementation)

Implements the write->read join. `context_state_flow.py`. JS-STATE untouched.

## Frozen invariant (from R11, source-confirmed)

State provenance does not live at the object level. The unit is:

```text
(context identity, property path, writer middleware, origin family,
 write strength, ordering)
```

never `ctx.validatedData -> HTTP_BODY`.

## Proof rule (narrow, as specified)

```text
same established route  +  same established context identity (parameter index 1,
POSITIONAL never by name)  +  compatible property path (prefix semantics)  +
writer BEFORE next()  +  reader in a downstream callback position  +  writer
identity ESTABLISHED (defined, non-external METHOD)   ->  candidate state flow
```

Strength classified separately: unconditional-before-next -> `MUST`;
conditional/nested-before-next -> `MAY`; after-next -> cannot establish.

Prefix semantics implemented exactly as specified: a write establishes a read
iff `writer_path` is a path-prefix of `reader_path`.

## Fixture: all 8 load-bearing negative controls PASS

```text
JS_PROV_R12=14/14
```

| Control | Result |
|---|---|
| 1 different object (unregistered) | never joins |
| 2 different route | `/r1` and `/r2` both write `shared`; **no cross-join**, and origins stay distinct (HTTP_BODY vs HTTP_QUERY) |
| 3 AFTER_NEXT writer | establishes nothing; recorded as abstention |
| 4 conditional writer | `MAY`, never `MUST` |
| 5 stub callback (`42 as any`) | establishes nothing; recorded as abstention |
| 6 wrapper `validate(schema)` | **joins** via R11's `RETURN -> METHOD_REF` hop |
| 7 siblings (`.user` write, `.email` read) | **no join** |
| 8 parent/child | whole-object write -> `.email` = ANCESTOR_WRITE; `.user` write -> `.user.id` = ANCESTOR_WRITE |

Plus ordering: a reader positioned *before* its writer establishes nothing.

Control 6 initially failed — the R11 wrapper hop was declared a prerequisite
but not wired. Fixed in the callback export
(`CALL -> callee METHOD -> RETURN -> METHOD_REF -> METHOD`) rather than by
relaxing the gate.

## Corpus B: 0 flows — and the cause is precisely located

```text
flows: 0
abstentions: WRITER_IDENTITY_UNKNOWN_OR_STUB          12
             WRITE_NO_NEXT_NOT_AVAILABLE_DOWNSTREAM   10
```

This is **not** a failure of the state export, which works correctly on the
real middleware:

```text
validate.middleware.js::program:validate:<lambda>1
    WRITE validatedData  ord=3  nextord=4      -> BEFORE_NEXT, correct
    READ  request.body   ord=1
```

The real `validate` middleware is exactly the expected shape
(`return async (ctx, next) => { ...; ctx.validatedData = value; await next(); }`),
and its write/read/ordering facts are all captured correctly.

**The break is in callback resolution, one layer up.** Corpus B reaches the
wrapper through CommonJS indirection:

```js
// middlewares/validate.middleware.js
function validate(schema) { return async (ctx, next) => { ... }; }
module.exports = validate;

// resources/account/sign-in/index.js
router.post('/sign-in', validate(schema), validator, handler);
```

`callback_args` resolves `validate(schema)` to the **module**
(`middlewares/validate.middleware`, 18 occurrences) rather than to the
`validate` METHOD. The R11 hop needs `callee -> METHOD -> RETURN`, but the
callee is a module object, so there is no RETURN to follow, and the module's
generic `(p0,p1,p2)` stub signature then correctly trips the stub gate.

**This is the same class as R03's cross-module problem — solved for *receivers*
by R08, unsolved for *callees*.** In the fixture `validate` is a local function
and the hop works; through `require(...)` + `module.exports = fn` it does not.

The 10 `WRITE_NO_NEXT` abstentions are the second-position `validator`
functions, whose writes (`ctx.validatedData.user = user`) were captured but
whose downstream readers could not be reached because the chain was already
broken at the first callback.

# JS-PROV-R12 VERDICT

```text
JOIN IMPLEMENTED:        YES. Property-path granular, prefix semantics,
                         route-scoped, positional context identity, strength
                         classified separately.
FIXTURE:                 JS_PROV_R12=14/14. All 8 specified negative controls
                         load-bearing and passing.
PREFIX SEMANTICS:        Verified in all four directions (whole-object ->
                         member COMPATIBLE; siblings INCOMPATIBLE; ancestor ->
                         descendant COMPATIBLE; descendant -> ancestor NOT).
NEXT BOUNDARY:           Enforced. AFTER_NEXT never establishes downstream.
WRITE STRENGTH:          MUST / MAY separated; conditional never promoted.
ORIGIN FAMILIES:         Carried per-property (HTTP_BODY / HTTP_QUERY /
                         DERIVED_FROM_* / NO_EXTERNAL_ORIGIN / UNKNOWN).
                         Two routes writing the SAME path keep DIFFERENT
                         origins — the R11 invariant holds under test.

CORPUS-B FLOWS:          0 ESTABLISHED / 0 MAY / all UNKNOWN
CORPUS-B CAUSE:          Callee resolution across CommonJS
                         `module.exports = fn` + `require(...)`. The state
                         facts themselves are correct on real code; the
                         callback identity is not.

MIDDLEWARE STATE LAYER PROMOTION_READY: NO — the join is sound on controlled
                         input but has produced zero real-code flows.
EXTERNAL INPUT ORIGIN PROMOTION_READY:  NO.

DOMINANT GAP:            Cross-module CALLEE resolution (`module.exports = fn`).
                         Precisely the analogue of the receiver problem R08
                         solved. R08 propagated argument types across a
                         resolved call edge; this needs the exported *function
                         identity* to survive the module boundary.

NEXT MILESTONE:          JS-PROV-R13 — Cross-Module Export Identity. Recover
                         `require(m)` / `module.exports = fn` so a call to an
                         imported function resolves to the METHOD rather than
                         the module object. Acceptance anchor already exists
                         and is unambiguous: Corpus B's 10 `validate(schema)`
                         callbacks must resolve to `validate:<lambda>1`, and
                         the R12 fixture must stay 14/14.
```

## Discipline note

The join works and every negative control it was given holds — including the
two that decide soundness (siblings must not join; separate routes must not
join). It still produced **zero** flows on real code.

Reporting 14/14 as success would have been the error the whole line has been
avoiding: a fixture-validated relation that has never fired in production. The
useful output is the diagnosis, not the score — the state facts are correct on
Corpus B's real middleware, and the single broken link is callee resolution
through CommonJS export indirection.

Notably this is the *third* time the same shape has appeared: R03 (receiver
type across modules), R10/R11 (wrapper-return one hop short), and now callee
identity across `module.exports`. Cross-module identity, not analysis
sophistication, remains the binding constraint on this line.

---

# Addendum — R12-1: returned-function identity promoted as a standalone primitive

Reviewing R12 against the R12-0..R12-6 sequence, six steps were covered but
**R12-1 was not**: the higher-order traversal was buried inside the callback
export rather than promoted. Corrected here.

New artifacts (`frontends/javascript-typescript/joern-ts/`):
`returned_function_identity.sc` + `returned_function_identity.py` ->
**`ReturnedFunctionIdentityFact`**.

```text
wrapper CALL -> callee METHOD -> RETURN -> METHOD_REF -> returned METHOD
```

Deliberately framework-neutral. It was found while characterizing Koa's
`validate(schema)`, but nothing about it is Koa-specific — any function
returning a function literal resolves here, so callback registration, event
handlers, decorators and other frameworks' middleware can reuse it.
`JS_PROV_R12` remains **14/14** after the extraction.

## An unexpected Corpus-B result, reported with its caveat

Run standalone against Corpus B the primitive emits **two** facts:

```text
middlewares/validate.middleware.js::program           -> validate:<lambda>1
middlewares/validate.middleware.js::program:validate  -> validate:<lambda>1
```

The second is the intended wrapper->returned mapping. **The first is a
module-level entry that happens to bridge exactly the gap R12 failed on** —
`callback_args` resolves `validate(schema)` to the module
`middlewares/validate.middleware`, and this fact maps that module to
`validate:<lambda>1`.

**This is not a solution to R13, and must not be treated as one.** The
module-level fact exists because the traversal uses `m.ast.isReturn` — all AST
*descendants* — so the module's program node inherits the `RETURN` belonging to
the `validate` function nested inside it. It is AST containment, not export
semantics. Consequences:

- A module containing **two** functions that each return a lambda would map to
  **both**, ambiguously, with nothing to disambiguate which one a given
  `require(...)` call reaches.
- It carries no evidence that the returned function is what `module.exports`
  actually exports.

Using it to close R12's Corpus-B gap would be joining on an accident of AST
nesting. R13 still needs real export identity (`module.exports = fn` +
`require(m)`), and this fact should be treated as a *hint to verify*, not a
resolution. Recorded here so a future milestone does not mistake the
coincidence for the mechanism.

**Also unchanged:** the Corpus-B replay remains 0 flows. This addendum promotes
a primitive and documents a caveat; it does not alter R12's verdict.
