# JS-PROV-R16 — Write-RHS Origin Dataflow Characterization

**Characterization only.** No implementation. No third-party semantics modelled.
The three sub-questions are answered separately and must not be conflated:
composition, opaque-call abstention, and destructuring are independent problems.

## Q1 — Object spread composition: **REPRESENTABLE**

`<operator>.spread` is a distinct CPG node carrying its source expression, and a
multi-spread literal keeps **both** sources as separate children:

```text
const a3 = { ...ctx.request.body, ...ctx.query }
    RHS label = BLOCK
      SPREAD src = _tmp_2, ctx.request.body
      SPREAD src = _tmp_2, ctx.query
```

```text
T1  { ...body }                -> {HTTP_BODY}
T2  { ...query }               -> {HTTP_QUERY}
T3  { ...body, ...query }      -> {HTTP_BODY, HTTP_QUERY}   <-- SET, not a merge
T4  { k: 1, ...body }          -> {HTTP_BODY}   (literal member contributes none)
T5  { ...other }               -> {} / UNKNOWN  (no HTTP origin)
```

T3 is the decisive one and it holds: the two spreads are **separately visible**,
so a set-valued origin is derivable rather than a single collapsed family. This
matches JS-PROV-R04's join semantics exactly — never last-writer-wins, never a
collapsed supertype. T4 confirms a literal member adds nothing and does not
dilute the set; T5 confirms a non-HTTP spread yields no HTTP origin rather than
a default.

**However:** the spread's own arguments are `(_tmp_2, ctx.request.body)` — the
first is the accumulating temporary. A composition rule must read the *source*
operand and ignore the accumulator, or every spread would appear to derive from
a temp. Measured, not assumed.

## Q2 — Opaque third-party call: **NO CALLEE, SO ABSTENTION IS FORCED**

```text
const r = await schema.validate(a3)
    methodFullName = <unknownFullName>
    callees        = 0
    args           = schema, a3
```

There is no resolvable callee at all — `@hapi/joi` is not in the analyzed
sources. So the frontend supplies nothing to over-trust here, and the correct
result is structural rather than a policy choice:

```text
ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL
```

The argument's own origin (`a3` -> `{HTTP_BODY, HTTP_QUERY}`) is visible and
should be **recorded on the fact**, but it must not be propagated to `r`:
`schema.validate()` may reshape, filter (`stripUnknown`), or replace the value.

T9 (`preserve(ctx.request.body)`, a hypothetically value-preserving wrapper) is
**deliberately not distinguished** from T8. Doing so would require a
value-preservation model for third-party functions, which this milestone
explicitly does not build. Both abstain. Treating a locally-defined passthrough
differently is possible in principle (JS-STATE-R01's structural-passthrough
proof) but is a separate capability and was not exercised here.

## Q3 — Destructuring: **MEMBER-PRECISE, siblings separable**

```text
const { value } = r   lowers to:
      _tmp_5 = r
      value  = _tmp_5.value
      (fieldAccess _tmp_5.value)
```

Destructuring becomes an ordinary member read through a temporary, so:

```text
T6  const { value } = r   -> reads r.value
T7  const { error } = r   -> reads r.error     <-- sibling, distinct
```

`.value` and `.error` are **separable**, exactly as R12's property-path prefix
semantics require. Destructuring is therefore *not* an additional barrier; it is
a member access with one temp hop, already within existing machinery.

This is a mirror of R13's object-literal export finding: both lower to a `BLOCK`
whose members are individually recoverable — but in R13's case the members were
*not* traversed and it abstained, whereas here the lowering is explicit
assignments and is traversable.

## Corpus B implication

The Corpus B chain is exactly T3 -> T8 -> T6:

```js
const { value, error } = await schema.validate({ ...ctx.request.body, ...ctx.query }, {...});
ctx.validatedData = value;
```

```text
composition:    {HTTP_BODY, HTTP_QUERY}   RECOVERABLE (Q1)
opaque call:    schema.validate           ABSTAINS, callee unresolvable (Q2)
destructuring:  value = _tmp.value        RECOVERABLE (Q3)
```

**Two of three hops are recoverable; the middle one is not.** So R15's
`origin_family = UNKNOWN` on all 23 Corpus-B flows is confirmed as the *correct*
answer, not a gap in the classifier. The most a sound analysis can say is:

```text
ctx.validatedData  <-  ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL
                       transform_input_origins = {HTTP_BODY, HTTP_QUERY}
```

That is strictly more informative than `UNKNOWN` and strictly weaker than
`DERIVED_FROM_HTTP_BODY`. It records what entered the transform without
asserting what came out.

# JS-PROV-R16 VERDICT

```text
SPREAD COMPOSITION:      REPRESENTABLE. `<operator>.spread` nodes keep multiple
                         sources separately -> SET-valued origins (R04 join
                         semantics). Caveat: the accumulator temp is the
                         spread's first argument and must be ignored.
LITERAL MEMBERS:         Contribute no origin and do not dilute the set (T4).
NON-HTTP SPREAD:         Yields no HTTP origin rather than a default (T5).
OPAQUE THIRD-PARTY CALL: callee UNRESOLVABLE (0 callees). Abstention is FORCED,
                         not chosen. Correct label:
                         ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL, carrying
                         transform_input_origins as evidence.
VALUE-PRESERVING WRAPPER: NOT distinguished (T9 == T8). Would require a
                         third-party value-preservation model, deliberately
                         not built.
DESTRUCTURING:           MEMBER-PRECISE. Lowers to `_tmp = r; x = _tmp.x`.
                         `.value` and `.error` separable -> compatible with
                         R12's prefix semantics. NOT an extra barrier.
CORPUS-B DIAGNOSIS:      R15's UNKNOWN is CONFIRMED CORRECT. Composition and
                         destructuring are recoverable; the Joi call in the
                         middle is not.
BEST SOUND CLAIM:        ctx.validatedData <- ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL
                         with transform_input_origins = {HTTP_BODY, HTTP_QUERY}.
                         Strictly more than UNKNOWN, strictly less than
                         DERIVED_FROM_HTTP_BODY.
PROMOTION_READY:         NO. Nothing implemented; and the headline result is
                         that the decisive hop is unmodellable without a
                         third-party semantics layer.
DOMINANT GAP:            Third-party call semantics. Everything either side of
                         it is now characterized as recoverable.
NEXT MILESTONE:          JS-PROV-R17 — Transform-Input Origin Fact
                         (implementation, narrow): emit
                         ORIGIN_TRANSFORMED_BY_UNMODELLED_CALL with a SET of
                         input origins, wire it into R12's join, and verify on
                         Corpus B that validatedData reports
                         {HTTP_BODY, HTTP_QUERY} as transform INPUTS while its
                         own origin_family stays UNKNOWN. Acceptance: R12 14/14,
                         R14 9/9 unchanged; T5 must contribute no HTTP origin;
                         T8 and T9 must both abstain.
```

## Discipline note

The tempting conclusion was that spread + destructuring being recoverable means
Corpus B's origins are recoverable. They are not — the two recoverable hops sit
on either side of the one that is not, and a chain is only as strong as its
weakest link.

The useful outcome is a *better abstention*: recording
`{HTTP_BODY, HTTP_QUERY}` as what entered `schema.validate()` is real evidence a
reviewer can act on, without claiming anything about what came out. T9 was
included specifically to make sure that convenience did not creep in — a
"value-preserving" wrapper is indistinguishable from an arbitrary one at this
layer, and both abstain.
