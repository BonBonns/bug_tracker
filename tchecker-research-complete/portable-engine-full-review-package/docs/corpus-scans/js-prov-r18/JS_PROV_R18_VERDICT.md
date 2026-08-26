# JS-PROV-R18 — Inline Expression Argument Resolution (implementation)

`JS_PROV_R17=18/18` (R17's 12 + R18's 6 node-identity teeth). R12 14/14,
R14 9/9 unchanged. JS-STATE untouched.

## Frozen invariant

```text
opaque transform + known input origins  !=  established output origin
```

Holds even when the inputs are confidently known. Gate-asserted across every
inline case.

## ArgumentValueRef — expression-general, keyed by node identity

Call arguments are now recorded as a reference, never as a code string:

```text
ArgumentValueRef
  LOCAL:<name>            |  EXPRESSION_NODE:<node-id>
```

Code strings are not identities. Object literals are the first supported
expression form, but the abstraction is deliberately general — arrays,
ternaries, binary expressions and nested calls can use the same mechanism once
characterized, with no `inline_object_literal` side channel.

## The nested-call control failed first, and that was the point

The penultimate tooth you specified caught a real defect on the first run:

```js
opaque(inner({ ...ctx.request.body }))   -> transform_input_origins = ['HTTP_BODY']   WRONG
```

The node walk descended two AST levels and reached a spread belonging to the
**inner** call's argument, attributing an inner transform's inputs to the outer
one — the same unsafe direction as R17's bug.

Fixed structurally: only an argument that **is itself an object literal**
contributes spread sources. A `CALL` argument is a nested transform and
contributes nothing.

```text
opaque({ ...body })                 -> transform input BODY        (correct)
opaque(inner({ ...body }))          -> no inputs harvested         (correct)
const out = opaque({ ...body })     -> out.origin NEVER HTTP_BODY  (correct)
```

Those last two are different claims and are now separated.

## R18 acceptance teeth — all pass

```text
named-local object still resolves exactly as before        (a1..a4 unchanged)
inline {...body, ...query} -> BOTH inputs
inline literal-only        -> no HTTP origin
inline unrelated spread    -> no HTTP origin invented
two identical inline objects at different callsites        -> distinct node ids
spread inside a NESTED call -> NOT harvested by the outer call
opaque-transform gate intact: no inline case establishes output
```

## Corpus B — promotion condition MET on real application code

```text
ctx.validatedData
  origin_family             : UNKNOWN
  transform_input_origins   : {HTTP_BODY, HTTP_QUERY}
  transform                 : UNMODELLED_CALL
  output_origin_established : false
```

Exactly the target state. Fable can now say, of real production middleware:

> This downstream state value passed through an unmodelled transformation whose
> known external inputs include both the HTTP body and the query string; the
> output's provenance itself is not established.

That tells a reviewer where to look next without manufacturing taint across the
opaque call.

# JS-PROV-R18 VERDICT

```text
IMPLEMENTED:             ArgumentValueRef (LOCAL | EXPRESSION_NODE), node-id
                         keyed, expression-general.
GATE:                    JS_PROV_R17=18/18. R12 14/14, R14 9/9 unchanged.
NESTED-CALL CONTROL:     FAILED on first run, fixed structurally. Only
                         object-literal arguments contribute spread sources.
CORPUS B:                PROMOTION CONDITION MET —
                         UNKNOWN / {HTTP_BODY,HTTP_QUERY} / not established.
STILL NOT ESTABLISHED:   Output provenance across Joi. That is correct and
                         permanent absent a third-party semantics layer.
PROMOTION_READY:         TransformInputOriginFact — YES (gated, abstaining,
                         evidence-labelled, verified on real code).
                         ExternalInputOriginFact — NO: output origin remains
                         unestablished, which is what that fact would assert.
NEXT MILESTONE:          JS-PROV-R19 — Carry transform-input evidence through
                         R12's state-flow join, so downstream reads
                         (ctx.validatedData.email) inherit
                         transform_input_origins WITHOUT upgrading
                         origin_family. Acceptance: property-granular
                         propagation on Corpus B; origin_family stays UNKNOWN
                         and output_origin_established stays false at every
                         reader; all current gates unchanged.
```

## Discipline note

Two of the three implementation steps in R17/R18 introduced a defect that
failed toward **claiming more evidence**, and both were caught only by controls
that were specified in advance rather than by the happy path. The nested-call
tooth in particular did not exist until it was asked for, and it failed
immediately.

The milestone's real output is not the 18/18. It is that on real code Fable now
occupies the middle state — preserving what entered an opaque transform without
inventing what came out — which neither `UNKNOWN` nor `DERIVED_FROM_BODY` could
express.
