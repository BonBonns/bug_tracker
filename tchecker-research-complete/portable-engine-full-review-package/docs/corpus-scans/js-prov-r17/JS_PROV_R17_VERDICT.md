# JS-PROV-R17 — Transform-Input Origin Fact (implementation)

`local_definitions.sc` + `transform_input_origin.py`. JS-STATE untouched.
`JS_PROV_R17=12/12`; R12 14/14 and R14 9/9 unchanged.

## Frozen three-way distinction — enforced in the gate

```text
DERIVED_FROM_HTTP_BODY      output provenance IS established
TRANSFORM_INPUT {..}        those origins ENTERED the transform;
                            output provenance NOT established
UNKNOWN                     no useful origin evidence
```

Gate assertions keep them from collapsing in either direction: an opaque
transform never becomes `DERIVED_FROM_*`, and established-origin paths are never
downgraded to transform-input evidence.

## Fixture results — all controls

```text
a1  {...body}              HTTP_BODY            established
a2  {...query}             HTTP_QUERY           established
a3  {...body, ...query}    {HTTP_BODY,HTTP_QUERY} established   (SET, R04 semantics)
a4  {k:1, ...body}         HTTP_BODY            established     (literal dilutes nothing)
a5  {...other}             UNKNOWN, no inputs                   (invents nothing)
value  destructured        UNKNOWN + TRANSFORM_INPUT {BODY,QUERY}  not established
error  sibling             UNKNOWN + TRANSFORM_INPUT {BODY,QUERY}  not established
p   preserve(body)         UNKNOWN + TRANSFORM_INPUT {BODY}        not established
```

`p` (T9) is deliberately **not** distinguished from `value` (T8): a
"value-preserving" wrapper is indistinguishable from an arbitrary one at this
layer, and both abstain on output while both retain input evidence.

Open-world is represented per JS-PROV-R04: `unconstrained_input` is carried on
every classification, so `{HTTP_BODY}` is never implied exhaustive.

## A soundness bug found and fixed mid-implementation

Unwrapping `await` (needed so a transform hidden behind it stays visible) caused
spreads **nested inside a call's arguments** to be harvested as if they were the
call's own result. On Corpus B this produced:

```text
ctx.validatedData -> origin_family = MULTIPLE, output_origin_established = TRUE
```

i.e. it claimed established body+query provenance **through** the unmodelled Joi
call — manufacturing exactly the evidence this milestone exists to refuse.
Fixed by guarding spread harvesting to RHS that is *itself* an object literal
(`label != "CALL"`). Corpus B then correctly returns to
`UNKNOWN / UNMODELLED_CALL / not established`.

Worth stating plainly: this bug was introduced by my own fix one step earlier,
and it failed in the unsafe direction. It was caught only because Corpus B was
re-checked after the change rather than trusting the fixture.

## Corpus B — partially achieved, reported precisely

```text
ctx.validatedData = value
  origin_family             : UNKNOWN
  transform                 : UNMODELLED_CALL          <-- correct
  output_origin_established : false                    <-- correct
  transform_input_origins   : []                       <-- NOT the hoped {BODY,QUERY}
  unconstrained_input       : true                     <-- honest
```

The transform boundary is identified correctly. The **input origins are not
recovered**, for a specific and newly-identified reason:

```js
// fixture (resolves):   schema.validate(a3)          <- named local
// Corpus B (does not):  schema.validate({ ...ctx.request.body, ...ctx.query }, {...})
```

Corpus B passes an **inline object literal** as the argument. `local_defs`
records call arguments as code strings and resolves them by looking up a *named
local*, so an inline literal has no entry and the resolver correctly falls
through to `unconstrained_input = true`.

This is a representational gap, not an unsoundness: the result is a correct,
conservative abstention. But the concrete payoff on real code —
`transform_input_origins = {HTTP_BODY, HTTP_QUERY}` — is **not** delivered.

# JS-PROV-R17 VERDICT

```text
IMPLEMENTED:              TransformInputOriginFact. Set-valued, open-world
                          (`unconstrained_input`), output never established
                          across an unmodelled call.
FIXTURE:                  JS_PROV_R17=12/12. All specified negative controls hold.
REGRESSIONS:              R12 14/14, R14 9/9 unchanged.
THREE-WAY DISTINCTION:    Frozen and gate-enforced; no collapse in either direction.
SOUNDNESS BUG:            One found and fixed during implementation (nested
                          argument spreads harvested through a transform).
                          Failed in the UNSAFE direction; caught by re-checking
                          Corpus B after the change.
CORPUS B:                 Transform boundary CORRECT (UNKNOWN / UNMODELLED_CALL /
                          not established). Input origins NOT recovered:
                          the Joi argument is an INLINE OBJECT LITERAL, not a
                          named local, so it resolves as unconstrained.
PROMOTION_READY:          Fixture-level YES; ExternalInputOriginFact still NO.
DOMINANT GAP:             Inline (unnamed) expression arguments. `local_defs`
                          resolves call arguments by named local only.
NEXT MILESTONE:           JS-PROV-R18 — Inline Expression Argument Resolution.
                          Narrow: give call arguments that are themselves object
                          literals / expressions a resolvable identity (node id
                          rather than code string), so their spread sources are
                          reachable. Acceptance: Corpus B's ctx.validatedData
                          reports transform_input_origins {HTTP_BODY, HTTP_QUERY}
                          while origin_family STAYS UNKNOWN and
                          output_origin_established STAYS false; R17 12/12,
                          R12 14/14, R14 9/9 unchanged.
```

## Discipline note

The headline is 12/12 with the three-way distinction frozen — but the two
findings that matter more are that the implementation briefly manufactured
provenance across the Joi call, and that the real-code payoff still is not
delivered.

The first is the sharper lesson: the bug arose from a *correct* fix (unwrapping
`await`) whose blast radius I had not bounded, and it failed toward claiming
more evidence rather than less. Fixture-only verification would have shipped it,
because the fixture passes a named local where Corpus B passes an inline
literal — the very difference that also blocks the payoff.
