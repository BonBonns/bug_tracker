# JS-PROV-R19 — Transform-Input Evidence Transport Through State Flow

`JS_PROV_R12=28/28`. R07 31/31, R08 12/12, R09 11/11, R14 9/9, R17 18/18.
Transport only — no new origin inference, no new transform semantics.

## Correction: the first R19 pass was incomplete

An earlier pass carried origin evidence but under-built this specification in
three ways. All three are now closed:

1. **Two axes were not named.** `state_flow_strength` and `origin_strength`
   (`ESTABLISHED | TRANSFORM_INPUT_ONLY | UNKNOWN`) are now explicit fields on
   every flow, not implied by `resolution` + a boolean.
2. **Writer precedence did not exist.** R12 emitted a flow for *every*
   prefix-matching writer, so a `.user` read still inherited the whole-object
   writer's evidence — the exact thing the critical overwrite tooth forbids.
3. **The overwrite tooth was untested**, and `ctx.validatedData.user` was not
   inspected on Corpus B.

## Two independent axes

```text
state_flow_strength = MUST | MAY | UNKNOWN
origin_strength     = ESTABLISHED | TRANSFORM_INPUT_ONLY | UNKNOWN
```

Gate-enforced independence: a `MUST` edge never upgrades
`TRANSFORM_INPUT_ONLY` to `ESTABLISHED`, and `MUST + TRANSFORM_INPUT_ONLY`
survives as exactly that combination.

## Writer precedence — the critical overwrite tooth

For a given (registration, reader, read path) the **most specific**
prefix-matching writer is `effective`; broader ones are **retained but marked**
`shadowed_by_more_specific_writer`, so the precedence decision stays
inspectable rather than silently dropping data.

Measured on the new `/ov` fixture route:

```text
read validatedData.user    writer=ovNarrow  spec=2  effective=TRUE   origin=ESTABLISHED
read validatedData.user    writer=ovBroad   spec=1  effective=FALSE  (shadowed)
read validatedData.email   writer=ovBroad   spec=1  effective=TRUE   origin=TRANSFORM_INPUT_ONLY {BODY,QUERY}
```

`.user` uses the specific writer and does **not** inherit the broad
transform-input evidence; `.email` **does**, because no more-specific `.email`
writer exists. Exactly the specified behaviour.

## Corpus B — required production result met

```text
23 effective flows
  state_flow_strength : MUST                  x23
  origin_strength     : TRANSFORM_INPUT_ONLY  x23

validatedData        MUST / TRANSFORM_INPUT_ONLY / UNKNOWN / est=false / {HTTP_BODY,HTTP_QUERY}
validatedData.email  MUST / TRANSFORM_INPUT_ONLY / UNKNOWN / est=false / {HTTP_BODY,HTTP_QUERY}
validatedData.token  MUST / TRANSFORM_INPUT_ONLY / UNKNOWN / est=false / {HTTP_BODY,HTTP_QUERY}
```

Never reported as HTTP_BODY- or HTTP_QUERY-originated.

**On `ctx.validatedData.user`:** no effective read appears in Corpus B's
established registrations. The `.user` writes R11 found sit in *validator*
middlewares whose own downstream readers are not reached — those remain in the
`WRITE_NO_NEXT` / `WRITER_IDENTITY_UNKNOWN_OR_STUB` abstentions. So the
`.user` vs `.email` origin distinction is demonstrated on the **fixture**, not
on Corpus B. Stating otherwise would overclaim.

# JS-PROV-R19 VERDICT

```text
STATE-FLOW TRANSPORT:        IMPLEMENTED, transport only.
ORIGIN-STRENGTH PRESERVATION: ESTABLISHED / TRANSFORM_INPUT_ONLY / UNKNOWN
                             explicit; never upgraded by a MUST edge.
SET PRESERVATION:            {HTTP_BODY, HTTP_QUERY} preserved as a set; no
                             last-writer-wins.
PROPERTY SPECIFICITY:        Prefix semantics unchanged; siblings never join.
WRITER PRECEDENCE:           IMPLEMENTED (new). Most-specific writer effective;
                             broader writers retained and marked shadowed.
ROUTE ISOLATION:             Unchanged, gate-verified; distinct routes keep
                             distinct origins after propagation.
CONTEXT ISOLATION:           Unchanged (positional context identity).
CONDITIONAL WRITES:          MAY preserved on the state-flow axis.
AFTER_NEXT EXCLUSION:        Unchanged; no downstream transport.

CORPUS-B DOWNSTREAM READS:   23 effective
TRANSFORM_INPUT_ONLY READS:  23
ESTABLISHED READS:            0
UNKNOWN READS:                0

PROMOTION_READY:  YES for transport + TransformInputOriginFact carriage.
                  ExternalInputOriginFact still NO — output provenance across
                  Joi is unestablished, correctly.
DOMINANT GAP:     Third-party transform semantics (unchanged). Secondary:
                  Corpus B yields no effective `.user` read, so the
                  mixed-origin container case is fixture-only on real code.
NEXT MILESTONE:   Optional; chain complete for scope. Ordered by evidence value:
                  (a) second real corpus for the whole chain (R02 lesson: one
                      corpus is not generalization);
                  (b) curated value-preservation profile (joi/zod/yup) to
                      convert TRANSFORM_INPUT -> DERIVED_FROM_* only where a
                      library is explicitly characterized;
                  (c) NestJS annotation path, where @Body() names the origin
                      family with no transform in the way.
```

## Discipline note

The frozen rule from R17/R18 stands and is now doubly relevant:

> Nested transforms do not donate their inputs to an outer transform unless
> there is an independently established value-flow edge.

Writer precedence is the same principle one level up: a broader writer does not
donate its evidence to a read that a more specific writer already governs.

Worth recording that this milestone's first pass shipped without the overwrite
tooth at all — the transport worked, Corpus B looked correct, and the gap was
invisible until the specification was re-read against the implementation. That
is a fourth instance in this line of a defect that would have overclaimed, and
the first found by re-reading rather than by a predeclared test.
