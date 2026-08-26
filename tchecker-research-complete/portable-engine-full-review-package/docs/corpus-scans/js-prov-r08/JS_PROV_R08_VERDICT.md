# JS-PROV-R08 — Receiver-Type Recovery Disposition

**Disposition + implementation.** First implementation milestone in the JS-PROV
line. `js_state_r07.py` and all JS-STATE gates unchanged.

Disposition chosen: **(a) implement R04's rule under R05's measured safe-input
constraints**, justified because R07 eliminated the alternative (resolved-callee
evidence cannot establish registration when the receiver is `ANY`).

## Frozen inputs from R07

```text
Q5 = RECEIVER_TYPE_REQUIRED
ANY receiver cannot establish framework identity
candidate-callee membership is insufficient
resolved callee may NOT be privileged over methodFullName without trustworthy
  receiver evidence
handler/context-role analysis stays blocked until registration is established
R04 type propagation is back on the critical path
```

## What was implemented

`frontends/javascript-typescript/joern-ts/observed_parameter_types.py` —
`ObservedParameterTypeFact` derivation. It records observational evidence in a
**separate fact** and never mutates `parameter.typeFullName`.

```text
ObservedParameterTypeFact
  callee_method_id / callee_full_name
  parameter_index / parameter_name
  declared_type            <- carried alongside, NEVER replaced
  observed_types[]         <- a SET (R04 Q2)
  unconstrained_callsite   <- TRUE if any callsite passed ANY
  domain_established       <- observed_types non-empty AND not unconstrained
  source_call_ids[] / abstained_call_ids[]
  resolution = CALLSITE_PROPAGATED
```

Wording adopted from the R07 review and enforced in the schema: the fact says a
parameter received **sufficient receiver-domain evidence under the R04/R05
evidence rules**, not that its type is *proven*. `resolution` is
`CALLSITE_PROPAGATED`, never `DECLARED`.

### Gates (all from prior measurements, none invented here)

| Gate | Source | Rule |
|---|---|---|
| G1 | R04 Q9 | callee resolved to exactly one method |
| G2 | R05 | argument is a plain IDENTIFIER (constructor calls → `BLOCK`, casts → `ANY`) |
| G3 | R05 Q8 | argument carries no `<operator>.cast` hint |
| G4 | R04 Q3 | callee parameter's declared type is `ANY` (stronger contracts preserved) |
| G5 | R04 Q5 / R05 | parameter is not variadic/rest (index maps to an array *element*) |
| G6 | R05-2 | argument type's short name is not ambiguous across the program |
| G7 | new, this milestone | callee is not an `<operator>.*` intrinsic |

**G7 was added during implementation, from measurement.** The first Corpus-B run
produced `<operator>.assignment` and `<operator>.fieldAccess` "facts" carrying
150+ observed types each — operand slots are not user-declared bindings, so
binding observed types into them yields noise, not evidence. This is a closed
set of language intrinsics (the same category as R07's builtin table), not a
heuristic over user-chosen names.

**`ANY` never reduces to a concrete type** (JS-STATE-R11 invariant). A callsite
passing `ANY` sets `unconstrained_callsite`, and `domain_established` is then
`False` **regardless of what else the set contains** — verified by the
`installAny` tooth, which observes `@koa/router` and still reports
`domain_established = False`.

## Decisive acceptance control — PASS

```text
JS_PROV_R08=12/12
```

| Tooth | Result |
|---|---|
| `/t2` real router via helper | `['@koa/router']`, established **YES** |
| `/t3` fake router via helper | `['t.ts::program:FakeRouter']` — **@koa/router NOT gained** |
| conflicting callsites | `['@koa/router', 't.ts::program:FakeRouter']` — SET, never last-wins |
| `ANY` contamination | observes `@koa/router` but `unconstrained=True`, **established=False** |
| cast-erased argument | ABSTAIN (G2/G3) |
| stronger declared param | ABSTAIN (G4) |
| rest parameter | ABSTAIN |
| schema discipline | `declared_type` always carried; `resolution` always `CALLSITE_PROPAGATED`; no operator targets |

`/t2` and `/t3` were **byte-identical in the exported CPG facts** under R07.
They are now separated — and separated by the *receiver's own origin*, not by
method spelling, callee-candidate membership, or any name.

## Real Corpus B (`paralect/koa-api-starter` @ `19b1a265`)

```text
ObservedParameterTypeFacts:                    80
  domain_established:                          47
  unconstrained (ANY-contaminated):            33
register-lambda `router` params gaining @koa/router:  14 / 14
  all domain_established:                      YES
  all singleton sets (no conflict):            YES
```

**All 14 registration-receiving parameters now carry `@koa/router` evidence** —
the hop R03 identified as missing, closed on real code.

Abstentions behaved as designed, and the R05-2 guard **fired on real code**:

```text
G2_ARG_NOT_IDENTIFIER(LITERAL/BLOCK/CALL/METHOD_REF)   406
G4_DECLARED_TYPE_PRESENT                                 3
G6_AMBIGUOUS_SHORT_NAME(validator)                       2
G6_AMBIGUOUS_SHORT_NAME(handler)                         2
```

`handler` and `validator` are declared in many Corpus-B modules, so G6 correctly
refused to bind a possibly-fabricated nominal type — the confirmed R05-2 defect
guarded in production code, not just in a fixture.

## What this does NOT close

**R02 Gate 1 is not yet closed.** This milestone restores the *receiver-domain
evidence*; it does not itself re-run registration recognition. The remaining
step is for the registration layer to consume `ObservedParameterTypeFact` — and
R07's finding must be carried forward: with the receiver now evidenced, the
`methodFullName` / resolved-callee path becomes usable, but **only** because
the receiver evidence is trustworthy, never on its own.

**`ctx.validatedData.*` remains entirely separate and untouched.** Per R03 and
restated in R07's review:

```text
router param type missing at parameter -> interprocedural TYPE-EVIDENCE problem  [ADDRESSED HERE]
ctx.validatedData.*                    -> middleware-derived PROVENANCE problem  [UNTOUCHED]
```

Establishing where a handler came from is not establishing where the value
inside it came from. Those are two different provenance edges, and closing the
first must not be reported as closing the second.

**Transitivity is not implemented.** R04 Q7 showed a fixpoint would be required
and would terminate, but this implementation is single-pass. Corpus B needs only
one hop; deeper chains remain uncovered.

---

# JS-PROV-R08 VERDICT

```text
DISPOSITION TAKEN:          (a) implement R04's rule under R05's constraints.
                            Option (b) (upstream-only) rejected: R07 showed no
                            alternative path exists, so waiting on upstream
                            would block the entire provenance line.

IMPLEMENTED:                observed_parameter_types.py — ObservedParameterTypeFact,
                            7 gates, SET join, ANY-never-reduces, declared_type
                            preserved alongside, resolution=CALLSITE_PROPAGATED.

DECISIVE CONTROL:           PASS. JS_PROV_R08=12/12.
                            /t2 gains @koa/router; /t3 does NOT. These were
                            byte-identical under R07.

CORPUS B:                   14/14 register-lambda `router` params gain
                            @koa/router evidence, all established, all
                            singleton. 47 established facts / 33 unconstrained
                            / 80 total. G6 (R05-2 defect guard) fired on real
                            code for `handler` and `validator`.

GATE ADDED FROM MEASUREMENT: G7 (operator intrinsics excluded) — found because
                            the first Corpus-B run produced operator "facts"
                            with 150+ observed types.

R02 GATE-1 CLOSED:          NOT YET. Receiver evidence restored; the
                            registration layer must now consume it. R07's
                            constraint carries forward: resolved-callee
                            evidence is usable ONLY because the receiver is now
                            evidenced.

TYPE PROPAGATION STATUS:    IMPLEMENTED, single-pass, non-transitive.
PROMOTION_READY:            ObservedParameterTypeFact — YES for promotion as a
                            neutral fact (gated, abstaining, evidence-labelled).
                            ExternalInputOriginFact — NO, unchanged.

DOMINANT RESIDUAL:          Two, now cleanly separated:
                            (1) registration recognition must consume the new
                                fact (mechanical, next milestone);
                            (2) middleware-derived properties
                                (ctx.validatedData.*) — a different provenance
                                edge, untouched by anything in R03-R08.

NEXT MILESTONE:             JS-PROV-R09 — Registration Recognition over
                            ObservedParameterTypeFact. Re-run JS-PROV-R02's
                            Corpus-B registration recognition with receiver
                            evidence available, and re-test R07's /t2-vs-/t3
                            control end-to-end at the REGISTRATION level (not
                            just the parameter level). Gate 1 closes only if
                            /t3 still produces no registration.
```

## Discipline note

Two things were deliberately not done.

The rule could have been made to "work" on more of Corpus B by relaxing G2 to
accept `CALL`-typed arguments (81 abstentions) — but R05 measured that
constructor calls type as `BLOCK` and casts as `ANY`, so those arguments carry
no trustworthy callsite type. Relaxing G2 would have manufactured coverage.

`domain_established` could have been set from `observed_types` alone, ignoring
`unconstrained_callsite` — which would have made `installAny` look like a
success. It is exactly the R11 error (treating `ANY` as ignorable rather than
as absence of a domain), and the tooth exists specifically to keep it out.

The result that matters is not 14/14. It is that `/t2` and `/t3` — identical in
every exported fact under R07 — are now separated by receiver origin, while
`installAny` is correctly *refused* despite observing the right type.
