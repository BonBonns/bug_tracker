# JS-PROV-R08 — Safe Receiver-Type Propagation

**IMPLEMENTED.** First implementation milestone in the JS-PROV line.

```text
JS_PROV_R08=15/15        (decisive adversarial gate, real Joern run)
```

Regressions, all real runs, all unchanged:

```text
JS_STATE_R07=31/31   JS_STATE_R03=30/30   JS_STATE_R02=28/28
GATE24_TS=27/27      JSTS_R05=8/8
```

R07's framework-registration logic was **not touched** (hash-verified:
`security_sensitive_reachability.py` `22a4f7ef…`, `export_ts_facts.sc`
`9411e4c7…`, both unchanged).

---

## What was implemented

`frontends/javascript-typescript/joern-ts/js_prov_r08.py` — the R04 mechanism
under R05 constraints, and nothing else. No framework heuristics were
broadened; candidate-callee membership is **not** used to compensate for a
missing receiver.

### The open-world type-evidence lattice

Two independent axes, kept separate exactly as specified:

```text
observed_types={T},     unconstrained=False  -> CLOSED_SINGLE  proof=True
observed_types={T},     unconstrained=True   -> OPEN_SINGLE    proof=False
observed_types={T,U},   unconstrained=any    -> CONFLICT       proof=False
observed_types={},      unconstrained=True   -> NO_EVIDENCE    proof=False
```

Only `CLOSED_SINGLE` sets `usable_as_exclusive_dispatch_proof`. This encodes
the distinction the milestone asked to make explicit: *"we observed Router"* is
not *"the receiver is provably Router."* Per R11's standing invariant, `ANY` is
not a domain — an unconstrained callsite can only **open the world**, never
contribute a member.

All four states are produced by the fixture and separately asserted.

### Constraints enforced (each independently, each auditable)

| Constraint | Source |
|---|---|
| callee resolved to exactly one method | R04 Q9 |
| argument is a plain IDENTIFIER (rejects `BLOCK` ctor-calls, `ANY` casts) | R05 Q8 |
| argument short name unique program-wide | R05-2 alias mis-binding |
| no `<operator>.cast` hint on the argument | R05 Q2/Q8 |
| target parameter declared type is `ANY` | R04 Q3 — never overwrite a contract |
| target parameter is not a rest parameter | R04 Q5 — structural, via `code` |
| callee is not an operator lowering | R08, measured (see below) |

Skipped callsites are **recorded with a reason**, not silently dropped. A
skipped callsite does *not* set `unconstrained=True` — declining to look is not
evidence that the world is open. An argument that *is* analyzable and *is*
typed `ANY` does set it. That asymmetry is deliberate.

### Architecture invariants (asserted by the gate)

- `declared_type` retained **alongside** observations; never overwritten.
- `parameter.typeFullName` never written.
- `resolution = CALLSITE_PROPAGATED` on every fact.
- Full `derivation` chain (`call_id`, argument code, raw and canonical type,
  and whether the callsite observed a type or opened the world) on every fact.

---

## Two implementation defects found by the fixture, not by assumption

Both were caught because the fixture produced visibly wrong output on the first
run, and both are recorded rather than quietly patched:

**1. The R05-2 short-name guard over-abstained to uselessness.** First run
skipped `/t3` entirely with `AMBIGUOUS_SHORT_NAME:FakeRouter`. Investigation
showed the "collision" was R05's **stub duplication**, not a real one:

```text
FakeRouter  full=gate.js::program:FakeRouter  external=false   <-- real
FakeRouter  full=FakeRouter                   external=true    <-- stub
```

Every locally-declared class has such a stub, so counting stubs marks *every*
class-typed argument ambiguous. Fixed by counting **non-external declarations
only**. This preserves the genuine R05-2 guard (two real declarations sharing a
short name) while removing the false one.

Worth noting: had this not been caught, `/t3` would have "passed" the decisive
gate by abstaining — the right answer for the wrong reason, and the exact kind
of accidental pass this milestone was designed to prevent.

**2. Operator lowerings produced meaningless facts.** The first run emitted
observations for `<operator>.assignment` / `<operator>.fieldAccess` synthetic
`p0`/`p1` parameters, including one with 11 unrelated observed types. These are
not ordinary functions; propagating into them is pure noise. Excluded
structurally by callee name.

---

## Decisive adversarial gate

```text
/t2  installReal(realRouter)   observed=['@koa/router']
                               unconstrained=False  CLOSED_SINGLE  proof=True
/t3  installFake(fakeRouter)   observed=['gate.js::program:FakeRouter']
                               unconstrained=False  CLOSED_SINGLE  proof=True
```

**Separated.** `/t2`'s receiver evidence includes `@koa/router` and is
sufficiently established; `/t3`'s **excludes** it and fabricates nothing —
it reports the fake's own concrete type, which is the truthful answer.

This is the pair R07 proved byte-identical under `ANY` receivers, including
`@koa/router:get` appearing among the candidate callees for **both**. The
separation here comes entirely from receiver-domain evidence established
*before* dispatch resolution, per the milestone's ordering requirement — no
candidate-callee membership rule was used.

Supporting states:

```text
C1 installBoth      {@koa/router, FakeRouter}  CONFLICT     proof=False
C2 installOpen      {@koa/router, JSON.parse}  CONFLICT     proof=False
C5 installOpenTrue  {@koa/router} unc=True     OPEN_SINGLE  proof=False
C4 installCanon     {@koa/router}              CLOSED_SINGLE
                    + skipped ARG_NOT_IDENTIFIER:CALL (makeRouter())
```

`C5` is the important one: `@koa/router` **was** observed, yet `proof=False`
because another callsite passed an unconstrained value. Observation did not
collapse into proof.

## Corpus-B replay

```text
router-parameter facts:                    16
CLOSED_SINGLE with observed=['@koa/router']: 14 / 14
```

All 14 `register(router)` targets recover `@koa/router` as a closed single
observation. This is the receiver evidence R03 found missing and R07 proved
could not be routed around.

**Explicitly not claimed:** this is receiver-domain evidence, measured *before*
dispatch resolution as required. Whether framework registration then resolves —
and whether R02's Gate 1 closes — is a **downstream consequence not tested
here**, because doing so would have required touching R07's logic, which the
milestone forbade. R07's registration path is unchanged and still sees `ANY`
receivers; consuming these facts is a separate, future wiring step.

And per the standing separation: `ctx.validatedData.*` remains a
**middleware-provenance** problem. Establishing where the *handler* came from
does not establish where the *value inside the handler* came from. Two
different provenance edges.

---

## Honest limitations

- **Canonicalization is implemented but UNEXERCISED.** No `:<init>` or
  `:<returnValue>` spelling appeared as an argument type in either the fixture
  or Corpus B — identifiers carry the declared spelling. The R04 Q1 hazard is
  handled in code but **not demonstrated** by a passing test. Recorded rather
  than claimed.
- **`NO_EVIDENCE` is unexercised** as an emitted state (facts with no sources
  are not emitted at all).
- **The R05-2 guard is now narrower than R05 specified.** It fires only on two
  *non-external* declarations sharing a short name. R05's actual defect
  (imported alias binding to a same-named local) would produce exactly that
  shape, so the guard should still cover it — but that was not re-tested here
  against the R05 fixture.
- **`unconstrained` is per-parameter, not per-path.** A single `ANY` callsite
  anywhere opens the world for all consumers of that parameter. Sound but
  coarse.
- The safe-input constraints remain narrow enough (R05) that many real
  parameters will simply produce no fact — consistent with R06's finding that
  78% of real parameters are `ANY`.

---

# JS-PROV-R08 VERDICT

```text
IMPLEMENTED:                 YES — js_prov_r08.py, gate 15/15, real Joern.
DECISIVE GATE (/t2 vs /t3):  SEPARATED. /t2 includes @koa/router and is
                             CLOSED_SINGLE; /t3 excludes it and fabricates
                             nothing.
LATTICE:                     All four states produced and separately asserted;
                             only CLOSED_SINGLE grants dispatch proof.
CONFLICT HANDLING:           Set preserved; no last-win, no supertype collapse.
UNCONSTRAINED RETAINED:      YES — OPEN_SINGLE demonstrates observation without
                             proof.
REST PARAMETERS:             Excluded structurally.
DECLARED CONTRACTS:          Never overwritten; retained alongside.
PROVENANCE INSPECTABLE:      YES — full derivation chain per fact.
R07 LOGIC MODIFIED:          NO (hash-verified).
REGRESSIONS:                 NONE (R02/R03/R07/Gate24-TS/JSTS-R05 all unchanged).
FALSE FRAMEWORK EVIDENCE:    ZERO. No registration justified by an ANY receiver;
                             no candidate-callee-membership rule exists.
CORPUS-B RECEIVER EVIDENCE:  14/14 CLOSED_SINGLE @koa/router.

R02 GATE-1 CLOSED:           NOT YET — and deliberately not attempted. Receiver
                             evidence is now established; wiring it into R07's
                             registration path is the next step and was out of
                             scope by instruction.

PROMOTION_READY:             YES for ObservedParameterTypeFact as a neutral,
                             separately-labelled evidence fact. NOT yet for
                             ExternalInputOriginFact, which still depends on
                             the unwired registration step and on the untouched
                             middleware-provenance problem.

DOMINANT RESIDUAL:           Consumption, not production. The evidence exists
                             and is sound; nothing reads it yet.

NEXT MILESTONE:              JS-PROV-R09 — Receiver-Evidence Consumption in
                             Framework Registration. Wire ObservedParameterType
                             Facts into R07's registration resolution under a
                             strict rule: a registration may be established
                             only from CLOSED_SINGLE receiver evidence whose
                             single observed type is a framework identity.
                             OPEN_SINGLE, CONFLICT and NO_EVIDENCE must all
                             abstain. Re-run the /t2-vs-/t3 gate end-to-end and
                             Corpus B for Gate-1 closure, and re-audit
                             lookalikes for false registrations.
```

## Discipline note

The milestone's instruction to *"measure the receiver evidence before measuring
resulting call resolution"* turned out to be load-bearing. It would have been
easy to wire this straight into R07, watch Corpus B jump 0/14 → 14/14, and
report Gate 1 closed. That would have conflated two claims — that the receiver
domain is established, and that registration resolution consumes it correctly —
and the second was explicitly out of scope.

The two defects above were both caught only because the fixture was run and
read rather than assumed to pass, and one of them (`/t3` abstaining via a bogus
ambiguity) would have produced a *green gate for the wrong reason*.
