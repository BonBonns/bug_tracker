# Fable Promotion Gate

A fact may be promoted only after **all six** stages pass. Stage 5 was added
after JS-PROV-R19, when a re-read of the specification against the shipped
implementation found a missing writer-precedence rule that no existing test
covered.

```text
1  CHARACTERIZE          measure what the frontend actually exposes; no rule yet
2  IMPLEMENT             the narrowest rule the characterization supports
3  ADVERSARIAL TEETH     predeclared negative controls, written BEFORE the rule
                         is trusted; each must be able to fail
4  REAL-CORPUS REPLAY    run on production code; a fixture-only pass is not
                         evidence (JS-STATE-R07: 31/31 synthetic, 0 real)
5  SPEC-VS-IMPLEMENTATION RE-READ   re-read the written specification line by
                         line against the shipped code, listing each required
                         behaviour and where it is enforced. Absence of a test
                         is NOT evidence of absence of a requirement.
6  PROMOTE               only if 1-5 hold and the residual gaps are named
```

## Why stage 5 exists

Four defects in the JS-PROV line failed in the **same** direction — claiming
more evidence than was established:

| Milestone | Defect | Caught by |
|---|---|---|
| R09 | trusted a concrete-but-wrong CPG receiver type | corpus replay |
| R17 | nested argument spreads harvested through a transform | corpus replay |
| R18 | spread inside a nested call attributed to the outer call | predeclared tooth |
| R19 | writer precedence absent; broad writer leaked into narrow reads | **spec re-read** |

Three were caught by stages 3-4. The fourth was invisible to both: transport
worked, the corpus looked correct, and no test existed for the missing rule
because the rule had never been implemented. Only re-reading the specification
surfaced it.

**Bias note:** every one of the four failed toward over-claiming, never toward
over-abstaining. Review effort should be spent asymmetrically on that side.

## Frozen invariants

These are load-bearing across the JS-PROV line and must not be relaxed:

```text
ANY is not a domain                    (JS-STATE-R11)
    ANY != OBJECT != MIXED  =>  DOMAIN_NOT_ESTABLISHED

A declared type is positive evidence about intended values, not proof that
runtime semantics cannot produce values outside that domain.   (R11, corrected)

AST containment is not symbol identity                          (R12/R13)
    a reachable descendant establishes no export, call, or binding relation
    without an explicit program relation connecting them

A resolved call edge is only as good as the receiver typing that produced it
    (R07) -- in a dynamic language "resolved callee" is itself an inference;
    agreement between methodFullName and callee can be correlated error

Nested transforms do not donate their inputs to an outer transform unless an
independently established value-flow edge exists                (R17/R18)

Specificity selects which writer is EFFECTIVE; it must not silently erase the
existence of broader writers                                    (R19)

State-flow certainty != origin certainty                        (R19)
    state_flow_strength = MUST | MAY | UNKNOWN
    origin_strength     = ESTABLISHED | TRANSFORM_INPUT_ONLY | UNKNOWN
    a MUST edge never upgrades TRANSFORM_INPUT_ONLY to ESTABLISHED

Observed callsite types are evidence about callsites, not an exhaustive
runtime-value model                                             (R04/R05)
```

## Current promotion status

```text
ObservedParameterTypeFact        PROMOTED   (R08, gate js-prov-r08)
FrameworkRegistrationFact        PROMOTED   (R09, gate js-prov-r09)
ReturnedFunctionIdentityFact     PROMOTED   (R12-1, direct-return contract)
ModuleExportIdentityFact         PROMOTED   (R14, gate js-prov-r14)
ContextStateFlowFact             PROMOTED   (R12/R19, gate js-prov-r12)
TransformInputOriginFact         PROMOTED   (R17/R18, gate js-prov-r17)
ImportBindingIdentityFact        PROMOTED   (R23b producer, R25 consumer;
                                            gate js-prov-r23b, 17/17)

ExternalInputOriginFact          PROMOTED   (R21, gate js-prov-r21)
    first established producer: NESTJS_PARAMETER_DECORATOR (family level).
    The Koa/Joi path correctly REMAINS at TRANSFORM_INPUT_ONLY -- same neutral
    fact, evidence strength per framework path.
```

## Standing requirement for corpus-based milestones (added after JS-PROV-R24)

Corpus eligibility criteria MUST be preregistered before any candidate is
inspected. R24 was BLOCKED rather than run on an ineligible corpus; relaxing a
threshold after seeing which candidate is available is not a threshold. A
blocked experiment is worse than a passing one and better than a fitted one.

Corollary from R23c: **every unexplained residual must close by identity, not
by narrative.** If `expected = established + abstained + omitted`, verify the
members of every term. Three defects in this line came from plausible
explanations offered for otherwise-satisfying numbers.

## Fixture rules (added after JS-PROV-R26)

```text
FIXTURE-DIRECTORY RULE  promotion fixtures are VERSIONED EXPERIMENTAL INPUTS,
                        not scratch files. Existing fixtures must NEVER be
                        overwritten by a later revision; new revisions get
                        their own file namespace.
R26-FIXTURE-INTEGRITY   every gate assertion key identifies exactly one
                        intended semantic case.
R26-SET-DISJOINTNESS    ESTABLISHED n ABSTAINED = {} for binding identities.
```

A coarse gate key can manufacture the appearance of an analyzer defect. A red
tooth is evidence that something is wrong, not evidence about what.

## Capability boundary (JS-PROV-R19, stated precisely)

```text
property-specific overwrite semantics : IMPLEMENTED + TESTED
mixed-origin container on fixture     : DEMONSTRATED
mixed-origin container on Corpus B    : NOT YET OBSERVED END-TO-END
```

Corpus B's `.user` writes sit in validator middlewares whose downstream readers
are not reached, so no effective `.user` read exists there. The semantics are
proven; the real-code observation is not.
