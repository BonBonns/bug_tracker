# JS-PROV-R09 — Registration Recognition over ObservedParameterTypeFact

**Implementation.** JS-STATE untouched. Consumes JS-PROV-R08's
`ObservedParameterTypeFact` to recognize framework registrations whose receiver
is a parameter the CPG cannot type correctly.

## Ordering constraint carried forward from R07

R07 measured that under an `ANY` receiver, `methodFullName` and the resolved
callee are **not independent signals** — 5/14 Corpus-B `get` sites had both
pointing at `ctx:cookies:...:get`. Agreement was correlated error.

`framework_registration.py` therefore derives framework identity **exclusively
from receiver-domain evidence (R08)**. `methodFullName` and resolved-callee
identity are never consulted. The call's own name only *selects the verb* once
the receiver is already established — Level 1 alone is never sufficient.

`identity_evidence` is emitted as `RECEIVER_DOMAIN_EVIDENCE` and gate-checked.

## Framework profile

Explicit, external, curated — policy, not inference, in the same spirit as
`security_sink_profile.py`. Exact string match against a closed table
(`@koa/router`, `koa`, `express`). An unrecognized module yields UNKNOWN,
never "not a framework".

## Headline finding: Joern's own type recovery mis-propagates, and recognition survives it

The first fixture run produced **zero** registrations. The cause was not the
rule but an assumption in it: the module skipped receivers whose `typeFullName`
was not `ANY`. In the fixture the receiver was concrete — and **wrong**:

```text
installReal  receiver `router`  typeFullName = t:ts::program:FakeRouter
installFake  receiver `router`  typeFullName = t:ts::program:FakeRouter
installBoth  receiver `router`  typeFullName = t:ts::program:FakeRouter
installAny   receiver `router`  typeFullName = t:ts::program:FakeRouter
```

jssrc2cpg assigned `FakeRouter` to **every** router parameter — including the
one that genuinely receives an `@koa/router` — and did so with the malformed
`:ts::` separator (the R04/R05 defect). **Joern performs a form of
argument→parameter propagation itself, and here it produced a confidently
wrong answer on 4/4 parameters.**

Fixed by not trusting `recv_type` at all, even when concrete. R08 evidence is
used instead, and disagreement is recorded (`cpg_receiver_type_disagrees`)
rather than silently resolved. This is now a permanent gate assertion.

Had the original assumption stood, `installReal` would have been recognized as
a `FakeRouter` registration — a fabricated relationship of exactly the kind
R06 warned about.

## Decisive control — end-to-end at the REGISTRATION level

```text
JS_PROV_R09=11/11

installReal   REGISTERED   @koa/router   evidence=RECEIVER_DOMAIN_EVIDENCE
                                         cpg_recv=t:ts::program:FakeRouter DISAGREES=True
installFake   ABSTAIN      RECEIVER_NOT_A_PROFILED_FRAMEWORK    {observed: [FakeRouter]}
installBoth   ABSTAIN      RECEIVER_AMBIGUOUS_ACROSS_CALLSITES  {observed: [@koa/router, FakeRouter]}
installAny    ABSTAIN      RECEIVER_DOMAIN_NOT_ESTABLISHED      {observed: [@koa/router], unconstrained: True}
installCast   ABSTAIN      NO_RECEIVER_EVIDENCE
installDeclared ABSTAIN    NO_RECEIVER_EVIDENCE
exactly ONE registration in the fixture
```

**Gate 1's condition is met**: `/t3` produces no registration. `installAny` is
also correctly refused despite observing `@koa/router`, because a single `ANY`
callsite means the domain is not established (JS-STATE-R11 invariant).

## Real Corpus B (`paralect/koa-api-starter` @ `19b1a265`)

```text
registrations ESTABLISHED:  14 / 14
by verb:  post 7, get 5, put 1, delete 1      <-- EXACT ground-truth match (JS-PROV-R02 Phase 3)
by framework: KOA_ROUTER 14
disagreeing cpg receiver types: 0
abstentions: NO_RECEIVER_EVIDENCE 253, RECEIVER_DOMAIN_NOT_ESTABLISHED 5
```

R02 measured Corpus B at **0/14**. It is now **14/14**, with the verb
distribution matching source ground truth exactly, and — critically — the 5
`get` sites that R07 found resolving to `ctx.cookies.get` are now registered
from receiver evidence instead, never from that fabricated callee.

## R02 Gate 1

```text
Gate 1 (>=2 independent framework mechanisms survive real code):  MET
  ANNOTATION   (NestJS)  — validated in JS-PROV-R02, unchanged
  REGISTRATION (Koa)     — 0/14 -> 14/14 here, via receiver-domain evidence
```

## What is still NOT established

- **Handler identity and context-parameter role** remain unmeasured. R07 froze
  them as downstream of registration; registration is now established, so they
  are unblocked — but not done, and R07 recorded that Corpus B uses **four
  distinct argument shapes**, so no "last argument is the handler" rule.
- **`ctx.validatedData.*` is untouched.** Where a handler came from is not
  where the values inside it came from. That remains a separate
  middleware-provenance edge (R03), and nothing in R08/R09 addresses it.
- **`ExternalInputOriginFact` is NOT promoted.** Registration is one link.

# JS-PROV-R09 VERDICT

```text
REGISTRATION RECOGNITION:   IMPLEMENTED over ObservedParameterTypeFact.
IDENTITY EVIDENCE:          RECEIVER_DOMAIN_EVIDENCE only. methodFullName and
                            resolved-callee deliberately unused (R07).
DECISIVE CONTROL:           PASS, JS_PROV_R09=11/11. /t2 registers, /t3 does not.
CORPUS B:                   14/14 (was 0/14 at R02), verb distribution an exact
                            ground-truth match, 0 false registrations.
R02 GATE-1 CLOSED:          YES — annotation + registration both survive real code.
NEW DEFECT MEASURED:        jssrc2cpg mis-propagates receiver types (FakeRouter
                            assigned to 4/4 router params incl. the real one,
                            with the malformed ':ts::' separator). Recognition
                            now survives it and records the disagreement.
PROMOTION_READY:            FrameworkRegistrationFact — YES (gated, abstaining,
                            evidence-labelled, 0 false registrations on real code).
                            ExternalInputOriginFact — NO, still.
DOMINANT RESIDUAL:          Handler identity + context-parameter role (now
                            unblocked, unmeasured), then middleware-derived
                            properties (ctx.validatedData.*), untouched.
NEXT MILESTONE:             JS-PROV-R10 — Handler Identity & Context-Parameter
                            Role over FrameworkRegistrationFact. Must
                            characterize Corpus B's four argument shapes rather
                            than assume a positional handler rule.
```

## Discipline note

The fixture returning zero registrations was the most valuable moment in this
milestone. The easy read was "the fixture is malformed." The actual cause was a
wrong assumption inside the new module — that a concrete receiver type means a
trustworthy one — and chasing it surfaced that Joern had silently assigned the
same wrong class to every router parameter in the file. Accepting the zero, or
patching the fixture instead of the assumption, would have hidden a defect that
now has a permanent gate assertion against it.
