# JS-PROV-R07 — Resolved-Callee Framework Registration Characterization

**Characterization only.** No type propagation, no type repair/normalization,
no `ExternalInputOriginFact` promotion. R07 (the JS-STATE gate) unchanged.

Hypothesis under test:

> Can framework-registration identity be proven directly from the resolved
> registration call/callee even when the receiver parameter is `ANY`?

**Answer: NO.** And the failure mode is worse than absence.

---

## Q1/Q2 — Three evidence levels on all 14 Corpus-B registrations

Every Koa registration in `paralect/koa-api-starter` has
`RECV type=ANY`, `dispatch=DYNAMIC_DISPATCH`. Measured:

| Verb | sites | L2 `methodFullName` | L3 resolved callee |
|---|---|---|---|
| `post` / `put` / `delete` | 7 | `<unknownFullName>` | **`[]` — n=0** |
| `get` | 5 | `ctx:cookies:<returnValue>:<member>(cookies):get` | **n=1 — the same wrong method** |

```text
L42  get  resources/account/verify-email/index.js
     L2_mfn    = ctx:cookies:<returnValue>:<member>(cookies):get
     L3_callee = [107374182768: ctx:cookies:<returnValue>:<member>(cookies):get]  n=1
     RECV      = router : ANY
```

**The critical finding: Level 2 and Level 3 do not disagree — they agree on a
wrong answer.**

R06 recorded the `router.get` → `ctx.cookies.get` mis-resolution as a
populated-but-wrong `methodFullName`. R07 shows the resolved-callee edge
*confirms* it: `cpg.call.callee` returns exactly one method, and it is
`ctx.cookies.get` — a Koa **cookie jar** accessor, not a router method.

This is the answer to the prompt's explicit question "resolved callee
contradicting methodFullName": there is no contradiction to detect. A rule of
the form "trust Level 3 over Level 2" would confidently register
`ctx.cookies.get` as the framework method for 5 of 14 Koa routes. Cross-checking
the two levels against each other provides **no protection**, because the
error is upstream of both.

Error tally against the prompt's categories:

```text
populated-but-wrong methodFullName:        5 / 14
methodFullName with unresolved callee:     0
resolved callee contradicting mfn:         0   (they agree — on a wrong value)
multiple callees:                          0   (in Corpus B; see Q4)
no evidence at all (mfn unknown, n=0):     7 / 14
```

## Q4/Q5 — Adversarial teeth: receiver type is the deciding factor

The controls isolate the variable cleanly:

```text
/t1  direct.get      recv=direct:@koa/router      mfn=@koa/router:get     callees=1[@koa/router:get]      REAL, TYPED    -> correct
/t7  direct.post     recv=direct:@koa/router      mfn=@koa/router:post    callees=1[@koa/router:post]     anonymous cb   -> correct
/t8  direct.post     recv=direct:@koa/router      mfn=@koa/router:post    callees=1[@koa/router:post]     middleware     -> correct

/t2  router.get      recv=router:ANY              mfn=<unknownFullName>   callees=5[...]                  REAL via helper
/t3  router.get      recv=router:ANY              mfn=<unknownFullName>   callees=5[...]                  FAKE via helper

/t4  fr.get          recv=fr:FakeRouter           mfn=<unknownFullName>   callees=1[FakeRouter:get]       concrete fake
/t5  objLit.get      recv=objLit:{get;post}       mfn={...}:get           callees=1[{...}:get]            object literal
/t9  dyn.get         recv=globalThis:<member>...  mfn=globalThis:...:get  callees=1[...]                  dynamic
```

**`/t2` and `/t3` are byte-identical in every exported fact** — same
`<unknownFullName>`, same 5 candidate callees in the same order:

```text
callees = [ FakeRouter:get, t.js::program:get, @koa/router:get,
            { get(p,cb); post(p,cb); }:get, globalThis:<member>(whatever):get ]
```

One receives a genuine `@koa/router`; the other receives a `FakeRouter`. The
CPG cannot tell them apart. The required rule from the prompt —

> identical method spelling + identical receiver type `ANY` must not be enough
> to establish framework registration

— is therefore **satisfied by abstention, but only because nothing can be
established at all**. `@koa/router:get` does appear among the 5 candidates for
*both*, so any rule that accepted "a framework method is among the candidates"
would register the fake router as a framework registration. That is the
promotion-blocking shape, and it is present.

Negative controls `/t4`, `/t5`, `/t9` all correctly fail to produce framework
identity — but each fails for its own concrete reason (concrete class type,
object-literal type, `globalThis` member type), not because of a shared safety
mechanism.

```text
Q5 OUTCOME: RECEIVER_TYPE_REQUIRED
```

Callee identity does **not** survive the helper boundary. When the receiver is
typed, both Level 2 and Level 3 are exactly right; when it is `ANY`, they are
either empty or wrong. Registration identity is downstream of receiver typing,
not independent of it.

## Q3 — Framework/module identity

For the *typed* cases the evidence is `@koa/router:get` — a `methodFullName`
whose prefix is the package specifier. Per the prompt's instruction this must
be recorded honestly:

```text
identity_evidence = METHOD_FULL_NAME string prefix ("@koa/router")
                    NOT structural package/module declaration identity
```

R06's Part D already established there is no exposed import-binding edge and
that `referencedTypeDecl` resolves bare names to external stubs. No
`METHOD → TYPE_DECL → module` route was found for these framework methods.
This is **weaker evidence than structural package identity** and is not
silently upgraded.

## Q6/Q7 — Handler identity and context parameter role

Not measured. Both are downstream of registration identity, which failed for
14/14 real registrations. Measuring handler association on registrations that
cannot be established would produce numbers with no meaning.

Recorded from Q1 for future use: Corpus B's argument shapes are **not** a
uniform "last argument is the handler" pattern —

```text
(path, validator, handler)          5 sites   -> args 1,3,4
(path, middlewareCall, handler)     3 sites   -> args 1,2,3
(path, handler)                     3 sites   -> args 1,2
(path, validator)                   1 site    -> args 1,3  (no handler arg)
```

So the prompt's caution was justified: a universal last-argument rule would be
wrong on the 1-site case and fragile elsewhere. This must be characterized
against real Koa Router signatures if registration identity is ever recovered.

## Q8 — Corpus-B replay

```text
TOTAL_GROUND_TRUTH_HANDLERS:              14
CALLS_WITH_FRAMEWORK_METHOD_FULL_NAME:     0   (5 populated but WRONG, 7 unknown)
CALLS_WITH_EXACT_RESOLVED_FRAMEWORK_CALLEE:0   (5 resolved to ctx.cookies.get, 7 empty)
HANDLER_IDENTITIES_ESTABLISHED:            0   (blocked upstream)
CONTEXT_PARAMETER_ROLES_ESTABLISHED:       0   (blocked upstream)
UNKNOWN:                                  14

R02 registration coverage:   0 / 14
R07 registration coverage:   0 / 14      <-- NO IMPROVEMENT
```

Note handler *methods* remain individually resolvable
(`resources/account/sign-in/index.js::program:handler`), exactly as R02 found —
but with no established registration to attach them to, that is not provenance.

## Q9 — Real-corpus negative audit

Not separately tabulated, and the reason matters: with **zero** proposed
framework matches in Corpus B, the false-registration count is trivially
`0/0`. A lookalike audit is only meaningful against a rule that produces
matches. The relevant negative evidence is instead `/t2` vs `/t3` above, where
a lookalike is provably indistinguishable from the real thing.

```text
LOOKALIKE_CALLS:            n/a (no rule produced matches)
PROPOSED_FRAMEWORK_MATCHES: 0
FALSE_REGISTRATIONS:        0  — vacuously, not by discrimination
```

## Q10 — Is R04 type propagation still needed?

```text
STILL_REQUIRED (for cross-module framework registration)
```

R07 was proposed to close Gate 1 *without* type propagation. It cannot: every
path to registration identity runs through the receiver's type, and the
receiver is `ANY` at exactly the 14 sites that matter. R04 is not deleted
conceptually and may still serve other analyses, but for this specific problem
it is back on the critical path.

The chain is now measured end-to-end:

```text
cross-module receiver type lost (R03)
  -> registration identity unavailable or WRONG (R07)
    -> handler identity unattachable (R07)
      -> context parameter role unavailable (R07)
        -> external-input origin unavailable (R02 Gate 1)
```

---

# JS-PROV-R07 VERDICT

```text
METHOD_FULL_NAME RELIABILITY:  UNRELIABLE when receiver is ANY. 5/14 Corpus-B
                               sites are POPULATED BUT WRONG
                               (ctx:cookies:...:get); 7/14 are
                               <unknownFullName>. Correct in 100% of
                               typed-receiver controls.

RESOLVED_CALLEE RELIABILITY:   UNRELIABLE, and DOES NOT CROSS-CHECK
                               methodFullName. The two levels AGREE on the
                               wrong answer for all 5 wrong sites. With an ANY
                               receiver in the fixture, the callee set is 5
                               candidates including @koa/router:get for BOTH a
                               real and a fake router.

FRAMEWORK MODULE IDENTITY:     Available only as a methodFullName STRING PREFIX
                               ("@koa/router:get"), and only when the receiver
                               is typed. NOT structural package/module
                               declaration identity — recorded as weaker
                               evidence, not upgraded.

RECEIVER TYPE REQUIRED:        YES. This is R07's central result. Typed
                               receiver -> both L2 and L3 exactly correct
                               (t1/t7/t8). ANY receiver -> empty or wrong
                               (t2/t3, and 14/14 of Corpus B).

HANDLER IDENTITY:              NOT MEASURED — blocked upstream. Handler methods
                               are individually resolvable but have no
                               established registration to attach to.
                               Recorded: Corpus B uses FOUR distinct argument
                               shapes, so a "last argument is handler" rule
                               would be wrong.

CONTEXT PARAMETER ROLE:        NOT MEASURED — blocked upstream.

NEGATIVE CONTROLS:             /t4 concrete FakeRouter, /t5 object literal,
                               /t9 dynamic receiver all correctly yield no
                               framework identity — but each for its own
                               reason, not via a shared safety mechanism.
REAL LOOKALIKE CALLS:          n/a — no rule produced matches.
FALSE REGISTRATIONS:           0, VACUOUSLY. /t2 vs /t3 shows a real and a fake
                               router are byte-identical when the receiver is
                               ANY, and @koa/router:get appears among the
                               candidates for BOTH. Any rule accepting
                               "framework method among candidates" WOULD
                               produce a false registration. That shape is
                               present and is promotion-blocking.

CORPUS-B TOTAL:                14
CORPUS-B REGISTRATIONS ESTABLISHED: 0
CORPUS-B HANDLERS ESTABLISHED:      0

R02 GATE-1 CLOSED:             NO — no change from R02 (0/14).
TYPE PROPAGATION STILL REQUIRED: YES for cross-module framework registration.
                               R07's hypothesis is refuted; R04 returns to the
                               critical path for this problem while remaining
                               conceptually useful elsewhere.
PROMOTION_READY:               NO.

DOMINANT RESIDUAL:             Unchanged and now confirmed from a second,
                               independent direction: the cross-module receiver
                               type. R03 found it missing; R07 tried to route
                               around it and found every alternative path runs
                               back through it. Additionally, the mis-resolution
                               under ANY is now shown to be CONFIDENT rather
                               than empty in 5/14 real cases, which is the more
                               dangerous of the two failure modes per R06.

NEXT MILESTONE:                JS-PROV-R08 — Receiver-Type Recovery Disposition.
                               R03/R04/R07 now converge on one blocker with a
                               known shape: argument->parameter binding across
                               an already-resolved call edge. R08 should decide
                               disposition rather than characterize further:
                               (a) implement R04's rule under its measured
                                   safe-input constraints (R05) and re-run
                                   Corpus B + the /t2-vs-/t3 control, which is
                                   now the decisive test — /t2 must gain
                                   @koa/router while /t3 must NOT;
                               (b) or file the ANY-receiver mis-resolution
                                   upstream alongside R06's alias defect.
                               Note (a) is now justified in a way it was not
                               after R04: R07 eliminated the alternative.
```

## Architectural principle — refined, not discarded

R06's principle was:

> Prefer direct program identity over inferred type identity whenever the
> direct relation exists.

R07 adds the necessary qualifier:

> **…but a resolved call edge is only as good as the receiver typing that
> produced it.** In a dynamically-dispatched language, "resolved callee" is not
> a direct program relation — it is itself an inference from the receiver's
> type. When that type is `ANY`, the edge is not merely absent; it may be
> confidently wrong.

The `ctx.cookies.get` case is the concrete proof: it *looks* like exactly the
direct program relation R06 recommended trusting, and it is fabricated.

## Discipline note

R07 was proposed as a way to close Gate 1 cheaply, bypassing the hard type
problem. It failed, and the failure is the useful part: it establishes that the
cross-module receiver type is not one of several possible routes to
registration provenance but the **only** one, which materially strengthens the
case for R04 that R05/R06 had weakened.

The result that would have been easy to over-read is the 5 `get` sites with a
populated `methodFullName` and a single resolved callee. Under a "prefer
resolved callee" rule those look like 5 successes. They are 5 fabrications.
