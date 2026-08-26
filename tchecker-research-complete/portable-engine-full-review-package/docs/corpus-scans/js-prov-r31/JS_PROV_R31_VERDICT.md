# JS-PROV-R31 — Object-Literal Export Member Identity

**Result: R31 succeeds as a member-identity result. The Corpus-D chain remains
blocked, for a NEW named reason.** The preregistration anticipated exactly this
split and required the reason be stated, not smoothed over.

## Claim discipline

R31 does **not** show L4/L5 are portable in any broad sense. It tested whether
statically named members of CommonJS object-literal exports can be established
soundly, and whether that unblocks the Corpus-D chain. The first holds; the
second does not.

## Member identity — established, with all controls holding

`module.exports = { a, b }` lowers to a BLOCK whose member assignments are
individually present (`_tmp_0.a = a`). Statically named members are now emitted
as their own export rows.

```text
named: localFn        static key, resolvable RHS -> member=named
                                                    rhs=lit.js::program:localFn   ESTABLISH
fromDep: realDep.thing static key, RHS is a module member -> emitted as kind=CALL,
                                                    handed to R26's re-export hop
[dynKey]: localFn      COMPUTED key (indexAccess)  -> NOT emitted   (M3 abstain)
...realDep             spread, no member name      -> NOT emitted   (M5 abstain)
```

**M1 holds — a static key alone is not sufficient.** The member row carries the
same `rhs`/`kind` columns every other export row uses, so a member whose RHS
lacks declaration identity still abstains downstream. Nothing was special-cased
to make members "count".

## Corpus B — unchanged, as required

```text
L5 flows: 23, IDENTICAL, all MUST, all MODULE_EXPORT_IDENTITY
no established fact disappeared; none added
```

## Corpus D — still 0, and the reason is new and specific

```text
L3 registrations: 28   L5 flows: 0   (23 abstentions, WRITER_IDENTITY_UNKNOWN_OR_STUB)
```

Traced, not inferred:

```text
routes/articles-router.js:  const ctrl = require("../controllers").articles
                            router.get("/articles", ctrl.get)

controllers/index.js members NOW RESOLVE (R31 working):
    users     -> { get(ctx); post(ctx); put(ctx); ... }
    tags      -> { get(ctx); }
    profiles  -> { byUsername(...); get(ctx); ... }
    articles  -> { bySlug(...); get(ctx); ... }
```

The barrel members resolve. But the import is
`require("../controllers").articles` — **a member access applied to the require
result at import time**, and `ctrl.get` is then a member of *that* member. The
remaining hop is:

```text
require(spec) . MEMBER          <-- import-time member selection
      -> that member's own module/object
            -> ITS member (`get`)
```

`articles`'s RHS resolves to a structural object type
(`{ bySlug(...); get(ctx); ... }`), not to a module file, so the second member
lookup has no export table to consult.

```text
NEW BLOCKER: import-time member selection (`require(x).member`) combined with
             nested member access on a structurally-typed object.
             DISTINCT from the object-literal gap R31 just closed.
```

## Invariants

```text
M1 static key alone insufficient                MET
M2 nonexistent member abstains                  MET
M3 computed key abstains                        MET
M4 unresolved RHS abstains                      MET
M5 spread abstains                              MET
M6 Corpus B 23 flows identical, none lost/added MET
M7 demonstrably wrong = 0                       MET
M8 R14/R25 semantics unmodified                 MET (export emission is additive)
Corpus D L4/L5 > 0                              NOT MET -- new blocker named
```

# JS-PROV-R31 VERDICT

```text
MEMBER IDENTITY:     ESTABLISHED for statically named object-literal export
                     members, with computed keys and spreads abstaining.
CORPUS B:            23 flows identical; no regression.
CORPUS D:            L3 28, L5 still 0.
BLOCKER (new):       `require(spec).member` import-time selection + nested
                     member access on a structurally-typed object.
WRONG EVIDENCE:      0
L4/L5 PORTABILITY:   STILL NOT REPRODUCED on a second corpus.
```

## The causal chain, as a record

Each step isolated a distinct missing fact or integration edge, and each null
result narrowed the explanation rather than being patched around:

```text
R24  second corpus fails at L3
 ->  R29  direct-local framework identity closes L3          (0 -> 28)
 ->  L4/L5 still fail
 ->  R30  consumer wiring added correctly                    (still 0, CORRECT)
 ->  still zero because the upstream export member is absent
 ->  R31  object-literal member identity established         (still 0, CORRECT)
 ->  still zero because of import-time member selection
```

This is materially stronger than "the engine missed Corpus D, so we added
support until it passed." Three of the six steps produced no movement, and each
of those nulls was correct given the facts then available.

**R30 is preserved as a successful null integration experiment.** R31's member
identity does not retroactively make R30 unsuccessful: R30's consumer did
exactly what was asked — consult established identity, not syntactic import
presence — and its zero was correct for the facts available at that time.

## Discipline note

The preregistration's most useful clause was the one allowing R31 to succeed
while the chain stayed blocked. Without it, the honest outcome — member identity
works, chain still zero — would have read as failure, and the pressure would
have been to keep hopping until Corpus D moved.

That pressure was real: the next hop is visible and probably small. But it is a
different mechanism from the one R31 preregistered, and taking it inside R31
would have made the milestone unfalsifiable — any amount of work could be
justified as "finishing" it.

---

> ## AMENDED — Corpus-B invariant was INCOMPLETE as recorded
>
> R31's verdict verified that Corpus B **state flows** were identical (23) but
> did **not** check module-identity facts. Those read **48** against a recorded
> baseline of 45.
>
> **The +3 is NOT R31's.** Audited at source, the facts involved
> (`security.util.js:generateSecureToken`,
> `services/email/email.service.js:sendForgotPassword`,
> `resources/account/*/index.js:register`) use `exports.X = ...` — the
> **named-member** form R14 has handled since it was written. None of these
> files contains an object-literal `module.exports = {...}`, so R31's member
> emission cannot have produced them.
>
> **Attribution: UNRESOLVED.** The 45 baseline was measured at R14 time; several
> revisions landed between (notably R26 re-export chains). Without the original
> 45-fact list the delta cannot be attributed, and it has already been
> misattributed twice — first to R33, then to R31. Recording it as open rather
> than guessing a third time.
>
> **Soundness is established independently of attribution.** All 48 facts were
> audited against source: every one names a target file that exists and a member
> that file demonstrably exports. `verified 48 / not verifiable 0`. The delta is
> an accounting gap in the record, not a correctness problem in the engine.
>
> **Process defect:** a corpus invariant that checks one layer (flows) and
> silently omits another (module identity) will hide real movement. Corpus
> invariants should enumerate the layers they cover.
