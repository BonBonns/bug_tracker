# JS-PROV-R31 — preregistered BEFORE implementation

## The question (narrow, as worded in review)
Can member identities be established soundly for **statically named properties
of CommonJS object-literal exports**, and does that newly established fact
unblock the previously observed Corpus-D callback/state-flow chain **without
altering previously validated Corpus-B behaviour**?

## Claim discipline
R31 does **not** show L4/L5 are "portable" in any broad sense. It tests whether
the same Koa chain becomes cross-corpus consistent on **one additional
repository** after recovering the object-literal barrel identity that currently
blocks it. Any success must be worded that narrowly.

## Preregistered invariants (mechanism, not counts)
```text
M1  a STATIC KEY ALONE IS NOT SUFFICIENT -- the member's RHS must itself
    resolve to a declaration identity
M2  nonexistent member                      -> abstain
M3  computed / dynamic key (`{[k]: v}`)     -> abstain
M4  known key whose RHS identity unresolved -> abstain
M5  spread inside the literal (`{...x}`)    -> abstain (no per-member identity)
M6  Corpus B: existing 23 state flows IDENTICAL; no established fact
    disappears; additions permitted ONLY if newly enabled by an established
    member fact AND verified against source
M7  demonstrably wrong = 0
M8  all gates green; R14/R25 producer semantics unmodified
```

## Corpus-D expectation
```text
L4 > 0 and L5 > 0 IF the recovered members are the callbacks that participate
in the preregistered ctx.state.user flow. If they are not, R31 still succeeds
as a member-identity result and the chain remains blocked for a NEW named
reason -- which must then be stated, not smoothed over.
```

## R30 preservation
R30 is recorded as a SUCCESSFUL NULL INTEGRATION EXPERIMENT. R31 movement must
not retroactively reframe it as unsuccessful: R30's consumer did exactly what
was asked (consult established identity, not syntactic import presence), and
its zero was correct given the facts then available.
