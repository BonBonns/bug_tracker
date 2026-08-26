# JS-PROV-R36 — Selector Resolution + Consumer Integration

**`JS_PROV_R36=8/8`.** Gates green: R12 28/28, R14 11/11, R33 8/8, R35 11/11.
Corpus B identical on all five enumerated layers.

## (a) Selector resolution — Defect A's T2b, CLOSED

R33 **refused** `require(spec).member` bindings; correct, but incomplete. R36
**resolves** them, and could not have been done earlier — the join runs through
R35's barrel-member alias:

```text
ctrl = require("./outer").inner
  -> spec ./outer -> outer.js
  -> outer.js member `inner`
  -> R35 alias: `inner` is a bare require-bound local -> ./inner
  -> ctrl denotes inner.js
```

```text
S1 resolves to ./inner (no longer refused)                          PASS
S2 outer.js and inner.js BOTH export `shared`, as DIFFERENT decls    PASS
S2 ctrl.shared reaches inner.js:innerShared                          PASS
S2 ctrl.shared NEVER reaches outer.js:outerShared                    PASS
S3 unresolved `.nope` ABSTAINS, no outer fallback                    PASS
S4 bare `require('./outer')` is not a selector binding               PASS
```

## (b) Consumer integration — C1 achieved

`context_state_flow`'s callback resolution now consumes both facts. On Corpus D:

```text
routes/articles-router.js  ctrl -> controllers/articles-controller.js
                           ctrl.get -> ...articles-controller.js::program:get
routes/profiles-router.js  ctrl -> controllers/profiles-controller.js
routes/tags-router.js      ctrl -> controllers/tags-controller.js
routes/users-router.js     ctrl -> controllers/users-controller.js
```

This is the chain that blocked R30, R31, R34 and R35.

## Corpus D L5 is still 0 — but the blocker MOVED, and that is the result

```text
                                        before R36   after R36
WRITER_IDENTITY_UNKNOWN_OR_STUB              23          9
WRITE_NO_NEXT_NOT_AVAILABLE_DOWNSTREAM        0         23
L5 flows                                      0          0
```

**23 writers that were previously unidentifiable are now identified.** They
abstain for a different and more advanced reason: their writes are not before a
`next()`, so they are not available downstream.

That is **correct**. Corpus D's controllers write `ctx.body` and terminate; a
terminal handler's writes genuinely are not visible to later middleware. The
`WRITE_NO_NEXT` rule is JS-PROV-R11's `next()`-boundary tooth doing its job.

Corpus D's real cross-middleware state is `ctx.state.user`, written in
`middleware/user-middleware.js`. Whether that middleware participates in a
registered chain the analysis reaches is the **next** question, and it is
distinct from callback identity.

```text
NEW BLOCKER: the identified callbacks are terminal handlers, not the
             middleware that writes ctx.state.user. Callback identity is no
             longer the constraint; chain membership is.
```

## Corpus B — identical on all enumerated layers

```text
L1 module-identity 48 | L3 registrations 18 | L5 flows 23 (all MUST)
import-binding 0      | validate() resolved 9
```

# JS-PROV-R36 VERDICT

```text
SELECTOR RESOLUTION:  CLOSED (Defect A T2b). Derived through R35's alias,
                      never guessed; shared-name control proves it.
CONSUMER INTEGRATION: DONE. C1 achieved -- ctrl.get reaches the real
                      controller declarations on Corpus D.
CORPUS D L5:          still 0, but the abstention reason MOVED from
                      identity-unknown (23) to no-next (23). The remaining 9
                      identity-unknown are a residue, not the main cause.
CORPUS B:             identical on all five enumerated layers.
GATES:                R36 8/8; R12/R14/R33/R35 unchanged.
WRONG EVIDENCE:       0.
```

```text
NEXT: JS-PROV-R37 -- chain membership. Does `middleware/user-middleware.js`
      (which writes ctx.state.user) participate in a registered chain the
      analysis reaches, and are its writes BEFORE next()? Distinct from
      callback identity, which R36 closed.
```

## Discipline note

The honest headline is not "Corpus D still 0". It is that **the reason changed**,
and the new reason is a rule working correctly rather than a gap.

`WRITE_NO_NEXT_NOT_AVAILABLE_DOWNSTREAM` on 23 newly-identified writers is
R11's `next()`-boundary tooth refusing to let a terminal handler's writes reach
downstream readers. Had R36 produced 23 flows instead, that would have been the
bug — and the preregistration said movement is not the success criterion,
correct resolution is.

The chain the review named is now complete on its first two legs:
R33 prevented the collapse, R35 established the alias, R36 resolved the selector
and consumed both. What remains is not part of that chain.
