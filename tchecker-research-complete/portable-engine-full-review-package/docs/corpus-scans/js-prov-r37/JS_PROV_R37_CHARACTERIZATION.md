# JS-PROV-R37 — Chain Membership: Characterization

**Characterization only. Nothing implemented.** Investigating the blocker
JS-PROV-R36 named.

## Finding: this is not a missing fact. It is a MODEL boundary.

The writer and the readers are in **different registration calls**, and R12's
join is deliberately scoped to a single registration.

```text
WRITER   lib/app.js:50        app.use(userMiddleware)         <- APP-level chain
READERS  routes/*-router.js   router.get/post/put(..., ctrl.*) <- ROUTER-level

registrations by declaring file:
  use  x13  lib/app.js
  get  x7   routes/{articles,profiles,tags,users}-router.js
  post x6   routes/{articles,profiles,users}-router.js
  put  x2   routes/{articles,users}-router.js
```

```js
// middleware/user-middleware.js  -- the WRITER
module.exports = async (ctx, next) => {
  if (has(ctx, "state.jwt.sub.id")) {
    ctx.state.user = await db("users")...     // conditional => MAY, and BEFORE next
  }
  return next()
}

// controllers/articles-controller.js  -- the READERS (6+ sites)
article.author = ctx.state.user.id
```

The writer's own shape is fine: the write is **before `next()`**, and it is
**conditional**, so R12 would classify it `MAY` — correctly.

## Why R12 refuses, and why that refusal is CORRECT as specified

R12's `js-prov-r12` gate contains this preregistered tooth:

```text
NEG-2  different route -> no join
       (/r1 and /r2 both write `shared`; no cross-join, and origins stay
        distinct HTTP_BODY vs HTTP_QUERY)
```

That control exists because a context object is conceptually **fresh per
request**, and two registrations that happen to use the same property name must
not be joined. Corpus D's writer and readers are in different registrations, so
the same rule that protects `/r1` from `/r2` also blocks `app.use` from
`router.get`.

**The rule is not wrong. The model is incomplete.** Koa has a real semantic
relationship the model does not represent:

```text
app.use(mw)  runs for EVERY request, BEFORE any router handler mounted on that app
```

So `app.use` middleware and `router.<verb>` handlers **are** in one chain at
runtime — but the model has no notion of app-level middleware being upstream of
router-level handlers.

## What would be required — and the risk

Establishing this needs a new relation, not a new fact:

```text
app-level `use` registration  --upstream-of-->  router-level registrations
                                                mounted on the same app
```

which in turn requires knowing that a given router **is mounted on that app**
(`app.use(router.routes())` or equivalent). That is a **mount relation**, and it
is exactly the kind of thing that, done loosely, would re-enable the
cross-request joins NEG-2 was written to forbid.

```text
RISK: any relaxation of registration scoping must NOT weaken NEG-2. A
      too-permissive mount relation joins unrelated routes through a shared
      property name -- the exact fabrication R12 was built to refuse.
```

## Corpus D would still yield MAY, not MUST

Even with a mount relation, the write is inside `if (has(ctx, "state.jwt.sub.id"))`,
so JS-PROV-R12's conditional rule gives `MAY_WRITE`. Any eventual flow here is
`MAY`, never `MUST` — worth stating so a future result is not over-read.

# JS-PROV-R37 VERDICT

```text
BLOCKER:          NOT a missing fact. Writer and readers are in DIFFERENT
                  registration calls; R12's join is registration-scoped.
R12's REFUSAL:    CORRECT as specified -- the same NEG-2 rule that stops
                  /r1 joining /r2 stops app.use joining router.get.
MODEL GAP:        Koa's `app.use` middleware IS upstream of router handlers at
                  runtime; the model has no upstream/mount relation.
WHAT IT NEEDS:    a MOUNT RELATION (router mounted on app), then an
                  app-upstream-of-router ordering. A new RELATION, not a fact.
PRINCIPAL RISK:   a loose mount relation re-enables the cross-route joins NEG-2
                  exists to forbid.
CEILING:          even if built, Corpus D yields MAY (conditional write),
                  never MUST.
IMPLEMENTED:      NOTHING.

NEXT (if pursued): JS-PROV-R38 -- mount-relation characterization.
  Preregistered teeth must include:
    - NEG-2 UNCHANGED: two routers on the SAME app, both writing the same
      property, must still not join to each other's readers
    - a router NOT mounted on the app must not receive its middleware
    - app.use registered AFTER the router mount must not flow to it
      (ordering, not mere co-membership)
    - Corpus B identical on all five enumerated layers
```

## Discipline note

The temptation here is to read "R12 refuses a real relationship" as a defect and
relax the scoping. It is not a defect: the scoping is what makes every flow R12
has ever emitted trustworthy, and NEG-2 is one of its load-bearing controls.

The honest statement is that **Fable currently models one registration as one
chain, and Koa does not work that way.** Extending it is a modelling decision
with a specific, named downside — and the downside is the fabrication class this
whole line has spent thirty milestones refusing.

This is also the fourth distinct blocker Corpus D has produced (L3 direct
receiver, callback identity, barrel members, now chain membership). Each was a
different layer, and none was found by guessing which layer was at fault.
