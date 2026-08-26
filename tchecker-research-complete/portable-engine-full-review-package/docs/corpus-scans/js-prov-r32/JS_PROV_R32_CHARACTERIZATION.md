# JS-PROV-R32 — Import-Time Member Selection: Characterization

**Characterization only. Nothing implemented.** Investigating the blocker
JS-PROV-R31 named.

## Headline: this is not one gap, it is two — and one is a latent FABRICATION, not a miss

### Defect A (consumer side) — a binding that asserts something FALSE

```text
source:                    const ctrl = require("../controllers").articles

require_bindings.tsv:      file=routes/articles-router.js
                           spec=../controllers        local=ctrl     <-- `.articles` DROPPED

local_defs.tsv (truth):    lhs=ctrl  kind=<operator>.fieldAccess
                           code=require("../controllers").articles
```

The require-binding extractor records `ctrl` as bound to the **whole
`../controllers` module**. It is not. `ctrl` is `controllers/index.js`'s
`articles` member, i.e. `articles-controller.js`.

**This is worse than an abstention: the binding is wrong, and any consumer
trusting it will look members up in the wrong module.**

Measured on Corpus D:

```text
ctrl.* members used:              bySlug comments del favorite feed get getOne post put
members of the WRONG module
  (controllers/index.js):         users tags profiles articles
members of the RIGHT module
  (articles-controller.js):       bySlug get getOne post put del feed favorite comments

overlap (would fabricate):        NONE
```

**The overlap is empty, so nothing wrong is currently produced — but that is
luck, not soundness.** A router written as `ctrl.users` would resolve against
`controllers/index.js`, find a real member, and establish a **fabricated**
identity pointing at the wrong module. R31's zero on Corpus D was a clean
abstention *by coincidence of naming*, not by construction.

This is the fourth instance in this line of a defect that fails toward
over-claiming, and the first found while investigating something else.

### Defect B (producer side) — module-alias members lose their module link

```text
controllers/index.js:  const articles = require("./articles-controller")
                       module.exports = { users, tags, profiles, articles }

emitted member row:    member=articles  kind=IDENTIFIER
                       rhs={ bySlug(...); get(ctx); ... }   <-- structural OBJECT type
                       reBase=  reMember=                   <-- module link absent
```

The member's RHS is an identifier that is itself a **require-bound local in the
same file** (`require_bindings.tsv` confirms `articles -> ./articles-controller`).
So the member denotes a *module*, but is recorded as an anonymous object type.

`articles-controller.js` **does** export `get` as a `METHOD_REF` — R31 already
emits it. The terminal fact exists; only the link to it is missing.

## Everything needed is already exported

```text
Defect A:  local_defs.tsv carries the fieldAccess and its code
           require_bindings.tsv carries ctrl -> ../controllers
Defect B:  require_bindings.tsv carries articles -> ./articles-controller
           module_exports.tsv carries articles-controller.js:get = METHOD_REF
```

No new frontend extraction is implied. Both are joins over facts already
present — the same shape as R26's re-export hop and R23a's destructuring
finding.

## Priority

**Defect A should be fixed first and independently of any coverage goal.** It is
a soundness defect that currently produces nothing only because of a naming
coincidence in one corpus. Defect B is a coverage gap and can wait.

Fixing A alone will not move Corpus D (it would correct the binding to
`articles-controller.js`, where `ctrl.get` genuinely resolves) — actually it
plausibly *would*. That must be measured, not assumed, and A's justification
should not depend on it either way.

# JS-PROV-R32 VERDICT

```text
BLOCKER FROM R31:     resolved into TWO distinct defects
DEFECT A (soundness): require-binding drops import-time member selection;
                      `ctrl` bound to the wrong module. LATENT FABRICATION,
                      masked on Corpus D only by empty name overlap.
DEFECT B (coverage):  export members whose RHS is a require-bound local lose
                      the module link; recorded as an anonymous object type.
FACTS AVAILABLE:      YES for both; joins over already-exported data.
IMPLEMENTED:          NOTHING
NEXT:                 JS-PROV-R33 -- fix Defect A alone, preregistered as a
                      SOUNDNESS fix, not a coverage one. Acceptance:
                      `require(x).member` binds to the member's module or
                      ABSTAINS, never to the outer module; a fixture where the
                      outer and inner modules SHARE a member name must not
                      resolve against the outer; Corpus B unchanged; gates green.
                      Defect B follows separately.
```

## Discipline note

This began as "look into why Corpus D is still blocked" — a coverage question.
The coverage answer (Defect B) is the less important half.

The soundness defect was only visible because the consumer-side binding was
checked against the source rather than taken at face value. `require_bindings`
said `ctrl -> ../controllers`, which is a well-formed, plausible, confidently
wrong record — the same shape as R09's receiver type, R13's fabricated callee,
and R23a's `isWildcard`. The engine has now produced this class of error at four
separate layers, and in every case the record looked exactly like a correct one.
