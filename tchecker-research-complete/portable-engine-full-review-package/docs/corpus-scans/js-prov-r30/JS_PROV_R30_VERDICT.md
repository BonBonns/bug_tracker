# JS-PROV-R30 — Module-Export Identity in Callback Resolution

**Integration only.** R14/R25 producers frozen and hash-verified unchanged.
Gates green: `JS_PROV_R12=28/28`, `JS_PROV_R29=9/9`.

## Implemented

`context_state_flow`'s callback resolution now resolves a callback argument that
is a **field access on an imported module object** —
`router.get('/x', ctrl.get)` where `ctrl = require('../controllers')` — through
the same export facts R14/R25 already produce, keyed on
`(file, base local, member)`.

Keyed on the **established export record**, never on the presence of an import:
a member the target module does not actually export resolves to nothing and the
callback stays unidentified.

## Result: Corpus D still 0 — and the abstention is CORRECT

```text
CORPUS D  L4/L5: 0     23 abstentions, all WRITER_IDENTITY_UNKNOWN_OR_STUB
```

Traced to a concrete case rather than assumed:

```text
routes/articles-router.js:  router.get("/articles", ctrl.get)
                            const ctrl = require("../controllers")

controllers/index.js:       module.exports = { users, tags, profiles, articles }
exported fact:              controllers/index.js  member=<none>  kind=BLOCK
```

Corpus D routes through a **barrel** — a directory import resolving to
`controllers/index.js`, which exports an **object literal**. Object-literal
export members carry no individual identity at the `BLOCK` level (JS-PROV-R13,
R23a). So `ctrl.get` cannot resolve, and the callback correctly abstains.

**This is the pre-existing object-literal-export gap, not an R30 defect.** R13
recorded it, R23a re-measured it (`module.exports = {a, b}` → `PARTIAL`), and
R14 has abstained on it since. Corpus D is the first corpus where it blocks a
whole chain.

## Preregistered expectations

```text
CORPUS B
  existing 33 callback facts identical          MET
  existing 23 state flows identical             MET (23, all MUST,
                                                all MODULE_EXPORT_IDENTITY)
  no previously established fact disappears     MET
  additional facts only if newly enabled        MET (none added)

CORPUS D
  L4 must rise above 0                          NOT MET
  L5 must rise above 0                          NOT MET
  every new L4/L5 fact traceable                vacuous (none)
  no export-abstained callback moves downstream MET
  demonstrably wrong = 0                        MET
```

The Corpus-D expectations are **not met**, and the mechanism-based wording is
what makes that statement clean: the consumer is correct, the producer is
correct, and the blocker is a third thing neither of them claims to handle.

## Decisive negative control — holds

```text
import OBSERVED  +  ModuleExportIdentityFact ABSTAINED
      -> callback identity does NOT establish
      -> no state flow through that callback
```

Corpus D is itself the strongest instance: `ctrl` is unambiguously imported and
observed, its export record abstains, and **nothing downstream moved**. R30
consumes the semantic identity fact, not the presence of an import.

# JS-PROV-R30 VERDICT

```text
INTEGRATION:        IMPLEMENTED (field-access-on-imported-module callbacks)
PRODUCERS:          R14/R25 frozen, hash-verified
CORPUS B:           23 flows IDENTICAL, all MUST, all MODULE_EXPORT_IDENTITY
CORPUS D:           L4/L5 remain 0 -- CORRECT abstention, not a defect
BLOCKER:            object-literal barrel export
                    (`module.exports = { users, tags, ... }` -> BLOCK)
                    Known since R13; first time it blocks an entire chain.
WRONG EVIDENCE:     0
GATES:              R12 28/28, R29 9/9
L4/L5 PORTABILITY:  STILL NOT REPRODUCED on a second corpus
```

```text
NEXT: JS-PROV-R31 — object-literal export member identity.
      `module.exports = { a, b }` lowers to a BLOCK whose member assignments
      ARE individually present (same shape as R26's re-export hop and R23a's
      destructuring finding: members recoverable one level in).
      Acceptance: Corpus D L4 > 0 and L5 > 0; Corpus B 23 flows identical;
      a member the literal does NOT contain still abstains; all gates green.
```

## Discipline note

R30 produced no movement, and that is the correct outcome rather than a failed
one. The integration works; Corpus D simply presents a shape that a *different*
known gap blocks.

The temptation was to keep patching until Corpus D moved — the barrel case is
one more hop, and R26 already showed such hops are usually recoverable. That
would have made R30 a semantics change wearing an integration label, exactly the
error R25 avoided. The barrel hop gets its own preregistered revision.

Worth noting how the diagnosis was reached: `ctrl.get` was traced to
`controllers/index.js` and its exported fact inspected, rather than inferring
"probably a barrel". Three earlier diagnoses in this line were plausible and
wrong (R12, R22, R23b); the standing rule is to measure the cause, not infer it
from the symptom.
