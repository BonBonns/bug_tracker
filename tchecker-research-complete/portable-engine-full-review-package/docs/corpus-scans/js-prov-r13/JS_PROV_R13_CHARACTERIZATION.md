# JS-PROV-R13 — Export Identity Resolution (characterization)

**Characterization only.** No implementation. R12 frozen at 14/14.

## Prerequisite landed: `ReturnedFunctionIdentityFact` contract narrowed

Per review, the primitive now follows **directly** returned functions only —
RETURNs belonging to nested methods are excluded
(`_.method.fullName == m.fullName`). Effect on Corpus B:

```text
BEFORE (descendant returns):
  middlewares/validate.middleware.js::program           -> validate:<lambda>1   <-- containment artifact
  middlewares/validate.middleware.js::program:validate  -> validate:<lambda>1

AFTER (direct returns only):
  middlewares/validate.middleware.js::program:validate  -> validate:<lambda>1
```

The module-level coincidence is gone **at its source** rather than being
filtered downstream. `JS_PROV_R12` remains 14/14.

## Export side: STRONG — the decisive negative is answerable

```text
m1.js  module.exports = other              RHS = IDENT other    type=m1.js::program:other
m2.js  exports.validate = validate         RHS = IDENT validate type=m2.js::program:validate
m4.js  module.exports.validate = validate  RHS = IDENT validate type=m4.js::program:validate
m3.js  module.exports = { validate, other } RHS = BLOCK          (object literal)
```

**The decisive negative passes on the export side.** `m1.js` declares *both*
`validate` and `other`, each returning a different lambda, and exports only
`other`. The export assignment resolves its RHS to
`m1.js::program:other` — explicitly, with module-qualified identity. A resolver
keyed on export assignments returns `other` and **cannot** return `validate`.
This is exactly the case the AST-containment shortcut would have gotten wrong.

Named-member shapes (`exports.validate`, `module.exports.validate`) preserve
member identity. The object-literal shape (`module.exports = { validate, other }`)
exposes only a `BLOCK` at this level; member identity would require walking the
literal's member assignments — measurable, but not measured here.

## Consumer side: WEAK, and fabricating

```text
require('./m1')  ->  typeFullName = ANY     (all four modules)
```

No binding from a `require` call to the target module. Worse:

```text
m1(1)           mfn = app.js::program:m1         callees = [app.js::program:m1]
m2.validate(1)  mfn = app.js::program:validate   callees = [app.js::program:validate]
m3.validate(1)  mfn = app.js::program:validate   callees = [app.js::program:validate]
m4.validate(1)  mfn = app.js::program:validate   callees = [app.js::program:validate]
```

**`app.js::program:validate` does not exist.** There is no `validate` function
in `app.js`. The frontend fabricated a same-file callee for all three
`.validate(1)` calls, and collapsed them onto one identity despite their coming
from three different modules with three different lambdas.

This is the R07 pattern again — a populated, confident, wrong resolution — and
it is the *fourth* independent instance of confidently-wrong resolution on
record (R02 `router.get`, R05-2 import alias, R09 receiver type, now callee
across `require`).

## Where the chain actually breaks

```text
CALL validate(schema)
  -> imported binding identity      <-- MISSING (require -> ANY)
  -> exported symbol identity       <-- AVAILABLE (export assignment RHS)
  -> validate METHOD                <-- AVAILABLE
  -> ReturnedFunctionIdentityFact   <-- AVAILABLE (frozen, direct-only)
  -> validate:<lambda>1             <-- AVAILABLE
```

Four of five links exist. The missing one is the **module specifier -> file ->
export assignment** join. Note the raw material is present and structural, not
name-based: the `require` call carries the literal `'./m1'`, and the export
assignment carries `filename = m1.js`. Joining a module specifier to a file is a
path relation, not a name heuristic — but it was not built or tested here, and
the fabricated callees above mean any implementation must **override**, not
consult, `methodFullName`/`callee` at these sites.

# JS-PROV-R13 VERDICT

```text
RETURNED-FUNCTION CONTRACT:  FROZEN to directly-returned. Containment artifact
                             eliminated at source. R12 still 14/14.
module.exports = fn:         RESOLVABLE (RHS IDENT with module-qualified type)
exports.X = fn:              RESOLVABLE (named member preserved)
module.exports.X = fn:       RESOLVABLE (named member preserved)
module.exports = {a, b}:     PARTIAL — RHS is a BLOCK; member identity needs
                             object-literal member traversal (unmeasured)
DECISIVE NEGATIVE:           PASSES on the export side. m1 exports `other`;
                             `validate` is never reachable through it.
require() BINDING:           NOT AVAILABLE — typeFullName = ANY for all modules.
CALLEE ACROSS require():     FABRICATED. `m2.validate(1)` resolves to
                             `app.js::program:validate`, which does not exist,
                             and all three modules collapse onto it.
EXPORT IDENTITY PROMOTION_READY: NO
DOMINANT GAP:                module specifier -> file -> export assignment join.
                             4 of 5 chain links exist; the raw material for the
                             5th is structural (require literal + export
                             filename), but any implementation must OVERRIDE the
                             frontend's fabricated callee rather than consult it.
NEXT MILESTONE:              JS-PROV-R14 — Module Specifier Resolution
                             (implementation). Acceptance anchors already exist:
                             (1) m1 must resolve to `other` and NEVER `validate`;
                             (2) m2/m3/m4 must resolve to their OWN module's
                                 validate, never collapse onto one identity;
                             (3) Corpus B's 10 `validate(schema)` callbacks must
                                 reach `validate:<lambda>1`;
                             (4) R12 fixture stays 14/14.
```

## Thesis principle (adopted from the review, now with a second instance)

> **AST containment is not symbol identity.** A structurally reachable
> descendant does not establish an export, call, or binding relationship
> without an explicit program relation connecting them.

This is the same lesson as R07's derived call edges, from a different
direction. Fable keeps finding places where graph proximity *looks* like
evidence: R07's resolved callee inherited a bad receiver type; R12's module
node inherited a nested function's RETURN; and here `require`-crossing calls
inherit a fabricated same-file callee. In each case the graph offered a
confident answer that no program relation supported.
