# JS-PROV-R23a — ESM Export Identity: Fixture & Control Suite

**Characterization only.** No implementation, no promotion, no downstream
replay. Per the stated experimental rule, the ESM fact must be proven against
independently enumerated ground truth **before** any downstream layer is
allowed to move.

## Headline: R22's diagnosis was wrong in an important way

R22 concluded layer 1 produced zero because "Corpus C is ESM; R14's producer is
CommonJS-specific." Measured directly, that is **not** the mechanism.

**`jssrc2cpg` lowers ESM to CommonJS-shaped nodes.** Exports become exactly the
`exports.X = Y` assignments R14 already reads:

```text
export function fDecl        ->  exports.fDecl     = fDecl      RHS IDENT lib.ts::program:fDecl
export const fConst = ...    ->  exports.fConst    = fConst     RHS IDENT (a: ANY) => ANY
function fLater; export {}   ->  exports.fLater    = fLater     RHS IDENT lib.ts::program:fLater
export { fOrig as fRenamed } ->  exports.fRenamed  = fOrig      RHS IDENT lib.ts::program:fOrig
export default fDef          ->  exports["default"]= fDef       RHS IDENT lib.ts::program:fDef
export default function h(){}->  exports["default"]= fInlineDefault  RHS IDENT lib2.ts::program:fInlineDefault
```

All six export shapes carry **module-qualified declaration identity** on the
RHS. The renamed case is particularly clean: `fRenamed` correctly resolves to
`fOrig`'s declaration, not to a synthetic named after the export alias.

So the ESM export side is **already supported** by R14's existing extractor.
R22's zero has a different cause.

## The actual gap: import binding, not export identity

R14 binds `local = require(spec)`. ESM named imports lower one level deeper —
the `require` is the **base of a field access**, not the assignment's RHS:

```text
import { fDecl }             ->  var fDecl      = require("./lib").fDecl
import { fConst as fAliased} ->  var fAliased   = require("./lib").fConst
import fDefault from './lib' ->  var fDefault   = require("./lib")
import * as ns from './lib'  ->  var ns         = require("./lib")
```

`inAssignment` still resolves, but to the *whole* assignment, so R14 records
the local as bound to the module **object** rather than to the specific
exported member. That is why `m2.validate(1)`-style member resolution worked on
Corpus B (CommonJS `require('x')` then `.member` at the call site) while
Corpus C produced nothing: in ESM the member is consumed at **import** time,
not at call time.

Notably `fDefault` and `ns` lower **identically** (`= require("./lib")`), so the
lowered form alone cannot distinguish a default import from a namespace import.

## A cleaner structural source exists: IMPORT nodes

`cpg.imports` carries the specifier, the exported member, and the local alias
as separate fields — no lowering, no code-string parsing:

```text
import { fDecl }                    entity=./lib:fDecl    as=fDecl
import { fConst as fAliased }       entity=./lib:fConst   as=fAliased
import fDefault from './lib'        entity=./lib:fDefault as=fDefault
import * as ns from './lib'         entity=./lib:ns       as=ns
import { fDecl as viaReexport }     entity=./reexport:fDecl as=viaReexport
```

`entity` = `<specifier>:<member>`, `as` = local binding. This resolves the
default-vs-namespace ambiguity the lowered form loses, and gives aliased
imports their true source member. **This is the right input for R23b**, not the
lowered `require` form.

## Dangerous controls — measured

```text
export * from './lib2'   ->  exports.lib2 = _lib2   RHS IDENT _lib2  type=ANY
```
No member identity whatsoever; the whole namespace is bound to an `ANY` local.
**Must abstain** — and does so naturally, since no per-member export assignment
exists.

```text
import * as ns           ->  entity=./lib:ns
```
`ns` is **not a real exported member** — it is a synthetic standing for the
namespace. Any resolver must reject `:<localAlias>` entities that do not match
an actual export assignment in the target file, or it would fabricate a member
named `ns`. **This is the sharpest fabrication risk found.**

```text
dynamic import()  ->  call name = `import`, NOT a require, NOT an IMPORT node
                      const dyn = await import('./lib')
                      const un  = await import('./does-not-exist')
```
Neither appears in `cpg.imports`, so both abstain naturally. Unresolved modules
are indistinguishable from resolved ones at this level — correctly, since
neither is claimed.

```text
export default (a) => a   ->  exports["default"] = <lambda>1
                              RHS IDENT type=danger.ts::program:<lambda>1
```
Contrary to expectation, an **expression** default *does* carry recoverable
identity — the lambda has a module-qualified fullName. This shape need not
abstain, though it should be marked as anonymous-declaration identity rather
than a named export.

## Re-export

```text
export { fDecl } from './lib'  ->  exports.fDecl = _lib.fDecl   RHS = CALL
```
The RHS is a **field access on the imported module object**, not a declaration
identity. One additional hop (resolve `_lib` to `./lib`, then look up `fDecl`
in that file's exports) would close it. Not attempted here.

# JS-PROV-R23a VERDICT

```text
ESM EXPORT IDENTITY:     ALREADY SUPPORTED. All six export shapes lower to
                         `exports.X = Y` with module-qualified declaration
                         identity on the RHS, including `export { a as b }`
                         resolving to a's declaration.
R22 DIAGNOSIS:           CORRECTED. Layer 1's zero was NOT "ESM exports are
                         invisible". It is an IMPORT-BINDING gap.
ACTUAL GAP:              ESM named imports lower to
                         `local = require(spec).member`, binding the local to
                         the module object rather than the member. Default and
                         namespace imports lower IDENTICALLY and cannot be
                         distinguished in the lowered form.
BETTER INPUT AVAILABLE:  `cpg.imports` exposes entity=`<spec>:<member>` and
                         `as`=<local> directly -- no lowering, no code strings.
                         This is the correct input for R23b.
MUST-ABSTAIN (measured): `export *` (no member identity, ANY-typed namespace);
                         namespace import (entity member is a SYNTHETIC name --
                         sharpest fabrication risk); dynamic `import()` (not an
                         IMPORT node); unresolved modules.
SURPRISE:                `export default <expression>` DOES carry identity
                         (`::program:<lambda>N`); it need not abstain.
NOT CLOSED:              Re-export (`export { x } from './y'`) RHS is a field
                         access on the module object, needing one more hop.

PROMOTION_READY:         NO (characterization only, by design).
NEXT MILESTONE:          JS-PROV-R23b — build the ESM import-binding producer on
                         `cpg.imports`, and validate it against INDEPENDENTLY
                         ENUMERATED Corpus-C export/import ground truth
                         (grep-derived, as Layer 6 was in R21/R22).
                         Acceptance: every established binding matches source;
                         `export *`, namespace imports, dynamic imports and
                         unresolved modules all abstain; ZERO fabricated
                         members. ONLY THEN freeze and replay downstream layers.
```

## Discipline note

The most important result is a correction to my own R22 verdict. "Corpus C is
ESM and R14 is CommonJS-only" was a plausible story that fit the zero, and it
was wrong: the frontend already normalizes ESM exports into the exact shape R14
reads. Had R23 been scoped as "add ESM export support", it would have
reimplemented working machinery and left the real gap — import binding —
untouched.

That is a second instance of a diagnosis being accepted because it explained
the observation, without being separately verified. The first was R12's module
-level coincidence. Both argue that a *cause* should be measured, not inferred
from a *symptom*, even when the inference is reasonable.
