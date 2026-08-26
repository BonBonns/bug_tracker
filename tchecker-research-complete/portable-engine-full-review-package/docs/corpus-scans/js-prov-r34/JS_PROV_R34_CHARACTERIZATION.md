# JS-PROV-R34 — Defect B: Module-Alias Export Members (characterization)

**Characterization only. Nothing implemented.** Investigating the remaining
blocker on Corpus D L4/L5, identified in JS-PROV-R32 as Defect B.

## Finding: the emitted type is WRONG, not merely missing

R32 described Defect B as "the module link is absent". Measured on a controlled
fixture, it is worse than that.

```js
// barrel.js
const leaf = require("./leaf");
module.exports = { leaf, sel, plain, localFn };
```

```text
emitted export row:   member=leaf   rhs=barrel.js::program   kind=IDENTIFIER
```

The member `leaf` denotes the **module `./leaf`**. Its recorded type is
`barrel.js::program` — the **containing file's** program scope. That is not an
absent link; it is a type that names a different program entity.

This is another **representation-collapse defect** (R09 receiver typing, R13
callee identity, R23a `isWildcard`, R32/R33 `require(spec).member`): a
well-formed record that denotes the wrong entity. Fifth instance.

**It does not currently fabricate**, because nothing downstream reads a member's
RHS as a module reference. But the same was true of Defect A before the
shared-name fixture removed its mask.

## The fabrication is reachable, and the fixture makes it so

```text
leaf.js  exports: leafFn
other.js exports: leafFn, otherFn      <-- deliberately SHARES `leafFn`

use.js:  b.leaf.leafFn   must resolve to leaf.js:leafFn, NEVER other.js:leafFn
```

Any implementation that guesses the module link — rather than deriving it from
the require binding — can return `other.js:leafFn`. The fixture removes the
naming coincidence that would otherwise mask a wrong join, exactly as R33's
`shared` control did.

## What is measured, per member

```text
member    RHS type                          require-bound?   correct disposition
leaf      barrel.js::program  (WRONG)       yes, bare        -> link to ./leaf
sel       (a: ANY) => ANY                   yes, SELECTOR    -> ABSTAIN (R33)
plain     { leafFn: __ecma.Number; }        no               -> ABSTAIN (not a module)
localFn   barrel.js::program:localFn        no               -> ordinary member,
                                                                already correct today
```

`localFn` matters: a member whose RHS is a plain local function **already
resolves correctly**. Only require-bound locals are affected, so the fix must be
conditioned on the require binding, never on the RHS being an identifier.

## Facts available for the join

```text
require_bindings.tsv          barrel.js  ./leaf   leaf        <- the module link
require_member_selection.tsv  barrel.js  sel  ./other  otherFn <- R33 guard
module_exports.tsv            leaf.js    leafFn  leaf.js::program:leafFn
```

Everything needed is exported. **What is missing is the RHS identifier NAME on
the member row** — the row carries `rhs` as a *type*, so there is nothing to
join against `require_bindings`.

## Delivery constraint (from R33)

`module_exports.tsv` now has multiple readers. Adding a column is a
cross-cutting schema edit — that is precisely what broke R33's first attempt.
**The RHS identifier name must go in a separate file**, e.g.
`export_member_alias.tsv`, which consumers opt into.

# JS-PROV-R34 VERDICT

```text
DEFECT B:          CONFIRMED, and sharper than R32 recorded -- the member's
                   type names the CONTAINING file, not the aliased module.
                   Fifth representation-collapse instance.
FABRICATES TODAY:  NO -- nothing reads a member RHS as a module reference.
                   Reachable the moment something does.
BLAST RADIUS:      require-bound locals only. Plain-function members
                   (`localFn`) already resolve correctly and must not change.
FACTS AVAILABLE:   YES, except the RHS identifier NAME on the member row.
DELIVERY:          new file (`export_member_alias.tsv`), never a new column --
                   R33's lesson, four confirmations.
IMPLEMENTED:       NOTHING.

NEXT: JS-PROV-R35 -- module-alias export member identity.
  Preregistered teeth:
    P1  `module.exports = { leaf }` where `leaf = require("./leaf")`
        -> member `leaf` links to ./leaf
    N1  SHARED-NAME CONTROL: `b.leaf.leafFn` must resolve to leaf.js:leafFn and
        NEVER other.js:leafFn
    N2  selector-bearing local (`require(x).member`) -> ABSTAIN (R33 guard holds)
    N3  non-module member (`plain`) -> ABSTAIN
    N4  plain-function member (`localFn`) -> UNCHANGED, still resolves
    N5  module_exports.tsv schema unchanged; alias in a separate file
    N6  Corpus B identical on ALL layers (module-identity 48, flows 23) --
        invariant must ENUMERATE the layers it covers (R31 amendment)
    N7  Corpus D movement permitted, not required
    N8  demonstrably wrong = 0
```

## Discipline note

R32 recorded Defect B as a coverage gap and Defect A as the soundness one. That
ordering was right on the evidence then available, but incomplete: Defect B is
*also* a wrong record, just one nothing currently reads.

The distinction that matters is not "wrong vs missing" but **"wrong and read"
vs "wrong and unread."** A latent wrong record is a fabrication waiting for its
first consumer — which is exactly what R30 would have become had it consulted
member RHS types.
