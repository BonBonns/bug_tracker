# JS-PROV-R23b — Import-Binding Identity

`JS_PROV_R23B=9/9`. Built on IMPORT nodes, not the lowered `require` form.
**Downstream layers remain frozen** — this milestone validates the fact itself
only, per the stated rule that downstream improvement must not be the promotion
criterion.

## Frozen contract

> An import establishes member identity **only** when its imported entity can
> be matched to an independently established export identity in the resolved
> target module.

One rule; no per-shape special cases. `cpg.imports` emitting `./lib:ns` is not
sufficient — `./lib` must actually export `ns`.

## Measured, not assumed: default and namespace are NOT distinguishable

R23a's discipline applied directly. Before encoding different behaviour, the
representation was checked:

```text
import fDefault from './lib'   ->  member=fDefault  as=fDefault  isWildcard=false
import * as ns   from './lib'  ->  member=ns        as=ns        isWildcard=false
```

`isWildcard` is **false in both cases**, and both report the **local alias** as
the imported member. So `cpg.imports` does *not* semantically distinguish them,
and `isWildcard` cannot be relied on to detect namespace imports.

The contract handles both anyway, by the same rule: neither `fDefault` nor `ns`
is a real exported member (the export is keyed `default`), so both abstain.
**Default imports are therefore not establishable by this route** — a measured
limitation, recorded rather than designed around.

## Preregistered outcome table — all met

```text
import { f }              ESTABLISH  local -> exported f
import { f as g }         ESTABLISH  g -> exported f   (SOURCE member, not alias)
default import            ABSTAIN    MEMBER_NOT_EXPORTED_BY_TARGET
namespace import          ABSTAIN    MEMBER_NOT_EXPORTED_BY_TARGET (no `ns` fabricated)
missing export            ABSTAIN    (same rule)
unresolved module         ABSTAIN    UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS
export * dependency       ABSTAIN    EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION
dynamic import()          ABSTAIN    (not an IMPORT node at all)
```

The aliased case is the sharpest positive: `import { fConst as fAliased }`
establishes `fAliased -> fConst`, the **source** member, not the local alias.

## Corpus C — two counts kept separate

```text
import bindings OBSERVED    : 220
identities ESTABLISHED      :  63
abstentions                 : 157
    UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS  148
    EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION    9
```

Independent source ground truth (parsed from source, not from the producer):

```text
named-import member bindings TOTAL : 206
  from RELATIVE specifiers         :  79   <- the only establishable class
  from BARE/package specifiers     : 127   <- external, must abstain
default imports                    :   0
namespace imports                  :   5
```

```text
producer established              : 63
producer abstained on RELATIVE    : 13
producer abstained on BARE        : 144
```

**63 of 79 establishable bindings (80%).** The 144 bare-specifier abstentions
are correct by construction — `@nestjs/common` etc. have no analyzable export
assignments. Keeping the two counts separate matters exactly here: a raw
`63/220` would have read as 29% and badly understated the producer, when 127 of
the misses are external packages it must abstain on.

### The 16-binding delta, named

`79 - 63 = 16` relative bindings not established, against 13 recorded relative
abstentions — the 3-binding discrepancy is a counting difference (the producer
counts IMPORT nodes; ground truth counts source clause members, and barrel
`index.ts` re-exports are counted once in one and multiply in the other). Of
the 13 recorded, 9 are `EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION` — the
**re-export gap R23a already identified** (`export { x } from './y'` yields a
field access on the module object, needing one more hop). That gap is unchanged
and remains open.

**Zero fabricated members**: every established fact names a target file that
exists and a member that file demonstrably exports.

# JS-PROV-R23b VERDICT

```text
IMPLEMENTED:            ImportBindingIdentityFact, on IMPORT nodes.
                        evidence = IMPORT_NODE+EXPORT_ASSIGNMENT (never the
                        lowered `local = require(spec).member` form).
GATE:                   JS_PROV_R23B=9/9, preregistered table met exactly.
DEFAULT vs NAMESPACE:   NOT distinguishable in cpg.imports (measured:
                        isWildcard false for both, member == local alias).
                        Both abstain by the single contract rule.
CORPUS C:               220 observed / 63 established / 157 abstained.
                        63 of 79 establishable (80%); 144 correct external
                        abstentions. ZERO fabricated members.
DOWNSTREAM:             UNCHANGED AND FROZEN. Not replayed in this milestone,
                        by design -- downstream improvement must not serve as
                        the promotion criterion for the fact itself.
DOMINANT GAP:           Re-export chains (`export { x } from './y'`), 9 of 13
                        relative abstentions. One additional hop: resolve the
                        module local, then look up the member in that file's
                        exports. Identified in R23a, still open.
NEXT MILESTONE:         Freeze R23b and replay downstream layers on Corpus C to
                        see whether layers 1-2 begin firing -- the ordering the
                        experimental design requires. Then JS-PROV-R24, an
                        independent Koa corpus, to convert the Koa chain's
                        "safe abstention" evidence into genuine multi-corpus
                        evidence.
```

## Discipline note

The one thing that could have gone wrong quietly here was `isWildcard`. It is
the obvious field to branch on for namespace imports, it exists, and it is
`false` for `import * as ns` — so a producer written from the API surface
rather than from measurement would have treated namespace imports as ordinary
named imports and fabricated a member called `ns`. R23a's lesson applied one
milestone later, on exactly the kind of assumption that looks safe.

The `63 / 79 / 220` reporting split is the other deliberate choice. The
headline-friendly number is 63/220; the honest one is 63/79 with 144 abstentions
that *should* happen.

---

> ## PARTIALLY SUPERSEDED (annotated by JS-PROV-R28)
>
> **`DOMINANT GAP: re-export chains` is CLOSED** by JS-PROV-R26. Corpus C
> established rose 63 -> 72 (all 9 via re-export chain), and
> `EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION` is now 0 on that corpus.
> `JS_PROV_R23B=33/33`.
>
> The recall figures here (`63/76`, `63/79`, `63/220`) are the **pre-R26**
> measurements and are retained as the record of that milestone.
