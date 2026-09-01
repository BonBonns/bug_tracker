# ReDoS npm-library fixtures (NPM-INTEG-R02)

Frozen raw output of `export_redos_npm_integ_r02.sc` (same Joern pin as R01) run over `src/`'s own
12 synthetic files, checked in so results reproduce without needing Joern again -- same convention
as `study/redos_npm/fixtures/` (R01).

Every shape below was verified against a REAL Joern jssrc2cpg CPG (probe scripts run in the
scratchpad, not committed) BEFORE the corresponding producer logic was written -- never guessed.
See `pilot25/audit/R02_IMPLEMENTATION.md` for the real probe output quoted verbatim and the full
capability-by-capability evidence.

| File | Capability / regression # | Shape | Expected (real, observed) outcome |
|---|---|---|---|
| `class_export_direct.js` | Cap 1 + **Regression #7** | `module.exports = SomeClass`, 2+ real instance methods | `process(input)` resolved+reachable, DANGEROUS; constructor stays `CLASS_CONSTRUCTOR_NOT_PUBLIC_API` (unchanged) |
| `named_class_export_with_this_field.js` | Cap 1 (named export) + Cap 3 (positive) | `export { Context }` (velociradix shape), `this.req` set from an exact ctor param, read as `this.req.body` in `graphql()` | Both resolved: `graphql`'s own `this.req.body` chain node reaches the DANGEROUS sink |
| `this_field_reassigned.js` | Cap 3 abstention + **Regression #3** | `this.req` assigned in ctor AND again in `reset()` before any read | Abstain (`REASSIGNED_THIS_FIELD`), zero rows |
| `this_field_computed.js` | Cap 3 abstention | `this.req = transform(req)` (a Call, not an exact Identifier) | Abstain (`COMPUTED_THIS_FIELD_ASSIGNMENT`), zero rows |
| `two_exported_classes.js` | Cap 1 + Cap 3 + **Regression #4** | Two exported classes (`Alpha`, `Beta`), each with own ctor field + 2 methods | 4 independent rows (`Alpha.run`/`x`, `Alpha.useField`/`this.a`, `Beta.run`/`y`, `Beta.useField`/`this.b`); zero cross-class confusion |
| `obj_shorthand_export.js` | Cap 2 + **Regression #6** | `module.exports = { foo, bar }` | Both resolve to real MethodRefs; `foo` (dangerous) reachable, `bar` (safe) resolved but never emitted |
| `obj_shorthand_dynamic_key.js` | Cap 5 abstention | `module.exports = { [computedKey]: foo }` | Abstain (`COMPUTED_OBJECT_LITERAL_PROPERTY_KEY`) -- distinct from the top-level dynamic-key shape |
| `dynamic_export_key_top_level.js` | Regression check (already-R01 shape) | `module.exports[key] = fn` (top-level, non-literal key) | Abstain (`DYNAMIC_COMPUTED_EXPORT_KEY`), identical to R01, zero regression |
| `closure_cross_scope.js` | Cap 4 + **Regression #1** | Two unrelated closures, each declaring its own same-named `RE`, each consumed by its own nested inner closure | `makeHandlerA`'s `RE` (dangerous) resolves and reaches; `makeHandlerB`'s `RE` (safe) resolves independently to its own pattern -- never cross-contaminated |
| `closure_shadow.js` | Cap 4 + **Regression #2** | Module-scope `const RE = /safe/`, inner-scope `const RE = /^(a+)+$/` inside exported `outer`, inner closure's sink uses the INNER `RE` | Resolves to the inner (nearest-enclosing) `RE`, DANGEROUS+reachable -- proof the outer/safe one was NOT silently picked |
| `closure_ambiguous_reassignment.js` | Cap 5 abstention (cap 4) | `RE` assigned twice at the same enclosing scope level before the nested closure's use | Abstain (`MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER`), pattern never resolved, zero rows |
| `multiple_candidate_constructors.js` | Cap 5 abstention | Same identifier reassigned to two different (anonymous) class expressions before export | Abstain -- real, confirmed mechanism is `UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT` (a class EXPRESSION assignment does not desugar to `Identifier = MethodRef` the way a class DECLARATION's own self-binding does; see R02_IMPLEMENTATION.md for the honest account) -- never guesses which class is "the real" export either way |

**Real result** (frozen raw output in `raw/`): 18 sink targets total, 14 classified DANGEROUS (1
more than R01's frozen resolver would find on this same source, because R01 cannot cross-scope-walk
`closure_ambiguous_reassignment.js`'s `RE` at all -- it would find 0 candidate assignments in the
calling method's own AST and abstain identically to R02's cross-scope walk, which also correctly
abstains here, just via a different, capability-4-specific reason code: `MULTIPLE_LIVE_ASSIGNMENTS_
TO_IDENTIFIER` vs `UNRESOLVED_IDENTIFIER`). **9 rows emitted** to `raw/source_facts.tsv`, all
`PACKAGE_API_INPUT` (this fixture set has no `Meteor.methods` ingress shape) -- exactly the 9
genuinely-resolved, genuinely-reachable cases across all 12 files, with every abstained/safe/
unreached case correctly contributing zero rows. Full abstention detail (stderr, all distinctly
labeled per the capability-5 discipline) is in `pilot25/audit/R02_IMPLEMENTATION.md`.

## Regression checking (R01 frozen producer vs R02, both fixture sets)

- **R01 (frozen, unmodified) run over `../fixtures/src/` (its own original 10 files)**: reproduces
  its own documented baseline exactly -- 11 sink targets, 10 DANGEROUS, 7 rows emitted (6
  `PACKAGE_API_INPUT` + 1 `APPLICATION_INGRESS`).
- **R02 run over the SAME `../fixtures/src/`**: emits all 7 of R01's own rows, byte-identical
  (same sink/source node ids, same lines) -- confirmed via a direct `diff`/`comm` of the two
  `source_facts.tsv` files, zero rows lost -- **plus exactly 1 new, correct row**: R01's own
  `class_export.js` fixture (`module.exports = Checker`, whose only method `check(input)` R01
  documents as "ABSTAINED -- resolves to the class's own `<init>`, not its real public methods")
  now resolves `check`'s own `input` parameter as a real PACKAGE_API_INPUT source, DANGEROUS,
  reachable -- this is capability 1 fixing exactly the gap R01's own README already flagged, not a
  regression.
- **R01 (frozen, unmodified) run over `src/` (this R02 fixture set)**: 18 sink targets, 12 DANGEROUS
  (2 fewer than R02's 14, since R01 cannot cross-scope-resolve `closure_cross_scope.js`'s or
  `closure_shadow.js`'s `RE` at all), **0 exported functions resolved, 0 rows emitted** -- every
  capability-1/2/3/4 shape in this fixture set is new territory R01 has no path for at all,
  confirming this fixture set genuinely exercises R02-only capabilities.

Regenerating (only needed if a fixture file changes):
```
export JOERN_HOME=/path/to/joern-cli   # same pin as fixtures/
"$JOERN_HOME/jssrc2cpg.sh" -o /tmp/x.cpg.bin src/
"$JOERN_HOME/joern" --script ../../../../tchecker-research-complete/tchecker-property-adjudicator/producers/export_redos_npm_integ_r02.sc \
    --param cpgFile=/tmp/x.cpg.bin --param rawDir=raw --param srcLabel=r02fixtures
```
