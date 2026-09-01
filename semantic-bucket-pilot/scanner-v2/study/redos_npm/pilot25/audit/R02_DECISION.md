# R02 decision record

## Decision 0: R02 is required (already mechanically determined)

Per the mechanical rule ("any export, flow, or parsing gap -> create R02, use all 21 packages as
development regressions"), `velociradix@8.3.1` alone already satisfies it: it carries both a real
`EXPORT_GAP` (no code path resolves a class's own instance methods as export sources) and a real
`FLOW_GAP` (no `this`-field taint tracing from a constructor's own parameters). This was
established before the remaining 6-package investigation ran; that investigation determines R02's
full SCOPE, not whether R02 exists. **R02 is required. Confirmed.**

## Full accounting: 21 selected packages

**Findings and packages are counted as separate units throughout** (a package can carry more than
one finding; `fuse-napi` is the one case in this pilot where that happens). The correct units,
stated exactly:

- **21 selected packages total.**
- `phplike`: **1 package, 1 `PACKAGE_API_INPUT_REACHABLE` finding, manually rejected**
  (`phplike_review/ADJUDICATION_RECORD.md`).
- `COMPLEXITY_ONLY`: **6 packages, 7 findings.**
- `NO_COMPLEXITY_CANDIDATE`: **14 packages, zero analyzer findings.**

(1 + 6 + 14 = 21 packages; 1 + 7 = 8 emitted complexity findings total across the pilot.)

### 6 packages / 7 findings: `COMPLEXITY_ONLY` (see `COMPLEXITY_ONLY_CATEGORIZATION.md` for full
detail and evidence)

| Bucket | Findings | Packages |
|---|---|---|
| `INTERNAL_UNDER_PACKAGE_API_MODEL` | 5 | `node-addon-api`, `@depup/node-addon-api`, `@h1x4dev/node-addon-api`, `koffi`, `fuse-napi` (finding 1 of 2) |
| `EXPORT_GAP` | 2 | `fuse-napi` (finding 2 of 2, object-literal-shorthand exports), `velociradix` (class instance methods) |
| `FLOW_GAP` | 1 (co-occurring with `velociradix`'s `EXPORT_GAP`, not a separate finding) | `velociradix` |
| `AMBIGUOUS_EDGE` | 0 | -- |
| `INTENTIONAL_ABSTENTION` | 0 | -- |

### 14 packages: `NO_COMPLEXITY_CANDIDATE` (8 from `PREFILTER_DIVERGENCE_AUDIT.md`'s original
sample + 6 from `REMAINING_SIX_NO_COMPLEXITY_CANDIDATE.md`, closing the sampling gap)

| Bucket | Packages | Count |
|---|---|---|
| `PREFILTER_APPROXIMATION` | `ember-one-way-controls`, `@appthreat/sqlite3`, `realm`, `linux-device`, `numbl`, `sdenv`, `uplink-nodejs`, `jsmeow` -- all 8 originally-sampled packages; every one traces to a jssrc2cpg file-exclusion parity gap or a JSDoc-comment misparse, both already fixed in the current (R02-prefilter, not to be confused with this document's R02 analyzer) `prefilter_select_25.py` | 8 |
| `SAFE_UNDER_FROZEN_COMPLEXITY_MODEL` | `argon2` (JSDoc misparse, same already-fixed prefilter bug, and zero real sink calls exist in the package at all), `x11-dri` (JSDoc misparse in an excluded `.d.ts`; 3 real sinks all correctly `UNKNOWN`), `tree-sitter-4dm` (a real, structurally-dangerous regex literal, but it is tree-sitter grammar-DSL data, never passed to a real JS regex sink method) | 3 |
| `UNSUPPORTED_REGEX_CONSTRUCTION` | `ssh2`, `mariasql` -- both a genuinely dangerous, genuinely reachable static regex literal whose declaration and consuming sink call sit in two different Joern CPG `Method`s (module scope vs. an inner closure); Stage 1's `resolvePattern` only searches the calling `Method`'s own AST, correctly abstains rather than guessing | 2 |
| `JOERN_PARSING_GAP` | `multi-spec-parser` -- a real, genuinely dangerous, genuinely package-API-reachable regex sitting in `dist/src/spec-validation.js`, the package's *entire* shipped runtime source (no parallel `src/` exists); jssrc2cpg's default `dist`-folder exclusion drops 100% of this package's real code | 1 |
| `CLASSIFIER_DISAGREEMENT` | -- none | 0 |

**14 = 8 + 3 + 2 + 1 + 0.** Confirmed by direct arithmetic against the table above.

**Zero classifier disagreements across all 21 selected packages, comprising eight emitted
complexity findings and fourteen packages with no emitted complexity finding.** (The eight: the
seven `COMPLEXITY_ONLY` findings plus `phplike`'s own single `PACKAGE_API_INPUT_REACHABLE`
finding, whose classification -- DANGEROUS under the rule's own stated text -- was itself correct;
its adjudication rejected the FINDING on real-world grounds, not the classifier's application of
its rule.) Every pattern Stage 2 was ever handed, across the entire 21-package pilot, was
classified consistently with `classifyPattern()`'s own documented logic.

## Decision 1: R02 source/dataflow scope

**Required** (already known, both real and directly confirmed by this pilot's own evidence):

1. **Exported class instance methods as sources.** `resolveExportRhs` currently handles a bare
   `MethodRef` or an identifier with exactly one prior `identifier = MethodRef` assignment; a class
   declaration desugars to neither. Driven by `velociradix`'s real, named `export { ..., Context,
   ... }`.
2. **Object-literal shorthand exports** (`module.exports = { foo, bar }` / `exports.default = {
   foo }`). Currently routed to the `UNRESOLVED_RHS_SHAPE` abstention catch-all. Driven by
   `fuse-napi`'s real `module.exports = { MACFUSE_URL, wrapMacFuseLoadError }` in `lib/macfuse.js`
   (this package's own dominant reachability blocker is still `INTERNAL_UNDER_PACKAGE_API_MODEL`
   for OTHER reasons -- see its record -- but the export-shape gap itself is real and independent).
3. **Constructor parameter -> `this.field` -> method-use propagation.** `this` is currently
   filtered out of parameter enumeration entirely (`p.method.parameter.filter(_.name !=
   "this")`); no capability traces a constructor's own real parameters into an instance field and
   from there into a later method call on that field. Driven by `velociradix`'s `Context.graphql()`
   reading `this.req.body`.

**Newly added by the 6-package investigation** (a real, previously-undocumented Stage 1
limitation, not previously known when items 1-3 were listed):

4. **Cross-`Method`-scope (module/closure-scope) static identifier resolution.** `resolvePattern`'s
   identifier-to-literal search (`method.ast.isCall.name("<operator>.assignment")`) is scoped to
   the calling `Method`'s own AST subtree only; it cannot find a `const`/`var` regex assignment
   that lives in an *enclosing* module or closure scope (a different CPG `Method`) than the call
   site that uses it. Driven by two real, independent instances (`ssh2`'s `RE_HEADER`, `mariasql`'s
   `RE_PARAM`) -- both plain static literals, correctly abstaining today (`UNRESOLVED_IDENTIFIER` ->
   `UNKNOWN`, never a wrong answer), but a real capability gap: this exact pattern (module-scope
   `const REGEX = /.../` consumed inside a later-defined method) is common, ordinary JS, not an
   edge case.

**All four are real, source/dataflow-side gaps in the redos adapter itself (`export_redos_npm_
integ.sc`), not the classifier (`classifyPattern`) and not the CPG-construction tool
(`jssrc2cpg`).** They belong in new R02 files, per direct instruction; the frozen R01 producer
(`export_redos_npm_integ.sc`) and the `phplike` adjudication record are left unchanged.

## Decision 2: classifier-core scope

**No changes required.** Zero classifier disagreements across all 21 selected packages, comprising
eight emitted complexity findings and fourteen packages with no emitted complexity finding --
every one hand-checked against `classifyPattern()`'s own frozen logic. The one adjudicated finding
(`phplike`) was a case where the classifier
correctly applied its own stated rule to produce `DANGEROUS`; the rule's own real-world precision
in that one alternation-branch shape was separately, narrowly adjudicated
(`phplike_review/ADJUDICATION_RECORD.md`) -- that is a disclosed limitation of the RULE's
generality, not a bug in the classifier's implementation of the rule, and per that record's own
explicit scope section, authorizes no rule change and no general suppression.

## A third, real finding this taxonomy has no slot for -- not silently folded into either decision

**`multi-spec-parser`'s `JOERN_PARSING_GAP` is neither an R02 (adapter dataflow) issue nor a
classifier-core issue.** Even a fully-implemented R02 could never find this package's real
`isHtml()` regex, because `jssrc2cpg` itself -- the CPG-construction tool `export_redos_npm_
integ.sc` runs against, upstream of anything the adapter or classifier can see -- drops the
package's entire `dist/` tree (its *only* shipped runtime source, no parallel `src/` exists)
before a CPG node for that file is ever created. This is a real gap in how the redos pipeline
*invokes* `jssrc2cpg` (its default ignore-folder list, `AstGenDefaultIgnoreFolders`, includes
`dist` unconditionally), not in any code this project owns and edits directly (`export_redos_npm_
integ.sc`, `classify_dangerous`/`classifyPattern`). Two real remediation paths exist and neither
has been attempted here: (a) check whether `jssrc2cpg.sh` exposes an ignore-list override flag and
invoke it without the `dist` default for this pipeline; (b) a pipeline-level pre-processing step
that copies `dist`-only packages' content to a non-ignored path before the CPG build. **Explicitly
flagged as its own open item, out of scope for both decisions above, not folded into R02's count
and not treated as "no change needed."**

## Exclusion of the 21 pilot packages from the next blind selection

**Already structurally satisfied.** `pilot_blind2_selection.json` (committed prior to this
message's instructions) already excludes all 21 package NAMES used in this pilot from its own
candidate pool -- confirmed again here as still correct now that the pilot's own findings/
packages accounting is complete: all 21 (`ember-one-way-controls`, `@appthreat/sqlite3`, `realm`,
`linux-device`, `numbl`, `sdenv`, `uplink-nodejs`, `jsmeow`, `argon2`, `ssh2`, `x11-dri`,
`multi-spec-parser`, `mariasql`, `tree-sitter-4dm`, `fuse-napi`, `node-addon-api`, `@depup/
node-addon-api`, `@h1x4dev/node-addon-api`, `koffi`, `velociradix`, `phplike`) remain excluded.
When R02 is implemented and a further blind selection round is run (a NEW rule, frozen before
outcomes are viewed, per direct instruction), the same 21-package exclusion carries forward.

## Status

`reportable` stays hardcoded `false`. No pipeline wiring touched. R02 implementation (the 4 items
in Decision 1) is the next concrete deliverable, built in new files, fixture-first, with the same
Joern-CPG-inspection-before-code discipline the original R01 adapter used -- not yet started as of
this document.
