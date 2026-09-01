# SERIALIZE-DOS-R04 -- the npm public-export source model

Continues from `R03_RESULTS.md`. This revision exists because the existing
size/structure engine only ever recognized `req.body`-style APPLICATION_INGRESS
sources -- it had no model at all for values entering a package through its own
**exported** npm API surface (function/method parameters, constructor parameters
stored on `this`). Three real R01-R03 draws (mozilla/fxa's `customs.js`,
`@sonatel-os/juf-xpress-logger`, `@rasla/logify`) all exposed this same gap: an
already-abstracted function parameter is never recognized as attacker-influenceable,
even when the function itself is the package's own public export. Separately, the
old `CANDIDATE_UNBOUNDED_SERIALIZE_SIZE` label overstated what the mechanical proof
actually establishes -- the analyzer only shows no *package-local* bound was proven,
never that the value is genuinely unbounded (it cannot see an upstream/external,
consumer-configurable bound, such as motifer's own documented body-parser limit).

R04 fixes both: a second, explicitly separate source family
(`PACKAGE_API_INPUT`, alongside the unchanged `APPLICATION_INGRESS_INPUT`), and two
terminology corrections that make the automated labels match the real mechanical
proof, no more and no less.

## 1. Reuse, not reinvention: the ReDoS property's own npm public-export model

Per instruction, R04 does not independently invent a second source-resolution engine.
It ports the finished ReDoS property's own frozen npm public-export source model
(`tchecker-property-adjudicator/producers/export_redos_npm_integ_r02.sc`, read-only,
never modified) into a new producer pointed at serialize sinks instead of regex sinks:
`producers/npm_public_export_sources_r04.sc`.

Ported verbatim in structure (not literally imported -- re-implemented against a
different CPG/sink context, same algorithm):
- `resolveExportRhs` / `resolveObjectLiteralExport` / `registerResolution` -- the
  CommonJS `module.exports.x = fn` / `module.exports = { a, b }` / desugared-ESM
  named-export resolution chain (ESM's `export function f(){}` already produces the
  identical CPG shape as CommonJS per the ReDoS work's own `R02_IMPLEMENTATION.md`
  finding, so no separate ESM path was needed).
- `collectFieldAccessChain` / `findThisFieldAssigns` -- exported class constructor
  parameter -> `this.field` -> later method flows.
- The same abstention vocabulary for ambiguous/unresolved export-assignment shapes
  (`UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT`, `AMBIGUOUS_...`,
  `COMPUTED_THIS_FIELD_ASSIGNMENT`), never guessed past.

Sink side, batched-reachability technique (also ported from the ReDoS work's own
proven at-scale design, necessary given `@rasla/logify`'s real 48,100-call CPG): one
`reachableByFlows(sources.iterator)` call per sink per family, not one call per
individual (sink, source) pair. "Never `.headOption`, enumerate everything" -- R03's
own discipline -- is carried into R04's enumeration of both sinks and both source
families.

**A real bug found and fixed during fixture verification**: the initial
`isSerializerSink` filter used a loose OR of code-regex checks (patterned after
`export_serialize_facts.sc`'s own style) applied broadly across `cpg.call.l`. Unlike
that producer's narrower `.name("stringify")`-first scoping, this wrongly matched a
synthetic hoisted-function-declaration `Call` node whose `.code` field embedded its
entire function body as text, producing false duplicate sinks (18 found vs. the true
10 static `JSON.stringify` sites across the 9 fixtures). Fixed by requiring `c.name`
match first (AND, not OR) with the regex -- confirmed by rerun.

## 2. Terminology corrections

- `CANDIDATE_UNBOUNDED_SERIALIZE_SIZE` -> **`CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED`**
  (the `RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS` / `RESOLVED_CANDIDATE_BY_ACCEPTED_HINT`
  taint-engine dispositions now map here).
- `SAFE_NOT_ATTACKER_CONTROLLED` -> **`NO_SUPPORTED_EXTERNAL_INPUT_FLOW`** (both the
  crash-DoS "no source" case and the size/structure "no families present" case).

Neither label claims more than the mechanical proof establishes: "no package-local
bound was proven" is not "unbounded," and "no source family this property recognizes
reaches this sink" is not "safe."

## 3. Validation: 12 required controls, all real-Joern-compiled

`check_serialize_dos_r04.py`, **`SERIALIZE_DOS_R04=14/14`** (12 controls, two of
which -- C1/C10-11 and C12 -- are checked with extra sub-assertions). Full detail in
that gate's own docstring; headline results:

| control | fixture / package | result |
|---|---|---|
| C1 exported function parameter, direct | `r4-param-direct` | `PACKAGE_API_INPUT` ESTABLISHED, `CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED` |
| C2 exported parameter through uniquely resolved helper | `r4-param-helper` | real interprocedural flow through `wrap()` (the only method of that name in the whole CPG, statically unambiguous); disposition `CANDIDATE_OPEN` -- "uniquely resolved" is a call-edge/trace-identity property, not a guarantee of ESTABLISHED |
| C3 constructor param -> `this.field` -> method | `r4-this-field` | `PACKAGE_API_INPUT` ESTABLISHED, `CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED` |
| C4 object-literal shorthand export | `r4-obj-shorthand` | only the one shorthand export whose value is actually serialized resolves; the other (never reaching a sink) is not a candidate at all |
| C5 internal-only parameter, never exported | `r4-internal-only` | zero `PACKAGE_API_INPUT` rows, `NO_SUPPORTED_EXTERNAL_INPUT_FLOW` |
| C6 same-name parameter, unrelated non-exported function | `r4-same-name-unrelated` | the exported function's own site resolves; the unrelated function is never even a candidate sink |
| C7 ambiguous call edge (reassigned identifier) | `r4-ambiguous-export` | abstain, zero rows; real observed reason `UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT` (`let Exported = A` is `Identifier=Identifier`-shaped in Joern's CPG, not `Identifier=MethodRef`-shaped -- matches the ReDoS work's own prior "honest note" on the analogous class-export case; never guessed either way) |
| C8 unknown member-method transform | `r4-unknown-transform` | abstain, `CANDIDATE_OPEN` |
| C9 proven package-local size bound | `r4-proven-bound` | real negative, `REJECTED_FALSE_POSITIVE_VALUE_NOT_PRESERVED` |
| C10 external bound never conflated with package-local proof | real `motifer@26.1.1` | automated classification stays `CANDIDATE_PACKAGE_LOCAL_BOUND_NOT_ESTABLISHED`; the real, documented external body-parser bound is recorded only in `MOTIFER_MANUAL_REVIEW.md`, never surfaced as an automated safety claim |
| C11 motifer APPLICATION_INGRESS_INPUT confirmed, four-tag record intact | real `motifer@26.1.1` | flow confirmed; see Sec.3.1 for a real, disclosed `PACKAGE_API_INPUT` over-approximation observed at the same sink |
| C12 logify rerun under R04 | real `@rasla/logify` (48,100-call CPG) | of 68 real sites, exactly 1 (line 1521, the vendored `ms` package's own exported function) is now `PACKAGE_API_INPUT` reachable |

### 3.1 Two new, real, disclosed limitations found during real-package reruns

Neither is a code bug to fix under this revision's scope -- both are disclosed
here rather than silently promoted or silently hidden.

1. **Closure-capture over-approximation, motifer.** The real batched R04 rerun flags
   motifer's own `express` parameter as a `PACKAGE_API_INPUT` source reaching the
   sink alongside the real `APPLICATION_INGRESS_INPUT` (`req.body`) flow. This is very
   likely a closure-capture-based dataflow over-approximation (lexical/closure
   proximity to the sink, not a genuine value-flow from `express`'s own call site) --
   shown in C11's own `external_input_families` list, never silently promoted as an
   additional genuine candidate.
2. **`adjudicate_js.py`'s own narrative `origin_family` arbitrary-pick.** The frozen
   adjudicator's own narrative-summary field (`srcf[0][3]`) picks an *arbitrary first*
   row when a sink has flows from multiple families -- on motifer it picked
   `PACKAGE_API_INPUT` even though motifer's real, previously-established finding is
   `APPLICATION_INGRESS_INPUT`. This is the same "arbitrary first pick" defect class
   R03 already fixed at the producer layer, now found again at a different,
   out-of-scope, frozen layer. Worked around, not patched: `serialize_dos_r04.py`
   computes family membership independently from the new producer's own
   `source_facts.tsv` (`_families_at_line`), never trusting that narrative field.

Frozen implementation hashes:
```
b285bc5bab7cd1deb44668fe672593cf887cb2a963aab1faa8a7bca9c7d9e251  serialize_dos_r04.py
37b27b352d5e2b31f1be9d2c9a8ab20e22e33738dee1fefc6e57b0f17bc074b2  check_serialize_dos_r04.py
00d89d06760113b543dd8606a9b7d291fa6597936d51f50dbad917f82c61bf9c  producers/npm_public_export_sources_r04.sc
```

## 4. Post-freeze: earlier packages as development evidence, new blind draw

Per instruction, after R04 froze: motifer, mongo-logger, logify, and every earlier
package become development evidence (motifer and logify are additionally R04's own
regression/rerun controls, C10-C12 above; mongo-logger remains R02's valid negative,
unchanged -- zero serialization sites, nothing for R04 to add).

A new blind set was then mechanically selected, per instruction, specifically to
contain supported serializer sites and public exports. Procedure recorded in full
before any inspection: `study/BLIND_PACKAGE_SELECTION_R04.txt`. Same index formula
against a live npm registry search, a fourth distinct keyword
(`keywords:data-model`) from R01/R02/R03's own draws
(`express-middleware`/`request-logging`/`http-logger`). Two earlier keyword attempts
this round (`npm-package-utility`: 0 results; `validation-schema`: only 7 results,
too few for the `%20` index formula) were discarded, disclosed, before any package
was read.

**Index 15 -> `miniml@1.0.19`.** Tarball sha256-verified against a fresh fetch
(`841abae5149f3caf44a80927c833918c26282589b4e6c4c06c6c3167fe52f0d7`; registry
`dist.shasum` `4e1ec4fbc10515554a55a0043230767098692fdb`). A small (795-line), real,
`"type": "module"` ESM package (LookML-inspired YAML-to-SQL modeling language) --
`index.js` uses `export * from "./lib/x.js"` re-export syntax, confirming the ported
ESM desugaring path handles a real (not fixture-only) ESM package correctly.

Compiled cleanly. **Mechanical scan result**: `serialize_sinks.tsv` finds exactly
**one** real `JSON.stringify` call site (`command.js:44`, the CLI entrypoint's own
`catch (err) { ...JSON.stringify(err)... }` block). The R04 producer resolves **192**
`PACKAGE_API_INPUT` source candidates (22 exported functions' parameters + 5 exported
classes' `this`-fields, across every `lib/*.js` module) and **0**
`APPLICATION_INGRESS_INPUT` candidates (a CLI tool; no `req.body`-shaped pattern
anywhere in the compiled source). Of all 192 considered pairs against the one sink:
**zero** flow. `err` at `command.js:44` is the CLI script's own local caught-exception
variable -- not a parameter of any exported function or method, and not reachable
from any of the 192 real export-surface candidates. `source_facts.tsv` is empty (no
`ESTABLISHED` rows), matching the "skip when there's nothing to check" convention
already established for `r4-internal-only`/`r4-ambiguous-export`-shaped negatives.

**Result**: `crash_dos_classification = NO_SUPPORTED_EXTERNAL_INPUT_FLOW`,
`size_structure_dos_classification = NO_SUPPORTED_EXTERNAL_INPUT_FLOW`,
`external_input_families = []`, `reportable = false`. A genuine mechanical negative,
reported as found -- not a positive-path portability draw this round (unlike R03's
logify draw), since the package's one real serializer site never receives any
supported-family input by construction. Full evidence: `study/blind_r04_miniml/`
(crash-DoS raw facts) and `study/r04_miniml/` (R04 producer output).

Per instruction, "keep `reportable=false` until a new blind finding survives manual
review and its resource consequence is actually established" describes future work
beyond this round's mechanical selection + scan (which is what was required this
round) -- and is already structurally satisfied regardless: `reportable` is
unconditionally hardcoded `false` in `serialize_dos_r04.py` for every finding, this
one included.

## Claims boundary (unchanged)

Nothing in this document is an exploitability, severity, or impact claim.
`reportable=false` on every finding, throughout -- all 9 fixtures, motifer, logify,
and the miniml blind draw. Motifer's crash-safety adjudication (rejected, per manual
review) and its four-tag size/structure record are unchanged by this revision; the
real external body-parser bound remains recorded only in
`MOTIFER_MANUAL_REVIEW.md`, never as an automated safety claim.

## 5. Scope and next steps

Touched only `tchecker-research-complete/serialize-dos-r01/` (new files: the R04
producer, its gate, `serialize_dos_r04.py`, its gate, this document, and `study/`
evidence for the 9 fixtures + motifer/logify reruns + the miniml blind draw). No
ReDoS file was modified (`export_redos_npm_integ_r02.sc` remains byte-for-byte
frozen, read-only), no `gates/serialize_dos_verdict.py` or
`gates/gate_serialize_dos.py`, no other `tchecker-property-adjudicator` producer or
`adjudicate_js.py`, and no `semantic-bucket-pilot/scanner-v2` shared pipeline module
was modified.

Branch history per instruction: the finished ReDoS work
(`claude/aggregate-kinds-producer-test-03zs7n`) was merged into `develop`
(`a187700`) before this revision started, so this producer could reuse its final
public-export adapter. A fresh integration branch,
`feature/serialize-dos-r04-integration`, was created from that updated `develop` and
carries the three property-local R01-R03 commits (cherry-picked, not rebased) plus
this revision's own commit. `feature/serialize-dos-r01` itself was never rebased and
remains at its original `196d174`.

Shared corpus pipeline wiring (provenance/applicability/reachability/aggregation)
remains explicitly deferred, unchanged from every prior revision.
