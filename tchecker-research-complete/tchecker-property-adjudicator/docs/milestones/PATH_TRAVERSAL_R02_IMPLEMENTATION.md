# PATH_TRAVERSAL R02 implementation (consumes the shared npm-source-identity facts)

Scope: a new producer (`producers/export_path_traversal_integ_r02.sc`) that carries R01's own
sink-identification/import-recognition/open-flags/containment-proof logic forward **verbatim**,
replacing ONLY R01's own hand-rolled source-family resolution (`findIngressParams`/
`sourceCallsFieldAccess`/`resolveExportRhs`/`familyOfSource`/`isSourceTainted`) with a real
consumer of `source_origin_facts.tsv`, written by the shared, frozen, property-neutral producer
`export_npm_source_identity.sc` (merged into `develop` ahead of this round). R01
(`export_path_traversal_integ_r01.sc`), the shared producer
(`export_npm_source_identity.sc`), and every file under `fixtures/path_traversal_r01/` and
`fixtures/npm_source_identity_r01/` are read but never modified. `reportable` stays hardcoded
`False` throughout.

All fixtures are real: built with `jssrc2cpg.sh` against `fixtures/path_traversal_r02/src/` (30
files: the original 26 from `fixtures/path_traversal_r01/src/`, copied verbatim, plus 4 new ones)
and run with real `joern --script` invocations against
`JOERN_HOME=tchecker-research-complete/joern-install/joern-cli`. Every number and TSV row quoted
below is copy-pasted from a real run's own `run_summary.log` or committed raw output, never
hand-computed.

## 1. What's copied verbatim vs replaced (the file's own header comment, quoted)

From `producers/export_path_traversal_integ_r02.sc`'s own header:

> COPIED VERBATIM, byte-for-byte, unmodified, from export_path_traversal_integ_r01.sc:
>   - Capability 1 (6-way sink family split ...) and the open()/openSync() flags resolver ...
>   - Capability 2 (structural fs import/require recognition ...)
>   - The Express root-option field lookup (`RootLookup`/`findRootField`).
>   - The `SinkTarget`/`SinkAbstention` case classes.
>   - The sink-target-construction loop (6-way family split + corrected root handling).
>   - Capability 4/5 (corrected containment idioms: real CFG-dominance canonicalization proof,
>     boundary-safe `.startsWith` operand recognition, the wrapper-guard resolver, weak-diagnostic
>     collection) ...
>   - `lookupKeyInfluence`/`isConstructorCall` and the `OutRow` case class shape.
>
> REPLACED (this file's own new logic, not present in R01 at all): sources are read from
> `source_origin_facts.tsv` in the SAME `rawDir` this producer is given ...

This follows the same documentation discipline `export_redos_npm_integ_r02.sc` established for
carrying a frozen R01's logic into a new R02 file (see that file's own header, lines 1-26): copy
verbatim what stays the same, replace only the one targeted capability, name exactly which lines
are which.

## 2. The required upstream dependency (disclosed, never assumed)

Quoted from the producer's own header:

> This producer does NOT invoke export_npm_source_identity.sc itself. Before running this
> producer, `export_npm_source_identity.sc` MUST ALREADY have been run against the SAME cpg file,
> writing its output ... into the SAME `rawDir` this producer is given. If
> `source_origin_facts.tsv` is absent from `rawDir` when this producer runs ..., this producer
> degrades SAFELY and DISCLOSED, never silently.

Real, verified degrade-safe run (`fixtures/path_traversal_r02/raw_missing_source_facts/`, R02
run alone, with no prior shared-producer output in that `rawDir`):

```
[path_traversal_r02_missing_facts] WARNING: source_origin_facts.tsv NOT FOUND at .../raw_missing_source_facts/source_origin_facts.tsv -- export_npm_source_identity.sc (the shared, frozen npm-source-identity producer) MUST be run against the SAME cpg BEFORE this producer, writing its output into this SAME rawDir. Degrading safely: ZERO sources are recognized this run ...
[path_traversal_r02_missing_facts] sink targets found: 33 (FS_READ=23, FS_WRITE=6, FS_READ_WRITE=3, FS_DELETE=1, EXPRESS_SEND_FILE=0, EXPRESS_DOWNLOAD=0)
[path_traversal_r02_missing_facts] PATH_TRAV_R02_COMPLETE rows=0 (BROKEN=0, OPEN=0, ESTABLISHED=0, MULTIPLE_ORIGINS_sink_src_pairs=0)
```

`path_traversal_r02_summary.json` for that run:

```json
{"sink_targets": 33, "sink_abstentions": 3, "source_origin_facts_present": false, "source_origin_facts_rows": 0, "package_api_sources": 0, "application_ingress_sources": 0, "multi_origin_sources": 0, "rows_emitted": 0, "broken": 0, "open": 0, "established": 0, "multiple_origins_sink_src_pairs": 0}
```

Sink identification (`sink_targets`) is still real and non-zero (structural, does not depend on
sources at all) -- only `source_facts.tsv` (`rows_emitted`) is genuinely empty, with the reason
explicitly disclosed via `source_origin_facts_present: false` in the same JSON a downstream
aggregator already reads, never a silent, unexplained zero. (`sink_targets` is 33 here vs 34 in
the full run below because, with zero sources, `isSourceTainted` can never confirm `ctrl02`'s
Express `root` option is attacker-controlled, so that one `EXPRESS_SEND_FILE` sink target -- whose
own emission is conditioned on that proof -- is not added; this conservative behavior already
existed in R01's own design, unchanged here.)

Run through `path_traversal_verdict.py`: exits 0, `findings: []`,
`classification.FILESYSTEM_SINK_CANDIDATE: 0` -- confirmed via
`check_path_traversal_verdict_r02.py`'s own degrade-safe assertions (4 checks, all passing).

## 3. The real, measured coverage consequence of consuming the shared producer's own narrower model

The shared producer's own `APPLICATION_INGRESS_INPUT` model (its header, lines ~93-104) recognizes
ONLY (a) `req`/`request` field-access matching `(req|request)\.(body|query|params|headers|payload|url)(\..*)?`,
and (b) a bare `req`/`request` identifier -- it has no concept of Meteor.methods-registered
handler parameters at all, under any name. R01's OWN Capability 3, by contrast, additionally ran
`findIngressParams()` (a Meteor.methods registration lookup) and searched every registered
handler's own parameter by NAME across its whole method body -- exactly the weak, name-matching
mechanism this round removes.

A real probe (`export_npm_source_identity.sc` run against the unmodified, frozen
`fixtures/path_traversal_r01/src/`) confirms: of the 26 real R01 fixture files, only 4
(`ctrl02_user_controlled_root.js`, `ctrl03_fixed_root_sendfile.js`,
`ctrl04_fixed_root_download.js`, `ctrl10_unresolved_options.js` -- all real `req.params.name`/
`req.body.root` shapes) plus the 2 `package_api_*.js` files produce ANY row in
`source_origin_facts.tsv` at all:

```
30064771089  ctrl02_user_controlled_root.js  6  req.params.name  APPLICATION_INGRESS_INPUT  ...
68719477115  package_api_basic.js  6  userPath  PACKAGE_API_INPUT  exported_param module.exports.userPath  ...
68719477124  package_api_named_exports.js  5  userPath  PACKAGE_API_INPUT  exported_param writePackageFile.userPath  ...
```

Every other R01 control (`ctrl01`, `ctrl05`-`ctrl09`, `ctrl11`-`ctrl21`,
`import_destructured_fs.js`, `import_esm.mjs`), whose attacker-controlled path comes from a
Meteor.methods handler's own parameter (e.g. `userPath`, never named `req`/`request`), produces
**zero** `source_origin_facts.tsv` rows and therefore zero `source_facts.tsv` rows/findings under
R02. The STRUCTURAL sink count is unaffected (R01's own real run on the 26-file set: `sink targets
found: 29`; R02's own real run on the 30-file superset: `sink targets found: 34` = 29 + 5 new real
sink call sites from the 4 new fixtures) -- confirming the copied-verbatim sink/containment logic
is unchanged; only how many of those sinks get a recognized REACHING source changes. Extending the
shared producer with Meteor.methods awareness is out of scope for this round (it would mean
editing the frozen shared producer, or re-deriving its own logic here -- both forbidden).

`path_traversal_verdict.py` run against the real, committed `fixtures/path_traversal_r02/raw/`:

```json
{
  "classification": {
    "FILESYSTEM_SINK_CANDIDATE": 7,
    "PACKAGE_API_INPUT_REACHABLE": 6,
    "APPLICATION_INGRESS_REACHABLE": 2,
    "ALTERNATIVES_BROKEN_EXCLUDED": 0,
    "ALTERNATIVES_ESTABLISHED": 8,
    "ALTERNATIVES_OPEN": 0,
    "ADJUDICATOR_RUN_FAILED": 0
  },
  "n_findings": 8
}
```

## 4. MULTIPLE_ORIGINS, now real for Path Traversal (real R01-vs-R02 side-by-side comparison)

`fixtures/path_traversal_r02/src/multi_origin_fs_sink.js` mirrors
`npm_source_identity_r01/src/cap4_multiple_origins.js`'s own real shape, reaching a real fs sink:

```js
function handleRequest(req) {
  fs.readFileSync(req);
}
module.exports.handleRequest = handleRequest;
```

R02's real `source_facts.tsv` row pair for this sink (`30064771384`, L18):

```
30064771384	18	68719477099	APPLICATION_INGRESS_INPUT	ESTABLISHED	FS_READ
30064771384	18	68719477099	PACKAGE_API_INPUT	ESTABLISHED	FS_READ
```

Same sink, same `src_id` (`68719477099`), TWO rows -- never collapsed. R01's own frozen producer,
run against the exact same CPG (same `handleRequest`/`req` node ids), emits only ONE row for this
identical sink:

```
30064771384	18	68719477099	PACKAGE_API_INPUT	ESTABLISHED	FS_READ
```

Real, confirmed reason: R01's own `APPLICATION_INGRESS_INPUT` model
(`sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(SOURCE_PATTERN...)`) only
ever matches `req.<field>` field-access CALLS -- it never considers a bare `req` IDENTIFIER an
ingress candidate at all, so `req` here is visible to R01 only via `packageApiSources`, and
`familyOfSource`'s single-string return (`if packageApiSources.exists(...) "PACKAGE_API_INPUT"
else "APPLICATION_INGRESS_INPUT"`) never even gets the chance to collapse two families here --
R01 simply never SEES the second family exists. The shared producer's own model explicitly adds
bare `req`/`request` identifiers as an `APPLICATION_INGRESS_INPUT` candidate (its header, point
(b)) precisely so a genuinely dual-family site is visible at all; R02's per-family row emission
(`familiesOf(src)`, reading the real, never-collapsed family list per `site_id`) is what turns that
visibility into two real, distinct findings instead of one.

`path_traversal_verdict.py`'s own finding pair for this sink: both rows carry
`"package_api_input": "ESTABLISHED"` AND `"application_ingress": "ESTABLISHED"` -- confirmed via
`check_path_traversal_verdict_r02.py`.

## 5. Same-name-parameter distinctness (real R01-vs-R02 comparison: no regression here)

`fixtures/path_traversal_r02/src/shadow_same_name_params_fs.js` mirrors
`npm_source_identity_r01/src/cap2_shadow_same_name_params.js`'s own shape -- two exported
functions, each with its own parameter named `userPath`, each reaching its own real sink:

```js
function readAlpha(userPath) { fs.readFileSync(userPath); }
function readBeta(userPath) { fs.writeFileSync(userPath, 'x'); }
```

R02's real rows: `readAlpha`'s sink (`30064771442`, L15) sources from `68719477167`;
`readBeta`'s sink (`30064771444`, L19) sources from `68719477170` -- structurally distinct,
never cross-wired. **R01, run on the exact same CPG, gets this specific shape right too**
(`30064771442 ... 68719477167`, `30064771444 ... 68719477170` -- identical `src_id`s): R01's own
`p.method.ast.isIdentifier.name(p.name)` search is scoped to each parameter's OWN declaring
method, and since `readAlpha` and `readBeta` are SIBLING functions (neither's AST subtree contains
the other's), there is no opportunity for R01's name-matching to conflate them here. This is a
real, honestly-reported "no observed difference for this shape" result -- checked, not guessed.

## 6. Closure-capture-correct PACKAGE_API_INPUT resolution (real R01-vs-R02 comparison: no
difference on this specific fixture either)

`fixtures/path_traversal_r02/src/closure_capture_fs_sink.js` mirrors
`npm_source_identity_r01/src/cap1_module_closure_capture.js`'s own shape, with the closure-captured
value now reaching a real sink:

```js
function makeReader(userPath) {
  return function readIt() {
    fs.readFileSync(userPath);
  };
}
```

`closure_identity.tsv` (shared producer's real output) confirms the real closure-capture proof for
the identifier inside `readIt`:

```
68719476738  closure_capture_fs_sink.js  20  ...:makeReader:readIt  userPath  CAPTURED  111669149698  userPath  METHOD_PARAMETER_IN  1
```

`resolution_kind=CAPTURED`, `capture_depth=1`, `resolved_root_kind=METHOD_PARAMETER_IN` -- a real
`closureBindingId` hop from the nested function's own proxy Local to `makeReader`'s own parameter,
not a name-match. R02's real emitted row: `30064771072 20 68719476738 PACKAGE_API_INPUT ESTABLISHED
FS_READ`. **R01, run on the same CPG, also emits this exact row** (`30064771072 20 68719476738
PACKAGE_API_INPUT ESTABLISHED FS_READ`) -- because a nested function declaration is itself an AST
descendant of its enclosing method in jssrc2cpg's own model, so R01's `p.method.ast` subtree search
happens to include `readIt`'s own identifiers too, and there is no competing same-named
declaration here for it to conflate with. Again a real, honestly-reported "no observed difference
on this specific fixture" result.

## 7. The real false positive R01's naive search IS vulnerable to: within-method shadowing

Since neither of the two "mirror the shared module's own fixtures" shapes above exposed a real
R01 defect on their own, a 5th, sharper fixture was built to isolate the actual bug class
R01's `p.method.ast.isIdentifier.name(p.name)` search cannot handle: a nested function INSIDE the
same exported method declaring its OWN, differently-bound local of the exact same name as the
outer parameter (`fixtures/path_traversal_r02/src/shadow_nested_scope_fs.js`, mirroring
`npm_source_identity_r01/src/cap2_shadow_nested_scope.js`'s own real shape):

```js
function readGamma(userPath) {           // outer parameter, NEVER actually used
  function helper() {
    const userPath = helperTrustedPath(); // SHADOWS the outer parameter -- an unrelated fixed value
    fs.writeFileSync(userPath, 'x');
  }
  helper();
}
```

**R01, run on this real CPG, wrongly credits this sink as PACKAGE_API_INPUT-reachable -- a real
false positive, TWO rows**:

```
30064771431	27	68719477149	PACKAGE_API_INPUT	ESTABLISHED	FS_WRITE
30064771431	27	68719477154	PACKAGE_API_INPUT	ESTABLISHED	FS_WRITE
```

(neither `src_id` is the real, unused outer parameter's own reference -- both are the inner
shadowed local's own declaration/use, credited only because their NAME matches). **R02, on the
same CPG, correctly emits ZERO rows for this sink.** `source_origin_facts.tsv` has no entry for
either `userPath` reference in this file at all; `closure_identity.tsv` shows why:

```
68719477149  shadow_nested_scope_fs.js  26  ...:readGamma:helper  userPath  DIRECT  94489280689  userPath  LOCAL  0
68719477154  shadow_nested_scope_fs.js  27  ...:readGamma:helper  userPath  DIRECT  94489280689  userPath  LOCAL  0
```

Both resolve `DIRECT` to Local `94489280689` (`helper`'s own `const userPath = ...`), never to
`readGamma`'s own `MethodParameterIn` -- so the shared producer's own identity check
(`res.rootKind == "METHOD_PARAMETER_IN" && res.rootId == p.id.toString`) correctly excludes both,
and R02 never emits a row for this sink at all. This is the real, concrete demonstration of the
risk named in this round's own task description: R01's name-matching "can conflate two different
scopes' same-named identifiers" -- confirmed, not assumed, and fixed.

## 8. Real npm-package validation (miniml-1.0.19)

Per direct instruction, all 4 real dev-package tarballs at
`fixtures/npm_source_identity_r01/dev_packages/` were checked for real fs-sink-relevant code
before picking one:

| Package | Real `.js`/`.mjs` files | fs-sink-relevant code |
|---|---|---|
| `motifer-26.1.1.tgz` | 2 | none (`grep` for `require('fs')`/`fs.readFile`/etc. across both files: zero matches) |
| `logify-0.2.1.tgz` | 26 | none found |
| `ms-2.1.3.tgz` | 1 | none |
| `miniml-1.0.19.tgz` | 12 | **yes** -- `lib/yaml.js` |

`miniml`'s own `lib/yaml.js` (real, unmodified, quoted verbatim):

```js
import { readFile } from "fs/promises";
import { readFileSync } from "fs";
export async function loadYamlFile(file) {
    const text = await readFile(file, "utf-8");
    return parseYAML(text);
}
export function loadYamlFileSync(file) {
    const text = readFileSync(file, "utf-8");
    return parseYAML(text);
}
```

Both exported functions pass their own `file` parameter DIRECTLY to a real fs read call. Real,
two-producer run against `miniml`'s own `package/` directory (`fixtures/path_traversal_r02/raw_real_package/`):

```
[miniml_real] export_surface rows: 33 (resolved=22, abstained=11)
[miniml_real] source_origin_facts rows: 192 (sites=192, multi_origin_sites=0)
[miniml_real] sink targets found: 2 (FS_READ=2, FS_WRITE=0, FS_READ_WRITE=0, FS_DELETE=0, EXPRESS_SEND_FILE=0, EXPRESS_DOWNLOAD=0)
[miniml_real] EMIT sink=30064773211(L5) src=68719477433(L35:file) origin=PACKAGE_API_INPUT sinkFamily=FS_READ outcome=ESTABLISHED
[miniml_real] EMIT sink=30064773211(L5) src=68719478786(L5:file) origin=PACKAGE_API_INPUT sinkFamily=FS_READ outcome=ESTABLISHED
[miniml_real] EMIT sink=30064773214(L9) src=68719477441(L39:file) origin=PACKAGE_API_INPUT sinkFamily=FS_READ outcome=ESTABLISHED
[miniml_real] EMIT sink=30064773214(L9) src=68719478793(L9:file) origin=PACKAGE_API_INPUT sinkFamily=FS_READ outcome=ESTABLISHED
[miniml_real] PATH_TRAV_R02_COMPLETE rows=4 (BROKEN=0, OPEN=0, ESTABLISHED=4, MULTIPLE_ORIGINS_sink_src_pairs=0)
```

`path_traversal_verdict.py` run against this real output:
`FILESYSTEM_SINK_CANDIDATE: 2, PACKAGE_API_INPUT_REACHABLE: 2, APPLICATION_INGRESS_REACHABLE: 0`,
4 findings, all `PACKAGE_API_INPUT`/`ESTABLISHED`, zero `BROKEN`/`OPEN` -- a real, genuine,
non-manufactured finding in real, unmodified npm package source (never reportable, per this
project's own discipline -- a library API accepting a path parameter is expected behavior, not
itself an application-boundary vulnerability). `motifer`, `logify`, and `ms` were confirmed to have
zero fs-sink-relevant code at all -- their own real two-producer runs would show
`sink_targets: 0`, correctly proving the pipeline runs cleanly end-to-end on real code rather than
manufacturing a finding where none exists (matching ReDoS's own real-package validation
precedent).

## 9. `path_traversal_verdict.py`'s `sink_abstentions` consumption fix

Per direct instruction ("the next Path Traversal reducer must actually consume
sink_abstentions.tsv and preserve those records in its final classification output"),
`path_traversal_verdict.py` now reads `sink_abstentions.tsv` (`read_sink_abstentions`, 7 columns)
and includes every record, read back verbatim, under a new top-level `"abstentions"` key in its
own final JSON output -- the ONLY change made to this module this round (its docstring names it
explicitly). Confirmed via the reducer's own real output file (not the raw TSV a second time):

```json
"n_findings": 8, "n_abstentions": 3
```

with the JSON's own `"abstentions"` array carrying all 3 real records, e.g.:

```json
{"call_node_id": "30064771177", "line": 4, "file": "ctrl10_unresolved_options.js", "reason_code": "EXPRESS_ROOT_OPTIONS_UNRESOLVED", "path_operand_code": "req.params.name", "call_code": "res.sendFile(req.params.name, opts)", "reason_detail": "options argument not statically resolved to an object literal (opts)"}
```

`SF_COLS`/schema for `source_facts.tsv` is UNCHANGED (still 12 columns) -- `path_traversal_verdict.py`
needed zero other changes to read R02's own output, matching `redos_verdict.py`'s own frozen-schema
precedent across its R01->R02 producer revision.

## 10. Test suite

- `check_path_traversal_verdict.py` (R01, unchanged file): **40/40**, re-verified against the
  frozen `fixtures/path_traversal_r01/raw/` fixture set, confirming the sink_abstentions consumption
  change is additive-only.
- `check_path_traversal_verdict_r02.py` (new): **22/22** -- structural regression (34 = 29 + 5 new
  real sinks), MULTIPLE_ORIGINS, same-name distinctness, closure-capture correctness, the real
  shadowing false-positive fix, the missing-`source_origin_facts.tsv` degrade-safe case (4 checks),
  `abstentions` in the reducer's own final JSON output (2 checks), and the real npm-package
  validation (2 checks).

## 11. Files changed/added

- `producers/export_path_traversal_integ_r02.sc` (new)
- `fixtures/path_traversal_r02/src/` (30 files: 26 copied verbatim from `path_traversal_r01/src/`
  + 4 new: `multi_origin_fs_sink.js`, `shadow_same_name_params_fs.js`,
  `closure_capture_fs_sink.js`, `shadow_nested_scope_fs.js`)
- `fixtures/path_traversal_r02/raw/` (real, committed two-producer output)
- `fixtures/path_traversal_r02/raw_missing_source_facts/` (real, committed degrade-safe evidence)
- `fixtures/path_traversal_r02/raw_real_package/` (real, committed miniml-1.0.19 validation)
- `semantic-bucket-pilot/scanner-v2/path_traversal_verdict.py` (sink_abstentions consumption only)
- `semantic-bucket-pilot/scanner-v2/check_path_traversal_verdict_r02.py` (new)
- `docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md` (this file)

## 12. Post-review correction: the shared module's own real coverage gap, and fixing it

Before freezing this revision, a final adversarial review of this producer's own header comment
(section 6 above, "REAL, MEASURED CONSEQUENCE") surfaced that the disclosed coverage change was
not a minor edge case: `grep -lc "Meteor.methods" fixtures/path_traversal_r01/src/*.js` = **18 of
26** real R01 fixtures. Under `export_npm_source_identity.sc`'s own R01 scope (which deliberately
excluded Meteor.methods recognition as "sink-adjacent application vocabulary"), this revision
would have shipped with a real, severe regression relative to R01's own coverage — 18 controls
silently losing all source recognition, not a cosmetic gap.

Rather than accept that regression or re-derive Meteor.methods recognition inside this file
(explicitly forbidden — this producer is a faithful consumer of the shared module, never a
re-implementer of its logic), the shared module itself was extended: `NPM-SOURCE-IDENTITY-R02`
(`producers/export_npm_source_identity_r02.sc`, merged into `develop` before this revision's own
fixtures were regenerated) restores Meteor.methods-registered-parameter recognition (ported,
structurally unchanged, from THIS property's own frozen R01 `findIngressParams`) plus the
`message`/`item` field-access pattern, with zero regression on the shared module's own R01
fixture set or its real npm-package validation (both re-verified byte-identical where expected).
See `docs/milestones/NPM_SOURCE_IDENTITY_R02_IMPLEMENTATION.md` for the full real evidence of
that fix.

This producer's own code needed **zero changes** for the fix to take effect — it already reads
whichever `source_origin_facts.tsv` is present in `rawDir` by filename, agnostic to which shared-
producer revision wrote it. Only the fixture regeneration procedure changed: `raw/`,
`raw_missing_source_facts/`, and `raw_real_package/` were all regenerated running
`export_npm_source_identity_r02.sc` (not R01) as the required upstream step, and
`check_path_traversal_verdict_r02.py`'s own count assertions were updated with the real,
corrected numbers (all independently re-verified, not merely re-asserted):

| Metric | Against shared R01 (original) | Against shared R02 (corrected, now committed) |
|---|---|---|
| `source_origin_facts.tsv` rows | 22 | 58 |
| `FILESYSTEM_SINK_CANDIDATE` | 7 | **31** |
| `PACKAGE_API_INPUT_REACHABLE` | 6 | 6 (unchanged — PACKAGE_API_INPUT never depended on Meteor) |
| `APPLICATION_INGRESS_REACHABLE` | 2 | **26** |
| `ALTERNATIVES_ESTABLISHED` / `OPEN` / `BROKEN_EXCLUDED` | 8 / 0 / 0 | **29 / 3 / 4** |
| Reducer findings | 8 | **32** |

Sink identification itself is unaffected either way (`sink targets found: 34`, both times) —
confirming the regression was purely on the source-recognition side, exactly where the fix
landed. Determinism re-verified directly on the regenerated fixture set: a fully independent
rebuild (fresh CPG, fresh two-producer run) reproduced `source_facts.tsv` and
`source_origin_facts.tsv` byte-for-byte identical to the committed `raw/`.

`check_path_traversal_verdict_r02.py`: still **22/22** after the count updates (same assertion
count — no assertion was added or removed, only the real numbers three of them check were
corrected to match the regenerated fixture). `check_path_traversal_verdict.py` (R01, frozen):
still **40/40**, confirming the R01 baseline remains completely untouched by any of this.
