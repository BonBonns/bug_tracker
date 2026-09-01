# NPM-SOURCE-IDENTITY-R01: property-neutral npm source identity infrastructure

New, shared, property-neutral infrastructure that a currently-frozen Path Traversal branch
(`feature/path-traversal-r01`) and a Serialize-DoS branch (`feature/serialize-dos-r01`) will
consume LATER by reading its output facts (TSV/manifest rows) -- never by importing its logic.
This round touched neither branch and did not merge into `develop`.

## What was built

- **New Scala producer**: `producers/export_npm_source_identity.sc` -- emits `export_surface.tsv`,
  `closure_identity.tsv`, `source_origin_facts.tsv`. Full schema documented as a header comment in
  the file itself (the same convention every other producer in this directory uses).
- **New Python module**: `semantic-bucket-pilot/scanner-v2/npm_source_identity.py`.
- **New fixtures**: `fixtures/npm_source_identity_r01/src/` (14 synthetic files), `raw/` (real,
  frozen Joern output for that synthetic set), `raw_real_packages/` (real, frozen Joern output for
  the real motifer+logify+miniml+ms combined run). `dev_packages/` (the 4 real npm tarballs) were
  already staged and untouched.
- **New regression suite**: `semantic-bucket-pilot/scanner-v2/check_npm_source_identity.py` --
  **37/37 PASS**.
- **One additive change** to `vendored_attribution.py` (see "vendored_attribution.py change"
  below) -- everything else read-only.

Nothing under `producers/` other than the one new file was modified. `provenance.py` was not
modified at all (import-only). `study/redos_npm/` was not touched. Neither frozen branch was
checked out.

## Grounding (read before writing anything, per direct instruction)

- `export_redos_npm_integ.sc`'s `resolveExportRhs` / `exportAssigns` dispatch -- CommonJS +
  ESM export-surface resolution baseline, re-derived (not imported) in property-neutral form.
- `export_redos_npm_integ_r02.sc`'s class-export / object-literal-shorthand capabilities --
  reused conceptually; its OWN `resolvePatternR02`/`walkUp` (a `Method.astParent`-chain
  name-matching approximation) was explicitly NOT reused, per direct instruction.
- `export_fail_open_candidates.sc`'s `exactHandlerDefinition` -- the one genuinely CPG-native
  closure-capture resolver in this repo (`refsTo`/`closureBindingId`/`ClosureBinding`). This
  round's own `resolveClosureIdentity` is a NEW, GENERALIZED version of that exact technique (see
  "Two real generalizations over `exactHandlerDefinition`" below).
- `provenance.py`'s `sha256_hex`/`compute_source_tree_sha256`/`classify_vendored_hint`/
  `build_source_manifest` -- imported and reused verbatim.
- `vendored_attribution.py` (whole file) -- `attribute_finding`/`aggregate_vendored_dedup` reused;
  one additive parameter added (see below).
- `export_sourcefact.sc`'s `multi_origin`/`origin_count` denormalized-column precedent, reused as
  design precedent (not code) for `source_origin_facts.tsv`.
- `redos_verdict.py`'s "producer emits a flat TSV, consumer groups it directly" convention, reused
  for `npm_source_identity.py`'s own `families_by_site`.
- `study/redos_npm/r02_fixtures/README.md` -- read; no filename reused, no fixture modified.

## Real, empirical CPG evidence gathered BEFORE writing the resolver (Joern probes, quoted verbatim)

All probes were run against `$JOERN_HOME/jssrc2cpg.sh`-built CPGs of the real dev-package
tarballs (`motifer-26.1.1`, `logify-0.2.1`, `miniml-1.0.19`, `ms-2.1.3`, extracted and combined
into one source root) and of this round's own synthetic fixtures, via throwaway `joern --script`
probes (not committed -- scratchpad only, per this project's own established convention).

### Two real generalizations over `exactHandlerDefinition`

**(a) `closureBindingId` can chain through MORE THAN ONE proxy `Local` before reaching the true
origin.** `exactHandlerDefinition` follows exactly one hop
(`direct.closureBindingId.toList.flatMap { cbid => ... }`). A real probe against motifer's own
2-level-nested closure (an arrow function passed to `express.use(...)`, itself nested inside
`ExpressLoggerFactory`) showed:

```
cb closureBindingId=Some(motifer/index.js::program:<lambda>15:logger) refOut=List((94489281129,logger,<iterator>))
cb closureBindingId=Some(motifer/index.js::program:<lambda>15:<lambda>16:logger) refOut=List((94489281204,logger,<iterator>))
```

The INNER lambda's own proxy Local's `ClosureBinding._refOut` resolves to ANOTHER proxy Local
(`94489281204`, itself still carrying its own `closureBindingId`), not directly to the module-scope
origin (`94489281129`). A synthetic 3-level fixture (`cap1_two_level_nested_capture.js`,
`makeOuter -> outer -> inner`) confirmed the full chain directly:

```
=== chain for counter proxy in inner() (94489280537) ===
  hop0: local id=94489280537 ... method=...makeOuter:outer:inner closureBindingId=Some(...:inner:counter)
    -> ClosureBinding(s) for ...inner:counter: refOut count=1 ids=List(94489280538)
  hop1: local id=94489280538 ... method=...makeOuter:outer     closureBindingId=Some(...:outer:counter)
    -> ClosureBinding(s) for ...outer:counter: refOut count=1 ids=List(94489280539)
  hop2: local id=94489280539 ... method=...makeOuter            closureBindingId=Some(...:makeOuter:counter)
    -> ClosureBinding(s) for ...makeOuter:counter: refOut count=1 ids=List(94489280534)
  hop3: local id=94489280534 ... method=...program                closureBindingId=None
```

`resolveClosureIdentity`'s own `closureBindingRoot` therefore walks the chain RECURSIVELY until
`closureBindingId` is `None`, with a depth guard (64) and a cycle guard, never stopping after one
hop.

**(b) A captured FUNCTION PARAMETER's own `ClosureBinding._refOut` resolves DIRECTLY to a
`MethodParameterIn` node, never a proxy `Local`.** `exactHandlerDefinition`'s own
`_refOut.collect { case l: nodes.Local => l }` silently drops this case. A direct probe against a
minimal `function handler(req) { return function inner(){ return req.body; }; }` fixture:

```
local id=94489280515 closureBindingId=Some(x.js::program:handler:inner:req) method=Some(x.js::program:handler:inner)
param id=111669149698 method=x.js::program:handler
cb closureBindingId=Some(x.js::program:handler:inner:req) refOut=List((111669149698,METHOD_PARAMETER_IN))
```

`resolveClosureIdentity`'s own root type is therefore `Local` OR `MethodParameterIn`, matched
explicitly at every step of the chain-walk (never only `Local`).

### Real evidence for `req`/`request` `refsTo` resolving DIRECTLY to distinct `MethodParameterIn`s

```
=== cap2_shadow_same_name_params.js: req identifiers + refsTo ===
id=68719476795 method=handleAlpha line=Some(6) refsTo=List((111669149720,METHOD_PARAMETER_IN))
id=68719476796 method=handleBeta line=Some(10) refsTo=List((111669149722,METHOD_PARAMETER_IN))
```

Two different exported functions' own identically-named `req` parameters resolve to two different
real `MethodParameterIn` node ids -- confirming requirement 2 (shadowing/same-name distinctness)
structurally, from `refsTo` identity alone, with no name-matching involved anywhere in the
resolution path.

### Real evidence for `module.exports = require(...)`-shaped re-export desugaring (miniml)

`miniml-1.0.19`'s own real `index.js` is `export * from "./lib/common.js"; export * from
"./lib/load.js"; export * from "./lib/query.js";`. A real probe of its own desugared AST:

```
CALL id=30064772406 code=var _common.js = require("./lib/common.js")
CALL id=30064772408 code=exports.common.js = _common.js
```

Two things had to be discovered and handled, both confirmed by this probe:
1. The desugared export target is `exports.common.js` -- a `<operator>.fieldAccess` whose OWN
   `FieldIdentifier` text contains a literal dot (`"common.js"`, taken directly from the imported
   module's own filename). `export_redos_npm_integ.sc`'s own frozen `namedExportLhs` regex
   (`^(module\.exports|exports)\.[A-Za-z_$][A-Za-z0-9_$]*$`) does NOT match this (dots are not a
   valid identifier character) -- so a producer built on that regex would silently DROP this
   export target entirely (not abstain -- never even see it). `export_npm_source_identity.sc`'s
   own export-assignment matcher was broadened to detect ANY `fieldAccess`/`indexAccess` whose
   receiver is `module.exports`/`exports`, structurally (not by validating the field name is a
   clean identifier), so this shape is seen and honestly abstained rather than silently missed.
2. The RHS (`_common.js`) is an identifier whose own (and ONLY) assignment's RHS is a `require(...)`
   Call, never a `MethodRef` -- resolved via this round's own identity-based
   `resolveIdentifierTarget` (using `resolveIdentity`'s real root, not text-matching) into the
   distinctly-labeled `REEXPORT_UNRESOLVED` abstention, rather than the generic
   `UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT`.

## Requirement-by-requirement regression evidence

### 1. Closure captures via real `refsTo`/`closureBindingId`/`ClosureBinding` identity

Synthetic (`fixtures/npm_source_identity_r01/raw/closure_identity.tsv`):

```
68719476757  cap1_module_closure_capture.js   9  ...configure    handlerState  CAPTURED  94489280525 handlerState LOCAL 1
68719476759  cap1_module_closure_capture.js  16  ...useState      handlerState  CAPTURED  94489280525 handlerState LOCAL 1
68719476771  cap1_two_level_nested_capture.js 17 ...makeOuter:outer:inner counter CAPTURED 94489280532 counter LOCAL 3
```

Both `configure()` and `useState()` (two DIFFERENT top-level functions) resolve `handlerState` to
the SAME real root Local -- never re-derived by name, always by identity. The 3-level nested case
resolves with `capture_depth==3`, the real chain-walk depth, matching the probe above.

Real (`fixtures/npm_source_identity_r01/raw_real_packages/closure_identity.tsv`, motifer-26.1.1):

```
68719480482 motifer/index.js  19 ...program                    logger DIRECT   94489281600 logger LOCAL 0
68719480070 motifer/index.js  32 ...program:LoggerObject        logger CAPTURED 94489281600 logger LOCAL 1
68719480212 motifer/index.js 128 ...program:LoggerFactory       logger CAPTURED 94489281600 logger LOCAL 1
68719480267 motifer/index.js 191 ...program:<lambda>15:<lambda>16 logger CAPTURED 94489281600 logger LOCAL 2
68719480325 motifer/index.js 198 ...program:ExpressLoggerFactory logger CAPTURED 94489281600 logger LOCAL 1
```

The real module-scope `let logger = null;` (line 19) is `DIRECT`; every real read from a nested
function (`LoggerObject`, `LoggerFactory`, the 2-level-nested `express.use(...)` callback,
`ExpressLoggerFactory`) is `CAPTURED`, ALL resolving to the SAME real root Local `94489281600` --
including the real 2-level chain, confirming the recursive generalization on genuine, unmodified
real-world code, not only a synthetic fixture.

**AMBIGUOUS** (never guessed): `ambiguous_closure_reassignment.js` reassigns `RE` twice at module
scope before a nested closure reads it:

```
68719476736 ...outer:inner RE AMBIGUOUS  MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL
68719476740 ...program     RE AMBIGUOUS  MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL
68719476742 ...program     RE AMBIGUOUS  MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL
```

`resolveIdentity` first resolves `RE`'s own real identity via the SAME `refsTo`/closure-chain
machinery (never text-matching), THEN checks -- using `refsTo` identity again, not name matching
-- whether more than one assignment targets that EXACT resolved Local. Two live assignments ->
abstain, never pick "the first" or "the last."

### 2. Lexical shadowing / same-name parameters kept distinct

`cap2_shadow_same_name_params.js` -- `handleAlpha(req)` and `handleBeta(req)`, two different
exported functions, each with its own `req` parameter:

```
68719476793 ...handleAlpha req DIRECT 111669149720 req METHOD_PARAMETER_IN 0
68719476794 ...handleBeta  req DIRECT 111669149722 req METHOD_PARAMETER_IN 0
```

Different real `MethodParameterIn` ids -- never conflated.

`cap2_shadow_nested_scope.js` -- module-scope `label` vs. an inner-scope, same-named `label`
declared inside `describeInner`:

```
68719476781 ...describeOuter          label CAPTURED 94489280542 label LOCAL 1   (outer, module-scope root)
68719476782 ...describeInner:nested    label CAPTURED 94489280541 label LOCAL 1   (inner, describeInner's OWN root)
```

Different real roots -- the nested closure's own read of `label` resolves to `describeInner`'s own
inner declaration, never falling back to the unrelated, same-named module-scope one.

Real (motifer vs. logify, in ONE combined CPG): motifer's own module-scope `logger`
(root `94489281600`) and logify's own two, completely unrelated `logger`
bindings -- `dist/index.js`'s `Logger.prototype.child()` local (`94489280655`) and
`plugin/event.js`'s own `init(logger)` parameter (`111669149787`, a THIRD, `METHOD_PARAMETER_IN`
case) -- are three real, structurally distinct CPG nodes, confirmed directly (not merely assumed
because the files differ):

```
=== logify logger closure identity ===
68719477134 logify/index.js       130 ...<lambda>0:value logger DIRECT 94489280655 logger LOCAL              0
68719477498 logify/plugin/event.js 15 ...program:init    logger DIRECT 111669149787 logger METHOD_PARAMETER_IN 0
```

### 3. Deterministic `origin_families`

All three output files are sorted before writing using stable, id-derived keys
(`export_surface.tsv` by `(file, line, export_id)`; `closure_identity.tsv` by `identifier_id` as a
`Long`; `source_origin_facts.tsv` by `(site_id as Long, origin_family)`) -- never Scala `Set`/`Map`
iteration order.

Verified directly: the producer was run TWICE against the SAME synthetic-fixture CPG
(`synth.cpg.bin`), writing to two separate raw dirs, then diffed:

```
$ diff raw_synth1/export_surface.tsv raw_synth2/export_surface.tsv && echo "export_surface IDENTICAL"
export_surface IDENTICAL
$ diff raw_synth1/closure_identity.tsv raw_synth2/closure_identity.tsv && echo "closure_identity IDENTICAL"
closure_identity IDENTICAL
$ diff raw_synth1/source_origin_facts.tsv raw_synth2/source_origin_facts.tsv && echo "source_origin_facts IDENTICAL"
source_origin_facts IDENTICAL
$ md5sum raw_synth1/*.tsv raw_synth2/*.tsv
953f98ccade5704e0b65347a9b4978fe  raw_synth1/closure_identity.tsv
efc1299d4f588fdc24a01d2d31cd6caf  raw_synth1/export_surface.tsv
2a06f7866f6d83e6b11a38d4a0e95345  raw_synth1/source_origin_facts.tsv
953f98ccade5704e0b65347a9b4978fe  raw_synth2/closure_identity.tsv
efc1299d4f588fdc24a01d2d31cd6caf  raw_synth2/export_surface.tsv
2a06f7866f6d83e6b11a38d4a0e95345  raw_synth2/source_origin_facts.tsv
```

Byte-for-byte identical, both runs. `check_npm_source_identity.py` additionally re-verifies this
structurally on every run (both the committed synthetic fixture AND the real
motifer/logify/miniml/ms output, 3329 `closure_identity.tsv` rows) by asserting the `identifier_id`
column is strictly non-decreasing -- a real, cheap regression check that a future edit breaking
the sort would fail immediately, without needing Joern.

### 4. `MULTIPLE_ORIGINS` -- never collapsed to one

`cap4_multiple_origins.js`: `function handleRequest(req) { return req; }`, exported. The bare
`req` reference is simultaneously (a) a `PACKAGE_API_INPUT` candidate (a reference to this
package's own exported-function parameter) and (b) an `APPLICATION_INGRESS_INPUT` candidate (bare
`req`/`request` naming convention):

```
68719476803 cap4_multiple_origins.js 8 req APPLICATION_INGRESS_INPUT bare req/request identifier reference true 2
68719476803 cap4_multiple_origins.js 8 req PACKAGE_API_INPUT         exported_param handleRequest.req      true 2
```

Same `site_id` (`68719476803`), TWO rows, `multi_origin=true`, `origin_count=2` denormalized onto
BOTH -- never collapsed to one, and a consumer reading either row alone already knows a second
family exists (never needs a second pass, per `export_sourcefact.sc`'s own precedent).

Negative control (`cap4_single_origin_control.js`, `handlePayload(payload)` -- a name that matches
neither ingress convention): exactly one row, `multi_origin=false`, `origin_count=1` -- the
machinery does not over-fire.

### 5. Canonical source paths and content hashes

`npm_source_identity.build_js_source_manifest` is a thin wrapper over
`provenance.build_source_manifest` (imported, never reimplemented -- `npm_source_identity.py`'s own
`sha256_hex`/`compute_source_tree_sha256`/`classify_vendored_hint` are literally
`provenance.py`'s own function objects, confirmed by identity in `check_npm_source_identity.py`:
`nsi.sha256_hex is provenance.sha256_hex` -- PASS). `lookup_source_fact` joins a raw-output row's
own real `file` field (confirmed real, Joern-native paths throughout this round's own committed
raw output -- e.g. `motifer/index.js`, `miniml/lib/dialect.js`) to that manifest, fails CLOSED
(`resolved=False`, a real, disclosed reason) for a path the manifest never saw, and supports an
optional `strip_prefix` for the real "one combined multi-package CPG root" convention this round's
own real-package regression run itself used.

### 6. Package-owned vs. vendored attribution

`vendored_attribution.attribute_finding` is called UNCHANGED, directly, against JS-finding dicts
whose own `provenance` sub-dict is built by `npm_source_identity.make_finding` from
`lookup_source_fact`'s own real output. `check_npm_source_identity.py`'s own synthetic
two-package/vendor scenario: a `PACKAGE_OWNED_HINT` finding is left completely untouched (no
`vendored_attribution` key attached at all); a `VENDORED_HINT` finding under `vendor/somelib/...`
is attributed `{"status": "ATTRIBUTED", "vendored_library_id": "somelib", "attribution": "somelib
as bundled by pkg-alpha"}` -- both PASS.

### 7. Vendored-code deduplication while retaining each package's own exposure

Same synthetic scenario, two packages (`pkg-alpha`, `pkg-beta`) each bundling a byte-identical
`vendor/somelib/shared.js`: `aggregate_vendored_dedup` (called via
`attribute_and_dedup_by_package`) collapses the two real occurrences to exactly ONE deduplicated
bucket (`len(buckets) == 1`), whose own `packages` field is `["pkg-alpha", "pkg-beta"]` -- BOTH
retained, never dropped -- with `raw_exposure_count == 2` preserving the real pre-dedup exposure
count alongside the deduplicated count (`summarize()` returns
`{"deduplicated_count": 1, "raw_exposure_count": 2}`, the two numbers never collapsed into one).

## `vendored_attribution.py` change (the only file outside this round's own new files that was
touched)

**What**: added one optional parameter, `keys=None`, to `aggregate_vendored_dedup`. When omitted
(every existing C/C++ caller), `scan_keys = ALL_FINDING_KEYS` -- byte-identical to the function's
prior, unparameterized behavior. When passed (this round's own `npm_source_identity.py`, via
`attribute_and_dedup_by_package`, passing `keys=(NPM_SOURCE_IDENTITY_FINDING_KEY,)`), the function
scans that key instead.

**Why it was necessary** (the zero-change path was tried FIRST, per direct instruction):
`attribute_finding(finding, package_name)` required ZERO changes -- it already operates on a
single finding dict + a package name string, with no dependency on `ALL_FINDING_KEYS` at all, and
`check_npm_source_identity.py`'s own CAP6 assertions call it completely unmodified.
`aggregate_vendored_dedup(records)`, however, was hard-coded (`out = {k: {} for k in
ALL_FINDING_KEYS}` and the scan loop `for key in ALL_FINDING_KEYS`) to only ever read the nine
C/C++-only keys named in that tuple (`r04_findings`, `oob_write_candidates`, etc.) -- a record
whose own findings live under a JS/npm-shaped key (`npm_source_identity_findings`, which is not
and should never become one of those nine names) would be silently skipped by every existing call
site with no way to opt in. This is exactly the "truly hard-coded" case the task's own
investigation prompt anticipated, so the smallest possible additive fix was made instead of
re-deriving a parallel dedup implementation.

**Verified non-regression**: `check_vendored_attribution.py` (the existing C/C++ frozen-fixture
regression suite for this exact file) still passes **16/16**, unmodified, after this change --
confirmed by running it after the edit:

```
$ python3 check_vendored_attribution.py 2>&1 | tail -3
PASS two distinct real sites in the SAME vendored file (different line+call) stay TWO separate deduplicated entries
VENDOR_ATTR_R01_CONTROLS=16/16
```

`check_npm_source_identity.py` additionally asserts the new parameter's own default (`keys=None`)
still yields the untouched `ALL_FINDING_KEYS` bucket shape for a record carrying none of this
round's own keys.

## Real npm package validation summary (motifer + logify + miniml + ms, one combined CPG)

```
[real_packages] export_surface rows: 81 (resolved=48, abstained=33)
[real_packages] closure_identity rows: 3329 (DIRECT=2834, CAPTURED=375, AMBIGUOUS=120, UNRESOLVED=0)
[real_packages] source_origin_facts rows: 317 (sites=317, multi_origin_sites=0)
[real_packages] NPM_SOURCE_IDENTITY_COMPLETE export_rows=81 identity_rows=3329 origin_rows=317
```

(Real wall-clock time for this run against the combined ~40-file, 4-package CPG: ~15s.)

- **motifer-26.1.1**: `module.exports = { LoggerFactory, ExpressLoggerFactory, Logger, ApmFactory
  }` -- 3 plain functions RESOLVED, `Logger`'s own constructor honestly ABSTAINED
  (`CLASS_CONSTRUCTOR_NOT_PUBLIC_API`), `Logger.prototype.getLogger` RESOLVED as the class's real
  public API surface. Module-scope `logger`/`serviceName`/`expressApp`/`apmClient` closures
  resolved throughout (see requirement 1 above).
- **logify-0.2.1**: Babel-transpiled `dist/` output (`main: "dist"`) -- every file's own
  `exports["default"] = X` (the real Babel ESM->CJS desugaring) RESOLVED; every file's own
  trailing `module.exports = exports["default"]` (a real, redundant Babel re-assignment idiom)
  honestly ABSTAINS `UNRESOLVED_RHS_SHAPE` (the RHS is an `indexAccess` expression, not a
  `MethodRef`/`Identifier`/`Block`/`require()` call -- a real, disclosed scope boundary: this
  producer does not chase an alias THROUGH a second `exports["default"]` read, but the underlying
  symbol is already correctly captured by the FIRST, real assignment either way, so no real
  export-surface coverage is lost in practice).
- **miniml-1.0.19**: a genuine ESM package (`"type": "module"`) whose own `index.js` is a 3-hop
  re-export chain (`export * from "./lib/common.js"; ...`). All 6 real re-export lines (across
  `index.js` and `lib/index.js`) honestly ABSTAIN `REEXPORT_UNRESOLVED` -- a real, distinctly
  labeled abstention, never a silent gap, per the task's own explicit scope discipline for this
  shape. Its own 15+ real named function exports (`validateSqlExpression`, `loadYamlFile`,
  `renderQuery`, `extractFieldReferencesFromNode`, ...) RESOLVED normally, alongside 4 honestly
  ABSTAINED class constructors (`SqlValidationError`, `UnsafeConstructError`,
  `UnknownColumnError`, `ComplexityLimitError`, each `CLASS_CONSTRUCTOR_NOT_PUBLIC_API`).
- **ms-2.1.3**: minimal positive control, `module.exports = function (val, options) {...}` RESOLVED
  directly.

A practical, non-obvious infrastructure finding along the way: `jssrc2cpg` ignores a directory
literally named `dist` by default (confirmed: `jssrc2cpg.sh -o x.cpg.bin real_src/logify` -- with
`logify`'s own source physically inside a `dist/` subdirectory -- produced a CPG with **zero**
parsed files; pointing `jssrc2cpg` directly at `real_src/logify/dist` parsed all 21 real files).
The real combined-package CPG used for this round's own `raw_real_packages/` evidence copies
`logify`'s own `dist/` CONTENTS directly into a `logify/` directory at the combined root (not
`logify/dist/...`) to work around this, which is also exactly why `npm_source_identity.py`'s own
`lookup_source_fact` needs (and has) a `strip_prefix` parameter -- a single package's own manifest,
built by walking that package's OWN pkg_dir, and a combined multi-package CPG's own real file-path
convention are not automatically the same relpath space.

## Regression suite

```
$ python3 check_npm_source_identity.py 2>&1 | tail -1
NPM_SOURCE_IDENTITY_R01=37/37
```

## `git status --short` (this round's own changes only)

```
?? semantic-bucket-pilot/scanner-v2/check_npm_source_identity.py
?? semantic-bucket-pilot/scanner-v2/npm_source_identity.py
?? tchecker-research-complete/tchecker-property-adjudicator/docs/milestones/NPM_SOURCE_IDENTITY_R01_IMPLEMENTATION.md
?? tchecker-research-complete/tchecker-property-adjudicator/fixtures/npm_source_identity_r01/
?? tchecker-research-complete/tchecker-property-adjudicator/producers/export_npm_source_identity.sc
 M semantic-bucket-pilot/scanner-v2/vendored_attribution.py
```

No file under `producers/` other than the one new producer was touched. `provenance.py` was not
modified. Nothing under `study/redos_npm/` was touched. Neither `feature/path-traversal-r01` nor
`feature/serialize-dos-r01` was checked out or read. `develop` was not merged into. All Joern
`workspace/` side-effect directories were removed before this doc was written.
