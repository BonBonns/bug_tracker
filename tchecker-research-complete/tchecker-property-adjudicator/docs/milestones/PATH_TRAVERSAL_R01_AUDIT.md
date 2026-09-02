# PATH_TRAVERSAL R01 audit (read-only, execution-verified)

Scope: `tchecker-research-complete/tchecker-property-adjudicator/` Path Traversal
(`ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION`) implementation only. This is an audit, not a
change: nothing in the repo was modified. All evidence below comes from a REAL Joern run
performed during this audit (CPG built via `jssrc2cpg.sh`, producers run via `joern
--script`), plus direct reading of the real source files. No claim here is taken from the
milestone docs without being checked against the real code/output.

## Environment / run setup

- `JOERN_HOME=/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli`
  (confirmed present, with `jssrc2cpg.sh` and `joern`), matching the invocation pattern used
  by `semantic-bucket-pilot/scanner-v2/study/redos_npm/pilot25/run_pilot25.py` and by
  `tchecker-property-adjudicator/recovered/serialize-dos-snapshot-2026-08-23/run.sh`.
- No runner script exists specifically for path-traversal (`grep -rn "path_traversal"
  --include='*.sh' --include='*.py'` across `tchecker-research-complete` found only an
  unrelated hit in `verification/verify_files.sh`). The invocation was therefore built by
  hand, following the same shape as the serialize-dos `run.sh`: copy both fixture files into
  one source directory, build ONE CPG with `jssrc2cpg.sh`, then run each producer against it
  with `--param cpgFile=... --param rawDir=...`.
- **No prior committed raw output existed to reproduce.** `fixtures/path_traversal_sinks/`
  and `fixtures/path_traversal_prop_effects/` each contain only the fixture `.js` file, no
  `raw/` subdirectory (confirmed via `find ... -path '*path*'` before any run in this audit).
  Every number in this report is a first, fresh execution, not a reproduction of an existing
  baseline.
- Fixtures were built together in one CPG (`fixtures/path_traversal_sinks/sink_shapes.js` +
  `fixtures/path_traversal_prop_effects/property_effects.js`), matching how the serialize-dos
  `run.sh` and ReDoS's `run_pilot25.py` combine source under one directory before `jssrc2cpg`.
- Real run log excerpt (`export_path_traversal_integ.sc`, `srcLabel=fixture_run`):
  ```
  [fixture_run] sink targets found: 32
    Meteor.methods ingress registrations found: identity,normalized,resolvedNoBase,joinedWithFixedBase,
    resolvedWithFixedBase,concatenatedWithFixedPrefix,stripsDotDotLiterally,guardDominatesSink,
    guardDoesNotDominateSink,resolveThenVerifyContainment,resolveThenVerifyContainmentDoesNotDominate,
    extensionCheckOnly,lookupByUserId,unresolvedWrapperTransform
  [fixture_run] overload-bridged sources added: 0
  [fixture_run] property-assignment-bridged sources added: 1
  [fixture_run] source candidates found: 22 (field-access: 0, ingress-param refs: 21, overload-bridged: 0)
  [fixture_run] PATH_TRAV_INTEG_COMPLETE rows=17
  ```
- `characterize_path_traversal_sinks.sc` real run: `CHARACTERIZATION_COMPLETE rows=35`.
- `characterize_path_traversal_property_effects.sc` real run: `PATH_PROPERTY_EFFECTS_COMPLETE rows=14`.
- `export_path_flow_context.sc` and `export_path_code_context.sc` both ran cleanly against the
  same CPG (`PATH_FLOW_CONTEXT_COMPLETE`, `PATH_CODE_CONTEXT_COMPLETE: ... (37 nodes)`).
- All raw TSV output and full logs are preserved in the session scratchpad
  (`/tmp/.../scratchpad/work/raw/*.tsv`, `*.log`), not in the repo.
- Full end-to-end integration with the adjudicator was also confirmed for real, using
  `TCH_PROPERTY_CONFIG=property_configs/path_traversal_host.json` against the fixture-derived
  raw facts (see item 6 and "Open questions" below): `adjudicate_js.py` ran cleanly and
  produced a real `llm_input_1.json` packet quoting the config's own
  `focused_question_template` verbatim.

## Shared-infrastructure determination (required before Task 2)

**`export_path_flow_context.sc` and `export_path_code_context.sc` are SHARED, generic
infrastructure, not path-traversal-owned.** The word "path" in their names refers to the
*dataflow path* (the source→sink route through the CPG), not to filesystem paths. Evidence:

- Neither file's own content mentions filesystem, `fs.`, or path-traversal at all — both
  operate purely on `source_facts.tsv` and `transform_identity.tsv`, which every property in
  this adjudicator (SSRF, serialize-dos, path-traversal, ReDoS, NoSQLi — anything driving
  `adjudicate_js.py`) already produces.
- `grep -rn "export_path_flow_context"` / `"export_path_code_context"` across the whole repo
  shows real consumers outside path-traversal: `adjudicator/adjudicate_js.py` (generic
  consumption at lines 274, 330-352, 360-380), `docs/milestones/PROPERTY_PROPAGATION.md`, and
  — decisively — two already-committed raw outputs that are **not** path-traversal findings at
  all:
  - `fixtures/customs_dos_serialize/cand1-ps/raw/path_code_context.tsv` — rows about
    `request.payload`/`JSON.stringify(requestData)` in `c1/customs.js` (serialize-DoS).
  - `fixtures/webext_ssrf_transform/raw/path_code_context.tsv` — rows about
    `fetch(rewriteTarget(message.url))` (SSRF).
- Conclusion, explicit per the task instructions: this audit phase must **not** modify these
  two producers even though they live in this property's `producers/` directory — they are
  shared pipeline plumbing already relied on by other properties' committed fixtures.

## 1. Supported filesystem sinks (real code vs. config)

`export_path_traversal_integ.sc` lines 13-33:
```scala
val FS_FAMILY = Set("readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "open", "openSync",
  "stat", "existsSync")
...
def familyOf(c: nodes.Call): Option[String] = {
  val code = c.code
  if (code.startsWith("fs.")) { if (FS_FAMILY.contains(c.name)) Some(s"fs.${c.name}") else None }
  else if (code.startsWith("res.sendFile(")) Some("express.sendFile")
  else if (code.startsWith("res.download(")) Some("express.download")
  else None
}
```
This is **exactly** the 14-entry `direct_sink_kinds` list in `path_traversal_host.json`:
`fs.readFile, fs.readFileSync, fs.writeFile, fs.writeFileSync, fs.createReadStream,
fs.createWriteStream, fs.unlink, fs.unlinkSync, fs.open, fs.openSync, fs.stat, fs.existsSync,
res.sendFile, res.download` — 12 `fs.*` names + 2 Express names = 14, matching the config
1-for-1, no more, no fewer. Confirmed by the real `characterize_path_traversal_sinks.sc` run
against the sink-shapes fixture (35 rows), which enumerated every one of the 12 `FS_FAMILY`
members plus both Express shapes, e.g.:
```
fs.existsSync   positional-path              ...  path is always arg0 for the fs family
express.sendFile positional-path-with-root   ...  root determines the base directory; path is resolved WITHIN it
express.sendFile positional-path-with-root   ...  path is bounded by root ... attacker may still choose WHICH file within root's subtree
express.download positional-path             ...  a present arg1 is a display filename, never path-bearing
UNRESOLVED_WRAPPER unresolved-call ... UNSUPPORTED  callee not a recognized sink family and not resolvable to a local body -- abstain
```
**Real, directly-observed limitation (found by testing, not documented anywhere in the
code):** sink recognition is a **literal string match on the receiver text**, `code.startsWith("fs.")`
— it is not import-binding-aware. A probe fixture (`const filesystem = require('fs');
filesystem.readFile(q, ...)`, alongside `const fs = require('fs'); fs.readFile(...)` in the
same file) produced `sink targets found: 1`, not 2 — the `fs.readFile(...)` call was detected,
the semantically identical `filesystem.readFile(...)` call (same module, different local
binding name) was silently missed. The same literal-text pattern governs Express detection
(`res.sendFile(`, `res.download(`) and Meteor-ingress detection (`Meteor.methods`, see item 2)
— none of these are resolved through import facts the way SSRF's own producers are described
as doing.

## 2. Application-ingress vs. npm-package-API sources — **application-ingress only**

This is the single most important finding of the audit. The real source-detection code
(`export_path_traversal_integ.sc` lines 20-21, 291-321):
```scala
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments)(\\..*)?"
...
def findIngressParams(): List[nodes.MethodParameterIn] = {
  val meteorMethodsCalls = cpg.call.name("Meteor.methods").l ++ cpg.call.filter(_.code.startsWith("Meteor.methods")).l
  ...
}
```
Every recognized source family is an **HTTP/RPC application-ingress boundary**: Express-style
`req.*`/`request.*` field access, a WebExtension-style `message.*`/`item.*` field access
(copied verbatim from the SSRF producer, per the file's own header comment: "Reuses every
source-provenance mechanism already verified for SSRF ... unmodified"), and Meteor RPC method
parameters (`Meteor.methods({...})` registrations). There is **no** source family for "this
function is an npm package's own exported API, and its parameter is attacker-supplied by the
package's caller" — the `PACKAGE_API_INPUT` tier that ReDoS's own R01 built as a second source
tier alongside `APPLICATION_INGRESS`. Confirmed emitted source-fact origin string
(`export_path_traversal_integ.sc` line 424): every row is hardcoded
`"HTTP_PATH_INPUT"` — there is only one origin family in this implementation, and it is
HTTP-application-shaped, not package-API-shaped.

This is corroborated by real, already-existing repository metadata (not invented for this
audit) in `semantic-bucket-pilot/scanner-v2/study/analyzer_class_inventory/data/`:
- `properties.csv`: `PATH_TRAVERSAL,...,"no dedicated frozen/gate doc found in scope -- gate
  status UNVERIFIED, see implementations.csv"`
- `implementations.csv`: `PATHTRAV_01,PATH_TRAVERSAL,adjudicate_js.py + property_configs/
  path_traversal_host.json,,UNVERIFIED,"no dedicated frozen/gate doc found in scope","wired
  but not freshly re-verified this pass"`
- `npm_readiness.csv`: `PATH_TRAVERSAL,UNVERIFIED,"no dedicated frozen/gate doc found in
  scope -- wired to the shared taint engine but soundness itself not independently confirmed;
  also needs its own specialized JS/TS export even if verified"`
- `historical_runs.csv`: **no row exists for PATH_TRAVERSAL at all** — unlike every other
  property in that table (including REDOS, SSRF, NOSQLI), path-traversal has never had a
  recorded real/corpus run.

All three CSV rows independently confirm the same fact from a different angle: this
implementation is wired to the shared engine and to `path_traversal_host.json`, but has never
been given its own JS/TS npm-package-API source export, and its soundness at even fixture
scale had not been re-verified before this audit (see execution results above — it now has).

## 3. Path transformations tracked

Real code, `export_path_traversal_integ.sc` lines 16-17:
```scala
val PATH_JOINING_CALLS = Set("join", "resolve")
val LOCATION_PRESERVING_TRANSFORM_NAMES = Set("normalize")
```
and the classification logic (lines 393-409):
```scala
val isPathJoiningCall = PATH_JOINING_CALLS.contains(calleeShort)
val isKnownPreserving = LOCATION_PRESERVING_TRANSFORM_NAMES.contains(calleeShort)
if (isPathJoiningCall) {
  transformChain += ((c, s"$calleeShort (no containment)"))
} else if (!isKnownPreserving && effect == "PRESERVES") {
  effect = "UNKNOWN"; note = s"unrecognized call: $calleeShort"
  transformChain += ((c, calleeShort))
} else {
  transformChain += ((c, calleeShort))
}
```
So exactly three named operations are modeled:
- `path.join` / `path.resolve` (matched by short name, not fully-qualified) — explicitly
  recorded as providing **no containment**, i.e. they do not change the classification away
  from attacker-controlled location.
- `path.normalize` — explicitly recorded as reformatting only, also not restrictive.
- Plain string concatenation (`<operator>.addition`) is invisible to this logic entirely — it
  is an `<operator>.*` call, filtered out by the `enclosingCall` guard, so it never becomes a
  transform-chain entry at all. Real evidence: `concatenatedWithFixedPrefix` (`'/safe/base/' +
  userPath`) produced **zero** `transform_identity.tsv` rows yet still correctly classified as
  `ESTABLISHED` (attacker-influenced, unbroken) via the default `effect = "PRESERVES"` — string
  concatenation is treated as a no-op pass-through, not tracked as a step.
- Regex-capture extraction (`.exec()` against a `new RegExp(...)` literal) is separately
  classified (`classifyRegexCapture`, lines 172-182) into `RESTRICTED_SAFE`,
  `EXCLUDES_SLASH_ALLOWS_DOT`, or `UNRESTRICTED` based on the pattern's own character classes —
  this is a real, non-trivial transform model, not an opaque break, but it is not exercised by
  either fixture (no regex-capture case exists in `property_effects.js`), so it is documented
  here from code reading only, not from a fixture-confirmed run.
- Anything else that survives to become an on-path call (real evidence: `someExternalPathNormalizer`
  in the `unresolvedWrapperTransform` fixture case) is treated as an **opaque, unrecognized
  transform** — `effect = "UNKNOWN"`, which surfaces as outcome `OPEN` (see item 6). It is
  correctly NOT assumed either safe or unsafe.

## 4. Guard/containment rules — real code confirms the config's claim, WITH a caveat found live

The config's `focused_question_template` states: "a fixed base argument to
path.join()/path.resolve() alone does NOT provide containment against '..' traversal -- only
an explicit resolve-then-verify-containment check (or equivalent) does." The real code
(`sinkIsGuardedBy`, lines 90-121) implements containment recognition only via:
```scala
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val CONTAINMENT_CHECK_METHODS = Set("includes", "startsWith")
```
guarded on an `if` whose `then`-block contains the sink call, requiring the check's own operand
to be one of the `trackedCodes` (the source's own text, or any identifier confirmed to be
derived from it along the established flow — see item 5). `path.join`/`path.resolve` are
**never** in `CONTAINMENT_CHECK_METHODS`, so a fixed base argument to either genuinely cannot,
by construction, produce a `BROKEN` (contained) classification — verified directly: real fixture
run, `joinedWithFixedBase` (`path.join('/safe/base', userPath)`) and `resolvedWithFixedBase`
(`path.resolve('/safe/base', userPath)`) both classified `ESTABLISHED` (attacker-influenced,
unbroken), matching the config's stated design exactly.

`endsWith` is deliberately excluded from `CONTAINMENT_CHECK_METHODS` (a format/extension check,
not a location check) — verified: `extensionCheckOnly` (`if (userPath.endsWith('.pdf'))`)
classified `ESTABLISHED`, not `BROKEN`.

**Real discrepancy found by direct execution, worth flagging prominently:** both
`property_effects.js`'s own comment (lines 55-61) and `characterize_path_traversal_property_effects.sc`'s
own case table (line 140: `"UNKNOWN EXPECTED (guard is on a DERIVED variable, not yet
recognized -- documented limitation, not a bug)"`) describe `resolveThenVerifyContainment`
(`const resolved = path.resolve('/safe/base', userPath); if
(resolved.startsWith('/safe/base'+path.sep)) { ... }`) as a case the guard logic is NOT yet
able to recognize. **The real, fresh run of both `characterize_path_traversal_property_effects.sc`
and `export_path_traversal_integ.sc` against this exact fixture function contradicts that
stale comment**: the guard IS recognized. Real output:
```
[fixture_run] EMIT sink=30064771118(L59) src=68719476787(L57:userPath) outcome=BROKEN note=guarded by: resolved.startsWith('/safe/base' + path.sep)
```
and from `characterize_path_traversal_property_effects.sc`'s own TSV:
```
resolveThenVerifyContainment  userPath  BREAKS (guarded by: resolved.startsWith('/safe/base' + path.sep))  UNKNOWN EXPECTED (guard is on a DERIVED variable, not yet recognized -- documented limitation, not a bug)
```
The `derivedNames` mechanism (both files, e.g. `export_path_traversal_integ.sc` lines
349-350: `val derivedNames: Set[String] = flows.flatMap(_.elements.collect { case id:
nodes.Identifier => id.code.trim }).toSet; val trackedCodes = Set(src.code.trim) ++
derivedNames`) already collects every identifier confirmed on the established dataflow path —
including `resolved` — and checks the containment call's operand against that whole set, not
just the original parameter name. So the "not yet recognized" limitation this code once had
(matching SSRF's own documented history of the same gap) has since been fixed in both files,
but the case-table comment/expectation string describing it as unrecognized was never updated
to match. The negative control in the same fixture,
`resolveThenVerifyContainmentDoesNotDominate` (identical guard, but placed where it does not
dominate the sink), correctly still classified `ESTABLISHED` — confirming the fix is a genuine
dominance-aware guard match, not an over-broad one.

## 5. Interprocedural behavior — confirmed real, cross-function tracing

The dataflow mechanism is Joern's standard `reachableByFlows` engine
(`import io.joern.dataflowengineoss.language._`, `import
io.joern.dataflowengineoss.queryengine.EngineContext`), the same interprocedural engine used
elsewhere in this repo (ReDoS, serialize-dos, SSRF), invoked at line 334-337:
```scala
cpg.all.id(destExpr.id).collectAll[nodes.Expression]
  .reachableByFlows(Iterator(src: nodes.Expression)).l
```
This is not merely asserted from the import — it was **directly tested** in this audit with a
purpose-built two-hop probe (kept in the session scratchpad only, not the repo):
```js
function readViaHelper(p) {          // Meteor RPC ingress param
  return doRead(p);                  // hop 1: argument passed into a sibling function
}
function doRead(innerPath) {
  return fs.readFile(innerPath, () => {});   // hop 2: sink inside the callee
}
```
Real run output:
```
[interproc_probe3] sink targets found: 1
  Meteor.methods ingress registrations found: readViaHelper,readViaAliasedModule
[interproc_probe3] source candidates found: 3 (field-access: 0, ingress-param refs: 2, overload-bridged: 0)
[interproc_probe3] EMIT sink=30064771117(L12) src=68719476785(L9:p) outcome=ESTABLISHED note=
```
The source (`readViaHelper`'s own parameter `p`, at its declaration line 9) was correctly
traced across the function-call boundary into `doRead`'s parameter `innerPath` and on to the
`fs.readFile` sink at line 12, in a wholly different function body — genuine, real,
directly-observed interprocedural tracing, not merely a same-function match. Beyond the base
engine, the file adds two explicit interprocedural BRIDGES that exist specifically to route
around cases the base engine's own callee resolution misses: `computeOverloadBridgedSources`
(TS-overload stub call sites, lines 245-263) and `computePropertyAssignmentBridgedSources`
(a call whose callee never resolves at all, bridged via a globally-unique
`Y.propName = function(){...}` assignment, lines 268-289) — both explicitly re-run
`reachableByFlows` after bridging, so a source found only through the bridge still gets the
same interprocedural treatment as a directly-resolved one.

## 6. Candidate and abstention vocabularies (real, exhaustive)

Per-alternative outcome (`property_outcome.tsv`, three values only — confirmed by real fixture
run, `property_outcome.tsv` and `EMIT ... outcome=` lines contain no other string):

| outcome | real condition that produces it (quoted) |
|---|---|
| `ESTABLISHED` | No genuine guard/strip/regex match found, AND every on-path transform is either a known-preserving call (`normalize`) or a path-joining call (`join`/`resolve`, explicitly no-containment) or untracked (`<operator>.*`, e.g. string concat). Real: `finalOutcome = effect match { case "PRESERVES" => "ESTABLISHED"; ... }` (line 410). Also produced directly (not via the default branch) when a regex capture classifies `UNRESTRICTED` (line 371-374). |
| `OPEN` | Two distinct real paths to this value: (a) no dataflow reaches the sink expression at all, but the source's own text reaches a lookup/index call whose result independently reaches the sink — `LOOKUP_KEY_INFLUENCE` (lines 339-345, real: `lookupByUserId` → `note=LOOKUP_KEY_INFLUENCE: key reaches fileRegistry[userId], value itself does not flow to sink`); (b) a genuine flow exists but hits an unrecognized on-path call — `effect="UNKNOWN"` folds to outcome `OPEN` via the same `finalOutcome` match (line 410, `case _ => "OPEN"`), real: `unresolvedWrapperTransform` → `note=unrecognized call: someExternalPathNormalizer`; (c) a regex capture classifies `EXCLUDES_SLASH_ALLOWS_DOT` (lines 365-370, "bounded single-level escape possible ... flagged for semantic review" — not exercised by either fixture, confirmed from code only). |
| `BROKEN` | A genuine value guard/comparison dominates the sink (`sinkIsGuardedBy`, real: `guarded by: userPath.includes('..')`), OR a literal `.replace()`-based `'..'` strip is found (`hasLiteralDotDotStrip`, real: `literal '..' strip: userPath.replace(/\.\./g, '')`), OR a regex capture classifies `RESTRICTED_SAFE` (line 361-364, not exercised by either fixture). |

There is no fourth top-level outcome string; `"UNKNOWN"` only ever appears as an *internal*
`effect` variable or as the `identity_status` column of `transform_identity.tsv` — it never
appears as a `property_outcome.tsv` value. `adjudicate_js.py`'s `join_existential` (unmodified,
read-only) expects exactly `ESTABLISHED`/`OPEN`/`BROKEN`/absence(`NO_FLOW`), which this
producer's vocabulary satisfies exactly — confirmed by a real, successful end-to-end
`adjudicate_js.py` run against the fixture-derived facts with
`TCH_PROPERTY_CONFIG=property_configs/path_traversal_host.json`
(`FINAL: CANDIDATE_OPEN (deterministic layer: SEMANTICALLY_OPEN)` for the
`unresolvedWrapperTransform` sink, with a real rendered `focused_question` quoting the config's
own template verbatim).

Sink-characterization vocabulary (`characterize_path_traversal_sinks.sc`, separate from the
above): `confidence` column is either `ESTABLISHED` (every recognized shape) or `UNSUPPORTED`
(the one `UNRESOLVED_WRAPPER` row, "callee not a recognized sink family and not resolvable to
a local body -- abstain") — real, confirmed by the 35-row characterization run.

## 7. Known soundness limitations (disclosed in code + newly discovered by direct testing)

**Disclosed in code (comments):**
- `characterize_path_traversal_property_effects.sc` lines 46-50 (also mirrored, unlabeled, in
  `export_path_traversal_integ.sc`'s equivalent function): guard recognition "only recognizes a
  guard on the ORIGINAL tracked identifier's own text. It does NOT yet recognize a guard on a
  DERIVED variable..." — **this comment is stale**; see item 4 above, directly disproven by a
  real run. The `derivedNames` mechanism it describes as missing is present and working in both
  files.
- `characterize_path_traversal_sinks.sc` / main producer: `UNRESOLVED_WRAPPER` /
  unresolved-callee cases are explicitly abstained rather than guessed (by design, not a gap).

**Newly discovered by direct testing in this audit (real, observed, not hypothetical):**
1. **Literal-text sink/source detection, not import-binding-aware.** `familyOf()`
   (`code.startsWith("fs.")`) and `findIngressParams()`
   (`cpg.call.name("Meteor.methods") ... cpg.call.filter(_.code.startsWith("Meteor.methods"))`)
   both match on literal receiver/callee text. A real probe (`const filesystem = require('fs');
   filesystem.readFile(q, ...)` alongside a correctly-named `const fs = require('fs')` sibling
   in the same file) showed `sink targets found: 1`, not 2 — the aliased-import call was
   silently missed, with no abstention note logged at all (it simply never becomes a
   `SinkTarget`). This is a real gap in the sink/source layer, independent of the
   dataflow-tracing layer (which, per item 5, is genuinely interprocedural and worked
   correctly once the literal-text gate was satisfied).
2. **`transform_identity.tsv`'s own sink-node column is a hardcoded placeholder.** Line 428:
   `ti.println(Seq("x", r.srcId, order.toString, c.id.toString, kind, "", "", "UNKNOWN")...)`
   — the first column, documented (in `historical/path_transform_identity.py`'s own docstring
   and in `adjudicate_js.py`'s consumption pattern) as `sink_node`, is the literal string
   `"x"` for every row, never `r.sinkId`. Confirmed in the real fixture output
   (`x  68719476745  0  30064771077  normalize   ...  UNKNOWN`, etc. — every row's column 0 is
   `x`). This is currently **harmless in practice**: `adjudicate_js.py`'s own
   `_build_alternative_evidence`/`build_evidence_v0` never reads `t[0]` from
   `transform_identity.tsv` (it matches transforms to an alternative via `t[1]` == source node
   id, per line `chain = sorted([t for t in tid if t[1] == origin[2]], ...)`), so the current
   adjudicator is not misled by it. It would matter to any future consumer (e.g. a
   `redos_verdict.py`-style reducer, or the historical `path_transform_identity.py` bridge
   script) that trusted the documented 8-column schema and tried to key on the real sink id.
3. **`historical/path_transform_identity.py` is not wired to (and would not work against) this
   producer's real output.** It requires `propagation_relations.tsv` column 2 (`status`) to
   equal the literal string `"ESTABLISHED"` before it will emit anything for a row. The real
   `propagation_relations.tsv` this producer writes (line 425:
   `pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "")...)`) leaves
   that column blank for every row (confirmed in the real fixture output). This is not a live
   bug in the current pipeline — `export_path_traversal_integ.sc` writes `transform_identity.tsv`
   directly and never calls the historical bridge script — but it does mean that script (listed
   in the task's own required-reading set) is effectively vestigial for this property, not an
   active or usable component of it.
4. **A per-origin `OPEN` outcome from `LOOKUP_KEY_INFLUENCE` never reaches semantic review.**
   Real, observed: running `adjudicate_js.py` against the `lookupByUserId` sink
   (`property_outcome.tsv` says `OPEN`) produced `rounds: 0` /
   `FINAL: CANDIDATE_OPEN (deterministic layer: SEMANTICALLY_CLOSED)` — because this outcome
   path (lines 339-345) never adds anything to `transform_identity.tsv`, so
   `build_evidence_v0`'s `chain` for that origin is empty and no
   `semantically_unresolved__SEMANTICALLY_UNRESOLVED` property is ever created for a human/LLM
   to review. The candidate correctly stays open (never silently resolved SAFE), but it is
   permanently stuck at `CANDIDATE_OPEN` with nothing surfaced to act on — there is no
   mechanism today by which this specific `OPEN` reason could ever be escalated past that
   point.
5. **No semantic-identity or definition-body resolution is wired for this property's own
   transforms.** Every `transform_identity.tsv` row this producer writes carries `module_spec`
   and `member` as empty strings and `identity_status` as the literal `"UNKNOWN"` (confirmed:
   every real output row ends `...UNKNOWN`) — there is no import-fact join the way the
   file's own header comment claims for source provenance ("Reuses every source-provenance
   mechanism already verified for SSRF ... the sibling-argument artifact filter, the
   TS-overload structural resolver"). Nor does any producer here emit
   `definition_resolution.tsv` or `trace_identity.tsv`. Practically: even a trivially
   resolvable transform (e.g. `path.normalize`, a Node builtin whose identity is completely
   unambiguous) is presented to any future semantic-review step as `definition_status: UNKNOWN`
   with no body — confirmed via a real rendered `llm_input_1.json` packet
   (`someExternalPathNormalizer` case): `"static_definition_identity": null,
   "static_definition_identity_status": "UNKNOWN", ... "definition_body": null`.

## Addendum: sink-family-specific containment semantics (verified against the real classification code, not just the sink-shape characterization)

Per direct instruction: `res.sendFile`/`res.download`, Node `fs` reads, and Node `fs` writes must
be treated as separate sink families, since their path and containment semantics are not
interchangeable. Verified directly against `export_path_traversal_integ.sc`'s real sink-target
construction (lines 27-74), not inferred from the sink-shape characterization output alone:

**`fs.*` reads, writes, and deletes are NOT differentiated by the real classification code.**
`FS_FAMILY` (line 13-15) names all 12 members once; every subsequent line of logic (`sinkTargets
+= SinkTarget(c, fam, a0)`, `sinkIsGuardedBy`, `hasLiteralDotDotStrip`, the transform-chain walk)
treats the whole set uniformly — confirmed by grepping the entire file for any per-operation
branch (`writeFile`, `readFile`, `unlink`, `isWrite`/`isRead`/similar): none exists outside the
initial `Set(...)` literal. A read (`fs.readFile`), a write (`fs.writeFile`), and a delete
(`fs.unlink`) reaching the identical unguarded resolved path today produce the identical
`ESTABLISHED` classification via the identical code path — the sink's own NAME is preserved in
`family` (so a downstream consumer *could* distinguish them from the raw facts), but no
containment or transform semantics differ by operation type. This is a real gap relative to the
instruction's own framing: reads, writes, and deletes are not the same operation and a future R01
phase should decide whether they warrant distinct guard/transform models (e.g., a write/delete
sink arguably deserves the same rigor a read does even under this property's own
impact-neutral framing, since "attacker controls the resolved location" is the modeled fact
regardless of operation — but a reviewer prioritizing candidates would reasonably want the
operation kind visible and NOT silently collapsed).

**`res.sendFile` and `res.download` are NOT treated identically to each other, and NOT identically
to `fs.*`, but the two Express sinks are inconsistently modeled relative to one another.** Real
code (lines 57-71):
```scala
} else if (fam == "express.sendFile") {
  val optionsArg = args.lift(1)
  val rootField = optionsArg.flatMap(opt => findObjectField(opt, Seq("root")))
  rootField match {
    case Some((_, rootExpr)) =>
      // root present: root is the genuine location-determining operand for this sink.
      // The path arg is CONTAINED (Express prevents '..'-escape above a fixed root) -- do
      // NOT enumerate it as a full-location alternative, matching the frozen Stage-1 finding.
      sinkTargets += SinkTarget(c, fam, rootExpr)
    case None =>
      sinkTargets += SinkTarget(c, fam, a0)
  }
} else if (fam == "express.download") {
  sinkTargets += SinkTarget(c, fam, a0)  // arg1, if present, is a display filename -- ignore
}
```
`res.sendFile` genuinely has its own, real, distinct containment model: when a `root` option is
present, the tracked operand SWITCHES from the raw path argument to the `root` expression itself
— correctly reflecting Express's own real behavior (`send`/`sendFile` resolves the given path
relative to `root` and cannot escape above it), and correctly re-flagging the sink only if `root`
ITSELF is attacker-influenced, not the sub-path within it. This is real, working, differentiated
containment modeling — not a gap.

**`res.download` has no equivalent handling at all** — it always tracks `a0` (the raw path
argument), with no check for a `root` option, even though real Express's `res.download(path,
[filename], [options], [callback])` passes `options` straight through to its own internal
`sendFile()` call, including `options.root`. This is a real, direct asymmetry: the SAME
underlying Express mechanism (`root`-bounded resolution) is modeled for `sendFile` but silently
un-modeled for `download` — a `res.download(userPath, {root: '/safe/base'})` call would today be
classified as if `userPath` itself were the unguarded, attacker-controlled operand, when Express's
own real resolution would in fact bound it to `root`, matching `sendFile`'s already-correct
treatment. This is a real, disclosed asymmetry a future R01 phase should close (mirror the
`sendFile` root-detection branch for `download`), not a difference intentionally chosen for a
documented reason.

**Summary against the instruction's own framing**: `res.sendFile` is the one sink family with
genuinely distinct, already-correct containment semantics recognized in code. `res.download`
shares `res.sendFile`'s real underlying mechanism but is NOT given the same treatment (a real gap,
not an intentional distinction). `fs.*` reads/writes/deletes are all modeled identically to each
other with no operation-specific containment or transform logic at all (both a real gap and,
arguably, a defensible simplification depending on whether operation-type ever needs to affect the
BOUNDARY-correctness classification itself, as opposed to just being visible for triage).

## Open questions for R01 (setup only — not performed by this audit)

Given item 2's finding (application-ingress-only, confirmed with real evidence and corroborated
by existing `npm_readiness.csv`/`implementations.csv`/`historical_runs.csv` rows), a future R01
phase building the npm-package-API tier and a `redos_verdict.py`-equivalent reducer would need,
at minimum:

1. **A `PACKAGE_API_INPUT` source family**, analogous to ReDoS's own two-tier
   `APPLICATION_INGRESS` + `PACKAGE_API_INPUT` design — currently there is no mechanism at all
   for treating "this is an exported function of the package under analysis, called by an
   unknown external caller" as a source; only `req.*`/`message.*` field access and
   `Meteor.methods` RPC registration are recognized (item 2).
2. **A `redos_verdict.py`-style reducer/verdict layer for path-traversal.** None currently
   exists. The only consumer of this property's raw facts today is the generic
   `adjudicate_js.py` driven by `path_traversal_host.json` — confirmed to work end-to-end in
   this audit — but there is no property-specific reducer that (like `redos_verdict.py` for
   ReDoS) collapses `adjudicate_js.py`'s per-round hint trace into a single final verdict
   string tailored to this property's own vocabulary. Building one is explicitly out of scope
   for this audit phase; this note only records that the gap exists.
3. **Import-binding-aware sink/source detection** (item 7.1) should be fixed before any
   npm-corpus run, since npm packages rewrite/rename their own `require('fs')` bindings far
   more freely than a single application's `req.*` idiom varies.
4. **Wiring `export_definition_resolver.sc`/trace-identity production** into whatever future
   npm-oriented producer is built, so `OPEN` alternatives whose blocking transform is a
   resolvable Node builtin or local function don't uniformly present as
   `definition_status: UNKNOWN` with no body to a reviewer (item 7.5).
5. **A real corpus/gate run.** `historical_runs.csv` currently has zero rows for
   `PATH_TRAVERSAL` — this property has never been run against real code, only fixtures (now
   including, for the first time via this audit, an actual fresh fixture execution). Before
   promotion, it needs the same kind of real-codebase validation SSRF/ReDoS/serialize-dos
   already have on record.
6. **Close the `res.download` root-option asymmetry** (see the sink-family addendum above): mirror
   `res.sendFile`'s already-correct `root`-option detection for `res.download`, which passes its
   own `options` straight through to the same underlying Express `sendFile()` mechanism.
7. **Decide whether `fs.*` reads/writes/deletes need distinct containment or transform models**,
   or whether preserving the operation name in the raw facts (already done) is sufficient and the
   uniform classification logic should stay as-is — a real design decision, not yet made, flagged
   by the sink-family addendum above.

All findings above describe the *modeled security property* only — a resolved filesystem
location that is attacker-influenced without a proven containment check — per
`path_traversal_host.json`'s own `established_meaning` field. No claim in this report asserts
exploitability, a confirmed vulnerability, or that an attacker can read/write any specific file;
filesystem permissions, symlink behavior, null-byte injection, and actual sensitive-file
presence remain explicitly out of scope, as the config itself states.
