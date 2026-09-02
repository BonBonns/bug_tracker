# Path-traversal R02 fixtures (PATH-TRAV-R02)

Frozen raw output of two real producers run in order against the SAME real Joern CPG of `src/`'s
own 30 real `.js` files (Joern install at `tchecker-research-complete/joern-install/joern-cli`),
checked in so `check_path_traversal_verdict_r02.py` reproduces without needing Joern again — same
convention as `fixtures/path_traversal_r01/`.

`src/` is the original 26 files from `fixtures/path_traversal_r01/src/`, copied verbatim (the
sink/containment logic is unchanged, so these are the main regression proof), plus 4 new files
exercising real closure-identity/shadowing/multiple-origin capabilities the shared,
property-neutral `export_npm_source_identity.sc` provides but R01's own hand-rolled Capability 3
never could:

| File | Real shape | What it proves |
|---|---|---|
| `multi_origin_fs_sink.js` | exported `handleRequest(req)` passes the bare `req` param directly to `fs.readFileSync` | MULTIPLE_ORIGINS is real: 2 rows in `source_facts.tsv` for the one (sink, src) pair, never collapsed — R01, run on the same CPG, emits only 1 |
| `shadow_same_name_params_fs.js` | two sibling exported functions each with their own `userPath` param, each reaching their own sink | same-name-parameter distinctness across siblings — both R01 and R02 get this right (real, honestly-reported "no difference" result) |
| `closure_capture_fs_sink.js` | an exported function's own param captured by a nested closure, which performs the real fs read | closure-capture-correct PACKAGE_API_INPUT resolution via real `closureBindingId` — both R01 and R02 get this specific fixture right too (a nested function is an AST descendant of its enclosing method) |
| `shadow_nested_scope_fs.js` | a nested function inside the SAME exported method shadows the outer param with its own, unrelated local of the same name | the real false positive R01's naive `p.method.ast.isIdentifier.name(p.name)` search IS vulnerable to: R01 wrongly credits 2 rows to the (unused) outer parameter; R02 correctly emits 0 |

See `docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md` for the full, quoted real evidence
(including the real R01-vs-R02 side-by-side comparison for all 4 new fixtures).

## Real numbers (from `raw/run_summary.log`, real Joern runs — never hand-edited)

**UPDATED**: regenerated against `export_npm_source_identity_r02.sc` (not R01) after that shared
module was itself corrected (NPM-SOURCE-IDENTITY-R02) to restore Meteor.methods-registered-
parameter recognition — a real, confirmed regression the ORIGINAL numbers below (kept here for
the historical record) had already disclosed as a known limitation of the shared producer's own
R01 scope, not a bug in this file. 18 of R01's own 26 real controls source their attacker-
controlled path from a Meteor.methods handler parameter, not `req`/`request` — regenerating
against the corrected shared module restores their own source recognition here too.

- `export_npm_source_identity_r02.sc`: `source_origin_facts rows: 58 (sites=57,
  multi_origin_sites=1)` (was 22 against R01's own narrower shared producer).
- `export_path_traversal_integ_r02.sc`: `sink targets found: 34` (unchanged — sink identification
  is structural and does not depend on sources at all), `PATH_TRAV_R02_COMPLETE rows=36
  (BROKEN=4, OPEN=3, ESTABLISHED=29, MULTIPLE_ORIGINS_sink_src_pairs=1)` (was rows=8 against R01's
  own narrower shared producer).
- `path_traversal_verdict.py`: `FILESYSTEM_SINK_CANDIDATE: 31, PACKAGE_API_INPUT_REACHABLE: 6,
  APPLICATION_INGRESS_REACHABLE: 26`, 32 findings, 3 abstentions (now also in the reducer's own
  final JSON output under `"abstentions"`).

<details>
<summary>Original numbers (against the shared producer's own R01 scope, before the Meteor.methods
fix — kept for the historical record, not the current committed <code>raw/</code>)</summary>

- `export_npm_source_identity.sc`: `source_origin_facts rows: 22 (sites=21, multi_origin_sites=1)`
- `export_path_traversal_integ_r02.sc`: `sink targets found: 34`, `PATH_TRAV_R02_COMPLETE rows=8
  (BROKEN=0, OPEN=0, ESTABLISHED=8, MULTIPLE_ORIGINS_sink_src_pairs=1)`.
- `path_traversal_verdict.py`: `FILESYSTEM_SINK_CANDIDATE: 7, PACKAGE_API_INPUT_REACHABLE: 6,
  APPLICATION_INGRESS_REACHABLE: 2`, 8 findings, 3 abstentions.
</details>

`raw_missing_source_facts/` is a real, separate run of ONLY `export_path_traversal_integ_r02.sc`
(the shared producer's own output never written into that `rawDir` first) — the degrade-safe
negative control: `sink_targets: 33` (still real/structural), `source_origin_facts_present: false`,
`rows_emitted: 0`, with a real, disclosed stderr WARNING naming the missing dependency.

`raw_real_package/` is a real, two-producer run against `miniml-1.0.19` (one of the 4 real
dev-package tarballs at `fixtures/npm_source_identity_r01/dev_packages/`; the only one of the 4
with real fs-sink-relevant code — `motifer`/`logify`/`ms` have none): `sink_targets: 2,
PACKAGE_API_INPUT_REACHABLE: 2` from its own real `lib/yaml.js` (`loadYamlFile(file)`/
`loadYamlFileSync(file)` passing `file` directly to `readFile`/`readFileSync`).

## Regenerating (only needed if a fixture file changes)

```
export JOERN_HOME=/path/to/joern-cli   # tchecker-research-complete/joern-install/joern-cli
"$JOERN_HOME/jssrc2cpg.sh" -o /tmp/pt_r02.cpg.bin src/
"$JOERN_HOME/joern" --script ../../producers/export_npm_source_identity_r02.sc \
    --param cpgFile=/tmp/pt_r02.cpg.bin --param rawDir=raw --param srcLabel=path_traversal_r02
"$JOERN_HOME/joern" --script ../../producers/export_path_traversal_integ_r02.sc \
    --param cpgFile=/tmp/pt_r02.cpg.bin --param rawDir=raw --param srcLabel=path_traversal_r02
```

Then re-run `python3 semantic-bucket-pilot/scanner-v2/check_path_traversal_verdict_r02.py` to
confirm the reducer's own counts and per-fixture assertions still hold against the regenerated
`raw/`.
