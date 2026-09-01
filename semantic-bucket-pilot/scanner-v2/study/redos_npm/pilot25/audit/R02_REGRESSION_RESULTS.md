# R02 regression run: real, complete results over all 21 development/regression packages

`run_pilot25_r02.py` reran all 21 pilot25 packages through the full corrected pipeline
(`frontend_coverage_check.py` -> `export_redos_npm_integ_r02.sc` -> the frozen, unmodified
`redos_verdict.py`), comparing every result against `pilot25_results.json`'s own real R01
baseline. This is the complete regression check the earlier 4-package (`R02_IMPLEMENTATION.md`)
and 2-package (`FRONTEND_COVERAGE_FIX.md`) spot checks did not individually cover, and the first
time either tool was exercised end-to-end together, on all 21 packages, through the real reducer.

**Result: 21/21 OK, 0 regressions.** No package's `dangerous_sinks` or `n_findings` ever
*decreased* relative to the R01 baseline. Full per-package comparison
(`pilot25_r02_results.json`):

| Package | R01 dangerous_sinks | R02 dangerous_sinks | R01 findings | R02 findings | Explained by |
|---|---|---|---|---|---|
| `ember-one-way-controls`, `@appthreat/sqlite3`, `realm`, `linux-device`, `numbl`, `sdenv`, `uplink-nodejs`, `jsmeow`, `argon2`, `x11-dri`, `tree-sitter-4dm` | 0 | 0 | 0 | 0 | unchanged (already-correct `PREFILTER_APPROXIMATION`/`SAFE_UNDER_FROZEN_COMPLEXITY_MODEL`) |
| `node-addon-api`, `@depup/node-addon-api`, `@h1x4dev/node-addon-api`, `koffi`, `velociradix` | 1 | 1 | 0 | 0 | unchanged (`INTERNAL_UNDER_PACKAGE_API_MODEL` / `EXPORT_GAP`+`FLOW_GAP` correctly still abstains -- velociradix's `this._req = new Request(ptr)` is still correctly not an exact constructor-parameter identity) |
| `fuse-napi` | 2 | 2 | 0 | **1 (new)** | capability 2 (object-literal shorthand exports) resolves the already-dangerous-classified sink; **manually reviewed, rejected** (`fuse_napi_review/ADJUDICATION_RECORD.md`) |
| `ssh2` | 0 | 1 | 0 | 0 | capability 4 (cross-closure resolution) resolves `RE_HEADER`, correctly classifies DANGEROUS -- does not promote (export shape, a static property assignment, outside all 4 capabilities' scope, per `R02_IMPLEMENTATION.md`) |
| `mariasql` | 0 | 2 | 0 | 0 | same mechanism as ssh2 for `RE_PARAM` (2 call sites) -- does not promote (ES5 prototype-assignment method, outside scope) |
| `multi-spec-parser` | 0 | 1 | 0 | **1 (new)** | frontend-coverage correction recovers the `dist/`-only entrypoint's real code; **manually reviewed, rejected** (`multi_spec_parser_review/ADJUDICATION_RECORD.md`) |
| `phplike` | 1 | 1 | 1 | 1 | unchanged -- the already-adjudicated `MANUALLY_REJECTED` finding (`phplike_review/ADJUDICATION_RECORD.md`) is untouched by either R02 or the frontend-coverage correction |

## Manual review of both new findings (per protocol: only `PACKAGE_API_INPUT_REACHABLE` proceeds to review)

Both were investigated with the same rigor as `phplike`'s own review -- real reachability tracing
against freshly re-fetched, integrity-verified source, and direct adversarial timing measurement
(5 repetitions per size, exact Node/V8 version recorded) -- never reasoning alone.

- **`fuse-napi@2.3.1`** (`fuse_napi_review/ADJUDICATION_RECORD.md`): **rejected on TWO independent
  grounds.** (1) Real reachability: `wrapMacFuseLoadError` is called exactly once, internally,
  with an error object `loadNativeBinding()` itself produces -- never a value an external caller
  supplies; it is not re-exported, and `package.json`'s own `"exports"` map blocks any external
  `require('fuse-napi/lib/macfuse')` outright. (2) Timing: linear scaling to 80,000 characters
  regardless. The `(?:\.\d+)*` nested-quantifier match is real under the frozen classifier, but
  its `.`-delimited group is character-class-disjoint from the digits it quantifies -- the same
  principle `phplike`'s own record established, applied here in its nested-quantifier form.
- **`multi-spec-parser@0.4.2`** (`multi_spec_parser_review/ADJUDICATION_RECORD.md`): **rejected on
  timing alone -- reachability here IS real and confirmed**, the closest match to `phplike`'s own
  disposition type. A public export, `fetchSpecText(url)`, fetches a URL's response and checks its
  first 4,096 characters (`MAX_VALIDATION_HEAD_BYTES`) against the flagged regex. Direct timing
  (adversarial and at the real bounded 4,096-character size) shows linear scaling throughout --
  0.004-0.009ms at the actual worst-case bounded input. The `\s+` quantifier is bracketed by
  literals disjoint from whitespace on BOTH sides (`"doctype"` before, `"html"` after), and is not
  nested -- a stronger version of the same disjointness protection.

**Zero `MANUALLY_CONFIRMED` findings among the 21 development/regression packages.** Both new
findings this round produced are confirmed false positives, each on real, directly-verified
evidence -- narrow, non-generalizable adjudication records, exactly matching `phplike`'s own
established discipline. No suppression rule of any kind was added to either the frozen classifier
or the new R02 capabilities as a result.

## Freeze

Per the mechanical process this whole audit has followed: **`export_redos_npm_integ_r02.sc` and
`frontend_coverage_check.py` are now frozen** at the state validated by this regression run. All
21 original pilot25 packages (plus the 3 manually-reviewed findings among them --
`phplike`/`fuse-napi`/`multi-spec-parser`, all `MANUALLY_REJECTED`) are development/regression
evidence, not held-out data, and remain excluded from any future blind selection.

`reportable` stays hardcoded `false` throughout every producer and reducer touched by this work.
No pipeline wiring (`provenance.py`, `staged_enablement.py`, `six_property_aggregator.py`) has
been touched.

## New blind set: already selected, still valid, not re-run

`pilot_blind2_selection.json` (frozen prior to this regression run) already excludes all 21
package names above and already reports a real, measured zero (0 qualifying packages of 473
scanned). That selection depends ONLY on the deterministic Python prefilter
(`prefilter_select_25.py`'s own text-level `classify_dangerous` proxy over raw tarball source) --
it never invokes Joern, `export_redos_npm_integ.sc`/`_r02.sc`, or `frontend_coverage_check.py` at
all. Since neither of today's two freezes touches the prefilter, re-running the (expensive,
~473-package) selection today would be a deterministic no-op, reproducing the identical empty
result -- not repeated here for that reason, not skipped by oversight. The existing selection's
own zero stands as the real, current blind-set result: no new blind package has yet been
identified to run the corrected pipeline against.
