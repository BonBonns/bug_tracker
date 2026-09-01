# Path-traversal R01 fixtures (PATH-TRAV-R01)

Frozen raw output of `producers/export_path_traversal_integ_r01.sc` (Joern install at
`tchecker-research-complete/joern-install/joern-cli`) run over `src/`'s own 18 synthetic
`.js`/`.mjs` files, checked in so `check_path_traversal_verdict.py` reproduces without needing
Joern again — same convention as `study/redos_npm/fixtures/`.

`src/` covers every one of the 12 required regression controls plus import-recognition and
package-API-source coverage, per `docs/milestones/PATH_TRAVERSAL_R01_IMPLEMENTATION.md`:

| File | Shape | Expected (new producer) | Old producer (`export_path_traversal_integ.sc`, real baseline) |
|---|---|---|---|
| `ctrl01_sibling_prefix.js` | `path.resolve('/safe', p)` then bare `.startsWith('/safe')` (no separator) — `/safe-backup/secret` textually matches | Finding, `containment_status=ESTABLISHED`, `weak_diagnostic_guards` notes the bare startsWith | **BROKEN** (confirmed real bug: `guarded by: resolved.startsWith('/safe')`) |
| `ctrl02_user_controlled_root.js` | `res.sendFile(path, {root: req.body.root})` | Finding, `EXPRESS_SEND_FILE`, never contained, note "root itself is source-tainted" | `ESTABLISHED` (same conclusion here since root literally IS the source, but via the generic engine, not an explicit taint proof) |
| `ctrl03_fixed_root_sendfile.js` | `res.sendFile(req.params.name, {root: '/safe/base'})` | Zero rows — genuinely contained | Zero rows (already correct in the old producer) |
| `ctrl04_fixed_root_download.js` | `res.download(req.params.name, {root: '/safe/base'})` | Zero rows — genuinely contained | **`ESTABLISHED`** (confirmed real asymmetry: old producer has no root-detection for `res.download` at all, so it tracks `req.params.name` directly and reports it as an unguarded candidate even though Express itself bounds it to the fixed root) |
| `ctrl05_aliased_fs_import.js` | `const filesystem = require('fs'); filesystem.readFile(...)` | Finding (caught) | **Missing entirely** (confirmed: `code.startsWith("fs.")` never matches `filesystem.readFile`) |
| `ctrl06_unrelated_object_named_fs.js` | `const fs = { readFile: (p,cb) => myCustomThing(p,cb) }; fs.readFile(...)` | Never counted as a sink at all (negative control) | **Wrongly counted as a real `fs.*` sink** (confirmed: literal `code.startsWith("fs.")` matches the impostor; old producer emits an `ESTABLISHED` row for it) |
| `ctrl07_family_split.js` | one function each for `fs.readFile`/`fs.writeFile`/`fs.unlink` | 3 findings, `sink_family` = `FS_READ`/`FS_WRITE`/`FS_DELETE` respectively | 3 rows, but the old producer's own `family` column is always `fs.<name>` (no read/write/delete grouping) |
| `ctrl08_windows_separator.js` | `if (!userPath.includes('../')) { fs.readFile(userPath, ...) }` | Finding, never BROKEN, weak `.includes` diagnostic | **BROKEN** (confirmed real bug: `guarded by: userPath.includes('../')`; also never accounts for `..\` at all, old or new) |
| `ctrl09_repeated_traversal.js` | `userPath.replace(/\.\./, '')` (non-global, single-pass strip) | Finding, `containment_status=OPEN` (the strip is an unrecognized on-path transform), weak `.replace` diagnostic, never BROKEN | **BROKEN** (confirmed real bug: `literal '..' strip: userPath.replace(/\.\./, '')`) |
| `ctrl10_unresolved_options.js` | `res.sendFile(req.params.name, opts)` (`opts` a plain parameter, not a literal) | Zero rows — abstained | **`ESTABLISHED`** (confirmed real gap, beyond the audit's own 3 findings: old producer's `findObjectField` returns `None` for an unresolved options arg exactly the same as "no root key found", so it silently guesses "no root" and tracks `req.params.name` directly instead of abstaining) |
| `ctrl11_wrapper_proven.js` | local `isContained(candidate)` performing a real canonicalize+boundary check internally, used to guard the sink | Excluded (`containment_status=BROKEN`) — the wrapper's own internal proof is verified | `ESTABLISHED` (old producer has no wrapper-guard resolution at all — a real capability gap, not a false-safe bug, since it never wrongly promotes to safe either) |
| `ctrl12_wrapper_unresolved.js` | `if (isSafeSomehow(userPath))`, `isSafeSomehow` never defined anywhere | Finding, `containment_status=OPEN` (abstain) | `ESTABLISHED` (same non-bug gap as ctrl11 — old producer doesn't recognize the guard shape at all, so it falls through to unguarded rather than guessing safe) |
| `ctrl13_boundary_aware_safe.js` | `path.resolve` then `resolved === base \|\| resolved.startsWith(base + path.sep)` directly guarding the sink | Excluded (`containment_status=BROKEN`) | `BROKEN` (already correct in the old producer — the equality half of this check was already recognized; kept correct here) |
| `import_destructured_fs.js` | `const { readFile } = require('fs'); readFile(userPath, ...)` (no `fs.` receiver at all) | Finding (caught) | **Missing entirely** (structurally cannot match — no `fs.` receiver text exists) |
| `import_esm.mjs` | `import fs from 'fs'`, `import * as fsNs from 'fs'`, `import { readFile as readFileAliased } from 'fs'`, `import { readFile as readFileNode } from 'node:fs'` | All 4 shapes caught | Only the default-import shape (`fs.readFile`) is caught; the other 3 are missing |
| `package_api_basic.js` | `module.exports = function readPackageFile(userPath) { fs.readFile(userPath, ...) }` | Finding, `origin_family=PACKAGE_API_INPUT` | **Missing entirely** — the old producer has no `PACKAGE_API_INPUT` source tier at all |
| `package_api_named_exports.js` | `module.exports.writePackageFile = writePackageFile` (named CommonJS export) | Finding, `origin_family=PACKAGE_API_INPUT`, `sink_family=FS_WRITE` | Missing entirely (same reason) |
| `package_api_abstentions.js` | dynamic export key (`module.exports[key] = ...`), `require()`-based re-export, class-constructor export | All 3 abstained — zero `PACKAGE_API_INPUT` sources resolved from this file (its own real `fs.readFile` calls exist but are unreachable from any exported-parameter source, so they correctly produce zero rows) | N/A (no `PACKAGE_API_INPUT` tier exists in the old producer at all) |

## Real numbers (from `raw/run_summary.log`, a real Joern run — never hand-edited)

- `sink targets found: 20` (`FS_READ=16, FS_WRITE=2, FS_DELETE=1, EXPRESS_SEND_FILE=1,
  EXPRESS_DOWNLOAD=0`) — `ctrl06`'s impostor `fs` is correctly excluded from this count (16 real
  `FS_READ` calls exist across the fixture set, not 17); `EXPRESS_DOWNLOAD=0` is *expected*, not a
  bug — `ctrl04`'s fixed-root `res.download` call produces zero sink targets because its root is
  proven fixed/untainted (see `ctrl04` row above), not because `res.download` itself is unrecognized.
- `APPLICATION_INGRESS_INPUT source candidates: 31`, `PACKAGE_API_INPUT source candidates: 2`
  (from the 2 resolved exported functions; 3 further export shapes correctly abstained, logged
  explicitly in `raw/run_summary.log`'s own `PACKAGE_API_INPUT export ABSTENTIONS` line).
- `PATH_TRAV_R01_COMPLETE rows=21 (BROKEN=3, OPEN=3, ESTABLISHED=15)`.
- The reducer (`path_traversal_verdict.py`) turns those 21 raw alternatives into 18 findings
  (`FILESYSTEM_SINK_CANDIDATE=18`), correctly excluding the 3 `BROKEN` alternatives
  (`ctrl11`'s 2 + `ctrl13`'s 1) from the findings list entirely.

`raw_old_baseline_for_regression_only/` is the SAME real Joern CPG run through the UNMODIFIED,
frozen `export_path_traversal_integ.sc` instead — the direct old-vs-new regression baseline this
task requires. It is not consumed by any reducer; it exists purely as checked-in evidence.

## Regenerating (only needed if a fixture file changes)

```
export JOERN_HOME=/path/to/joern-cli   # tchecker-research-complete/joern-install/joern-cli
"$JOERN_HOME/jssrc2cpg.sh" -o /tmp/pt_r01.cpg.bin src/
"$JOERN_HOME/joern" --script ../../producers/export_path_traversal_integ_r01.sc \
    --param cpgFile=/tmp/pt_r01.cpg.bin --param rawDir=raw --param srcLabel=r01_fixture
# old-producer baseline (frozen file, unmodified, read-only comparison):
"$JOERN_HOME/joern" --script ../../producers/export_path_traversal_integ.sc \
    --param cpgFile=/tmp/pt_r01.cpg.bin --param rawDir=raw_old_baseline_for_regression_only --param srcLabel=old_baseline
```

Then re-run `python3 semantic-bucket-pilot/scanner-v2/check_path_traversal_verdict.py` to confirm
the reducer's own counts and per-control assertions still hold against the regenerated `raw/`.
