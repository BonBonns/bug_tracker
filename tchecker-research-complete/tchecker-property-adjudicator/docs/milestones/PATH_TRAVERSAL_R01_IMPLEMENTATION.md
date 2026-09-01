# PATH_TRAVERSAL R01 implementation (new, standalone, fixture-verified)

Scope: a new producer (`producers/export_path_traversal_integ_r01.sc`) and reducer
(`semantic-bucket-pilot/scanner-v2/path_traversal_verdict.py`) for
`ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION`, built additively per
`docs/milestones/PATH_TRAVERSAL_R01_AUDIT.md`'s own real, execution-verified findings. The
audited file (`export_path_traversal_integ.sc`) and its two sibling frozen producers
(`characterize_path_traversal_sinks.sc`, `characterize_path_traversal_property_effects.sc`),
`property_configs/path_traversal_host.json`, and the shared pipeline files
(`export_path_flow_context.sc`, `export_path_code_context.sc`, `adjudicate_js.py`) were read but
never modified. `reportable` stays hardcoded `False` throughout; nothing here is wired into
`provenance.py`, `staged_enablement.py`, or any aggregator. No npm-package validation or
historical vulnerable/fixed differential was performed — out of scope for this phase.

All fixtures are real: built with `jssrc2cpg.sh` against
`fixtures/path_traversal_r01/src/` (18 files) and run with real `joern --script` invocations
against `JOERN_HOME=tchecker-research-complete/joern-install/joern-cli`. Every CPG shape quoted
below is copy-pasted from a real probe's stdout, not assumed.

## 1. Import/module identity recognition (fixture-first CPG evidence)

Probe fixture (`const fs = require('fs')`, `const filesystem = require('fs')`,
`const { readFile, writeFile } = require('fs')`, `const fsNode = require('node:fs')`,
`const fsProm = require('fs/promises')`, `const notFs = { readFile: (p) => doOtherThing(p) }`),
real `joern --script` probe output:

```
readFile call methodFullName=fs:readFile receiver=List(fs.readFile)
readFile call methodFullName=fs:readFile receiver=List(filesystem.readFile)
readFile call methodFullName=probe_import.js::program:readFile receiver=List(readFile)
readFile call methodFullName=node:fs:readFile receiver=List(fsNode.readFile)
readFile call methodFullName=fs/promises:readFile receiver=List(fsProm.readFile)
readFile call methodFullName={ readFile: (p: ANY) => ANY; }:readFile receiver=List(notFs.readFile)
```

`fs.readFile` and the **aliased** `filesystem.readFile` resolve to the *identical*
`methodFullName == "fs:readFile"` via js2cpg's own `JavaScriptTypeRecovery` pass — the aliasing
gap the audit confirmed (item 7.1) is closed by a single structural check
(`methodFullName.startsWith("fs:")` / `"node:fs:"` / `"fs/promises:"` / `"node:fs/promises:"`),
with **no extra code needed to reject the negative control**: `notFs.readFile`'s methodFullName is
an object-literal type name that never matches any of those prefixes.

A second probe (`.mjs`) confirmed every ESM shape resolves the same way:
`import fs from 'fs'` → `fs:fs:readFile`; `import * as fsNs from 'fs'` → `fs:fsNs:readFile`;
`import { readFile as readFileAliased } from 'fs'` → `fs:readFile`;
`import { readFile } from 'node:fs'` → `node:fs:readFile`. All four are caught by the same prefix
check. **Real bug found and fixed while building this**: the CALL node's own `.name` for
`readFileAliased(userPath, ...)` is `"readFileAliased"` (the local alias text), not `"readFile"` —
gating sink recognition on `FS_ALL_NAMES.contains(c.name)` first (as an early version of this file
did) silently misses every aliased named import even though `methodFullName` resolves correctly.
The fix (`realFsMemberName`) always derives the real member name from the `methodFullName` suffix
when it resolves, falling back to `c.name` only for the destructured case.

**CommonJS destructuring is the one shape `methodFullName` does not resolve** (confirmed:
`const { readFile } = require('fs'); readFile(x)` → `methodFullName == "fs"`, no member suffix, or
in a same-scope variant a local-file stub). Real desugared shape (probe output, verbatim):
```
assign id=... lhs=_tmp_0 rhs=require('fs')
assign id=... lhs=readFile rhs=_tmp_0.readFile   (a <operator>.fieldAccess Call: arg(1)=base
                                                   Identifier, arg(2)=FieldIdentifier)
```
This file's `identifierIsDestructuredFsMember` resolves this two-hop chain explicitly. **Second
real bug found and fixed**: the require/destructuring assignment lives at module/program top-level
scope while the call site is typically inside a nested function (e.g. a `Meteor.methods` handler);
scoping the search to the call's own single enclosing `Method` (`c.method`) — as an early version
did — misses this, the overwhelmingly common real case, entirely, because that Method's own `.ast`
does not include the outer program scope's statements. The fix scopes the search by **file**
(`cpg.call.filter(fileOf(_) == filename)`) instead.

## 2. Five-way sink family split

`FS_READ` (`readFile`, `readFileSync`, `createReadStream`, `stat`, `existsSync`, `open`,
`openSync`), `FS_WRITE` (`writeFile`, `writeFileSync`, `createWriteStream`), `FS_DELETE`
(`unlink`, `unlinkSync`), `EXPRESS_SEND_FILE`, `EXPRESS_DOWNLOAD` — five real, distinct tags
carried into `source_facts.tsv` column 5 (never collapsed into one `fs.*` family the way the
audited file's own `family` string always was). `open`/`openSync` are classified `FS_READ`: Node's
own default `flags` value when omitted is `'r'` (read), and this producer does not analyze the
`flags` argument itself to distinguish a read-mode open from a write/append-mode one — a
documented, disclosed, conservative default, not a silent assumption; a future phase could inspect
`flags` explicitly to split further. Real fixture confirmation
(`ctrl07_family_split.js`, one function each for `readFile`/`writeFile`/`unlink` on the same
attacker-influenced parameter): all three findings carry distinct `sink_family` values
(`FS_READ`/`FS_WRITE`/`FS_DELETE`) in the reducer's own output — see
`fixtures/path_traversal_r01/raw/source_facts.tsv` rows for sinks `30064771132`/`30064771134`/
`30064771136`.

## 3. Corrected containment idioms (the 3 previously-unsound shapes)

Real probe evidence used to build the corrected logic:
```
call id=... code=resolved.startsWith('/safe') ... arg idx=0 code=resolved  arg idx=1 code="/safe"
call id=... code=resolved.startsWith('/safe/base' + path.sep) ... arg idx=1 code='/safe/base' + path.sep
add id=... code='/safe/base' + path.sep  arg idx=1 code="/safe/base"  arg idx=2 code=path.sep
call id=... code=userPath.replace(/\.\./, '')   arg idx=1 code=/\.\./
call id=... code=userPath.replace(/\.\./g, '')  arg idx=1 code=/\.\./g
```
`<operator>.startsWith`'s own receiver sits at `argument(0)`, its argument at `argument(1)`;
`<operator>.addition`'s own operands sit at `argument(1)`/`argument(2)` (a `<operator>.fieldAccess`
whose `.code` ends in `.sep`, or a literal `/`/`\`/`\\`, structurally identifies a real
path-separator operand). Regex-literal `.code` carries its own flags verbatim.

**Corrected rule** (`findGenuineBoundaryCheck`): a comparison only counts as proven containment
when its own operand is BOTH (a) in the confirmed dataflow-derived `trackedCodes` set for this
alternative, AND (b) itself assigned, in the same method, from a real `path.resolve`/
`path.normalize` call (`hasCanonicalizationAssignment`) — canonicalization is now a REQUIRED
precondition, not incidental — AND (c) either an equality/strict-equality comparison, or a
`.startsWith(X)` call whose `X` is structurally `<base> + <path-separator>`
(`isBoundarySafeStartsWithArg`), never a bare literal/identifier. This closes all three previously
unsound shapes:

| Bug (per the audit) | Old producer, real output | New producer, real output |
|---|---|---|
| (1) sibling-prefix `.startsWith(base)` alone | `EMIT sink=...(L11) ... outcome=BROKEN note=guarded by: resolved.startsWith('/safe')` | `outcome=ESTABLISHED`, `weak_diagnostic_guards=weak startsWith check without proven canonicalization+boundary: resolved.startsWith('/safe')` |
| (2) bare `.includes('..')` alone | `EMIT sink=...(L10) ... outcome=BROKEN note=guarded by: userPath.includes('../')` | `outcome=ESTABLISHED`, `weak_diagnostic_guards=weak includes check without proven canonicalization+boundary: userPath.includes('../')` |
| (3) non-global `.replace(/\.\./, '')` strip | `EMIT sink=...(L9) ... outcome=BROKEN note=literal '..' strip: userPath.replace(/\.\./, '')` | `outcome=OPEN` (unrecognized on-path transform — `.replace` sits directly on the source→sink dataflow chain, not merely in a guard condition, so the generic unrecognized-transform rule applies, which is *more* conservative than `ESTABLISHED`), `weak_diagnostic_guards=literal '..' strip via .replace (never treated as containment proof): userPath.replace(/\.\./, '')` |

Design decision, disclosed: **no regex-strip shape (global or non-global) is ever promoted to
`BROKEN`** in the new producer — item 4's own exhaustive list of narrowly-proven idioms (fixed
Express root; canonicalized+boundary-aware base check; a structurally-proven containment wrapper)
does not include any `.replace`-based strip at all, and the audit's own bug description explicitly
notes neither `.replace` nor `.includes` "accounts for alternate path separators... or repeated/
nested traversal components" regardless of the regex's global flag. This closes bug (3) for both
regex-flag variants, not only the literally non-global one the audit's own repro used.

**Boundary-aware positive control** (`ctrl13_boundary_aware_safe.js`,
`resolved === base || resolved.startsWith(base + path.sep)`, both old and new correctly recognize
containment): confirmed identical `BROKEN` outcome in both producers, proving the fix narrows
*only* the unsound shapes without regressing the one that was already legitimate.

**Repeated-traversal control** (`ctrl09_repeated_traversal.js`) and **Windows-separator control**
(`ctrl08_windows_separator.js`, `.includes('../')`): both fall through to the same corrected
weak-diagnostic path by construction — since no bare `.includes`/`.startsWith`/`.replace` is ever
treated as proof regardless of what pattern it checks for, neither the forward-slash-specific
check nor the single-pass strip can produce a false-safe result, closing both controls without
separator-specific code.

## 4. `res.sendFile` / `res.download` root proof (4 conditions)

Real probe confirmed the options-object shape: `res.sendFile(path, {root: X})`'s 2nd argument
desugars to a `Block` containing `<operator>.assignment _tmp_0.root = X` (LHS a
`<operator>.fieldAccess`) — identical for `res.download`. An unresolved options variable
(`res.sendFile(path, opts)`) is instead a bare `Identifier`, structurally distinguishable from "a
resolved `Block` with no `root` key."

`findRootField` returns one of three real, distinct outcomes (`RootFound`/`RootAbsentResolved`/
`RootUnresolvedOptions`) rather than the audited file's binary `Option`, which conflated the
latter two into a single `None`. All four required proof conditions:

1. **exact options object supplies `root`** — `RootFound` requires a resolved `Block`.
2. **root is fixed/untainted** — `isSourceTainted(rootExpr)`, the SAME `reachableByFlows` engine
   used for the main source→sink trace, run explicitly against the combined
   `PACKAGE_API_INPUT`+`APPLICATION_INGRESS_INPUT` source set.
3. **the path arg is the operand Express's root-relative resolution confines** — structurally
   guaranteed by only ever inspecting `argument(1)`/`argument(2)` of the `sendFile`/`download` call
   itself, never a different operand.
4. **no laundering** — condition 2's explicit taint check is exactly this: a tainted `root` is
   never silently treated as a safety proof; instead the tracked operand becomes `root` itself
   (correctly re-flagged as the real attacker-controlled location).

Real regression evidence, same combined CPG, old vs. new:

| Control | Old producer (real output) | New producer (real output) |
|---|---|---|
| `ctrl02` (`root: req.body.root`, tainted) | `EMIT sink=...(L6) ... outcome=ESTABLISHED` (correct *outcome* here only because `root` trivially reaches itself via the generic engine — old code never explicitly proves condition 2) | `EMIT ... outcome=ESTABLISHED note= weak_diagnostic_guards=root itself is source-tainted -- root is the real attacker-controlled operand, not contained` (same outcome, now an explicit, auditable, dedicated proof) |
| `ctrl03` (`root: '/safe/base'`, fixed, `sendFile`) | zero rows (already correct) | zero rows (unchanged, ported forward) |
| `ctrl04` (`root: '/safe/base'`, fixed, **`download`**) | **`EMIT sink=30064771105(L5) src=30064771107(L5:req.params.name) outcome=ESTABLISHED`** — the confirmed real asymmetry: `res.download` has no root-detection in the audited file at all, so it always tracks the raw path arg, wrongly presenting a genuinely-Express-contained call as an open, unguarded candidate | **zero rows** — `res.download` now receives the identical, corrected root-detection `sendFile` gets; the asymmetry is closed |
| `ctrl10` (unresolved `opts` variable) | **`EMIT sink=30064771169(L4) src=30064771171(L4:req.params.name) outcome=ESTABLISHED`** — a real, newly-discovered gap beyond the audit's own 3: old `findObjectField` returns the same `None` for "no root key" and "can't tell," so it silently *guesses* no-root rather than abstaining | zero rows, explicit `ABSTAIN: EXPRESS_SEND_FILE at L4: options argument not statically resolved to an object literal (opts) -- ABSTAIN on root-presence, no sink target emitted` logged |

## 5. `PACKAGE_API_INPUT` source model

Ported the same real, empirically-grounded design ReDoS's own `export_redos_npm_integ.sc`
validated (`module.exports = <MethodRef>`; `module.exports.NAME=`/`exports.NAME=`/indexAccess with
a literal key resolved via a single prior `Identifier = MethodRef` assignment; abstain on dynamic
keys, `require()`-based re-exports, ambiguous assignments, class constructors), re-derived fresh in
this file and verified against this file's own fixtures. Real run:
```
PACKAGE_API_INPUT exported functions resolved: 2 (writePackageFile@writePackageFile,module.exports@readPackageFile)
PACKAGE_API_INPUT export ABSTENTIONS: module.exports[key]=DYNAMIC_COMPUTED_EXPORT_KEY | module.exports.reexported=UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT | module.exports.SomeClass=CLASS_CONSTRUCTOR_NOT_PUBLIC_API
```
(`package_api_abstentions.js`'s own 3 real abstention shapes, all correctly producing zero
resolved exports; its own real `fs.readFile` calls still exist as sink targets but correctly never
appear in any output row since no source reaches them.) `APPLICATION_INGRESS_INPUT` (the existing
`req.*`/`message.*`/`Meteor.methods` model) is carried over unchanged — it is not import-binding
based (an Express `req` parameter is never a module import to alias), so it does not share
capability 2's weakness; the two families are tagged into `source_facts.tsv` column 3
(`origin_family`) and never conflated, matching ReDoS's own `origin_family` column convention
exactly. Old producer, real output: **zero rows** for every `package_api_*.js` file — confirmed,
the audited file has no `PACKAGE_API_INPUT` mechanism at all.

## 6. Reducer schema (`path_traversal_verdict.py`)

Three-tier classification, documented in full in the reducer's own header docstring:
`FILESYSTEM_SINK_CANDIDATE` (a real sink family + ≥1 reachable source alternative) ×
`PACKAGE_API_INPUT_REACHABLE` / `APPLICATION_INGRESS_REACHABLE` (independently tagged, never
merged; unlike ReDoS's npm-only reducer, EITHER family alone is sufficient here since this
property serves both the npm-package and the original application-deployment use case) ×
`containment_status` (`BROKEN`/`OPEN`/`ESTABLISHED`, read per-`(sink_id, origin_id)` alternative
directly from `property_outcome.tsv`, never from `adjudicate_js.py`'s own single-origin
`evidence_final.json` summary). A `BROKEN` alternative is **never** surfaced as a finding; `OPEN`
and `ESTABLISHED` both are (neither is "safe"). `weak_diagnostic_guards` (source_facts.tsv column
6) is carried through into every finding verbatim as a reviewer-facing note that never itself
changes the classification. `reportable` is hardcoded `False` on every finding. Real run against
the frozen fixture: `FILESYSTEM_SINK_CANDIDATE=18` (of 21 raw alternatives, 3 `BROKEN` correctly
excluded), `PACKAGE_API_INPUT_REACHABLE=2`, `APPLICATION_INGRESS_REACHABLE=16`,
`ADJUDICATOR_RUN_FAILED=0` (a real `adjudicate_js.py` run, using the unmodified
`property_configs/path_traversal_host.json`, succeeded for every one of the 18 candidate sinks).

## 7. Regression results — all 12 required controls, old vs. new, real Joern output

Both producers were run against the SAME real combined CPG built from
`fixtures/path_traversal_r01/src/` (18 files). Full real logs:
`fixtures/path_traversal_r01/raw/run_summary.log` (new) and
`fixtures/path_traversal_r01/raw_old_baseline_for_regression_only/run_summary.log` (old,
unmodified). `semantic-bucket-pilot/scanner-v2/check_path_traversal_verdict.py` encodes every
control below as an executable assertion against the reducer's own real output:
`PATH_TRAVERSAL_VERDICT_R01=23/23`.

| # | Control | Result |
|---|---|---|
| 1 | Sibling-prefix bypass | PASS — old `BROKEN` (bug reproduced live), new `ESTABLISHED` + weak note |
| 2 | User-controlled Express root | PASS — never treated as contained in either; new adds an explicit dedicated taint proof |
| 3 | Fixed-root `res.sendFile` | PASS — zero rows in both (already correct, ported forward) |
| 4 | Fixed-root `res.download` | PASS — old `ESTABLISHED` (asymmetry reproduced live), new zero rows (closed) |
| 5 | Aliased `fs` import | PASS — old misses entirely, new catches it |
| 6 | Unrelated object named `fs` | PASS — old wrongly counts it as a real sink, new correctly never counts it at all |
| 7 | Read/write/delete family separation | PASS — 3 distinct `sink_family` tags in new; old collapses to one `fs.*` family string |
| 8 | Windows/POSIX separator | PASS — old `BROKEN` (bug reproduced live), new `ESTABLISHED` + weak note, regardless of separator style |
| 9 | Repeated traversal / single-pass strip | PASS — old `BROKEN` (bug reproduced live), new `OPEN` (never safe) |
| 10 | Unresolved options object | PASS — old guesses "no root" (`ESTABLISHED`), new explicitly abstains (zero rows) |
| 11 | Proven containment wrapper | PASS — new correctly excludes as `BROKEN`; old has no wrapper capability (falls through to `ESTABLISHED`, not a false-safe bug, just a missing capability) |
| 12 | Unresolvable wrapper | PASS — new explicitly abstains (`OPEN`); old again falls through to `ESTABLISHED` (no false-safe result, but no explicit abstention either) |

All 3 previously-unsound guard shapes (sibling-prefix, bare `.includes('..')`, non-global
`.replace` strip) are directly reproduced as real `BROKEN` bugs in the unmodified old producer
against the same fixtures, and confirmed to never produce a `BROKEN`/safe result in the new
producer. The `res.download` root asymmetry and the unresolved-options guessing gap are two
*additional*, newly-discovered soundness issues (beyond the audit's original 3) found live while
building these regression fixtures, and both are closed in the new producer.

## 8. Post-review hardening (FIX01, FIX02) — 2 more real gaps found and closed

Independent review of this file after the above was built found two further real gaps, neither
previously disclosed. Both are now fixed, each with its own real fixture and matched-sink-id
before/after evidence (same combined CPG, same real sink node id in both runs):

**FIX01 — `open()`/`openSync()` were always tagged `FS_READ`, ignoring their own `flags`
argument.** The original design disclosed this as a "conservative default," but never actually
inspected `flags` to narrow it. Now: a literal write-intent flag (`'w'`, `'wx'`, `'w+'`, `'wx+'`,
`'a'`, `'ax'`, `'a+'`, `'ax+'`, `'as'`, `'as+'`) reclassifies the sink `FS_WRITE`; the documented
default `'r'` and any UNRESOLVED flags expression (a variable, not a literal) both stay `FS_READ`
-- the fix only ever narrows the existing conservative default, never guesses toward write.
Fixture: `fixtures/path_traversal_r01/src/ctrl14_open_flags_write.js`. Real, sink-id-matched
before/after (same sink `30064771224`, `fs.open(userPath, 'w', ...)` at L9):
```
pre-fix:  EMIT sink=30064771224(L9) ... sinkFamily=FS_READ  outcome=ESTABLISHED
post-fix: EMIT sink=30064771224(L9) ... sinkFamily=FS_WRITE outcome=ESTABLISHED
```
Explicit read-mode (`'r'`) and unresolved-flags subcases (sinks `30064771226`/`30064771228`)
confirmed to correctly stay `FS_READ` in both runs -- the fix narrows, it does not widen.

**FIX02 — `hasCanonicalizationAssignment` never checked that the canonicalizing assignment
happens BEFORE the boundary check it's meant to justify**, only that one exists somewhere in the
method. A canonicalizing assignment written AFTER a boundary check (a real, if unusual, ordering
bug in the code being analyzed) was wrongly credited toward that earlier check. Fixed with a
disclosed, conservative LINE-NUMBER-ORDER approximation (not full CFG-dominance, which this file
has no query for) -- the canonicalizing assignment's own line must be `<=` the check's own line.
This can only ever REMOVE previously-accepted canonicalization evidence, never add new false
containment, matching this whole file's own safe-failure-direction discipline. Fixture:
`fixtures/path_traversal_r01/src/ctrl15_canonicalize_after_check.js` (`resolved` checked while
still raw, only canonicalized via `path.resolve()` on a LATER line). Real, sink-id-matched
before/after (same sink `30064771246`, `fs.readFile(resolved, ...)` at L14):
```
pre-fix:  EMIT sink=30064771246(L14) ... outcome=BROKEN     note=canonicalized boundary-aware check: resolved.startsWith('/safe' + path.sep)
post-fix: EMIT sink=30064771246(L14) ... outcome=ESTABLISHED note= weak_diagnostic_guards=weak startsWith check without proven canonicalization+boundary: resolved.startsWith('/safe' + path.sep)
```
The already-existing `ctrl13_boundary_aware_safe.js` positive control (canonicalize-then-check in
the CORRECT order) was re-run and still correctly classifies `BROKEN` after this fix -- confirming
the ordering requirement narrows only the unsound case, without regressing the legitimate one.

Both fixes' fixtures were folded into the SAME frozen `fixtures/path_traversal_r01/raw/` set (now
20 source files, 22 `FILESYSTEM_SINK_CANDIDATE`s, up from 18); `check_path_traversal_verdict.py`
was updated with the new real totals and two new explicit assertions (FIX01, FIX02), all 12
original controls re-verified unaffected: `PATH_TRAVERSAL_VERDICT_R01=25/25`.
