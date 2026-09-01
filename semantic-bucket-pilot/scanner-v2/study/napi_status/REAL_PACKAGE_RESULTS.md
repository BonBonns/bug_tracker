# NAPI-STATUS-R01: real-package results

Per the pre-registered protocol in `NAPI_STATUS_R01.md`. **Claims boundary applies to
every line below:** these are API-handling classifications with node-id evidence --
never vulnerability, severity, exploitability, or impact claims.

## Candidate triage (frozen-order walk, tarball hashes verified)

Rows 0-9 of `overnight_100/overnight_sample_100.tsv` fetched and verified against
their pinned `tarball_sha256`; the token triage (`napi_create_buffer` in C/C++
sources; triage selects packages, never verdicts) produced, in frozen order:

- row 7: `@gjsify/napi@0.44.0` -- first candidate -> **development package**
- row 9: `@farcaster/rocksdb@5.5.0` -- next candidate -> **blind package**

(rows 0-6 and 8: verified, no token; walk stopped at the second candidate, per
protocol.)

## Development package: `@gjsify/napi@0.44.0` (disclosed before reading)

Pipeline: pinned tarball verified (sha256
`52a217e29e00c4302fc01504c9effa0d5ab70c3ae09de9a5c9f94a195cfef6bf`) -> c2cpg
v4.0.608 -> export_c_cpp_facts_v03.sc -> napi_status_verdict.py.

Result: `classification: {}` -- **zero supported creation call sites**. Root cause,
confirmed in the package's own sources: `@gjsify/napi` is an N-API *implementation*
library -- it **defines** `napi_create_buffer` / `napi_create_buffer_copy`
(`src/cc/arraybuffer.cc:163/:177`) and declares them (`src/napi-headers/node_api.h`),
but contains no call site of either. The triage token came from those
definitions/declarations. The analyzer keys on CALL facts only, so a pure-provider
package correctly contributes nothing: no false candidate, no false abstention.

Development outcome: no representation bug surfaced; the implementation was NOT
modified after this read. All 32 gate checks re-verified green.

## Freeze (recorded BEFORE blind selection was acted on)

```
45bf86bd05169ed66f3e5f48028296a3adf7d939bb0112d5eca8a1ad2ead5918  napi_status_verdict.py
265002baa38ede3a31d1a0a5301f590d9d4c7a5492f5a2f622ec173a72ade0ce  check_napi_status.py
3546835f9203c77e7e7db9b54cbfcf645865a51417229830738a1391b4396813  study/napi_status/fixture_source.c
```

## Blind package: `@farcaster/rocksdb@5.5.0` (single post-freeze run, reported as-is)

Pipeline: pinned tarball verified (sha256
`cdc0e3e6cd625330831c0bb325a660cb3d4c535d042ac60bb5828d90e12908a9`) -> c2cpg v4.0.608
-> export_c_cpp_facts_v03.sc -> the FROZEN napi_status_verdict.py (hash re-verified
`45bf86bd...918` immediately before the run).

Parse scope disclosure: the full-tree parse OOM-crashed c2cpg twice (6g, then 12g
heap; ~1000 vendored C++ files). The parse was scoped with c2cpg's own `--exclude` to
omit `package/deps/` (the vendored rocksdb C++ library) and `package/prebuilds/`
(compiled binaries). Token triage over the verified sources shows
`napi_create_buffer` appears in exactly one source file, `package/binding.cc`, and
nowhere under `deps/` -- so the exclusion cannot add or remove any supported call
site; its only possible effect is turning a provable wrapper into an abstention
(the conservative direction). The analyzer itself was NOT modified.

Result (verbatim):

```
classification: {'SUPPORTED_CREATION_CALL_FOUND': 1, 'NO_OUTPUT_USE': 1}
```

The one supported site: `napi_create_buffer_copy` at `package/binding.cc:344`,
method `Convert` -- `napi_create_buffer_copy(env, s->size(), s->data(), NULL,
result)`. Verdict `NO_OUTPUT_USE` (reason `USES_EXIST_BUT_NONE_REACHABLE_FROM_CALL`):
the napi_status result is discarded, but no reference to either output is
CFG-reachable after the call inside `Convert` -- the function ends immediately; the
`result` output escapes through the forwarded caller-supplied pointer parameter, and
`NULL` is passed for `result_data` (N-API's documented opt-out of that output). An
API-handling classification only; no impact statement is made or implied.

Findings-count summary: 0 STATUS_GUARD_MISSING, 0 abstentions, 1 NO_OUTPUT_USE, out
of 1 supported creation call site.

### Outcome classification (per review; the three permitted categories)

`@farcaster/rocksdb@5.5.0` is reported as **ANALYZED with zero guard-missing
findings** -- not an infrastructure failure: the two full-tree c2cpg OOMs were an
infrastructure HAZARD, but the disclosed scoped parse recovered usable facts, the
supported site was recognized, and the frozen analyzer ran once. Task #34's earlier
`CPP_CPG_FAILED` for this package is consistent with that hazard being real. The
caveats stand: this is LIMITED blind semantic evidence (one site, whose honest
classification under R02 is a caller-analysis abstention, see below), and it is NOT
real positive-path evidence -- positive-path behavior remains established on compiled
fixtures only (R02's w01/w02/w03 controls).

### Pre-registered fallback rule (for any future package run in this protocol)

If a selected package fails before producing usable facts (CPG generation or fact
export fails; a scoped parse per the disclosed rule above also failing), it is
recorded as an INFRASTRUCTURE FAILURE -- never as a scanner negative and never as
blind semantic evidence -- and the replacement is selected mechanically: among the
remaining frozen-sample packages, excluding all previously reviewed packages (rows
0-9 above, and any prior study's reviewed set), produce facts for each candidate with
the same pinned toolchain and select the one with the HIGHEST count of
`napi_create_buffer`/`napi_create_buffer_copy` call rows in its own `calls.tsv`
(structural count, no source reading before selection). Ties break by frozen-sample
row order. Only an analyzed result counts as the blind portability test.

### R02 correction of this site (see NAPI_STATUS_R02.md)

The `NO_OUTPUT_USE` above is R01's frozen verdict and stands AS the R01 record; it
is also exactly the boundary the review identified: the required `napi_value*
result` output escapes through a caller-provided pointer, so intraprocedural
analysis cannot prove it unused (`result_data == NULL` is the documented opt-out of
the OPTIONAL raw-data pointer -- a different thing entirely). Under
`napi_status_verdict_r02.py` this real site -- its facts now frozen at
`raw_blind_rocksdb/` -- classifies as
**`OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`** (callers unresolvable from these
facts: `Convert` is an overloaded member, so call sites carry no single callee id),
pinned by `check_napi_status_r02.py` as a permanent regression.

## Targeted 10-package validation + FIRST REAL POSITIVE PATH -> property ENABLED

`evidence_bundles_100/` was searched for machine-wide and is absent, so facts were
rebuilt fresh for exactly the 10 mechanically token-selected packages
(`VALIDATION_10_FROZEN.json`; token presence is only a selection mechanism, never
evidence of a call site or of incorrect handling). The frozen R02 analyzer
(`napi_status_verdict_r02.py`, sha256 `638eddd2...`) was run ONCE per package. All 10
analyzed (only rocksdb needed the disclosed scoped parse; nine parsed in full).

| package | supported sites | classification |
|---|---|---|
| @gjsify/napi (dev) | 0 | provider library -- defines, never calls |
| @depup/node-addon-api | 0 | provider (node-addon-api fork) |
| @h1x4dev/node-addon-api | 2 | 2 ABSTAIN_WRAPPER_UNRESOLVED |
| @cocktailpeanut/node-pty-...@0.11.16 | 0 | no supported call site |
| @fugood/whisper.node | 0 | no supported call site |
| @zowe/db2-for-zowe-cli | 0 | no supported call site |
| @farcaster/rocksdb (blind) | 1 | OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED |
| napi-ldap | 1 | ABSTAIN_BRANCH_POLARITY_UNRESOLVED |
| smart-whisper | 2 | 2 ABSTAIN_WRAPPER_UNRESOLVED |
| **@8crafter/leveldb-zlib@1.6.0** | **3** | **2 STATUS_GUARD_MISSING + 1 abstention** |

Separated as the review asked: provider-definitions-not-calls (2), unsupported/no
site (3), ambiguous/unresolved abstentions (rocksdb escape, napi-ldap polarity,
h1x4dev + smart-whisper wrapper), established handling (0), no-output-use (0), and
one **genuine positive-path package**.

### Manual review of the positive-path candidate (@8crafter/leveldb-zlib@1.6.0)

`package/src/bindings.cpp`, `HandleOKCallback` (real lines 1440, 1447): two
`napi_create_buffer_copy(env_, key.size(), key.data(), NULL, &returnKey)` /
`(..., value.data(), NULL, &returnValue)` calls that DISCARD their `napi_status`
(no assignment, no check), pass `NULL` for the optional `result_data`, and use the
required outputs `returnKey`/`returnValue` immediately at `napi_set_element` (lines
1453/1454) with no success established. The same file uses a `NAPI_STATUS_THROWS`
status-checking idiom at other sites, so these two are a real handling discrepancy.
Read against the real source: `STATUS_GUARD_MISSING / STATUS_DISCARDED` is CORRECT at
both. The third site (line 950, `&argv[1]`) writes into an array element, so output
identity is genuinely unresolvable -- `ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED` is CORRECT.
An API-handling classification, not an impact claim.

### Frozen regression + enablement

`fixture_leveldb_real.cpp` copies those two real methods verbatim (types stubbed to
compile hermetically); `raw_leveldb_real/` is its frozen real Joern v4.0.608 facts;
`check_napi_status_leveldb_regression.py` (7/7) pins the exact classifications. With
the first real package exercising the positive path (`STATUS_GUARD_MISSING`) and
surviving manual review, `NAPI_STATUS_ENABLED` was flipped to **True** -- the class is
no longer fixtures-only. The two real gates (allowed reachability tier + resolved
provenance -> applicable) still decide each individual finding's reportability;
enabling lifts only the blanket diagnostic-only suppression. All gates re-run green
(R01 32/32, R02 16/16, integration 28/28 now testing enabled semantics, leveldb 7/7,
six-property aggregator 11/11).

## Full JS-to-native pipeline on @8crafter/leveldb-zlib -> BLOCKED BY REACHABILITY

The complete pipeline was run on the positive-path package with REAL facts (not empty
JS): pinned c2cpg + jssrc2cpg (astgen 3.47.0 built from source -- see
`../TOOLCHAIN_MAVEN_ASSEMBLY.md`) produced real native facts (3411 functions / 31114
calls) AND real JS facts (191 functions / 1555 calls, a 189 KB JS CPG over the
package's own JavaScript), then: frozen R02 scanner -> provenance -> reachability
(real JS + native) -> applicability -> adjudication -> staged enablement (enabled) ->
`aggregate_record_r02`. Frozen record: `FULL_PIPELINE_LEVELDB_RESULT.json`; reproducer:
`reproduce_full_pipeline_leveldb.py`.

Result, reported SEPARATELY across the five stages (frozen in
`FULL_PIPELINE_LEVELDB_RESULT.json`), for both `STATUS_GUARD_MISSING` findings:

| # | stage | outcome |
|---|---|---|
| 1 | raw N-API candidates | 3 supported sites: **2 STATUS_GUARD_MISSING / STATUS_DISCARDED** (returnKey@1440→1453, returnValue@1447→1454) + 1 ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED (`&argv[1]`) |
| 2 | JS/native reachability | **TIER_INTERNAL_UNREGISTERED** -- with REAL js+native facts (191 JS fns / 1555 calls, 189KB CPG), no proven JavaScript-to-native path to `HandleOKCallback` was established |
| 3 | provenance | **RESOLVED** -- `package/src/bindings.cpp`, real content hash |
| 4 | applicability | **NOT_YET_DETERMINED** -- raw-N-API applicability requires an allowed reachability tier; TIER_INTERNAL_UNREGISTERED is not allowed |
| 5 | reportability | **False** -- stage `REACHABILITY_REQUIRED_FOR_REPORTING`; aggregate napi row raw=3, reportable=0 |

The JS frontend used here is the rigorously-pinned astgen 3.47.0 (source build, integrity
anchored in `ASTGEN_PIN.json`: commit `e456abfe`, dist sha256 `fddb57ca`), validated
FIRST on a minimal JS fixture (`check_js_frontend.py` 4/4) before this real run.

**The two confirmed API-handling discrepancies do NOT become reportable -- they are
blocked at the reachability gate.** With real JS and native facts, the effective
function (`HandleOKCallback`, an async-worker callback) classifies as
`TIER_INTERNAL_UNREGISTERED`: the analysis examined it but established no proven
JavaScript-to-native path, so the reachability gate holds both findings non-reportable
(the same fail-closed discipline that keeps re2's internal helpers non-reportable).
Manual API-handling confirmation is explicitly NOT equated with JS exposure. These
remain confirmed API return-handling discrepancies, not confirmed vulnerabilities.

## Why HandleOKCallback is TIER_INTERNAL_UNREGISTERED (structural trace) -> stays unresolved

The `TIER_INTERNAL_UNREGISTERED` classification was traced structurally over the real
cpp facts (`HANDLEOK_REACHABILITY_TRACE.json`; reproduced as a permanent regression on
`fixture_asyncworker_reach.cpp` / `raw_asyncworker_reach/` /
`check_napi_status_reachability_asyncworker.py`, 9/9). The finding site is
`NextWorker::HandleOKCallback` (a NAN/napi async-worker override). The source chain is
real: `iteratorNext` (JS) -> `iterator_next` export -> `new NextWorker` + `Queue()` ->
`napi_queue_async_work` -> [async] `BaseWorker::Complete` (static trampoline) ->
`DoComplete` -> **virtual** `HandleOKCallback` -> the two sites. But the facts cannot
prove it:

1. **Zero** METHOD_REF/address-of references to `HandleOKCallback` -- it is never a
   callback reference; only the static trampolines `Execute`/`Complete` are.
2. `napi_create_async_work` registers `Execute`/`Complete`, **not** `HandleOKCallback`.
3. `new NextWorker` and `Queue()` carry **0** candidate targets (unresolved edges).
4. **The break:** `DoComplete -> HandleOKCallback` resolves in the facts to a **single,
   static candidate -- the BASE `BaseWorker::HandleOKCallback`**, not the derived
   override. `NextWorker::HandleOKCallback` has **no incoming call edge at all**; the
   polymorphic hop to the derived override is invisible to the frontend.
5. Abstention categories hit: second-order callback handoff (reached only through the
   `Complete` trampoline), ambiguous/unmodeled virtual dispatch (base-bound), and
   unresolved construction/queue edges.

**Controlled contrast (frozen fixture):** the async-work registration IS recognized --
`Execute`/`Complete` both classify `TIER_CALLBACK_OR_WORKER_PROVEN` -- yet
`NextWorker::HandleOKCallback` stays `TIER_INTERNAL_UNREGISTERED`. So the classification
is specifically the second-order/virtual-dispatch break, not a failure to see
`napi_create_async_work`.

**Verdict:** the facts cannot prove a unique JS-to-native chain to the site, so it
**stays internal/unresolved** -- no reclassification to the callback/worker tier, and
it remains non-reportable. **Because reachability is not established, no controlled
failure injection is performed:** these remain two confirmed API return-code handling
discrepancies, NOT confirmed vulnerabilities. No runtime behavior or security impact is
established or claimed.

## Live provenance gate: REPAIRED and passing (51/51)

`check_provenance.py` failed only because its hardcoded `JOERN_HOME` pointed at the
bootstrap install the environment cannot download. Repaired at the toolchain level (no
frozen-file edits): shim launchers at `joern-install/joern-cli/` exec the same
Maven-assembled Joern 4.0.608 (plus source-built astgen 3.47.0) already used
successfully, and `check_provenance.py` gained a `_resolve_joern_toolchain()` fallback
to the Maven classpath. It now reaches a **real 51/51 pass** -- node-libcurl runs the
full download->c2cpg->export->normalize->jssrc2cpg->export->link pipeline to ANALYZED
and reproduces the real Easy::ReadFunction finding. Not waived -- genuinely run and
recorded. Recipe: `../TOOLCHAIN_MAVEN_ASSEMBLY.md`.

## Provenance correction: full package-root manifest, conservative suffix reconciliation

**Correction applied (per review): an earlier pass narrowed `pkg_dir` to `src/` to make
the raw `bindings.cpp` field match trivially -- this silently changed the MEANING of
`source_tree_sha256` (no longer the complete package tree) and is wrong.** Fixed
properly: `pkg_dir`/the provenance manifest are always the FULL extracted package root
(208 real files; `source_tree_sha256` computed over the complete tree, unchanged by this
fix everywhere else in the pipeline). `napi_status_integration.reconcile_source_path`
(gate: `check_provenance_reconciliation.py`, 13/13) reconciles a raw methods.tsv file
field against the full manifest conservatively: exact path first; else a unique
path-suffix match (canonicalized to the real manifest path, e.g. `src/bindings.cpp`);
**abstains as `AMBIGUOUS_SOURCE_PATH`** (never guesses) when two or more real files share
the same suffix/basename; an unmatched field falls through to the existing
`PATH_NOT_IN_MANIFEST` reason, unchanged. Both findings' provenance re-verified RESOLVED
under this corrected, full-tree manifest (see `COMBINED_LEVELDB_RESULT.json`).

## Real pinned-addon runtime test (per review: build the real addon, real interposition)

**Correction applied: the earlier failure-injection result (hand-seeded stub, deterministic
sentinel) is relabeled `MODEL_FAILURE_PATH_CONFIRMED`** -- a useful sanity check of the
control-flow shape, not a runtime observation of the actual package. The harder proof was
then completed: the REAL pinned `linux-6-x64` prebuilt addon, loaded and driven through
the package's real public JS API (`db.open()` -> `db.put()` -> `db.getIterator()` ->
`it.next()`, the real `iterator_next` path), with `napi_create_buffer_copy` forced to fail
via test-only `LD_AUDIT` symbol-bind interposition (LD_PRELOAD was tried first and found
ineffective against this specific node binary, documented honestly).

**Result: the real addon reproducibly CRASHES (SIGSEGV, exit 139)** when the two flagged
sites' `napi_create_buffer_copy` calls fail -- baseline and a pass-through audit-machinery
control both exit 0, isolating the forced failure as the cause. A bounded `gdb -batch`
backtrace shows the exact real chain: `NextWorker::HandleOKCallback` ->
`napi_set_element` -> V8's `Object::Set`/`AddDataProperty`/`AddDataElement`, crashing
where the unavailable output is used. See `REAL_ADDON_TEST_RESULT.md` for the full setup,
all four run logs, and the backtrace. **No security impact, severity, or exploitability
is inferred from this outcome** -- it is a bounded, reproducible reliability/crash
observation only.

## Honest classification (updated)

```
Confirmed static API-handling discrepancies:      yes
Complete JS-to-native reachability:                yes (three-proof virtual tier)
Reportability:                                     yes (corrected, full-package-root
                                                    provenance; both findings resolved)
Modeled failure-path consequence:                  yes (MODEL_FAILURE_PATH_CONFIRMED)
Actual pinned-addon failure-path consequence:      yes -- reproducible SIGSEGV (exit 139)
                                                    in the real addon, real JS path,
                                                    bounded LD_AUDIT interposition
Confirmed vulnerability:                           no claim made
```

## Integration status (NAPI-STATUS-INTEGRATION-R01, per review)

Wired additively in `napi_status_integration.py` (gate: `check_napi_status_
integration.py`, 25/25): exact candidate allowlist -- `STATUS_GUARD_MISSING` AND its
caller-side `STATUS_DISCARDED_OUTPUT_USED_IN_CALLER` are BOTH candidates (the
vocabulary-mismatch correction; an unrecognized sub_reason fails closed loudly) --
provenance enrichment via the EFFECTIVE caller function, reachability via
reachability_tier's own classifier on that same function, raw-N-API applicability
(exact API, required outputs resolved, provenance resolved, allowed tier, NO
exception-configuration premise), an EMPTY exact-match adjudication registry
section, diagnostic-only staged enablement, and aggregator revision
`aggregate_record_r02` (delegates the six frozen properties to
`six_property_aggregator.aggregate_record` unchanged). The property is
DIAGNOSTIC-ONLY (`NAPI_STATUS_ENABLED = False`) until a real package exercises its
positive path.

## 97-bundle preserved-facts replay (review item 9): attempted, infrastructure result

`replay_napi_status_97.py` implements the replay over the preserved evidence bundles
(preserved cpp_raw for the scanner, preserved cpp_facts/js_facts for reachability,
optional pinned-tarball refetch for provenance, diagnostic-only enablement, r02
aggregation). Its `--selftest` proves the mechanics end to end on a synthetic bundle
built from the frozen R02 fixture facts (7 sites, full classification, 0 reportable).
The REAL run in this checkout: **INFRASTRUCTURE_FAILURE / PRESERVED_BUNDLES_ABSENT**
(`replay_97/replay_report.json`) -- `evidence_bundles_100/` is a gitignored scratch
output that exists only on the machine that ran the overnight corpus pass. Per the
pre-registered rule this is an infrastructure result, not a scanner negative and not
semantic evidence. The driver is ready to run where the preserved bundles exist.

## Mechanical candidate map (token triage, all 100 frozen-sample packages)

All 100 pinned tarballs fetched and hash-verified; per-package count of C/C++ files
containing the `napi_create_buffer` token (triage data for the pre-registered
fallback selection; a token-free package provably contains no direct supported call
site -- barring token-pasting macros, disclosed assumption):

| row | package | token files |
|---|---|---|
| 7 | @gjsify/napi@0.44.0 (dev pkg -- provider library) | 2 |
| 9 | @farcaster/rocksdb@5.5.0 (blind pkg) | 1 |
| 12 | @8crafter/leveldb-zlib@1.6.0 | 1 |
| 31 | @cocktailpeanut/node-pty-prebuilt-multiarch@0.11.16 | 1 |
| 37 | @depup/node-addon-api@8.9.2-depup.0 | 1 |
| 48 | @fugood/whisper.node@1.1.3 | 1 |
| 55 | @h1x4dev/node-addon-api@2.0.0 | 1 |
| 87 | napi-ldap@1.0.4 | 1 |
| 96 | smart-whisper@0.8.1 | 3 |
| 99 | @zowe/db2-for-zowe-cli@6.1.17 | 1 |

The other 90 packages: verified, zero token files. (Note: two of the ten are
node-addon-api forks -- likely provider libraries like the dev package, i.e.
definitions rather than call sites; the facts, not this table, decide.)

### Refinements surfaced by the blind run (addressed in R02 except where noted)

1. A literal `NULL` out-argument was resolved as a trackable "variable" (CDT binds
   `NULL` to a synthetic same-named local). ADDRESSED IN R02: optional roles record
   an explicit `opted_out`; NULL in a required role abstains.
2. Outputs escaping via forwarded pointer parameters place the real uses in CALLERS.
   ADDRESSED IN R02: escape detection, one-level caller analysis, derived
   proven-wrapper sites, and the `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`
   abstention (this site's corrected classification).
3. `input_size_origin` labels a call-expression size argument (`s->size()`) as
   `unresolved`; a `call_result` label would be more informative. NOT addressed in
   R02 (diagnostic field only; no verdict depends on it) -- candidate R03 polish.
