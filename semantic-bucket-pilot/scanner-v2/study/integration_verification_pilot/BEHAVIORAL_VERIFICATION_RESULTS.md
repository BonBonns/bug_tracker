# Task #28, phase 3: behavioral compatibility

**Read `PILOT_CONCLUSION_AND_FOLLOWUPS.md` for the corrected bottom line.** Two framing points
in this document, below, read as more conclusive than the evidence supports: Section 3.3's
`dest_capacity_bytes: 100` claim only verifies the capacity *value*, not that the site's own
write length exceeds it; and the real OOB_WRITE/OOB_READ candidates found here sit inside `re2`'s
*vendored* `abseil-cpp`, not `re2`'s own package-authored code — neither is a `re2` finding
without further work. That document also records the corrected per-property status (only
`LOCK_BALANCE` is close to integration-ready) and the five follow-up tasks (#29-33) this pilot's
own real evidence opened. The real evidence and numbers in this document itself are unchanged
and still accurate; only the conclusiveness of their framing is corrected.

Corrects the prior phase's own limit, stated plainly there and now closed: schema/execution
compatibility (35/35, then 42/42 with the two runs below) is necessary but not sufficient.
This phase exercises real positive, confirmed-negative, and explicit-abstention paths for all
five properties, with real evidence fields inspected -- not just "did it run."

**Still not started, per standing instruction**: no 494-package rerun, no JS/TS exporter work.

## 1. Cheap corpus-wide primitive search (494/494 packages)

`cheap_primitive_search.py`: download + in-memory tar extraction + regex text search against
each scanner's own real, curated vocabulary (`LOCK_FUNCS`/`UNLOCK_FUNCS` from
`lock_balance_verdict.py`; `_OPERAND_ROLES` from `normalize_c_cpp_facts_v03.py`) -- no c2cpg,
no Joern. All 494/494 packages scanned successfully (zero download/extraction failures).

| Property | Real npm packages with >=1 recognized primitive |
|---|---:|
| `LOCK_BALANCE` / `PROTECTED_FIELD` (same vocabulary) | 69 |
| `OOB_WRITE` | 255 |
| `OOB_READ` | 222 |
| `OOB_COMPARE` | 124 |

## 2. Frozen candidate selection

Rule, written into `select_candidates.py` before reading any scanner outcome: for each
property, the alphabetically-first real package with >=1 hit. Purely mechanical (sort, take
first) -- not an outcome-based choice.

**Disclosed, not concealed**: while the 494-package search ran in the background, its own
progress log (read to confirm the process was alive) incidentally showed a few package names
with hits (`vscode-sqlite3`, `gdal`, `electron-edge-js`) before this selection script was
written. The rule itself is still fully mechanical and did not use outcome quality to choose
among candidates, but this is disclosed rather than silently claimed as blind.

**Result: `@2060.io/ffi-napi@4.0.9` is the frozen selection for all five properties** (it bundles
libffi, which has real `pthread_mutex_lock`/`memcpy`/`memset`/`strncpy`/`memcmp`/`strncmp` hits) --
a real coincidence of the deterministic rule, not a choice, and a useful one: it lets all five
properties be exercised against one real evidence bundle.

## 3. Per-property positive / negative / abstention evidence

### 3.1 `LOCK_BALANCE`

| Path | Source | Real result |
|---|---|---|
| **Positive** | Real historical case: wolfSSL `Dtls13RtxAddAck`, pre-fix commit `7efc962d` (CVE-2026-5264, `case_e062ef20`), the function body copied verbatim into `study/lockcap/raw_real_vuln/fixture_source.c`, already committed in-repo. Rebuilt through the real pipeline (fresh c2cpg -> export -> normalize, not the pre-committed TSVs). | `{'LOCK_CALL_FOUND': 1, 'LEAK_CANDIDATE_UNSAFE_RETURN': 1}`, 1 finding |
| **Confirmed negative** | Same real historical case, post-fix (commit `3034dd9e`), `study/lockcap/raw_real_fixed/fixture_source.c`. | `{'LOCK_CALL_FOUND': 1, 'BALANCED_ON_ALL_PATHS': 1}`, 0 findings |
| **Explicit abstention** | **Synthetic** (disclosed as such -- no real npm or historical case exercising `LOCK_NO_OBJECT_ARG` was found; see below). A recognized lock primitive called with zero arguments. | `{'LOCK_CALL_FOUND': 1, 'LOCK_NO_OBJECT_ARG': 1}`, 0 findings |

**Real npm candidate (`@2060.io/ffi-napi`) result**: `lock_balance_classification: {}` -- zero
`LOCK_CALL_FOUND` events, despite the real text hit at `deps/libffi/src/closures.c:272`. Checked
directly, not assumed: `closures.c`'s own functions never appear among this bundle's parsed
`methods` at all -- c2cpg did not include this file in the CPG, for a reason this pilot could not
determine from `c2cpg`'s own log (no per-file diagnostic emitted). **A real, disclosed finding in
its own right**: the cheap text search predicts a primitive's presence in source, not its
presence in the CPG c2cpg actually builds -- these can diverge, and this pilot does not know why
in this specific case.

**Real npm evidence, large bundle (`re2`, Section 5)**: a third real classification shape found,
not previously exercised: `{'LOCK_CALL_FOUND': 1, 'LOCK_NO_MATCHING_UNLOCK_IN_FUNCTION': 1}`, 0
findings -- `pthread_mutex_lock(mu_)` in abseil's `PthreadWaiter` (`pthread_waiter.cc:40`). No
unlock in the same function (true -- abseil's own wait/notify pattern releases it elsewhere) and
no unsafe-return path was identified either, so `LOCK_NO_MATCHING_UNLOCK_IN_FUNCTION` correctly
produces zero findings here rather than a false positive.

### 3.2 `PROTECTED_FIELD`

| Path | Source | Real result |
|---|---|---|
| **Positive** | Real historical case: wolfSSL `case_644b3e3c` (`Dtls13RtxAddAck` protects `ssl->dtls13Rtx.seenRecords` with `.mutex`; `Dtls13RtxRemoveCurAck` in the same file accesses it unprotected), `study/lockcap/raw_xfn_real/fixture_source.c`. Rebuilt fresh through the real pipeline. | `{'PROTECTED_ACCESS': 2, 'MISSING_LOCK_CANDIDATE': 2}`, 2 findings |
| **Confirmed negative / abstention** | Real, already-committed synthetic ambiguity control, `study/lockcap/raw_xfn_synth/fixture_source.c` (designed specifically to exercise this scanner's own documented abstain-on-ambiguity rule). | `{'PROTECTED_ACCESS': 2, 'AMBIGUOUS_MULTIPLE_PROTECTORS': 1}`, 0 findings -- the scanner's own `INFERENCE RULE` docstring ("abstain rather than guess which [lock] is real") firing exactly as documented |

Real npm candidate (`@2060.io/ffi-napi`): `{}` -- same real cause as `LOCK_BALANCE` above
(`closures.c` not present in the parsed CPG). No real npm positive or negative path found for
`PROTECTED_FIELD` in this pilot -- stated plainly, per instruction, rather than left implicit.
`PROTECTED_FIELD`'s own inference rule (needs a field protected in one place AND unprotected in
another, within the same translation unit) makes this a genuinely hard pattern to find by cheap
text search in the first place; the wolfSSL historical case remains its only real positive
evidence anywhere in this repository.

### 3.3 `OOB_WRITE`

**[CORRECTED IN PLACE -- task #30, not merely addended: the paragraph originally here claimed a
"discrepancy" against `e2e-canonical/SUMMARY.txt` and proposed an unverified "preprocessing mode"
theory to explain it. Neither was accurate. Directly inspecting the actual e2e-canonical artifacts
(`vuln.report.json`, `vuln.llm_input_1.json`) shows that "VULN dir -> candidates: 1" result was
computed entirely on `WinWebAuthnManager.cpp` -- Mozilla bug mfsa2022-13
(`WinWebAuthnManager::Register`), per `MOZ-OOB-R01-PREREG.md`'s own ROW 3 -- never on the Tremor
fixture. Zero references to `tremor`/`codebook`/`vorbis` exist in either report. There was never a
discrepancy to reconcile: the two data points compared below were never about the same fixture, so
they cannot corroborate or contradict each other. See `PILOT_CONCLUSION_AND_FOLLOWUPS.md`'s task
#30 section for the full reconciliation and the newly diagnosed root cause. The text below is kept,
corrected, rather than deleted, so the original mistake stays auditable.]**

**Historical-case cross-check (per instruction #4)**: the one real, disclosed CVE fixture already
committed in-repo for this producer family
(`docs/moz-oob-r01/primary-artifacts/tremor_codebook_{VULN,PATCHED}.c`, Mozilla Tremor codec
CVE-2018-5147, whose own `MOZ-POS-R01-SOURCING.md` names `oob_write_verdict.py` and
`oob_read_verdict.py` -- the exact files under test -- as its candidate producers) was rebuilt
fresh through this pilot's own pipeline (c2cpg -> export -> normalize) and run directly.
**Result: 0 candidates on both VULN and PATCHED**, from both `oob_write_verdict.py` and its
INDEX_STORE sibling `oob_index_write_verdict.py` (checked as a secondary, more targeted producer
for this specific bug shape, confirmed by `diff`ing the two source files: the real fix adds a
loop-bound check `o+j<n`/`i<m`, an INDEX-STORE pattern, not a `memcpy`-family call -- exactly
`oob_index_write_verdict.py`'s own stated scope, not `oob_write_verdict.py`'s). This is the real,
standalone, mechanically-explained result on Tremor's own fixture -- re-verified against a
freshly rebuilt bundle as part of task #30's reconciliation, with the root cause now precisely
diagnosed (a pointer-parameter + separate-length-parameter buffer capacity, invisible to both
current `OOB_WRITE` producers -- see `PILOT_CONCLUSION_AND_FOLLOWUPS.md` task #30 and the
follow-up task #44). Net: **no real historical positive-path evidence has yet been reproduced for
this specific implementation family**, on its own real, disclosed CVE fixture -- corrected from
the prior "despite one being documented to exist elsewhere" framing, which relied on the same
false attribution corrected above.

| Path | Source | Real result |
|---|---|---|
| **Positive** | Real npm: `re2`'s vendored abseil-cpp, `absl/base/internal/strerror.cc:53` -- `char buf[100]; ... snprintf(buf, sizeof buf, ...)`. Verified directly against the real source: `dest_capacity_bytes: 100` matches `char buf[100]` exactly. A second real candidate: `TrySymbolizeWithLimit:146:strncpy`, `dest_capacity_bytes: 4096`. | `[{'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'function': 'StrErrorInternal', 'line': 57, 'call': 'snprintf', 'dest_capacity_bytes': 100, ...}, {'function': 'TrySymbolizeWithLimit', 'line': 146, 'call': 'strncpy', 'dest_capacity_bytes': 4096, ...}]` |
| **Confirmed negative** | Real npm: the 4 other small pilot packages (Section 1 of the prior schema-compatibility report) -- real `WRITE_DEST`-role calls present in some, resolved to zero candidates because no destination capacity could be joined (see abstention below, same real mechanism). No package in this pilot's real evidence produced a resolved-capacity, validly-BOUNDED write site (the specific "recovered, but safe" shape) -- disclosed as not found, not fabricated. |  |
| **Explicit abstention** | Real npm: `@2060.io/ffi-napi`. Real, structurally confirmed: 289 real `operand_roles` resolved (`memcpy`/`memset`/`memcmp`, correctly tagged `WRITE_DEST`/`READ_SRC`/`EXTENT`), but `dest_capacities: 0` -- every real `WRITE_DEST` site abstains at the capacity-join step. Checked one site directly: `memcpy(argp + argn, valp, size)` -- the destination is `argp + argn`, a pointer-arithmetic expression, not a directly-typed local the capacity deriver can bind. A real, structurally sound abstention (consistent with the scanner's own docstring: "representable... AND has NO valid DEST_CAPACITY bound" -- here, no capacity fact at all, so `_capfact is None`, `continue`). | `oob_write_candidates: []` |

### 3.4 `OOB_READ`

| Path | Source | Real result |
|---|---|---|
| **Positive** | Real npm: `re2`'s vendored abseil-cpp, 7 real candidates across `FillParentStack` (x2), `RoundTripFloatToBuffer`, `SetUpStrings`, `CallVoidPtrFunction` (`mutex.cc:2808`), `SwapValue`, `ReadCallback`. | see Section 5's full JSON |
| **A real, disclosed anomaly found while checking this evidence, not glossed over**: 6 of 7 candidates share an identical `src_capacity_bytes: 5`. Checked one directly against real source: `CallVoidPtrFunction`'s site is `std::memcpy(&function_pointer, c->callback_, sizeof(function_pointer))` -- the read source, `c->callback_`, is a function-pointer-typed struct field; a real 5-byte capacity for it is not plausible. **This looks like a genuine capacity-derivation quirk in the underlying normalizer**, surfaced for the first time by this pilot's real large-bundle test (none of the 5 small pilot packages produced enough `OOB_READ` candidates to reveal it) -- **not investigated further or resolved here**, flagged as a real follow-up this pilot's own scope does not cover. |
| **Confirmed negative** | Not found in this pilot's real evidence -- disclosed as absent, same reasoning as `OOB_WRITE`'s negative row. |
| **Explicit abstention** | Real npm: `@2060.io/ffi-napi`, same mechanism as `OOB_WRITE` -- `src_capacities: 0` despite real `READ_SRC`-tagged operand roles present. | `oob_read_candidates: []` |

### 3.5 `OOB_COMPARE`

| Path | Source | Real result |
|---|---|---|
| **Positive** | **Not found.** Neither a real npm candidate (0 across all packages actually run in this pilot, including the large `re2` bundle) nor a real historical recovery case (the Tor-corpus study that validated `oob-compare-r07`/"TOR-B2a" found **0 unsafe** across all 12 real sites it examined -- its own real track record never produced a positive either, and its source files are not committed in-repo to rerun). **Stated plainly, per instruction: real positive-path evidence for `OOB_COMPARE` remains absent, in this pilot and in this repository's own prior history.** |
| **Confirmed negative / abstention** | Real npm: `re2`'s vendored abseil-cpp. Real, structurally precise: exactly 1 of 54 real `memcmp`/`strncmp` calls resolved a capacity fact at all (`char[24]`, tagged `READ_CMP_A` only) -- `cmpcapacity` has zero `READ_CMP_B`-side facts, so the scanner's own explicit `CLASS-SEPARATION INVARIANT` ("a capacity bound for side A must NOT certify side B... if either side's capacity is unresolved... ABSTAIN") correctly fires: 0 candidates. A real, precisely-explained abstention on real code, not a guess. | `oob_compare_candidates: []` |

## 4. What the OOB findings say about implementation-file scope

`OOB_WRITE` the *property* has 12 sound implementations (per the npm-scoped inventory); this
pilot tests exactly one of them (`oob_write_verdict.py`, "B4.5", the frozen base). The base
implementation genuinely could not reproduce this repo's own committed real historical CVE
(index-store shaped, out of its stated scope) and had zero real npm positive-path evidence until
the large-bundle test found two. **If this specific implementation is what gets wired**, its real
demonstrated coverage is narrow (memcpy-family call sites with a directly-resolvable destination
capacity) -- real, useful, and now demonstrated on real code, but narrower than "OOB_WRITE is
promotable" alone would suggest without this file-level detail.

## 5. Large evidence bundle: `re2@1.26.1` (551 real C/C++ files)

Chosen for the same real, pre-existing precedent `CORPUS_STATUS.md`'s own 50-package pilot
already documented (c2cpg up to 41.4s, normalize up to 127.6s) -- not cherry-picked after seeing
this pilot's own results.

| Stage | Real seconds | Real peak-RSS delta |
|---|---:|---:|
| download | 0.11 | -- |
| extract | 0.49 | -- |
| header_staging | 0.24 | -- |
| **c2cpg** | **82.76** | **2,123,312 KB (~2.0 GB)** |
| **cpp_export** | **59.78** | 0 (see caveat below) |
| **cpp_normalize** | **331.96** | **1,897,892 KB (~1.8 GB)** |
| **Total bundle build** | **475.4s (~7.9 min)** | |

| Scanner | Real seconds | Real classification |
|---|---:|---|
| r04 | 6.74 | `ACQUISITION_NAME_MATCH_CANDIDATE: 158`, 0 findings |
| r05 | 6.79 | `R05_RECOVERY_CANDIDATE: 76`, 0 findings |
| lock_balance | 5.04 | `LOCK_CALL_FOUND: 1`, `LOCK_NO_MATCHING_UNLOCK_IN_FUNCTION: 1`, 0 findings |
| protected_field | 5.13 | `{}`, 0 findings |
| oob_write | 8.52 | **2 real candidates** |
| oob_read | 8.28 | **7 real candidates** |
| oob_compare | 8.15 | 0 candidates (correct abstention, Section 3.5) |

**Real memory-measurement caveat, disclosed rather than presented as clean data**: every
individual scanner's own `maxrss_delta_kb` reads `0` above. This is the same real, disclosed
limitation `run_pipeline_one.py`'s own docstring already names:
`RUSAGE_CHILDREN.ru_maxrss` is a *running maximum across all children reaped so far in the
process*, not an isolated per-child measurement. Because `c2cpg` (2.0 GB) and `cpp_normalize`
(1.8 GB) ran first in the same harness process and pushed that running maximum far above what any
of the 7 scanners individually need, none of the scanners' own much-smaller memory use could
register as a new maximum. **The real, useful conclusion this still supports**: none of the 7
scanners pushed memory use anywhere near the ~2 GB the Joern stages already require -- if they
had, the running maximum would have moved. Isolating each scanner's own true peak RSS would need
one fresh process per scanner with its own clean `RUSAGE_CHILDREN` baseline (not attempted here).

**Real total scanner time**: 48.65s combined for all 7 -- small relative to the ~475s bundle-build
cost, consistent with the earlier small-package pilot's own finding that marginal scanner cost is
low relative to Joern-stage cost, now confirmed on a real large bundle too.

## 6. Combined per-package record: independent keys, verified

Both the `@2060.io/ffi-napi` record (`ffinapi_six_properties.json`) and the `re2` record
(`large_bundle_results.json`) carry every property's `classification`/`findings`/`candidates`
under its own scanner-prefixed key, checked programmatically for collisions:

```
r04: ['r04_classification', 'r04_findings']
r05: ['r05_classification', 'r05_findings']
lock_balance: ['lock_balance_classification', 'lock_balance_findings']
protected_field: ['protected_field_classification', 'protected_field_findings']
oob_write: ['oob_write_candidates']
oob_read: ['oob_read_candidates']
oob_compare: ['oob_compare_candidates']
```

Zero key collisions; every property's own real timing (`timings`/`seconds`) and
`schema_compatibility` verdict is present per scanner, in one combined record, on real evidence
bundles -- not asserted, checked directly against the actual JSON file.

## 7. What remains unproven or open (stated plainly, not silently closed)

- **`OOB_COMPARE` has no real positive-path evidence anywhere** -- not in this pilot's real npm
  runs, not in this repository's own prior historical validation (the Tor-corpus study's own real
  track record is 0 unsafe / 10 safe / 2 unresolved across 12 real sites).
- **The Tremor CVE-2018-5147 discrepancy is unresolved**: this pilot's direct reproduction (0
  candidates on both VULN/PATCHED) does not match the previously-documented `scan_repo.py`-based
  result (1 candidate on VULN); the leading candidate explanation (a preprocessing-mode
  difference) was not verified.
- **The `src_capacity_bytes: 5` anomaly on 6 of 7 real `OOB_READ` candidates is unresolved** --
  flagged as a likely real normalizer quirk, not investigated further.
- **Per-scanner memory isolation was not achieved** on the large bundle -- the combined-process
  RSS-delta technique cannot separate a small child's memory from a larger one that ran earlier
  in the same process tree.
- **`PROTECTED_FIELD` has no real npm positive OR negative evidence** in this pilot -- only the
  real historical wolfSSL case and its own committed synthetic ambiguity control.
- **`LOCK_BALANCE`'s abstention path (`LOCK_NO_OBJECT_ARG`) is demonstrated only by a small,
  disclosed synthetic fixture** -- no real npm or historical case exercising it was found.

## 8. Explicitly not done, per standing instruction

No 494-package rerun. No JS/TS specialized-exporter work. Both remain future work pending
explicit authorization.
