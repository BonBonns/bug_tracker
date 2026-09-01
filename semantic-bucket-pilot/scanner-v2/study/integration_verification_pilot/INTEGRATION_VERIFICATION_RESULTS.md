# Task #28: integration-verification pilot — results

Phase 1 (schema compatibility) and phase 2 (combined six-property pilot) of task #28, run per
direct instruction, on a new isolated branch (`claude/oob-lockbalance-integration-pilot`, based
on `claude/aggregate-kinds-producer-test-03zs7n` — the branch carrying the header-staging fix
and the finalized R05 corpus results). **No 494-package rerun and no JS/TS exporter work was
started — both remain explicitly out of scope until these outputs and their resource costs are
reviewed**, per direct instruction.

## What this ran

`run_pilot.py` reuses `run_pipeline_one.py`'s own download/extract/header-staging/c2cpg/export/
normalize functions **verbatim** (imported as a module, not reimplemented), so every evidence
bundle here was produced by the exact same real pipeline code the stopped 494-package corpus
scan itself used — the only difference is that intermediate artifacts are *kept*, not deleted,
so they exist as real, inspectable evidence bundles under `/tmp/integration_pilot_bundles/`
(not committed — real per-package Joern fact tables are large TSV/JSON data, consistent with the
existing pipeline's own disk-bounding discipline).

For each package, all **six properties'** scanners ran against the **same** real bundle:

| Property | Scanner | Reads |
|---|---|---|
| `FALLIBLE_BOUNDED_RESOURCE` (already executed by the stopped pipeline — run again here only so this pilot's six-property record is directly comparable) | `resource_guard_verdict_r04.py` + `_r05.py` | `cpp_raw/` (raw TSVs) |
| `LOCK_BALANCE` | `lock_balance_verdict.py` | `cpp_raw/` (raw TSVs) |
| `PROTECTED_FIELD` | `protected_field_verdict.py` | `cpp_raw/` (raw TSVs) |
| `OOB_WRITE` | `oob_write_verdict.py` | `cpp_facts.json` + `.operandrole.json` + `.destcapacity.json` + `.bound.json` |
| `OOB_READ` | `oob_read_verdict.py` | `cpp_facts.json` + `.operandrole.json` + `.srccapacity.json` + `.bound.json` |
| `OOB_COMPARE` | `oob_compare_verdict.py` | `cpp_facts.json` + `.operandrole.json` + `.cmpcapacity.json` |

**A real finding from this phase, established by reading source before running anything**: the
inventory's `READY_TO_WIRE_WITH_CURRENT_FACTS` classification said all five properties "consume
`export_c_cpp_facts_v03.sc`, the same raw fact table `run_pipeline_one.py` already generates."
That is exactly true for `LOCK_BALANCE`/`PROTECTED_FIELD` (both read `cpp_raw/` directly, same
as R04/R05) — but for `OOB_WRITE`/`OOB_READ`/`OOB_COMPARE`, it understated one real intermediate
step: they don't read the raw TSVs at all, they read `cpp_facts.json` and five sidecar files
(`.operandrole.json`, `.destcapacity.json`/`.srccapacity.json`/`.cmpcapacity.json`, `.bound.json`)
produced by `normalize_c_cpp_facts_v03.py` — the SAME normalizer `run_pipeline_one.py` already
runs for every package (`cpp_raw -> cpp_facts.json`), which turns out to *also* emit those five
sidecar files as a documented side effect, confirmed by reading `normalize_c_cpp_facts_v03.py`'s
own source before running anything. So the inventory's classification holds in substance — no
new Joern export stage is needed, only feeding the OOB scanners a byproduct the pipeline already
produces and currently discards — but it was an inventory-level inference until this pilot
actually generated real sidecar files from a real bundle and confirmed each scanner could read
them without a schema error.

## Phase 1: schema compatibility (`schema_check_results.jsonl`)

One package: `@fqlan/add-example-prebuild` — the same package `run_pipeline_one.py`'s own module
docstring says the *original* pipeline was manually validated against before that script was
written, making it the most directly comparable real evidence bundle available.

**Result: all 7 scanner invocations (6 properties; R04+R05 are two revisions of one property)
ran to completion with no schema error, no missing-file exception, no crash.**

| Scanner | schema_compatibility | seconds |
|---|---|---:|
| `r04` | COMPATIBLE | 0.08 |
| `r05` | COMPATIBLE | 0.04 |
| `lock_balance` | COMPATIBLE | 0.03 |
| `protected_field` | COMPATIBLE | 0.03 |
| `oob_write` | COMPATIBLE | 0.00 |
| `oob_read` | COMPATIBLE | 0.00 |
| `oob_compare` | COMPATIBLE | 0.00 |

Real bundle-build timing for this package: download 0.28s, extract 0.004s, header_staging
0.22s, **c2cpg 4.96s, cpp_export 13.32s** (the two real dominant costs, consistent with the
50-package pilot's own documented real numbers in `CORPUS_STATUS.md`), cpp_normalize 0.06s.

## Phase 2: combined six-property pilot (`multi_pilot_results.jsonl`)

Five small real packages (`n_cpp_files == 1` each, from `eligible_packages.tsv`), deliberately
kept small per the "before any corpus rerun" instruction: `@fqlan/add-example-prebuild`,
`@camol/file-lock`, `@archwayhq/keyring-go`, `@deepfocus/get-windows`, `@co_snow/hello`.

**Result: 35 of 35 real scanner invocations (5 packages × 7 scanner runs) reported
`COMPATIBLE`. Zero schema errors, zero missing-sidecar exceptions, zero crashes.**

### Real behavior recorded (not just "did it run")

| Counter | Value across all 5 packages |
|---|---:|
| `r04_classification[ACQUISITION_NAME_MATCH_CANDIDATE]` | 76 |
| `r05_classification[R05_RECOVERY_CANDIDATE]` | 76 |
| `r04_findings` / `r05_findings` | 0 / 0 |
| `lock_balance_classification` | `{}` (zero `LOCK_CALL_FOUND` events — see disclosure below) |
| `protected_field_classification` | `{}` |
| `lock_balance_findings` / `protected_field_findings` | 0 / 0 |
| `oob_write_candidates` / `oob_read_candidates` / `oob_compare_candidates` | 0 / 0 / 0 |

**Honest disclosure, checked directly rather than assumed**: the zero counts for
`LOCK_BALANCE`/`PROTECTED_FIELD`/all three OOB properties are not a sign of a broken
integration — verified by inspecting one real bundle's own facts directly.
`@camol/file-lock`'s real C++ code calls `flock()` (POSIX advisory file-locking), not any
function in `LOCK_FUNCS`'s curated table (`pthread_mutex_lock`, `wc_LockMutex`, `k_mutex_lock`,
`spin_lock`, `mutex_lock`, `PR_Lock`, `EnterCriticalSection`) — a real, correct "not applicable"
result given this package's own real API choice, not a missed match. Its
`cpp_facts.json.operandrole.json` genuinely contains `operand_roles: []` — confirmed empty
because this package's only 34 distinct call names are file-I/O and string calls
(`c_str`, `flock`, ...), none matching the `WRITE_DEST`/`EXTENT`/`READ_SRC` role table at all —
not an empty file from a broken producer.

**This is a real, disclosed limitation of this specific 5-package sample, stated plainly**: it
proves schema compatibility (structurally: every scanner read real facts and produced
real-shaped output) but does **not** exercise a true positive path for `LOCK_BALANCE`,
`PROTECTED_FIELD`, or any of the three OOB properties — none of these 5 tiny packages happens to
contain the specific API calls any of those five scanners are built to recognize. `R04`/`R05`
did exercise real candidate/recovery-candidate volume (76 each) because `Napi::`-style
constructor calls are common in any node-addon-api package, but did not exercise a real
`VALUE_ACQUISITION_GUARD_MISSING` finding on this particular sample either. Proving a genuine
positive path for the other five properties needs a package independently known to use a
recognized lock primitive or a raw `memcpy`/`strcpy`-family write/read/compare — not attempted
in this pilot, consistent with keeping it small before review, and flagged here as the next
open question rather than silently left implicit.

### Real resource costs (the numbers this review is specifically for)

| Stage | avg seconds (5 packages) | max seconds |
|---|---:|---:|
| download | 0.31 | 0.57 |
| extract | 0.02 | 0.08 |
| header_staging | 0.22 | 0.35 |
| **c2cpg** | **3.25** | 3.50 |
| **cpp_export** | **11.67** | 14.22 |
| cpp_normalize | 0.10 | 0.14 |
| r04 scan | 0.06 | 0.08 |
| r05 scan | 0.05 | 0.06 |
| lock_balance scan | 0.04 | 0.04 |
| protected_field scan | 0.04 | 0.06 |
| oob_write scan (in-process) | 0.01 | 0.01 |
| oob_read scan (in-process) | 0.01 | 0.01 |
| oob_compare scan (in-process) | 0.01 | 0.01 |

**The marginal real cost of adding all 5 new scanners to a per-package pipeline run is
negligible relative to the existing c2cpg/cpp_export stages** — roughly 0.15s of new scanner
time against ~15s of Joern-stage time already paid for every package today (these 5 packages
are trivially small; `CORPUS_STATUS.md`'s own 50-package pilot numbers show c2cpg up to 41.4s
and `cpp_export` proportionally larger on real, larger packages — the marginal scanner cost
should scale sub-linearly relative to Joern's own cost either way, since none of these 5 new
scanners re-runs Joern itself, only reads facts Joern already produced). This pilot did not
attempt to characterize scanner cost on a large, real bundled C++ codebase (e.g. `re2`,
`pqclean` from the original 50-package pilot's own documented exceptions) — a real, disclosed
gap in this cost estimate, not resolved here.

## What this does and does not establish

- **Does establish**: real input-schema compatibility for all 5 `READY_TO_WIRE_WITH_CURRENT_FACTS`
  properties, on real evidence bundles built by the real pipeline code, not synthetic fixtures.
  Confirms the OOB family's exact real fact-chain (`cpp_facts.json` + 5 sidecar files, all
  produced by the normalizer stage the pipeline already runs). Real per-scanner timing, showing
  negligible marginal cost against the existing Joern-stage cost. Independent JSON keys per
  scanner, verified non-colliding with the existing `r04_`/`r05_` keys.
- **Does NOT establish**: a true positive-path validation for `LOCK_BALANCE`, `PROTECTED_FIELD`,
  `OOB_WRITE`, `OOB_READ`, or `OOB_COMPARE` on any real npm package — this 5-package sample
  happens to contain none of the triggering API calls for any of those five. Also does not
  characterize resource cost on a large, real bundled C++ package. Both are open, honestly
  flagged next steps, not attempted here given the explicit "small pilot" scope.

## Explicitly not done, per direct instruction

No 494-package rerun was started. No JS/TS specialized-exporter work was started. This document
and its two `.jsonl` result files are the complete output for review before either of those
proceeds.
