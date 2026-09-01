# Overnight 100-package frozen diagnostic run — morning report

Run: `run_diagnostic_100.py --sample overnight_sample_100.tsv --output
overnight_diagnostic_working.jsonl --bundle-dir evidence_bundles_100 --workers 2 --resume
--diagnostic-only`, `claude/overnight-diagnostic-100`. Started and finished within this session
(no restart needed); background task id `bprg6djcd`, exit code 0.

Per the launching instruction, this report contains **only** completion status, timing,
resource usage, raw candidate/finding counts, unresolved/abstention distributions, reachability
status, provenance-hint distribution, and failure detail. It draws **no vulnerability totals, no
true-negative claims, and no corpus-prevalence claims** from this run. The remaining 394
packages were **not** launched.

## 1. Completion status

- **100/100** sampled packages recorded. Process exited on its own (exit code 0) after
  processing all 100 — no manual stop was needed, no stop condition was tripped.
- Status distribution: `ANALYZED: 97`, `CPP_CPG_FAILED: 2`, `EXPORT_FAILED: 1`.
- 10/10 checkpoints written (`checkpoint_0010.json` … `checkpoint_0100.json`), one every 10
  packages as specified.
- No timeout, disk-floor, or consecutive-failure stop condition appeared anywhere in the run log.

## 2. Failures (3/100)

| package | version | status | notes |
|---|---|---|---|
| `@farcaster/rocksdb` | 5.5.0 | `CPP_CPG_FAILED` | c2cpg stage failed; download/extract/provenance/header-staging stages all completed normally first |
| `duckdb` | 1.4.4 | `CPP_CPG_FAILED` | c2cpg stage failed; same — earlier stages completed normally |
| `@driftlog/tree-sitter-dart` | 1.0.4 | `EXPORT_FAILED` | slowest run in the whole sample (1358.9s) before failing at export |

None of the three produced an evidence bundle (bundle count matches exactly the 97 `ANALYZED`
packages — no bundle silently dropped for a success, none spuriously created for a failure).

## 3. Per-stage timing (real, all 100 packages, seconds)

| stage | n | mean | max | total |
|---|---:|---:|---:|---:|
| download | 100 | 0.54 | 12.70 | 53.6 |
| extract | 100 | 0.62 | 17.62 | 61.9 |
| provenance_manifest | 100 | 0.11 | 3.43 | 10.9 |
| header_staging | 100 | 0.34 | 6.63 | 34.3 |
| c2cpg | 100 | 21.73 | 734.71 | 2173.4 |
| jssrc2cpg | 98 | 5.89 | 27.94 | 577.6 |
| cpp_export | 98 | 23.24 | 613.64 | 2277.8 |
| js_export | 97 | 12.99 | 52.54 | 1260.2 |
| cpp_normalize | 97 | 19.02 | 436.91 | 1844.7 |
| js_normalize | 97 | 4.62 | 397.58 | 447.7 |
| polyglot_link | 97 | 5.69 | 87.91 | 552.0 |
| r04_scan | 97 | 0.68 | 9.28 | 65.9 |
| r05_scan | 97 | 0.70 | 9.23 | 68.0 |
| lock_balance_scan | 97 | 0.49 | 7.77 | 47.9 |
| protected_field_scan | 97 | 0.54 | 8.38 | 52.1 |
| oob_write_scan | 97 | 0.93 | 12.76 | 90.2 |
| oob_index_write_scan | 97 | 10.31 | 180.70 | 999.7 |
| oob_read_scan | 97 | 0.95 | 11.56 | 92.4 |
| oob_compare_scan | 97 | 0.92 | 12.09 | 89.4 |

Whole-package wall time across the 100: min 24.9s, median 41.0s, mean 116.5s, max 1358.9s
(`@driftlog/tree-sitter-dart`, the export failure), total 194.2 minutes. c2cpg/cpp_export/
cpp_normalize dominate the tail latency (largest real C/C++ trees — `@confluentinc/kafka-
javascript`, `@flyskywhy/react-native-gcanvas`, `@appthreat/sqlite3` among the slowest).

**Memory**: no per-package peak-memory metric was instrumented in this run — disclosed honestly
rather than fabricated. The 4GB/package ceiling (section 7 of the launch spec) was enforced as a
resource *limit* on the subprocess environment, not *measured and logged* per package; no
package was observed to fail from resource exhaustion (all 3 failures were tool-stage failures
at c2cpg/export, not OOM).

## 4. Evidence bundle disk usage

`evidence_bundles_100/`: **465M** total, 97 bundles (one `<pkg>@<version>.tar.gz` per `ANALYZED`
package, none for the 3 failures) — average ~4.8MB/bundle. Disk remained well above the 5GB
floor throughout (60% used / 16G free on the run's own filesystem at completion, vs. the 5GB
stop-condition floor).

## 5. Raw candidate/finding counts by property (NOT filtered by reportability — this run enforces
`reportable=False` on all of them by design; these are raw scanner output counts, not a
vulnerability count)

| property | raw count |
|---|---:|
| `oob_index_write_candidates` | 3290 |
| `protected_field_findings` | 233 |
| `oob_write_candidates` | 252 |
| `oob_read_candidates` | 115 |
| `lock_balance_findings` | 12 |
| `r05_findings` | 7 |
| `r04_findings` | 2 |
| `oob_compare_candidates` | **0** |

Total: 3911 raw records across 97 analyzed packages. `oob_compare_candidates` being 0 in this
100-package diagnostic sample is a real, disclosed diagnostic observation — not evidence toward
task #33's "definitively rule out" question (100 packages is not the corpus, and OOB_COMPARE
remains `UNVALIDATED_PROPERTY` regardless of this count).

`lock_balance_findings` reason breakdown: `NO_RELEASE_ANYWHERE_IN_FUNCTION` 8,
`RETURN_REACHABLE_WITHOUT_MATCHING_UNLOCK` 4. `protected_field_findings`: all 233
`FIELD_ACCESSED_OUTSIDE_ITS_INFERRED_LOCK`. `r04_findings`: all 2
`ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED`. `r05_findings`: `VALUE_ACQUISITION_GUARD_
MISSING` 5, `ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED` 2 (totals 7, matching the raw
count above).

## 6. `reportable` / diagnostic-enforcement confirmation

**Every one of the 3911 raw records has `reportable: false`.** Verified directly, not sampled:
`reportable` value distribution across all 3911 records is `{False: 3911}` — zero `True`,
matching the diagnostic-only mode's own preflight assertion (`preflight_assert_non_reportable`)
run twice per record during the live pipeline. `diagnostic_override` is `ALREADY_NON_REPORTABLE`
on all 3911 (provenance.py's own reportable formula already computed `False` for every one of
them, so diagnostic-only mode never needed to force-override a `True` — `FORCED_NON_REPORTABLE_
diagnostic_only_run` occurs 0 times in this run, meaning the reportable formula and the
diagnostic-only guard agreed on every record, not that the guard was untested).

Diagnostic labels attached as designed:
- `resource_guard_status: PRECISION_FIX_NOT_INTEGRATED` on all 9 `r04_findings`/`r05_findings`
  (task #41 not yet merged).
- `property_status: DEVELOPMENT_ONLY` on 1310/3290 `oob_index_write_candidates` — specifically
  those whose `derivation.capacity_source == PARAM_LENGTH_PAIR` (task #44's own producer; the
  other 1980 come from the pre-existing, differently-derived index-write path and carry no
  `property_status` override).
- `property_status: UNVALIDATED_PROPERTY` would appear on `oob_compare_candidates` — moot here
  since the raw count is 0.

## 7. Reachability status

`reachability_status: REACHABILITY_UNRESOLVED` on all 3911 records — expected and correct: task
#32 (tiered JS/native reachability) was not yet complete when this run launched
(`promote_via_js_linkage.py` is real but unused in this pipeline, as documented in
`prelaunch_gates.log`), so every finding correctly abstains on reachability rather than guessing.

## 8. Provenance-hint distribution

`VENDORED_HINT: 2413`, `PACKAGE_OWNED_HINT: 1498` — all 3911 records had `provenance.resolved:
true` (0 unresolved). This is the raw hint distribution over findings, not a deduplicated or
attributed count — task #31's `vendored_attribution.py` (completed after this run had already
launched, on `claude/provenance-preservation-task35`) was not part of this pipeline's own code
path; applying it as a downstream post-process against this run's own JSONL is straightforward
future work, not done here since it would mean editing already-frozen run output.

## 9. What this run does NOT establish

Per the launch instruction, restated for the record: this run makes no vulnerability-count claim,
no true-negative claim, and no corpus-prevalence claim. Every one of the 3911 raw records is
`reportable=False` by construction (diagnostic-only mode) and additionally carries
`applicability_status: NOT_YET_DETERMINED` / `adjudication_status: NOT_ADJUDICATED` on all 3911
— none of them have been through applicability or adjudication review. The remaining 394
packages in the 494-package corpus were not launched and remain untouched.
