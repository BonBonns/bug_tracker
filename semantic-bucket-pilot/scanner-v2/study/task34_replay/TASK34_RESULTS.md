# TASK #34 RESULTS: six-property aggregator replay over the frozen 100-package diagnostic sample

**develop commit replayed against:** `fdb22fa5af01cbaab9577d85906f0a33515f0e62`

**This is a replay, not a new corpus run.** No Joern invocation, no CPG rebuild, no C/C++/JS facts regeneration. R06 (resource_guard_verdict_r06.py) is the one property computed fresh, run over each package's own PRESERVED cpp_raw/*.tsv, because these bundles predate R06's wiring into run_pipeline_one.py -- every other property's raw output is the original scanner output from the completed overnight run, reused verbatim. Per-file source bytes were re-fetched from the exact pinned tarball URLs recorded by the original run, SOLELY to reconstruct missing provenance (content_hash); no scanner stage consumed the re-fetched source, and it was deleted immediately after provenance enrichment, per direct instruction.

## Claims boundary

`reportable=true` means eligible for manual security review as a scanner candidate -- it does NOT mean confirmed vulnerability. This section reports NO vulnerability totals, NO true-negative claims, NO package-safety claims, and NO corpus-prevalence claims. Raw candidates, gated/reportable candidates, abstentions, and confirmed false positives are kept strictly separate throughout.

## Identity reconciliation (performed BEFORE any replay work)

- 100 frozen package identities, 97 ANALYZED, 2 CPP_CPG_FAILED, 1 EXPORT_FAILED, 0 other statuses.
- Bundle identities == ANALYZED identities: **True**
- Missing-3 == CPP_CPG_FAILED ∪ EXPORT_FAILED: **True**
- Final accounting: **97 replayed + 3 inherited upstream failures = 100/100, 0 silently omitted.**

### Inherited upstream failures (never attempted as a bundle replay; no bundle was ever produced for these -- not corrupt bundles)

- `@driftlog/tree-sitter-dart@1.0.4`: EXPORT_FAILED -- cpp export rc=1
- `@farcaster/rocksdb@5.5.0`: CPP_CPG_FAILED -- c2cpg rc=1
- `duckdb@1.4.4`: CPP_CPG_FAILED -- c2cpg rc=1

## Six-property matrix, as actually enforced this replay

| Property | Enabled | Raw candidates | Reportable |
|---|---|---|---|
| R04 (comparison diagnostic) | enabled | 2 | 0 |
| R05 (comparison diagnostic) | enabled | 7 | 0 |
| FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven) | enabled | 7 | 0 |
| LOCK_BALANCE | enabled | 12 | 0 |
| PROTECTED_FIELD | enabled | 233 | 0 |
| OOB_WRITE | enabled | 252 | 0 |
| OOB_INDEX_WRITE | enabled | 3290 | 0 |
| OOB_READ | enabled | 115 | 0 |
| OOB_COMPARE | **disabled** | 0 | 0 |

OOB_COMPARE's disabled reason (recorded on every aggregate record, unconditionally): task #33's real 33-package corpus survey of memcmp/strncmp/CRYPTO_memcmp found zero real candidates and root-caused why; the detector itself is proven sound on its own positive-control fixture. Its zero-candidate output here is NOT presented as safety evidence -- it is a corpus-survey result, not a proof of absence.

## Reachability-tier distribution (staged properties only; R04/R05/R06 use their own separate applicability/adjudication path, never touched by reachability_tier.py)

- `oob_index_write_candidates`: REACHABILITY_UNRESOLVED=125, TIER_INTERNAL_UNREGISTERED=3165
- `oob_write_candidates`: REACHABILITY_UNRESOLVED=8, TIER_INTERNAL_UNREGISTERED=244
- `lock_balance_findings`: REACHABILITY_UNRESOLVED=1, TIER_INTERNAL_UNREGISTERED=11
- `oob_read_candidates`: REACHABILITY_UNRESOLVED=2, TIER_INTERNAL_UNREGISTERED=113
- `protected_field_findings`: TIER_INTERNAL_UNREGISTERED=233

## Provenance-resolution distribution

- Total resolved findings (across all 9 property keys): **3918**
- Unresolved findings by reason: 
- Package-level re-fetch outcome: REFETCHED_PINNED_TARBALL=97
- Packages with BOTH tarball_sha256 and source_tree_sha256 independently re-verified: **97/97**
- All 97 packages: both hash checks passed. No metadata substitution occurred.

## Package-owned vs. vendored counts (among RESOLVED findings only)

- PACKAGE_OWNED_HINT: 1505
- VENDORED_HINT: 2413

## Vendored-code deduplication (task #31)

| Property | Deduplicated count | Raw exposure count |
|---|---|---|
| R04 (comparison diagnostic) | 0 | 0 |
| R05 (comparison diagnostic) | 0 | 0 |
| FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven) | 0 | 0 |
| LOCK_BALANCE | 6 | 6 |
| PROTECTED_FIELD | 2 | 39 |
| OOB_WRITE | 137 | 137 |
| OOB_INDEX_WRITE | 2036 | 2130 |
| OOB_READ | 101 | 101 |
| OOB_COMPARE | 0 | 0 |

## Timing and disk-usage summary

- Packages replayed: 97, replay failures: 0, inherited upstream failures: 3 (never attempted -- no usable bundle was ever produced for these, not a corrupt one).
- Total wall time (sum across packages): 348.0s, mean per package: 3.59s
- Stage totals (seconds): bundle_extract_seconds=28.81, download_seconds=31.66, extract_seconds=22.22, hash_seconds=3.11, r06_scan_seconds=69.12
- Evidence bundle directory on disk: 487.2 MB

## Exact hashes of all driven analyzer files (this replay's own dependencies, hashed fresh at run time -- not reused from any bundle's own, earlier, analyzer_hashes)

- `npm_corpus/evidence_bundle.py`: `b1234e2170e754c377621b49177027e44a231aa0f5c88f9815bdad116550743f`
- `npm_corpus/extract_build_config.py`: `a4aa4011796c6a10b01f6ee80ead79f1eddc6268d89a2f7fdeecf0742d30e559`
- `provenance.py`: `1f362988ccac406e19638a327db54c496b7eb34084e80377295073f4d1648039`
- `reachability_tier.py`: `c13c3931c942e2faeb549621b1bbdd824ddeb5bdf0e7bf78469e475cae908df1`
- `resource_guard_verdict_r06.py`: `4ce5b73984bf89190aacc9aa8384094c8476c64a58e83d8ae28a4fa94a31ebef`
- `six_property_aggregator.py`: `bf2fdb8d6366fe0e58d0918e500eb01d466be1ef3544e447fc3f695207c8c05e`
- `staged_enablement.py`: `bdd8f5dc3f3318efcbd356ed32c20d249ce41106eb6b9e3655e0202495bac661`
- `vendored_attribution.py`: `fbbdfef9c6f07c65eeb873318165bf043e684a7db4b1f27049388a9ecbb7ffa9`

## Fail-closed invariant re-verification (over the real replay output, not asserted in the abstract)

- PASS: A disabled property (OOB_COMPARE) never has reportable=true
- PASS: TIER_INTERNAL_UNREGISTERED never clears to reportable=true
- PASS: UNRESOLVED/unknown reachability tiers never reportable=true
- PASS: Unresolved provenance never reportable=true
- PASS: applicability_status != APPLICABLE never reportable=true
- PASS: CONFIRMED_FALSE_POSITIVE never reportable=true
- PASS: node-libcurl's known false positive stays non-reportable
- PASS: re2's internally-unregistered OOB candidates stay non-reportable
- PASS: No duplicate package records
- PASS: All 100 packages accounted for (97 replayed + 3 inherited)

## Combined gate suite: ALL PASS

See `gate_results.log` for the full per-gate output.

## Completion criteria (task #34's own definition)

- [x] All combined gates pass.
- [x] All 100 bundles processed or explicitly accounted for as replay failures (97 replayed + 3 inherited, 0 silently omitted).
- [x] No duplicate package records.
- [x] Every fail-closed invariant passes (see above).
- [x] Rerunning the aggregator produces byte-identical semantic results -- ACTUALLY VERIFIED, not merely asserted from design: a full independent second replay of all 97 packages was run (see `results/determinism_verification.json`); **97/97 produced an identical semantic digest** (sha256 of each record with only the real, expected-to-vary wall-clock timing fields excluded), 0 mismatched, 0 rerun failures.
- [x] Results and documentation committed and pushed to `develop`.

---
*No new corpus run was launched. Task #34 is the 97-bundle replay only, per its own explicit scope. The remaining 394 packages were not started.*