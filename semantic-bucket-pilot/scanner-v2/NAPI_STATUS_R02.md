# NAPI-STATUS-R02: the interprocedural output-escape revision

R02 exists because R01's blind run exposed a boundary, not a bug in the controls: the
one real site (@farcaster/rocksdb `Convert`, binding.cc:344) got `NO_OUTPUT_USE` from
intraprocedural analysis while its required `napi_value* result` output escapes
through a caller-provided pointer -- "unused" was never provable from inside the
callee. The honest classification is an explicit caller-analysis abstention, and that
real site is now a frozen regression fixture with the corrected expectation.

`napi_status_verdict_r02.py` is a copy of the frozen R01 (hash `45bf86bd...918`
unchanged) with four deltas -- same copy-not-import lineage as resource_guard R02-R06.
The R01 fixture must classify identically under R02 (gated).

## Deltas

1. **Optional vs required output roles.** `data`/`result_data` are optional
   (node_api.h documents NULL to ignore them); `result` is required. NULL in an
   optional role -> `opted_out` recorded, excluded from use tracking (R01 wrongly
   resolved NULL to CDT's synthetic binding and tracked it). NULL in a required role
   -> `ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED / REQUIRED_OUTPUT_NULL`.
2. **Escape detection.** A required output whose referent is a parameter of the
   enclosing method escapes; a would-be `NO_OUTPUT_USE` at such a site is never
   reported as a clean negative.
3. **One-level caller analysis** where the status is PROVABLY dead (discarded, or a
   never-returned, never-consumed local -- nothing in the program can ever check it):
   each TU-visible, unambiguous caller has the escaping role mapped by parameter
   index and resolved by the same identities as any out-arg. Resolved reachable use
   -> `STATUS_GUARD_MISSING / STATUS_DISCARDED_OUTPUT_USED_IN_CALLER` (no guard can
   exist anywhere). Any unresolved caller (second-level escape, NULL, unresolvable
   arg, ambiguous callee) or zero visible callers ->
   `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`. All resolved and clean ->
   `NO_OUTPUT_USE_IN_KNOWN_CALLERS` (deliberately TU-scoped wording). Status neither
   provably dead nor provably propagated ->
   `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED / CALLEE_STATUS_HANDLING_NOT_PROVEN_FOR_CALLERS`.
4. **Derived wrapper sites.** A method that forwards outputs and provably returns the
   creation status on every return (or returns the call directly) is a
   proven-propagating creation wrapper; every unambiguous TU call to it is analyzed
   as a derived creation site with the full status/guard/use machinery (records carry
   `derived_from`/`wrapper_method_id`). One level only.

## Gate: check_napi_status_r02.py (16/16)

- R01-fixture invariance: full 17-row table identical under R02.
- fixture_r02.c controls (real Joern v4.0.608 facts, frozen in
  `study/napi_status/raw_synthetic_r02/`): proven wrapper registration (w_make),
  derived caller ESTABLISHED (w01) and derived caller MISSING (w02) -- the real
  positive-path machinery R01 never exercised on a call-site beyond fixtures --
  caller-use finding (w03), second-level escape abstention (w04, the rocksdb shape),
  NULL opt-out (w05), required-NULL abstention (w06), no-caller-facts abstention
  (w07), TU-clean callers (w08).
- RocksDB regression (real blind facts, frozen in
  `study/napi_status/raw_blind_rocksdb/`): `Convert` ->
  `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED` (reason NO_CALLER_FACTS: `Convert` is an
  overloaded C++ member, so caller sites do not resolve to a single callee id --
  ambiguity abstains, per design), `result_data` NULL recorded as opt-out, zero
  guard-missing findings.

## Evidence status (current, stated plainly)

| dimension | status |
|---|---|
| fixture behavior | strong -- R01 32/32, R02 16/16, all controls compiled + real facts |
| real site recognition | established (rocksdb site found, roles resolved, opt-out modeled) |
| real positive-path behavior | **ESTABLISHED** -- @8crafter/leveldb-zlib@1.6.0, two real STATUS_GUARD_MISSING/STATUS_DISCARDED sites in HandleOKCallback, manually reviewed and frozen as a permanent regression (fixture_leveldb_real.cpp / raw_leveldb_real/ / check_napi_status_leveldb_regression.py); NAPI_STATUS_ENABLED flipped to True |
| real blind + targeted portability | 10 token-selected packages analyzed once each: 1 positive-path package, 1 escape abstention (rocksdb), several other abstentions, and provider/no-site packages -- see study/napi_status/REAL_PACKAGE_RESULTS.md |

## Candidate vocabulary (CORRECTED -- the exact allowlist)

An earlier draft of this section said "`STATUS_GUARD_MISSING` is the only
candidate-shaped verdict" without naming the caller-side identifier -- a vocabulary
mismatch that would let an integration recognizing only the intraprocedural shapes
silently discard R02's STRONGEST caller-side finding. The corrected, exact candidate
allowlist (implemented and gated in `napi_status_integration.py`):

  - `STATUS_GUARD_MISSING` with an intraprocedural sub_reason (`NO_RELATED_CHECK`,
    `STATUS_DISCARDED`, `RELATED_CHECK_AFTER_USE`,
    `NON_TERMINATING_OR_BYPASSED_FAILURE_PATH`, `UNRELATED_CHECK_ONLY`);
  - `STATUS_GUARD_MISSING` / **`STATUS_DISCARDED_OUTPUT_USED_IN_CALLER`** -- the
    caller-side finding. It satisfies the property's candidate definition just as
    strongly: the status was discarded, the required output escaped, and the caller
    used that output afterward.

Both are candidates. Every abstention -- `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`
included -- and every `NO_OUTPUT_USE*`, `STATUS_PROPAGATED*`, `*_ESTABLISHED` record
is a NON-candidate. The allowlist is exact-match and fails closed: a
`STATUS_GUARD_MISSING` record carrying an unrecognized sub_reason is counted loudly
as `CANDIDATE_VOCABULARY_UNRECOGNIZED` (gated to zero) rather than silently dropped
OR silently admitted.

## Pipeline wiring (integrated additively -- see NAPI_STATUS_INTEGRATION.md)

Integration now exists in `napi_status_integration.py` following the Nan-integration
precedent (additive extension, own gate), with a NEW aggregator revision
(`aggregate_record_r02`) that delegates the six frozen properties to
`six_property_aggregator.aggregate_record` unchanged rather than rewriting the task
#34 schema. The property is now ENABLED (`NAPI_STATUS_ENABLED = True`) after a real
package (@8crafter/leveldb-zlib) exercised and survived review of its positive path;
the per-finding reachability + provenance + applicability gates still decide each
finding's reportability.

## Claims boundary

Unchanged from R01, and load-bearing: every record is an API-handling classification
with node-id evidence -- never a vulnerability, severity, exploitability, or impact
claim. The gate lints the analyzer output for vulnerability language.
