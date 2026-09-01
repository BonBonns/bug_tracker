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
| real positive-path behavior | **not yet established on a real package** -- the caller-side positive path is proven on compiled fixtures (w02/w03) only |
| real blind portability | limited -- one analyzed site, whose honest classification is an abstention at the interprocedural boundary |

## Pipeline wiring (explicit decision, not an oversight)

NAPI-STATUS remains a STANDALONE property in both revisions. Wiring it into the live
pipeline requires extending per-property vocabularies in frozen modules --
`provenance.py`'s PROPERTY_CANDIDATE_RULES, `reachability_tier.py`,
`applicability_gate.py`, `adjudication_registry.py`, and the six-property aggregator
whose schema task #34's replay artifacts pin -- i.e., the same staged-enablement path
(staged_enablement.py) every previously integrated property went through, with its
own gates. Finding records already carry the fields that path consumes (file, line,
method/call node ids, verdict vocabulary with an explicit candidate subset:
`STATUS_GUARD_MISSING` is the only candidate-shaped verdict; every `ABSTAIN_*`,
`OUTPUT_ESCAPES_*`, `NO_OUTPUT_USE*`, `STATUS_PROPAGATED*`, `*_ESTABLISHED` record is
a non-candidate). Integration is deliberately a separate change with its own
freeze/controls, not a rider on this revision.

## Claims boundary

Unchanged from R01, and load-bearing: every record is an API-handling classification
with node-id evidence -- never a vulnerability, severity, exploitability, or impact
claim. The gate lints the analyzer output for vulnerability language.
