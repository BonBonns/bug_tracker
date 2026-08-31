# R06/FIX01I integration freeze -- 4-package smoke test

Branch `claude/r06-fix01i-integration`. Both source branches (`claude/r06-precision-fix`,
`claude/crosslang-linker-fix`) kept untouched -- verified their tip commits are unchanged
before and after this integration's own work (`60891f9`/`c2585b5`).

## Real smoke test, all 4 required packages

| Package | R06 (items 1+2) | Item 3 (FIX01I promotion) |
|---|---|---|
| `node-libcurl@5.1.2` | Target-scoped build config resolves `Easy.cc` to real `enabled` -> `CONTRACT_NOT_APPLICABLE`. **0 actionable findings.** | `ReadFunction` has no `Napi::CallbackInfo` parameter at all -- correctly rejected, no structural source found. |
| `node-crc16@2.0.7` | `SIZE_ATTACKER_INDEPENDENT` (fixed-literal size), unaffected by items 1/2. **0 findings.** | N/A -- nothing to promote. |
| `@cartesi/machine@1.0.0-alpha.1` | 3 real `VALUE_ACQUISITION_GUARD_MISSING` findings, `source_boundary_evidence` unpromoted (`SOURCE_BOUNDARY_UNRESOLVED`/untraced, `attacker_controlled: False`). | Real registration found (3/3, new `InstanceMethod` recognition); real structural `info[N]` source found (3/3); **real JS linkage absent** in Cartesi's own published package -- correctly NOT promoted on real data. Full chain validated via one disclosed synthetic JS call built on Cartesi's own real C++ facts (see `R06_FIX01I_INTEGRATION.md`). |
| `jpeg-turbo@0.4.0` | 2 real gyp targets, both `unresolved` (no textual exception evidence -- the well-known jpeg-turbo default-resolution case R04 handled manually is NOT replicated by this automated extractor, disclosed scope). 0 recovered R05 candidates -> **0 findings.** No crash/regression on this real corner case. | N/A -- nothing to promote. |

All 4 packages run cleanly through the full wired pipeline (`run_pipeline_one_r06.py` +
`resource_guard_verdict_r06.py` + `promote_via_js_linkage.py`), no exceptions, no silent
failures. Real, not synthetic, for every package except the one disclosed JS-call-site
addition for Cartesi's positive-mechanism validation (see above).

## Test suite (all real, all PASS)

- `npm_corpus/tests/test_target_scoping.py` -- 5 adversarial gyp fixtures + real node-libcurl regression.
- `npm_corpus/tests/test_make_checkpoint.py` -- 11 real fixtures.
- `npm_corpus/tests/test_evidence_bundle.py` -- 28 real fixtures (atomicity, completeness, integrity fields).
- `tests/test_source_boundary.py` -- 7 unit + 6 real `r05_controls` fixture checks.
- `tests/test_target_scoping_e2e.py` -- 8 real end-to-end checks (real node-libcurl `build_config.json`).
- `tests/test_promote_via_js_linkage.py` -- 10 real/disclosed-synthetic checks (this integration).

## What this freeze does NOT do

- Does not touch the live R05 baseline scan (`claude/aggregate-kinds-producer-test-03zs7n`,
  PID 6956) -- confirmed running and healthy throughout this entire integration's work.
- Does not merge this branch, `claude/r06-precision-fix`, or `claude/crosslang-linker-fix`
  into the R05 lineage branch.
- Does not run the post-freeze targeted rerun (`R06_POST_FREEZE_PLAN.md`) -- that still
  waits for the live R05 scan to finish on its own, per standing instruction.
- Does not claim Cartesi as a real, corpus-confirmed positive promotion case -- it is not,
  on real currently-available facts, and is reported as such rather than glossed over.

## Frozen

- `promote_via_js_linkage.py` -- new, this branch only.
- `resource_guard_verdict_r06.py`, `extract_build_config.py`, `run_pipeline_one_r06.py`,
  `evidence_bundle.py` -- inherited unchanged from `claude/r06-precision-fix` (`60891f9`).
- `link_napi_facts.py` and the rest of the crosslang frontend -- inherited unchanged from
  `claude/crosslang-linker-fix` (`c2585b5`).
