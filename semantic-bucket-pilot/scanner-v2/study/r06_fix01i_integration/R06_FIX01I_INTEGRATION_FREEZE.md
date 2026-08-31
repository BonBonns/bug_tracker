# R06/FIX01I integration freeze -- 4-package smoke test (Phase B refined)

Branch `claude/r06-fix01i-integration`. Both source branches (`claude/r06-precision-fix`,
`claude/crosslang-linker-fix`) kept untouched by this branch's own commits -- `claude/
r06-precision-fix` received its own further, separate Phase B refinement commit (`8ac2477`,
attaching `source_boundary_evidence`/per-target metadata to every applicability-gate
finding) and was merged forward into this branch; `claude/crosslang-linker-fix` (`c2585b5`)
was never touched at all.

## Required promotion boundary (verified -- see `R06_FIX01I_INTEGRATION.md` for full detail)

Promotion to `JS_ARGUMENT_CONTROLLED` requires ALL three: (1) real registration, (2) a real
FIX01I link, (3) the internal trace terminating at a specific `CallbackInfo[index]` value
feeding the allocation size. Explicitly verified NOT promoted for each of the 4 required
non-promotion cases (every JS-reachable value; a native callback parameter like libcurl's
`size`; a linked function whose size is literal/internally computed; an unresolved
out-parameter trace) -- see the table in `R06_FIX01I_INTEGRATION.md`.

## Real smoke test, all 4 required packages

| Package | R06 (items 1+2, Phase B refined) | Item 3 (FIX01I promotion) |
|---|---|---|
| `node-libcurl@5.1.2` | Target-scoped build config resolves `Easy.cc` to real `enabled` -> `CONTRACT_NOT_APPLICABLE`. **0 actionable findings.** The finding now carries BOTH `source_boundary_evidence` (`SOURCE_BOUNDARY_UNRESOLVED`, `size` param is `size_t`) AND the exceptions-enabled evidence, plus `resolution_scope`/`resolved_target_name`/`package_wide_diagnostic` showing per-target (`enabled`) genuinely differs from package-wide (`unresolved`). | `ReadFunction` has no `Napi::CallbackInfo` parameter at all -- correctly rejected, no structural source found. |
| `node-crc16@2.0.7` | `SIZE_ATTACKER_INDEPENDENT` (fixed-literal size), unaffected. **0 findings.** | N/A -- a literal size is never even a promotion candidate. |
| `@cartesi/machine@1.0.0-alpha.1` | 3 real `VALUE_ACQUISITION_GUARD_MISSING` findings, each `SOURCE_BOUNDARY_UNRESOLVED`/untraced (temporarily unresolved, per instruction -- NOT forced positive). | Real registration found (3/3, new `InstanceMethod` recognition); real structural `info[N]` source found (3/3); **real JS linkage absent** in Cartesi's own published package -- correctly NOT promoted on real data. Full chain validated via one disclosed synthetic JS call. |
| `jpeg-turbo@0.4.0` | **Honest, real, corrected account**: jpeg-turbo is `nan`-based (confirmed via its own real `header_staging` evidence), not `node-addon-api`-based -- its real acquisition calls never match the curated `Napi::Buffer::New` contract's structural requirements (`R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`, 28/28), so it never reaches the applicability gate at all. **0 findings**, but no literal `BUILD_CONFIGURATION_UNRESOLVED`/`CONTRACT_NOT_APPLICABLE` record exists for it -- a real, disclosed scope boundary of the curated contracts (nan predates node-addon-api), reported precisely rather than forced to match the initial expectation. | N/A -- nothing reaches the promotion layer. |

All 4 packages run cleanly through the full wired pipeline, no exceptions, no silent
failures. Real, not synthetic, for every package except the one disclosed JS-call-site
addition for Cartesi's positive-mechanism validation, and the one purely-adversarial
internally-computed-size negative control (neither ever presented as a real corpus finding).

## Test suite (all real, all PASS)

- `npm_corpus/tests/test_target_scoping.py` -- 5 adversarial gyp fixtures + real node-libcurl regression.
- `npm_corpus/tests/test_make_checkpoint.py` -- 11 real fixtures.
- `npm_corpus/tests/test_evidence_bundle.py` -- 28 real fixtures (atomicity, completeness, integrity fields).
- `tests/test_source_boundary.py` -- 7 unit + 6 real `r05_controls` fixture checks.
- `tests/test_target_scoping_e2e.py` -- 16 real end-to-end checks (real node-libcurl `build_config.json`; per-target-selects-the-correct-target assertions; package-wide-diagnostic-differs-from-authoritative assertions).
- `tests/test_promote_via_js_linkage.py` -- 12 real/disclosed-synthetic/adversarial checks (this integration, including the internally-computed-size negative control).

## What this freeze does NOT do

- Does not touch the live R05 baseline scan (`claude/aggregate-kinds-producer-test-03zs7n`,
  PID 6956) -- confirmed running and healthy throughout this entire integration's work.
- Does not merge this branch, `claude/r06-precision-fix`, or `claude/crosslang-linker-fix`
  into the R05 lineage branch.
- Does not run the post-freeze targeted rerun (`R06_POST_FREEZE_PLAN.md`) -- that still
  waits for the live R05 scan to finish on its own, per standing instruction.
- Does not claim Cartesi as a real, corpus-confirmed positive promotion case -- it is not,
  on real currently-available facts, and is reported as such rather than glossed over.
- Does not force jpeg-turbo into a "configuration not applicable" finding it does not, in
  reality, produce -- reports the real, honest reason (a nan-based addon, out of the
  curated contracts' scope) instead.

## Frozen

- `promote_via_js_linkage.py` -- new, this branch only.
- `resource_guard_verdict_r06.py`, `extract_build_config.py`, `run_pipeline_one_r06.py`,
  `evidence_bundle.py` -- from `claude/r06-precision-fix` (`8ac2477`, merged forward).
- `link_napi_facts.py` and the rest of the crosslang frontend -- inherited unchanged from
  `claude/crosslang-linker-fix` (`c2585b5`).
