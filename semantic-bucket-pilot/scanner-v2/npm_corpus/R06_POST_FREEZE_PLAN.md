# Option C: targeted post-freeze plan (not run yet -- recorded for when R05 finishes)

Per explicit instruction: let the currently-running R05 baseline (`claude/aggregate-kinds-
producer-test-03zs7n`, PID 6956) finish completely, unchanged. Nothing in this file is
executed until that happens. This plan intentionally does NOT propose a full 494-package
rebuild for the two R06 corrections, because both are conservative: they only REMOVE
previously-unsupported findings (`SOURCE_BOUNDARY_UNRESOLVED` instead of a false
attacker-controlled claim; `BUILD_CONFIGURATION_UNRESOLVED`/`CONFLICT` instead of a
package-wide misresolution) -- neither can manufacture a new true positive that wasn't
already a real R05 candidate, so the SAME 494 packages' raw C++ facts (once persisted, see
`CHECKPOINT_METADATA_ERRATUM.md`'s sibling fix and `evidence_bundle.py`) are sufficient
input; nothing about the source code itself needs re-parsing.

## Steps, in order

1. **Re-extract build configuration for all 494 packages -- cheap.** `extract_build_config.py`
   already has the R06 target-aware fix (`f18f931`/`f19db32`). Re-running it is a pure
   network-refetch-and-reclassify pass (no Joern, no CPG) -- the SAME real per-stage cost
   already measured for the original extraction (`npm_build_configuration.tsv`'s own
   generation), not a new resource class. Output: `npm_build_configuration_r06.tsv`, kept
   SEPARATE from the R05-era `npm_build_configuration.tsv` (never overwritten -- the old file
   remains the disclosed provisional-baseline input, per the standing "R05 run is the
   provisional before-fix baseline" instruction).

2. **Identify packages whose configuration or existing R05 findings change.** Two real,
   independent diff classes, both cheap (no re-scan needed for this step):
   - Build-config diff: `npm_build_configuration_r06.tsv` vs. `npm_build_configuration.tsv`,
     row by row, `exception_configuration` column.
   - Source-boundary diff: for every existing R05 finding recorded in
     `full_scan_r05_working.jsonl`'s `r05_findings`, check whether its
     `attacker_influence_evidence.traced_to_parameter` was ever set (R05's own field name --
     R06 renames it to `source_boundary_evidence`, see `resource_guard_verdict_r06.py`'s own
     commit `acd9b69`) -- ANY finding that reached a parameter is a candidate for a verdict
     change under R06, since R06 only downgrades that specific evidence path, nothing else.
   The union of these two package sets is "the affected subset."

3. **Regenerate persistent facts only for that affected subset**, using the corrected,
   persistent pipeline (`run_pipeline_one_r06.py` + `evidence_bundle.py`, this branch) -- NOT
   the frozen `run_pipeline_one.py`. This is the one step that still needs real Joern
   re-runs, but scoped to the affected subset rather than all 494 -- real cost bounded by
   however many packages the diff in step 2 actually names, not assumed up front.

4. **Retry resource-limit/error packages.** The existing `RESOURCE_LIMIT`/`*_FAILED` rows in
   `full_scan_r05_working.jsonl` (real count as of the last check-in: see the corpus status
   doc) get one retry pass through the SAME corrected persistent pipeline, at the existing
   `NPM_CORPUS_TIMEOUT_MULTIPLIER=8` high-resource tier already established in
   `PIPELINE_FREEZE.md` -- unchanged retry-queue design, just run against the new pipeline so
   any newly-succeeding package also gets a persisted evidence bundle rather than being
   thrown away again.

5. **Perform the broader JS-to-C++ corpus pass separately**, with the corrected persistent
   pipeline, once FIX01H/I (`claude/crosslang-linker-fix`, currently frozen and unmerged) is
   actually merged and this pipeline's `JS_FRONTEND` export step is upgraded to the CFG/
   closure-aware `export_neutral.sc` FIX01I needs (see `evidence_bundle.py`'s own docstring,
   "NOT kept" section, for why `js_raw/` isn't bundled by the current pipeline -- that gap is
   exactly what this step exists to close, deliberately not attempted piecemeal here).

## What this plan does NOT do

- Does not touch or restart PID 6956 before it finishes on its own.
- Does not quote a corpus-wide flip rate before step 2's real diff is actually run (same
  standing instruction that applied to the 40% number in `R06_TARGET_SCOPING.md`/similar).
- Does not merge `claude/r06-precision-fix` or `claude/crosslang-linker-fix` into the R05
  lineage branch -- that branch receives checkpoint-only commits, unchanged.
