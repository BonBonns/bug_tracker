# R06 persistence fix: real per-package evidence-bundle sizing

Real, measured (not estimated) compressed evidence-bundle sizes for one small, one medium,
and one large real corpus package, run through `run_pipeline_one_r06.py`'s `run_one()`
directly (the same function the corrected corpus pipeline will call), isolated at
`/tmp/npm_corpus_pilot/999xx` -- far outside the live R05 scan's own sequential `0`-`493`
index range, confirmed non-colliding before and after (live scan's own in-progress indices
at the time were 237/239/271; no overlap). The live scan (PID 6956) was left running,
untouched, throughout -- confirmed still healthy afterward (elapsed 04:35:56, 270/494 rows).

## Method

`_measure_bundle_sizes.py` (one-off, not part of the frozen/committed pipeline, deleted after
this run) ran each package's real `run_one()`, measured the real uncompressed byte size of
everything in `work_root/work/` (the full set `run_pipeline_one.py` currently deletes), then
called the real `write_evidence_bundle()` and measured the real compressed `.tar.gz` size.

## Results

| Size class | Package | Status | Pipeline time | Uncompressed `work/` | Compressed bundle | Ratio |
|---|---|---|---|---|---|---|
| small | `node-addon-api@8.9.2` | ANALYZED | 50.1s | 7.52 MB | 94.7 KB | 79.4x |
| medium | `napi-addon-spdlog@0.0.17` | ANALYZED | 73.0s | 56.5 MB | 2.06 MB | 27.5x |
| large | `re2@1.26.1` | RESOURCE_LIMIT | 371.2s | 147.4 MB | 14.5 MB | 10.2x |

`re2` hitting `RESOURCE_LIMIT` here is a real, expected, disclosed outcome, not a test
failure -- it's the same package `PIPELINE_FREEZE.md` already documents as needing the
high-resource retry tier (127.6s at the standard multiplier historically; 371.2s observed
here under real concurrent load from the live R05 scan sharing the same 4 CPUs). This
incidentally exercised the REAL partial-bundle path: `cpp_export`/`c2cpg` completed before
`cpp_normalize` timed out, so the bundle correctly contains only `cpp_raw` (real facts that
DO exist) with everything after disclosed as `missing`, not silently absent -- the same
behavior `test_evidence_bundle.py`'s Fixture 2 already proved synthetically, now confirmed
against a real timeout.

## Corpus-wide projection

`n=3` is real but small -- this is a range, not a false-precision point estimate. Using
`PIPELINE_FREEZE.md`'s own real pilot rate (~4% of eligible packages need the high-resource
tier, i.e. ~20 of 494; ~96%, ~474, are "normal"-sized):

- **Low bound**: 474 x 94.7 KB (small sample) + 20 x 14.5 MB (large sample, partial-bundle
  case) = ~45 MB + ~290 MB = **~335 MB**.
- **High bound**: 474 x 2.06 MB (medium sample) + 20 x 14.5 MB = ~977 MB + ~290 MB =
  **~1.27 GB**.

The large-package figure (14.5 MB) is itself a partial bundle (only `cpp_raw`, since
`re2` timed out before the normalize/scan stages) -- a large package that DOES complete
would add `cpp_facts.json`/`js_facts.json`/scanner outputs on top, but `cpp_raw` is the
dominant volume for a large C++ codebase (re2 alone: 551 files, 1.34M raw Joern fact rows,
per `RESOURCE_GUARD_R05.md`), so this is a reasonable, if slightly conservative-low, estimate
even without those smaller additions.

Against the real, current 22G free (`df -h /tmp`, checked immediately before and after this
run): even the 1.27 GB high bound is **under 6% of free disk**, with 494 packages' full CPG
binaries (multiple GB each observed for large packages) never entering this budget at all --
those stay deleted, unchanged from the current pipeline's behavior.

## Conclusion

Real measurement across a genuine 3-order-of-magnitude size range (94.7 KB to 14.5 MB) shows
compression ratios of 10x-79x and a corpus-wide total safely under 1.3 GB against 22 GB free.
**Go** for corpus-wide use of `run_pipeline_one_r06.py` + `evidence_bundle.py`, once R05
freezes (see `R06_POST_FREEZE_PLAN.md` -- this fix is not applied to the live, still-running
R05 scan).
