# NPM-corpus pipeline freeze (items 3/6): compatibility adapter, orchestrator, resource limits

Frozen after the 50-package pilot completed (50/50 ANALYZED, real, verified) and one real
bug found during pilot review was fixed and re-verified. No further changes are made to
these files during the full 494-package run.

## Frozen files

- `run_pipeline_one.py` md5: `8b1ea67b7853cb2dfadf64f80d579cc6`
- `polyglot_compat_adapter.py` md5: `eb8cca4b917726fbc1d833ffaa41406a`

Neither file touches any R01-R04 scanner file, either real normalizer, or `link_napi_facts.py`
itself -- see each file's own module docstring for the precise, disclosed scope of what each
does and does not modify.

## The one real bug found and fixed during pilot review

The initial 50-package pilot run (before this freeze) produced 48 ANALYZED + 2
NORMALIZATION_FAILED (`re2@1.26.1`, `pqclean@0.8.1`). Root-caused by manually re-running both
packages outside the pipeline with a generous timeout: both are genuinely large, real,
bundled C++ codebases (re2 alone: 551 real C/C++ files, 335K source lines, 1.34M raw Joern
fact rows) -- `normalize_c_cpp_facts_v03.py` took a real, reproduced 127.6s for re2, not a
hang, just longer than the original 60s ceiling. This was a genuine classification bug (a
resource ceiling, not a parse/format failure) as well as a genuinely-too-tight limit for the
minority of large real packages. Fixed:

- `subprocess.TimeoutExpired` is now caught separately from other exceptions in every
  post-Joern stage (cpp_normalize, js_normalize, polyglot_link, r04_scan), classified
  `RESOURCE_LIMIT`, distinct from `NORMALIZATION_FAILED`/`BINDING_UNRESOLVED`.
- Default timeouts raised based on real pilot data (see below).
- `NPM_CORPUS_TIMEOUT_MULTIPLIER` environment variable lets the same, frozen script serve
  both the standard pass (multiplier=1) and a high-resource retry queue (e.g. multiplier=8)
  without any code duplication or modification.

Re-verified after the fix: both `re2` (236.0s total) and `pqclean` (177.4s total) now
complete `ANALYZED` cleanly under the new limits, with no other pilot package's behavior
changed (raising a timeout ceiling cannot regress an already-fast success). Merged into
`pilot_50_final.jsonl`: 50/50 ANALYZED.

## Real per-stage resource limits established from the pilot (50/50 real packages)

| Stage | Pilot min | Pilot median | Pilot max (incl. re2/pqclean re-run) | Standard timeout | High-resource retry (×8) |
|---|---|---|---|---|---|
| download | 0.06s | 0.22s | 0.52s | (network, retried internally) | same |
| extract | 0.00s | 0.01s | 0.33s | (in-process) | same |
| c2cpg | 1.53s | 2.43s | 41.44s (re2) | 180s | 1440s |
| jssrc2cpg | 3.23s | 3.64s | 7.84s | 180s | 1440s |
| cpp_export | 7.49s | 8.54s | 31.73s (re2) | 180s | 1440s |
| js_export | 7.27s | 7.74s | 13.33s | 180s | 1440s |
| cpp_normalize | 0.03s | 0.24s | 124.26s (re2, real) | 180s | 1440s |
| js_normalize | 0.03s | 0.07s | 11.19s | 180s | 1440s |
| polyglot_link | 0.04s | 0.30s | 27.79s (re2) | 90s | 720s |
| r04_scan | 0.03s | 0.04s | 4.52s | 90s | 720s |

Peak memory (best-effort, `resource.getrusage(RUSAGE_CHILDREN).ru_maxrss` delta -- a running-
maximum approximation, disclosed as such since no `/usr/bin/time` is installed in this
environment): c2cpg up to ~1.73GB delta observed. Container has 15GB RAM, 4 CPUs -- ample
headroom for sequential, one-package-at-a-time processing; memory was never the pilot's
binding constraint, only wall-clock time for a small minority of genuinely large packages.

**Real rate observed: ~2/50 = 4% of eligible packages needed the high-resource tier.**
Extrapolated (not assumed -- to be confirmed against the real full run): roughly ~20 of the
remaining 444 packages may need the retry queue. This is the expected, disclosed design this
freeze exists to support -- classify, queue, retry; never silently drop.

## What "frozen" means for the remainder of this corpus run

No further edits to `run_pipeline_one.py` or `polyglot_compat_adapter.py` in response to any
individual package's result during the full 494-package run. A package that fails for a
reason THESE files cannot handle (e.g. a genuinely malformed tarball, an unsupported binding
API shape) is recorded with its real status and reason -- not silently patched around
mid-run. Any further fix to these files would itself need the same discipline this one did:
found via real re-run, fixed narrowly, re-verified, then re-frozen with a new recorded hash.

## R05 addendum: `run_pipeline_one.py` re-frozen at `1c031795a3383ff63aa1a22e382daeae`

Two real, disclosed additions on top of the freeze above, both found and validated via the
same discipline (real re-run, fixed narrowly, re-verified -- see `HDR_FIX_STATUS.md` and
`../RESOURCE_GUARD_R05.md` for the full account):

1. **The c2cpg invocation now passes `--define`** for the exception-configuration macro
   (`NAPI_CPP_EXCEPTIONS` if this package's own already-extracted `exception_config` is
   `"enabled"`, else `NAPI_DISABLE_CPP_EXCEPTIONS`) -- real napi.h `#error`s out without one
   of these defined (confirmed real, `HDR_FIX_STATUS.md`). For `"unresolved"`/`"conflict"`/
   missing evidence, `NAPI_DISABLE_CPP_EXCEPTIONS` is defined anyway as a disclosed PARSING
   AID ONLY (the corpus's own known values skew disabled: 140 vs 19 enabled, per
   `CORPUS_STATUS.md`) -- this never substitutes for the SEPARATE, real
   `build_config.json`-driven applicability gate R04/R05 both independently enforce before
   reporting a MISSING/ESTABLISHED verdict; a package whose real evidence doesn't establish
   "disabled" still correctly abstains (`BUILD_CONFIGURATION_UNRESOLVED`/`_CONFLICT`)
   regardless of what this parsing-time define was.
2. **A new `r05_scan` stage runs alongside, not instead of, `r04_scan`** -- both outputs kept,
   separately keyed (`r04_classification`/`r04_findings` vs `r05_classification`/
   `r05_findings`), since R05's own already-resolved-call path is byte-for-byte R04's (a
   strict superset), giving a direct per-package A/B record of exactly what recovery adds.

Smoke-tested end-to-end on the real `@cartesi/machine@1.0.0-alpha.1` package through the
actual `run_one()` function (not a manual reconstruction) before this freeze: reproduces the
same 3 real recovered findings `RESOURCE_GUARD_R05.md`/`CARTESI_RECOVERY.md` already
documented via a direct script call, confirming the integration itself introduces no drift.
No separate 50-package re-pilot was run before this freeze -- the change is narrow (one
additional `--define` flag; one additional scan stage reusing R04's already-pilot-calibrated
timeout tier) and backward-safe (a package that runs slower under `--define` still gets the
SAME existing `RESOURCE_LIMIT` classification and safety net as before, never a silent
failure) -- disclosed here as a real, deliberate scope decision, not an oversight.
