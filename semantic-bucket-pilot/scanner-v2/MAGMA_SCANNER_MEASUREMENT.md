# Magma frozen-scanner measurement (no aliases added; no model calls)

Measured the **frozen, unmodified** scanner on the 7 source-mapped Magma bugs, building
vulnerable and fixed variants at pinned commits with the canary/`MAGMA_ENABLE_*` markers
resolved away. **No sink aliases or write-models were added** — recognition is measured
before any scanner change, so a later fix cannot be evaluated on the bugs that motivated it
(training-on-test prohibition). The recall-audited screen and 7-mapped set were frozen
first (`study/magma/FROZEN_screen.json`).

## Build integration (the previously-blocking step, now solved per target)

Real bodies parse once the target's generated headers + include paths are supplied:
- libsndfile @86c9f9eb: CMake-configured (`config.h`, `sndfile.h`); `common.c` → 2188 calls.
- libtiff @c145a6c1: CMake (`tif_config.h`, `tiffconf.h`); `tif_pixarlog.c` → 2967 calls.
- libpng @a37d4836: CMake; `pngrutil.c` → 16396 calls.
- openssl @3bd5319b: `./config` (`opensslconf.h`); `x509_obj.c` → 274 calls.
- c2cpg invoked with `--include <dirs> --with-include-auto-discovery`.

## Result — the frozen scanner recognizes 0 of 6 *parsed* bug write-sites

**Denominator:** build integration succeeded for **6 of 7** sites; frozen-scanner
recognition was **0 of 6**. TIF013 was **not tested** (build-incomplete — JBIG optional
dependency unconfigured, 0 call bodies), so it is neither a recognition success nor a
measured miss. Do not report "0 of 7".

| bug | family / obligation | parsed | bug-site recognized | miss form |
|-----|--------------------|:------:|:-------------------:|-----------|
| SND010/012/013 | positioned write (one family) | yes | **NO** | dest `&(psf->header.ptr[indx])` — address-of indexed struct-field buffer |
| TIF002 | write_extent ≤ tbuf_size | yes | **NO** | external decoder call `inflate(&sp->stream)` |
| PNG003 | count ≤ fixed array | yes | **NO** | pointer-walk struct write `pal_ptr->red = …` |
| SSL004 | length ≤ sizeof(fixed_buf) | yes | **NO** | library wrapper `ascii2ebcdic(ebcdic_buf, num)` |
| TIF013 | length ≤ param capacity | no | N/A | build-incomplete: JBIG optional dep not configured (0 call bodies) |

The scanner is not broken on real code — it *does* recognize simple-dest writes in the same
files (4 ops in `common.c` at dests `ptr`/`mem`/`pnew`/`data`; an unrelated `memcpy(p,…)` in
`X509_NAME_oneline`). It misses the **bug** sites because their write forms are outside its
model. Recognition is identical for vulnerable and fixed variants (it does not depend on the
fix).

## Interpretation and consequence (honest)

The frozen scanner — tuned on Juliet-style simple array/`malloc` dests — recognizes **none**
of the mapped Magma bug write-sites. Real-code writes use forms it does not model:
offset-into-struct-field-buffer dests, decoder calls, pointer-walks, and library copy
wrappers. Each is **recorded as a scanner-coverage finding, not fixed**.

- No Magma bug is currently **evaluation-eligible** (`scanner_recognized` fails for all 7).
- `_TIFFmemcpy`, `ascii2ebcdic`, pointer-walk, `inflate`, and the `&(ptr[offset])` dest form
  are the concrete coverage gaps.
- **If** generic support for these forms is later added, the 7 Magma bugs become
  development/regression cases, **not** confirmatory evidence, and a separate **held-out**
  corpus would be required to measure accuracy without training on the test set.

The SND trio is one positioned-write topology family (a pipeline feasibility tier), not
three families. So the build-integration tier delivered a working real-code parse+scan
pipeline and a rigorous **negative** recognition result — the honest input to deciding
whether to invest in scanner coverage next.

## Corrected status line

- Real-code parsing succeeded for **6/7** sites (TIF013 build-incomplete).
- Frozen-scanner recognition was **0/6** on the parsed sites.
- Four **general representation gaps** identified (not four bug-specific aliases):
  address-of-indexed dest, wrapper-copy sink, pointer-walk write, external-decoder write.
- **Magma is now the development corpus** (all 7 bugs are development/regression cases,
  never confirmatory). A **separate held-out corpus** (statement-level, e.g. SecVulEval)
  must supply confirmatory accuracy/coverage evidence.
