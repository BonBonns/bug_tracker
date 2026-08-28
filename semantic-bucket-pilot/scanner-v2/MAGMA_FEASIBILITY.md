# Magma feasibility probe — result (no model calls)

Bounded probe against the pre-registered Magma property (`PREREGISTER_MAGMA.md`). Confirms
what works and pins the one concrete engineering blocker for the Magma phase.

## What works

- **Reachable**: `git clone https://github.com/HexHive/magma.git` succeeds in this
  environment; `targets/<t>/fetch.sh` pins each upstream source to an exact commit
  (e.g. libtiff `c145a6c14978…`), fetched successfully (23 MB).
- **Oracle-rich and diverse**: 116 canaried bugs; **11 eligible** destination-capacity
  *write* relations across **6 real targets** (PNG/SND/TIF/SSL/PHP/PDF), 3 in the cleanest
  fixed-`sizeof`/`ARRAY_LEN` form — structurally different real code, the diversity Juliet
  lacked. Catalog: `study/magma/bug_catalog.json`.
- **Pair + oracle-strip mechanism validated**: for TIF013 (`libtiff/tif_jbig.c`,
  `_TIFFmemcpy(buffer, pImage, decodedSize)` with canary `decodedSize > size`), applied
  the bug patch and built the vulnerable variant with the `MAGMA_LOG("%MAGMA_BUG%", …)`
  canary and `MAGMA_ENABLE_*` blocks resolved away — the oracle is cleanly removable from
  the packet, and `MAGMA_ENABLE_FIXES` on/off gives the safe/vulnerable pair at one site.

## The blocker — the frozen frontend needs the target's build environment

Scanning the real `tif_jbig.c` (single file, and again with a naive `--include` of the
libtiff headers) produced **method shells but zero bodies**: raw `methods.tsv` = 9
functions, but `calls.tsv` = 0, `identifiers.tsv` = 0, so
`oob_runtime_capacity_v2` recognized **0 operations**. A trivial control
(`memcpy(d,b,n)` into `char d[50]`) scans correctly (3 calls incl. `memcpy`), so the
frozen pipeline is fine — c2cpg's frontend simply cannot build ASTs for real libtiff
bodies without full type/macro resolution: the generated config headers (`tif_config.h`,
`tiffconf.h` are produced by the target's autoconf/cmake build, not present in source) and
the complete, correct include graph. A naked or stubbed scan yields empty shells.

## What the Magma phase therefore requires (scoped)

1. **Build-driven scanning**, per target: run the target's `prebuild.sh`/`build.sh` far
   enough to generate config headers and a `compile_commands.json`, then drive c2cpg from
   that so real bodies parse into facts. This is the "Magma is heavy" cost, now pinned to a
   specific cause (frontend needs the build's type environment), not a vague warning.
2. **Sink-alias recognition**: real code copies via library wrappers (`_TIFFmemcpy`,
   `memcpy`-macros); the scanner's sink set must include the target's copy aliases (or scan
   post-preprocess).
3. **Parameter / interprocedural capacity**: many real overflow sites bound the
   destination by a *caller-provided* parameter (e.g. `buffer`/`size` in `JBIGDecode`),
   not a local extent — exactly the packet-insufficient / propagated-capacity case the
   Juliet `juliet_packet_expansion.py` machinery already handles. Reuse it.

## Honest status

Magma is the right source (real, oracle-backed, structurally diverse) and the property +
pair + oracle-strip mechanics are validated. The remaining work is a genuine per-target
**build-integration** phase (items 1–3), materially larger than the Juliet work. No usable
Magma yield is claimed until real bodies parse and the pre-registered inclusion rule runs
over the safe/vulnerable pairs. No model calls were made.
