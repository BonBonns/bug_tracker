# Overnight 100-package diagnostic sample: selection method

Frozen before any scanner in THIS diagnostic run produced output -- every input is either
real, already-completed prior pipeline evidence (eligible_packages.tsv,
npm_build_configuration.tsv, npm_pipeline_status.tsv, from the real 452/494 corpus run) or a
real, already-completed corpus-wide text search (primitive_search_results.jsonl, task #28).

## Composition
- 75 packages, deterministic greedy stratified coverage (ties broken by package_name, ascending
  -- no randomness in this half at all).
- 25 packages, deterministic random controls from the remaining pool, `random.Random(20260831)`.
- Forced inclusions (counted within the 75): node-libcurl, node-crc16, re2, @2060.io/ffi-napi, node-snap7.
- Deduplicated by real, freshly-computed `source_tree_sha256` (provenance.py's own
  `build_source_manifest`, real tarball fetch, no c2cpg) -- any true content duplicate was
  replaced by the next candidate from the remaining pool.

## Strata targeted by the greedy cover
prim:lock, prim:write, prim:read, prim:cmp; binding:{nan,node-addon-api,raw-napi,node-v8-buffer,none};
size:{small,medium,large}; build:{binding.gyp,cmake,meson,gn,none}; status:{ANALYZED,RESOURCE_LIMIT,CPP_CPG_FAILED}.

## Coverage achieved
Total distinct strata across the whole 494-package eligible cohort: 19
Strata covered by this 100-package sample: 19
Strata NOT covered (real, disclosed gap -- no eligible package satisfies them at all, or the
greedy budget was exhausted before reaching them): none

## Real duplicate content found during dedup
0 replacement(s) made.

## Outputs
- overnight_sample_100.tsv
- overnight_sample_100.json
- selection_method.md (this file)
