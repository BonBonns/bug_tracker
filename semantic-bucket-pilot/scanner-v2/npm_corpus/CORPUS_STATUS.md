# NPM corpus construction status

This file is the authoritative, current status record for the corpus-construction phase. It
supersedes any earlier framing in commit messages or this session's own prior narration that
described the search-derived discovery cohort as validating coverage against CHARON's
reference count, or that described item 2 as complete -- both of those were wrong and are
corrected here.

## Status, per item

- **Item 1 (freeze the complete analyzer): COMPLETE.** See `ANALYZER_FREEZE.md`. Hashes
  recorded for R01-R04 and every other scanner-v2 capability, the C/C++ exporter/normalizer,
  the JS/TS Joern frontends, and the existing cross-language binding resolver
  (`link_napi_facts.py`). No semantic change has been made to any of these files during
  corpus construction.
- **Item 2 (pin the npm universe): SCOPE FINALIZED per direct instruction.** The corpus's
  eligible-package pool is the fully-processed `SEARCH_DERIVED_CANDIDATE_COHORT` alone (see
  below) -- registry-wide enumeration is retained ONLY as a documentation-of-universe-size
  artifact and explicitly does NOT feed eligibility, deduplication, build-configuration
  extraction, or scanning. This narrows the earlier plan (union of two discovery-provenance
  cohorts before scanning) to the simpler, directly-instructed scope: finish the 7,653-name
  eligibility pass, count/freeze eligible packages, dedup, extract build config, pilot, scan.
- **Search-derived discovery cohort: 7,653 candidates, COMPLETE eligibility processing.**
  `discover_candidates.py` queried the npm registry's relevance-ranked search API across 10
  indicator terms, bounded at 2000 results per term -- a real, reproducible, but
  coverage-bounded PRE-FILTER candidate list (`SEARCH_DERIVED_CANDIDATE_COHORT`), not a
  measurement of the npm universe. **The earlier comparison of this cohort's 7,653 unique
  names to CHARON's approximately 8.2K reference count implied a coverage validation that
  does not hold and remains withdrawn.**
- **Search-derived eligibility processing: COMPLETE, 7,653/7,653.** Real counts: ANALYZED
  (eligible) 494; NO_CPP_SOURCE 5,928; NO_JS_TS_SOURCE 792; NO_PACKAGE_OWNED_NATIVE_BINDING
  318; DOWNLOAD_FAILED 121. Frozen in `eligible_packages.tsv` (494 rows) and
  `checkpoints/eligibility_search_cohort_FINAL_00007653_*`.
- **Deduplication (item 4): COMPLETE.** All 494 eligible packages hashed
  (`npm_source_deduplication.tsv`); 494 distinct source trees, zero exact duplicates found in
  this cohort (`unique_source_trees.tsv`).
- **Build-configuration extraction (item 5): COMPLETE.** `npm_build_configuration.tsv`, all
  494 packages: unresolved 302, disabled 140, conflict 33, enabled 19.
- **Registry-wide enumeration: COMPLETE, documentation-only.** `enumerate_registry.py`
  walked the full public registry via `_all_docs`: 4,342,485 package id/rev pairs enumerated
  (registry grew slightly, from a 4,342,471 snapshot doc_count, during the ~35-minute walk --
  a real, expected fact about a live system, not an error). Recorded in
  `registry_universe_snapshot_metadata.json`. Per direct instruction, this number is cited
  ONLY to document registry universe size -- it is not fetched, scanned, prefiltered, or
  unioned into the eligible-package pool.
- **50-package Joern infrastructure pilot (item 6): COMPLETE, 50/50 ANALYZED.** See
  `PIPELINE_FREEZE.md` for the frozen pipeline hashes and real per-stage resource limits.
- **Full frozen-scanner run across all 494 eligible packages (item 7): COMPLETE.**
  473 ANALYZED, 18 RESOURCE_LIMIT (flagged, not yet retried), 3 CPP_CPG_FAILED. See
  `npm_pipeline_status.tsv` / `npm_pipeline_full_results.jsonl`.
- **Finding review (item 5): COMPLETE -- with a major, corpus-wide caveat, see
  `FINDINGS_REVIEW.md`.** Zero raw R04 findings across all 473 ANALYZED packages -- traced
  to a real, confirmed, corpus-wide PIPELINE GAP (c2cpg is never given the packages'
  declared native dependencies' headers, e.g. `node-addon-api`'s `napi.h`, so it cannot
  resolve ANY `Napi::` static-factory call -- confirmed by direct re-inspection of two real
  packages, 1,173/1,173 "New" calls unresolved). This is NOT evidence about real-world
  `Napi::Buffer::New()` prevalence; it is evidence of a gap in this pipeline specifically.
  Not yet fixed -- flagged for a deliberate decision, per instruction not to make further
  scanner/contract changes without direction.

## Discovery provenance values (used from this point forward)

Every candidate package name carries a `discovery_provenance` value once the union is built:

- `REGISTRY_RELEVANCE_SEARCH` -- surfaced only by `discover_candidates.py`'s search-API
  queries.
- `REGISTRY_ENUMERATION` -- surfaced only by `enumerate_registry.py`'s `_all_docs`
  walk + metadata prefilter.
- `BOTH` -- surfaced by both methods independently.

## Why the current eligibility run is still useful, and why it is not being discarded

The 1,789+ real, individually-verified eligibility records already produced (real tarball
downloads, real file-content inspection, real exclusion reasons) remain valid regardless of
which discovery method surfaced the candidate name -- eligibility is a property of the
package's own distributed source, not of how the package was discovered. This run continues
to completion over the full 7,653-name search-derived cohort and its results will be unioned
into the final eligibility table once registry enumeration also supplies its own candidates
for the same treatment. Nothing here is thrown away; the correction is to the FRAMING (what
this run does and does not establish), not to the run itself.
