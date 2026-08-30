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
- **Item 2 (pin the npm universe): IN PROGRESS.** A single immutable snapshot manifest of
  "the npm universe" has NOT yet been produced. What exists so far is described precisely
  below -- neither piece, alone or combined so far, constitutes item 2's deliverable.
- **Search-derived discovery cohort: 7,653 candidates, INCOMPLETE / COVERAGE-BOUNDED.**
  `discover_candidates.py` queried the npm registry's relevance-ranked search API across 10
  indicator terms, bounded at 2000 results per term. This is a **`SEARCH_DERIVED_CANDIDATE_
  COHORT`** -- a real, reproducible, but coverage-bounded PRE-FILTER candidate list, not a
  measurement of the npm universe and not comparable to any post-filter eligible-package
  count. **The earlier comparison of this cohort's 7,653 unique names to CHARON's
  approximately 8.2K reference count implied a coverage validation that does not hold and is
  withdrawn.** CHARON's number describes packages that passed real eligibility filtering;
  this cohort is pre-filter, produced by a fundamentally different (relevance-search, not
  registry-enumeration) discovery method, and the two counts happening to be the same order
  of magnitude is not evidence of comparable coverage.
- **Search-derived eligibility processing: real-time count, see below.** The eligibility
  filter (`eligibility_filter.py`) is running against the search-derived cohort in the
  background. Current completed-row count is reported at each checkpoint (see
  `checkpoints/`, newest `eligibility_search_cohort_*.json` sidecar for the authoritative
  current count) -- this document does not restate a point-in-time number that would go
  stale; check the newest checkpoint metadata instead.
- **Registry-wide enumeration: NOT YET STARTED as of this correction** (build underway in
  this same work session -- see `enumerate_registry.py` once committed). Will use the public
  npm CouchDB `_all_docs` interface, checkpointed key-based pagination, and a documented
  high-recall metadata prefilter, producing a `REGISTRY_ENUMERATION`-provenance candidate set
  independent of the search-derived cohort.
- **Final candidate union: NOT YET FROZEN.** The eventual pinned npm universe manifest
  (item 2's real deliverable) will be the union of the search-derived cohort
  (`REGISTRY_RELEVANCE_SEARCH` provenance) and the registry-enumeration cohort
  (`REGISTRY_ENUMERATION` provenance), with `BOTH` recorded for names appearing in both.
  That union has not been constructed or frozen.
- **Full Joern dataset evaluation: NOT YET STARTED.** Deduplication, build-configuration
  extraction, and the dual-CPG (jssrc2cpg + c2cpg) cross-language scan pipeline (items 4-7)
  do not begin until the candidate union above is frozen. The currently-running eligibility
  pass over the search-derived cohort is explicitly an infrastructure/early-cohort run, not
  the start of the final corpus evaluation.

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
