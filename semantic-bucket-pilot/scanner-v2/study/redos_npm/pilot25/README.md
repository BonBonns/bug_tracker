# Frozen 25-package ReDoS discovery pilot (pre-registered)

Per direct instruction: "Freeze a deterministic npm discovery sample before viewing results.
Don't continue selecting packages manually one at a time." This directory is that
pre-registration -- `prefilter_select_25.py` is the complete, deterministic selection
mechanism, `pilot25_selection.json` is its frozen output, committed BEFORE any of the 21
selected packages was run through the real Joern pipeline.
`pilot25_selection_provenance.json` adds the corpus/prefilter integrity hashes and exact
selection criteria (added retroactively, per direct instruction; attests to the same,
unmodified frozen file).

**Terminology, precise**: the 21 packages below are the pilot's own `PREFILTER_SELECTED` INPUT
set -- packages chosen for deeper analysis, never ReDoS findings themselves, and unrelated to any
other unresolved item elsewhere in this project. Only records that reach `PACKAGE_API_INPUT_
REACHABLE` after the real pipeline runs proceed to manual review; see
`PILOT25_MANUAL_REVIEW.md`/`pilot25_categorized_results.json` for the full category breakdown
(`PREFILTER_SELECTED` -> `PIPELINE_ANALYZED`/`INFRASTRUCTURE_FAILURE` -> `NO_COMPLEXITY_CANDIDATE`/
`COMPLEXITY_ONLY`/`PACKAGE_API_INPUT_REACHABLE` -> `MANUALLY_CONFIRMED`/`MANUALLY_REJECTED`/
`ABSTAINED`).

## Protocol

1. **Candidate pool**: `npm_corpus/eligible_packages.tsv`'s own `ANALYZED` rows (494 packages,
   the project's own already-frozen npm native-addon corpus) -- its own row order is the tie-break
   ("frozen corpus order"), never invented.
2. **Cheap source-only prefilter** (no Joern): each package's real tarball is fetched fresh and
   its `.js`/`.ts`/`.mjs`/`.cjs` files (excluding `node_modules/`, `test/`, `.min.js`) are scanned
   as TEXT for three required conditions:
   - an exported-function-shaped statement (`module.exports=`, `module.exports.NAME=`,
     `exports.NAME=`, `export function`, `export default`, `export const NAME = (...) =>`);
   - at least one regex literal;
   - among those literals, at least one matching the FROZEN Stage 2 classifier's own DANGEROUS
     shape -- `prefilter_select_25.py`'s `classify_dangerous()` is a direct, function-for-function
     Python port of `export_redos_npm_integ.sc`'s own `classifyPattern`/`NESTED_QUANTIFIER`/
     `splitTopLevelAlternation`/`hasQuantifierFollowedByMoreContent`, NEVER a separate or looser
     heuristic -- verified byte-identical against all 6 patterns already validated in Scala
     (CVE-2025-5892, autotranslate.ts, the cors-safe negative, the textbook nested-quantifier
     case, `safe_export.js`'s pattern, and `ms`'s real pattern) before being trusted for
     selection.
3. **Score** = count of DANGEROUS-shaped regex literals found ("supported-sink count", direct
   instruction's own term) -- a cheap proxy for what the real Joern pipeline would confirm.
4. **Select**: descending score, ties by ascending `row_index` (frozen corpus order). Target
   ceiling 25; only 21 packages in the 494-package corpus actually satisfied all three required
   conditions -- reported as-is, the ceiling was never artificially filled.
5. **Freeze**: `pilot25_selection.json` written and committed BEFORE step 6.
6. **Run the frozen ReDoS pipeline once** over exactly those 21 packages -- `run_pilot25.py`,
   `pilot25_results.json`.
7. **Manual review** of every full-path (`PACKAGE_API_INPUT_REACHABLE`) candidate the real
   pipeline produces -- `PILOT25_MANUAL_REVIEW.md`. The analyzer (`export_redos_npm_integ.sc`,
   `redos_verdict.py`) is NOT modified between step 5 and the completion of step 7, per direct
   instruction.

## Selection result

21 packages qualified (full list and scores: `pilot25_selection.json`). Top 5 by score:
`ember-one-way-controls` (89), `@appthreat/sqlite3` (29), `realm` (16), `linux-device` (8),
`numbl` (6).
