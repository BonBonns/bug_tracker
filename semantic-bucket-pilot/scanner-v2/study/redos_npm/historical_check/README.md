# Historical known-positive validation (REDOS_NPM_FIRST_PASS_RESULTS.md)

`historical.js` wraps the EXACT two real, disclosed regex patterns
`ATTACKER_CONTROLLED_REGEX_COMPLEXITY` was originally built from (RocketChat's own real
CVE-2025-5892 and the autotranslate.ts finding -- see `docs/REDOS_SINK_SEMANTICS_MATRIX.md` in
tchecker-property-adjudicator) in a realistic npm named-export shape, plus one fully-anchored
safe pattern as a negative control. Run through `export_redos_npm_integ.sc` directly: both real
patterns correctly classified DANGEROUS and correctly resolved as PACKAGE_API_INPUT-reachable;
the safe pattern correctly excluded. Confirms the copy-paste of the frozen Stage 1/2 logic into
the new producer preserved its behavior exactly on real, disclosed ground truth -- not just
re-derived analytically.

Regenerating: same procedure as `fixtures/README.md`, pointed at this directory instead.
