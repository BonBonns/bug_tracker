# JS-REAL-R01 — Real JS/TS Corpus Scan (mozilla/fxa)

First real-codebase measurement pass for the JS-STATE fact family, following
the fixture-only validation in JS-STATE-R02..R05. **Measurement/adjudication
pass only — no engine changes were made.**

Read `JS_REAL_R01_VERDICT.md` first for the summary. Full phase-by-phase
detail:

1. `PHASE1_CORPUS.md` — repository, commit, exact scoped directories, file/LOC
   counts, tool versions.
2. `PHASE2_FRONTEND_VALIDITY.md` — what the real frontend actually parsed vs.
   silently dropped (two distinct findings: expected `.spec.*` exclusion, and
   an unexplained `tokens/bundle.js` drop).
3. `PHASE3_SECURITY_ANALYSES.md` — JS-STATE run unchanged against the real
   corpus facts.
4. `PHASE4_ADJUDICATION.md` — full manual adjudication of the single finding.
5. `PHASE5_RESIDUAL.md` — false-positive root-cause table.
6. `PHASE6_NEXT_MILESTONE.md` — evidence-based next-step nomination
   (JS-STATE-R06, return-contract characterization — explicitly *not*
   CFG/reaching-definitions unification, despite that being the pre-scan
   expectation).

`reproduce.sh` re-runs the exact pipeline against a fresh checkout of the
corpus at the recorded commit. `evidence/` has the raw fact JSON and the
file-inventory diffs (`all_input_files.txt` / `parsed_files.txt` /
`missing_files.txt`) backing Phase 2's claims.

Bulky intermediate artifacts (`state_facts.json` ~17MB, `capture_facts.json`
~1.5MB — the property/closure fact dumps referenced by their summary counts in
Phase 2) are not archived here; regenerate via `reproduce.sh` if needed.
