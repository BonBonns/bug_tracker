# JS-REAL-R01 — Real JavaScript/TypeScript Corpus Scan

Full phase reports: `PHASE1_CORPUS.md`, `PHASE2_FRONTEND_VALIDITY.md`,
`PHASE3_SECURITY_ANALYSES.md`, `PHASE4_ADJUDICATION.md`, `PHASE5_RESIDUAL.md`,
`PHASE6_NEXT_MILESTONE.md`. No engine changes were made during this pass
(confirmed: `frontends/` and `core/` untouched relative to the JS-STATE-R05
checkpoint).

## Semantic-signature comparison note

Per the "equal finding counts do not prove semantic stability" instruction:
this is JS-REAL-R01's first run against this corpus, so there is no prior run
to diff against yet. The one finding's full semantic signature (site,
value/storage identity, transformation, guard, sink, path evidence, verdict)
is recorded in full in `PHASE4_ADJUDICATION.md` specifically so a future
re-run of this same corpus/commit can be compared signature-by-signature, not
just by count, once JS-STATE-R06 or any other change lands.

---

# JS-REAL-R01 VERDICT

```text
CORPUS: mozilla/fxa @ e856cffdbf261c0b73ff51cde86045f77d26044b,
        packages/fxa-auth-server/lib/{routes,tokens,crypto,oauth}
        (198 files, 77,966 LOC; a deliberate, disclosed narrowing from the
        package's full 463-file/150,109-LOC lib/, not the whole monorepo)

FRONTEND HEALTH: PARTIAL. 113/198 staged files (57%) produced facts.
        85/198 excluded: 84 are *.spec.* test files (known, previously-
        documented jssrc2cpg AstGenRunner behavior, expected and benign for
        this scan's purpose), 1 is tokens/bundle.js -- a real,
        security-relevant, syntactically ordinary source file silently
        dropped with zero diagnostic output, cause not fully confirmed
        (best-supported hypothesis: filename collision with the common
        webpack/rollup "bundle.js" build-output naming convention). CFG
        facts: NOT EXPORTED by this pipeline at all (matches the
        pre-disclosed known limitation exactly). Both gaps are stated, not
        papered over; Phase 3-5 findings exclude tokens/bundle.js entirely
        rather than silently treating it as scanned-and-clean.

FINDINGS: 1 raw JS-STATE erasure candidate (out of 50,638 calls, 2,098
        control structures). 0 findings reached a profiled sensitive sink.
        0 excluded by the R04 branch approximation. 0 excluded by the R05
        reassignment approximation.

TRUE CANDIDATES: 0

FALSE POSITIVES: 1 (100% of findings), root cause RETURN_CONTRACT --
        classified RETURN_CONTRACT_NOT_ESTABLISHED. Full mechanism in
        PHASE4_ADJUDICATION.md: a template-string coercion correctly
        identified as an erasing transformation was applied to a plain
        database-record field with no success/failure return contract
        anywhere in its provenance, feeding a Set-membership dedup check
        (`seen.has(key)`), not a failure-state guard.

UNRESOLVED: 0

DOMINANT RESIDUAL: RETURN_CONTRACT (1/1 of observed false positives; the
        only nonzero root-cause bucket). Explicitly weak evidence at n=1,
        stated as such -- not inflated into a general claim. The more
        robust structural observation from this phase is the near-zero raw
        finding rate itself (1 candidate across 50,638 calls), which is a
        recall question this scan cannot resolve, but which materially
        undercuts treating R04/R05's known path/CFG approximation as
        automatically the most urgent gap: those approximations had zero
        opportunities to matter on this corpus.

NEXT MILESTONE: JS-STATE-R06 -- Return-Contract Establishment
        Characterization (proposed, NOT implemented in this pass). Full
        scope in PHASE6_NEXT_MILESTONE.md. CFG + Reaching-Definitions
        Unification (the pre-scan "known limitation") is explicitly NOT
        nominated as the immediate next step, because the evidence from
        this specific corpus does not support it as the dominant blocker --
        stated as a deliberate departure from the pre-scan expectation, not
        an oversight.
```
