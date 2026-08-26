# RECOVERED SNAPSHOT: tchecker-serialize-dos.zip (2026-08-23)

An older, self-contained serialize-DoS adjudication package recovered 2026-08-24 from a
user-provided archive. Integrated whole (per the "forgetting is worse than an extra
file" rule) because it contains 14 files absent from the main bundle by any name:

- 8 design docs not in docs/milestones/: TCHECKER_WRITEUP.md, EXPLOITABILITY_ADJUDICATION.md,
  OPEN_BRANCH_TEST.md, POLYMORPHISM_CONTROL.md, NEWREPO_EVALUATION.md, TS_GENERALIZATION.md,
  STEP4_TRACE_IDENTITY.md, STEP6_DISPOSITION_FIX.md
- run.sh: a single-file end-to-end demo pipeline (CPG -> setup_candidate ->
  property_propagation -> trace_identity -> adjudicate) the main bundle has no equivalent of
- fixtures/demo_{direct,lookup_falsepos,member_transform,ambiguous}.js + VERIFICATION.md
  with documented expected outcomes per fixture

Everything else in this snapshot is an OLDER version of files the main bundle already has
(notably adjudicate_js.py 28KB vs the current 48KB, and export_llm_facts.sc without the
KNOWN_LLM_HTTP_DOMAINS enhancement). No regressions were found in the current versions;
treat this snapshot's copies as historical.

RE-VERIFIED 2026-08-24 with Joern 4.0.608: all four demo fixtures run through ./run.sh
reproduce VERIFICATION.md's documented outcomes exactly:
  demo_direct            -> ESTABLISHED / RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS
  demo_lookup_falsepos   -> NO_FLOW     / REJECTED_NO_STRUCTURAL_FLOW
  demo_member_transform  -> OPEN        / CANDIDATE_OPEN
  demo_ambiguous         -> OPEN        / CANDIDATE_OPEN
This snapshot remains runnable as-is (it is self-contained by design; set JOERN_HOME).

## 2026-08-24 pruned to unique content
61 files byte-identical to copies already in the main bundle were removed from this
snapshot on request; the 48 remaining files are those whose content exists nowhere
else in the bundle (the 14 unique-by-name files plus older-but-differing versions of
adjudicator/producer code kept as history). The snapshot is no longer independently
runnable; run.sh's sibling dependencies now live in the main bundle.
