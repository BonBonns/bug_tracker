# Branch reconciliation: one definitive scanner commit

Per the frozen ordering (PREREGISTER_BIGVUL.md / PREREGISTER_ARVO.md): pooled held-out
population frozen FIRST, then this reconciliation, then all gates, and only then any
held-out scanner measurement or capability 2 work.

## Branch state at reconciliation

- `claude/how-claude-code-works-j9lpw0` = `c3007c0` (the PostCutoff freeze).
- `claude/previous-conversation-context-6gr99h` = this branch. `c3007c0` is a STRICT
  ANCESTOR of this branch's history; the two lines share every commit (verdict-producer
  accounting work included) and NEVER diverged in code — the earlier "separate thread"
  reading was wrong. Reconciliation is therefore a declaration, not a merge:
  **this branch's head is the single definitive scanner commit.** The `j9lpw0` branch
  name can be fast-forwarded to it (no force needed) or retired; until then it simply
  points into this branch's past.
- No scanner/verdict/engine code changed between `c3007c0` and this commit — only
  corpus-construction artifacts (pre-registrations, freeze scripts, frozen manifests),
  which are scanner-independent by design. So no held-out scanner measurement anywhere
  predates this reconciliation with an ambiguous scanner version.

## Gate inventory at this commit (all run on this container, this commit)

- `run_all_gates.sh` (tests/run_all.py): EXECUTED 26/26 PASS, HISTORICAL_RECORDED 8/8,
  REGRESSIONS 0.
- Scanner-line gates (not covered by run_all.py), all PASS at full marks:
  OOB_ADJ_R01 10/10, OOB_CALLCTX_R01 11/11, OOB_CALLSINK_R01 7/7, OOB_COPYLEN_R01 11/11,
  OOB_CURSOR_R01 10/10, OOB_INDEX_R01 9/9, OOB_INTERPROC_R01 6/6, OOB_PTRINC_R01 6/6,
  OOB_RUNTIMECAP_CFG_R01 6/6, OOB_RUNTIMECAP_R01 18/18, ANALYSIS_RECORD_R01 53/53,
  OOB_COMPARE_CONTROLS PASS, STATIC_EXTENT_SAFE_CONTROLS PASS.
- BLOCKED (environmental, not code): gates requiring real Joern/jssrc2cpg/c2cpg
  (GATE 24/24-TS, JSTS-R05/R06, JS-STATE-R02/R03/R07, JS-PROP-R03, JS-PROV-R08..R36,
  CPP-*, SINK-R01, SOURCE-R02, GUARD-R01 fixture regen, POLY-R01-H). These need the
  external toolchain installed; they were equally blocked at `c3007c0` and no code
  they exercise changed since. They are inventory, not regressions.

## What is now unlocked

Capability 2 may begin against the frozen pooled population
(`study/pooled/FROZEN_heldout_pooled.json`: 83 mapped vulnerable sites, 19 distinct
proof-obligation families, 12-family gate MET) — measured ONLY at or after this commit,
with all capabilities frozen before any pooled yield is inspected.
