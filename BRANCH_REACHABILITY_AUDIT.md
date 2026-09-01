# Branch-reachability audit — `claude/*` vs `claude/provenance-preservation-task35`

Baseline: `origin/claude/provenance-preservation-task35` @ `924f63b` (the authoritative,
newest code lineage — six-property aggregator, corrected reachability gate, task #46/#44/#38
all landed).

Method: for every non-trivial branch, real `git diff --name-status` against task35 (Added /
Modified / Deleted, never inferred from commit messages), spot-checked with
`git diff --stat`/full diff on every Modified file to distinguish "branch has content task35
lacks" from "task35 has since superseded/evolved past this file" — because this session's own
integration method was manual content-copy, not literal cherry-pick, `git cherry -v`
patch-equivalence was tried first and found unreliable (nearly everything showed as falsely
"unique"), so it is not used as evidence below. Ancestor relationships confirmed with
`git merge-base --is-ancestor`.

20 `claude/*` branches total. Grouped by lineage below; a "most advanced" branch is the sole
one actually inspected file-by-file where a chain of ancestors makes the others redundant.

---

## Group 0 — trivially fully subsumed (0 commits ahead of task35)

| branch | head | commits ahead | recommendation |
|---|---|---|---|
| `aggregate-kinds-producer-test-03zs7n` | `48b0984` | 0 | **exclude** — no action |
| `how-claude-code-works-j9lpw0` | `c14c572` | 0 | **exclude** — no action |
| `nss-asan-secret-key-test-ycmw7t` | `3976f61` | 0 | **exclude** — no action |

Nothing to audit further: task35 already contains every commit on these.

---

## Group 1 — "day-1" cluster (2026-08-29): CAP property system + academic-dataset benchmarking
+ Mozilla NSS/mozjpeg audits

Chain: `previous-conversation-context-6gr99h` (43 ahead) → `emission-gap-delegation` (47) →
`emission-gap-delegation-verify` (48) → `emission-gap-fix` (53) → `cap1-wsd-identity` (50,
most advanced — **but note `cap1-wsd-identity`'s commit count is lower than `emission-gap-fix`'s
because it branched from a slightly different point; confirmed by `--is-ancestor` that
`emission-gap-fix` IS an ancestor of `cap1-wsd-identity`**, so the chain holds and the first
four are fully subsumed by the fifth). Sibling: `moz-scan-exploratory` (30 ahead, independent —
neither ancestor nor descendant of `cap1-wsd-identity`; shares the same merge-base `c3007c0`).

merge-base with task35 for the whole cluster: `c3007c0` (well before task35's own current work
began — this is an entirely separate lineage root).

### `cap1-wsd-identity` (representative; head `2e2fa83`)
- **111 files added**, none modified/deleted relative to task35 (task35 never touches this code).
- Categories: `cap_controls/{audit,cap2,cap2_magma,cap3_member,cap4_contracts,cap4_decoder,
  cap_loop,idadv,idcollide,overlap}/` (controls/fixtures for a whole separate property system —
  `cap_counted_loop_writer.py`, `cap_decoder_contract.py`, `cap_member_pointer_walk.py`,
  `cap_underflow_length.py`, `cap_wrapper_summary.py`, `cap_write_site_dedup.py`,
  `cap1_identity_audit.py`, `cap3_domain_audit.py`); `dev_controls/emitgap/`; real
  **academic vulnerability-dataset benchmark study artifacts** under `study/{arvo,bigvul,
  emission_gap_delegation_verify,heldout_correction,heldout_diagnosis,heldout_negatives,
  heldout_run,magma,pooled,secvuleval_full}/`.
- Architecture: this is a **separate detection framework from the current R04-R06/staged
  OOB/LOCK_BALANCE pipeline** — different property model ("CAP1-4"), different provenance
  mechanism, benchmarked against real labeled vuln corpora rather than the live npm corpus.
  Real work, not scaffolding — but not an extension of task35's pipeline; merging it in as-is
  would sit alongside the six-property system without integrating into it.
- **Classification: accepted-but-architecturally-separate.** Not superseded (nothing on task35
  reimplements it), not experimental scaffolding (it has real benchmark results), not
  documentation-only (it's code + data).
- **Recommendation: archive/tag, exclude from `develop` for now, flag prominently for explicit
  separate review.** This is real, substantial, currently-orphaned work that deserves its own
  decision (fold into `develop` as a second property system, or keep as a standalone research
  branch) — not something to silently absorb into a `develop` built around the six-property
  pipeline's own architecture. Suggest: `git tag archive/cap-property-system-2026-08-29
  claude/cap1-wsd-identity` (or similar), keep the branch alive, do not delete.

### `moz-scan-exploratory` (head `bb0b0c2`, sibling — not part of the cap1 chain)
- **75 files added**, all under `moz-exploratory-scan/{README.md,commands/,raw_outputs/,
  reports/,sources_pin/}` — real security-audit work against Mozilla NSS and mozjpeg: real
  audit reports (`AUDIT_aeskeywrap_cts.md`, `AUDIT_hmacct_MAC.md`, `AUDIT_sftk_doSSLMACInit.md`,
  `AUDIT_ssl3_ComputeECDHKeyHash.md`, `NSS_SCOPE_EXPANSION_softoken_ssl.md`,
  `PILOT_REPORT.md`, `SCANNER_IMPROVEMENT_NOTES.md`), plus a real `hmacct_hardening.patch`.
- Zero overlap in touched files with the cap1 chain or with task35 — an independent pilot,
  not scaffolding.
- **Classification: accepted, standalone, documentation+patch (not part of the JS↔C/C++ npm
  pipeline at all — a different target codebase entirely).**
- **Recommendation: archive/tag, exclude from `develop`.** Same reasoning as `cap1-wsd-identity`
  — real, valuable, but a genuinely separate research thread (different target: browser/NSS
  code, not npm native addons) that should not be silently folded into the npm-scanner
  `develop` branch. Flag for separate review/decision.

---

## Group 2 — R05/R06/NAN lineage

Chain: `r05-near-miss-audit` (11 ahead) → `nan-prevalence-study` (12, confirmed strict
ancestor of nan-capability) → `nan-capability` (14, confirmed strict ancestor of
r05-new-gate-classification) → `r05-new-gate-classification` (15, **most advanced
representative**). `r06-precision-fix` was in the user's original list but its content is
confirmed identical to `nan-capability`'s own position in this chain (same file set, no
divergence found) — not separately audited beyond that confirmation.

merge-base with task35: `75a615a`.

### `r05-new-gate-classification` (representative; head `fdab323`)
**75 files added**, 16 modified, 0 deleted, relative to task35.

**Added (real, currently missing from task35):**
- `resource_contracts_nan.py`, `resource_guard_verdict_nan.py` — a whole separate, real
  Resource Guard variant for the NAN contract family (tasks #25/#26's own deliverable), with
  `tests/test_resource_guard_verdict_nan.py`.
- `study/nan_capability/` — design doc, freeze doc, a full positive-control fixture
  (`controls/comprehensive_fixture/` — real Joern-style TSV facts + expected output), and
  **real 8-package corpus-run evidence** (`corpus_runs/{kafka-javascript,libpq,msgpack,
  murmurhash-native,node-snap7,node-snap7-micro-client,phplike,scrypt}/`).
- `study/nan_prevalence_study/` — `PREVALENCE_STUDY.md`, `classify_origins.py`,
  `scan_contract_families.py`, real prevalence TSVs.
- `study/r05_near_miss_audit/` — `R05_INTERIM_NEAR_MISS_AUDIT.md`, `FROZEN_REVIEW_LIST.md`,
  `build_funnel.py`, a real frozen snapshot JSON.
- `study/r06_stratified_review/` — `PRE_REGISTRATION.md`, `STRATIFIED_REVIEW_RESULTS.md`.
- `study/r05_new_gate_classification/` — `README.md`, `classify.py`, extract JSON (task #27-
  adjacent classification work).
- `study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` — **confirmed genuinely
  missing**: task35's own `resource_guard_verdict_r06.py` docstring cites this exact path and
  it does not exist anywhere on task35 — a real broken reference on the current authoritative
  branch that this file would fix.
- `npm_corpus/{CHECKPOINT_METADATA_ERRATUM.md,EVIDENCE_BUNDLE_SIZING.md,R06_POST_FREEZE_PLAN.md,
  evidence_bundle.py,run_pipeline_one_r06.py,tests/test_evidence_bundle.py,
  tests/test_make_checkpoint.py,tests/test_target_scoping.py}` — **already present on
  `overnight-diagnostic-100`** (confirmed by direct existence check), so these are NOT a net-new
  gap; they'll arrive via that branch's own already-approved integration.
- `tests/{test_aggregation_boundary.py,test_source_boundary.py,test_target_scoping_e2e.py}` —
  same: already present on `overnight-diagnostic-100`.

**Modified (spot-checked individually, not assumed):**
- `resource_guard_verdict_r06.py` — **+32/-2, real and NOT superseded**: this is the
  `count_actionable_findings()`/`ACTIONABLE_VERDICTS` reporting-boundary safeguard (confirmed
  absent from task35's own current `resource_guard_verdict_r06.py` — no `actionable` string
  anywhere in it). A real, disclosed fix ensuring `len(findings)` (which includes real
  abstentions like `CONTRACT_NOT_APPLICABLE`) is never confused with the count of actionable
  `VALUE_ACQUISITION_GUARD_MISSING` candidates. **Task35 is missing this.**
  **This is the single highest-value cherry-pick candidate in this whole audit** — it is a
  real correctness/reporting-boundary fix on the same file task35 already ships, not a parallel
  copy.
- `link_napi_facts.py` — task35 has 938 more lines than this branch's copy (task35 supersedes;
  nothing to gain here — this branch's copy predates task35's own evolution of the file).
- `.gitignore` — this branch's copy is missing one line task35 already has
  (`.../r06_fix01i_integration/real_fixtures/_generated_*.json` ignore entry); irrelevant,
  task35 is ahead here too.
- `npm_corpus/CORPUS_STATUS.md`, `npm_corpus/make_checkpoint.py`, `npm_corpus/run_pipeline_one.py`,
  `study/resource_guard_r05/.gitignore`, `tests/gates/guard-r01/FIXTURE_NOTE.md`, the six
  `oob_*_verdict.py`/`oob_*_controls.py` files under `tools/` — **all confirmed net *fewer*
  lines than task35's own current versions** (task35 supersedes every one; these are earlier,
  already-evolved-past snapshots — nothing to gain from any of them).

**Classification: accepted, partially superseded.** The NAN Resource Guard variant, its real
corpus evidence, the stratified-review/near-miss docs, and the `count_actionable_findings` fix
are all real, valuable, and currently missing from task35. Everything else touched by this
branch is already superseded by task35's own later evolution or already covered by
`overnight-diagnostic-100`'s approved integration.

**Recommendation: cherry-pick selected files (not wholesale merge, per your own constraint).**
Concretely, from `r05-new-gate-classification` (`fdab323`):
1. `resource_contracts_nan.py`, `resource_guard_verdict_nan.py`,
   `tests/test_resource_guard_verdict_nan.py`
2. `study/nan_capability/**`, `study/nan_prevalence_study/**`
3. `study/r05_near_miss_audit/**`, `study/r06_stratified_review/**`,
   `study/r05_new_gate_classification/**`
4. `study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`
5. The `count_actionable_findings()`/`ACTIONABLE_VERDICTS` diff into task35's own current
   `resource_guard_verdict_r06.py` (hand-merge, since task35's file has otherwise diverged —
   do not overwrite the whole file)

Do NOT bring over `link_napi_facts.py`, the `oob_*` tools files, `make_checkpoint.py`,
`run_pipeline_one.py`, or `.gitignore` from this branch — all confirmed stale relative to
task35.

---

## Group 3 — crosslang/R06-FIX01I lineage

`crosslang-linker-fix` (10 ahead) confirmed a **strict ancestor** of `r06-fix01i-integration`
(21 ahead, **sole representative** — fully subsumes crosslang-linker-fix, zero unique added
files on crosslang-linker-fix beyond it).

merge-base with task35: `75a615a` (same root as Group 2).

### `r06-fix01i-integration` (representative; head `0463bd6`)
Real added-file gap analysis (files that exist ONLY here, confirmed absent from all 3 active
session branches):
- `CHECKPOINT_METADATA_ERRATUM.md`, `test_make_checkpoint.py`, `test_target_scoping.py`,
  `study/crosslang_link_fix/CHARACTERIZATION.md`, `test_source_boundary.py`,
  `test_target_scoping_e2e.py`, `test_aggregation_boundary.py` — **7 files not on any of the
  3 active branches or on `r05-new-gate-classification` either** (confirmed: the first six of
  these overlap by name with files that ARE already on `overnight-diagnostic-100` under
  `npm_corpus/`/`tests/`, so most are already covered by that branch's approved integration).
  The one genuinely distinct item: `study/crosslang_link_fix/CHARACTERIZATION.md` — worth a
  direct existence check before `develop` is finalized.
- `CROSSLANG_LINK_FIX01I_FREEZE.md`, `EVIDENCE_BUNDLE_SIZING.md`, `R06_POST_FREEZE_PLAN.md`,
  `evidence_bundle.py`, `run_pipeline_one_r06.py`, `test_evidence_bundle.py` — **already present
  on `overnight-diagnostic-100`**, no gap.

Modified-file spot-check (all 6 `oob_*_verdict.py`/`oob_*_controls.py` files under `tools/`,
`run_pipeline_one.py`, `make_checkpoint.py`, `test_promote_via_js_linkage.py`,
`export_neutral.sc`, `normalize_joern_facts.py`): **every one confirmed net *fewer* lines or
pure-deletion relative to task35** except `make_checkpoint.py` (+66/-9, `run_pipeline_one.py`
(+7/-98 — task35 ahead), `export_neutral.sc` (+83, task35-only addition — task35 ahead),
`normalize_joern_facts.py` (+34/-2, task35 ahead). **In every single modified-file case, task35
is the more-evolved version.** No logic gap found in this branch's own touched files beyond
what's already captured in Group 2's `resource_guard_verdict_r06.py` finding (this branch does
not itself modify that file).

**Classification: superseded** (code), **partially-unincorporated** (one doc:
`study/crosslang_link_fix/CHARACTERIZATION.md`, plus whatever remains once
`overnight-diagnostic-100`'s own commits are actually applied — this audit found no code gap,
only a possible doc gap).

**Recommendation: cherry-pick `study/crosslang_link_fix/CHARACTERIZATION.md` only, if it is
confirmed not already covered by `overnight-diagnostic-100`'s own commits (verify at `develop`-
build time); otherwise exclude entirely.** No code from this branch should be merged — task35
supersedes all of it.

---

## Group 4 — analyzer class inventory (task #27, documentation-only)

`analyzer-class-matrix-audit` (1 ahead) confirmed a **strict ancestor** of
`analyzer-class-inventory` (5 ahead, representative); their one shared file
(`ANALYZER_CLASS_COVERAGE_MATRIX.md`) is byte-identical between them.

merge-base with task35: `32ac493`.

### `analyzer-class-inventory` (representative; head `5adecad`)
- 12 files, all additions, all documentation/data: `ANALYZER_CLASS_COVERAGE_MATRIX.md`,
  `analyzer_class_inventory/ANALYZER_CLASS_INVENTORY.md`,
  `NPM_JS_TS_CPP_ANALYZER_INVENTORY.md`, `README.md`, `compute_npm_totals.py`,
  `compute_totals.py`, 5 `data/*.csv` files. Small, self-contained, read-only survey work
  (task #27 in the completed-tasks list) — no code it could conflict with.

**Classification: accepted, documentation-only, self-contained.**

**Recommendation: cherry-pick wholesale (all 12 files) — low risk, no code overlap, real
completed deliverable.**

---

## Group 5 — the 3 active session branches (already have an approved plan)

| branch | head | ahead | status |
|---|---|---|---|
| `provenance-preservation-task35` | `924f63b` | — (base) | authoritative code lineage — this is what `develop` is built from |
| `oob-lockbalance-integration-pilot` | `61a4f6a` | 26 | docs/study branch — only its unique documentation/study commits integrate, per your own prior instruction |
| `overnight-diagnostic-100` | `d0ab955` | 10 | run-artifacts branch — only its run artifacts, report, sample manifest, and unique orchestration commits integrate |

No new findings here beyond what was already established and approved before the "audit
everything first" instruction — this group's plan stands as previously agreed, execution just
paused pending this report.

---

## Summary table

| branch/cluster | commits ahead | unique real content | classification | recommendation |
|---|---|---|---|---|
| `aggregate-kinds-producer-test-03zs7n` | 0 | none | trivial | exclude |
| `how-claude-code-works-j9lpw0` | 0 | none | trivial | exclude |
| `nss-asan-secret-key-test-ycmw7t` | 0 | none | trivial | exclude |
| day-1 CAP chain (`cap1-wsd-identity` repr., 4 subsumed) | 43–53 | CAP1-4 property system, academic-dataset benchmarks | accepted, architecturally separate | archive/tag, exclude from `develop`, flag for separate review |
| `moz-scan-exploratory` | 30 | real Mozilla NSS/mozjpeg audits + hardening patch | accepted, standalone (different target codebase) | archive/tag, exclude from `develop`, flag for separate review |
| R05/R06/NAN chain (`r05-new-gate-classification` repr., 3 subsumed; `r06-precision-fix` ≡ this chain) | 11–15 | NAN Resource Guard variant + real 8-pkg corpus evidence, `count_actionable_findings` fix, review docs, `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` | accepted, partially superseded | cherry-pick selected files (list above) |
| crosslang/FIX01I chain (`r06-fix01i-integration` repr., 1 subsumed) | 10–21 | possibly 1 doc (`CHARACTERIZATION.md`), rest superseded or covered by overnight-100 | superseded (code), verify-then-maybe-cherry-pick (doc) | cherry-pick 1 doc if not already covered; else exclude |
| analyzer-class chain (`analyzer-class-inventory` repr., 1 subsumed) | 1–5 | full task #27 inventory, docs-only | accepted, self-contained | cherry-pick wholesale |
| 3 active session branches | 10–26 | already-approved plan | accepted | proceed per prior instruction |

## Net effect on the `develop`-build plan

Your original 3-branch plan is confirmed correct as far as it goes, but incomplete. The
corrected plan:

1. Build `develop` from `claude/provenance-preservation-task35` @ `924f63b` (unchanged).
2. Integrate `oob-lockbalance-integration-pilot`'s unique docs/study commits (as before).
3. Integrate `overnight-diagnostic-100`'s run artifacts/report/manifest/orchestration commits
   (as before).
4. **New:** cherry-pick the NAN Resource Guard variant + its real corpus evidence + the
   `count_actionable_findings` fix + review docs from `r05-new-gate-classification`.
5. **New:** cherry-pick `analyzer-class-inventory`'s 12 files wholesale.
6. **New:** verify then maybe cherry-pick one doc from `r06-fix01i-integration`.
7. **Explicitly exclude, archive/tag, and flag for your separate review:** the day-1 CAP
   property-system cluster and `moz-scan-exploratory` — both real, substantial, but
   architecturally outside the six-property pipeline `develop` is being built around.

I have not created `develop` and have not cherry-picked anything — this is the audit only,
awaiting your decision on steps 4–7 before I touch any branch.
