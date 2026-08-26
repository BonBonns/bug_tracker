# WORKSPACE_INVENTORY

Result of a systematic (not memory-based) search of the entire source workspace
(`/home/claude/work`, top-level, where all of this session's work actually lives), diffed
programmatically against the bundle's contents by filename, then individually investigated file
by file. Search terms used: `gate_`, `test_`, `verify_`, `fixture`, `_verdict.py`,
`build_evidence_`, `resolver_`, plus the full milestone-identifier sweep in `MILESTONE_INDEX.md`.

## 1. Gate matrix — all 13 gates, re-verified fresh from their final bundled locations

| Gate | Purpose | Dependencies | Fixture present | Current result | Bundled |
|---|---|---|---|---|---|
| `gates/gate_denylist_bypass.py` | Forminator `forminator_allowed_mime_types()` denylist/pattern-matcher-kind mismatch bypass | `denylist_bypass_verdict.py` (self-contained) | YES (`fixtures/deny-out/`) | **PASS** `DENYLIST_BYPASS=6/6` | YES |
| `gates/gate_globalmut.py` | Unleash `Mustache.escape` override, CWE-116 global shared-singleton mutation | `globalmut_verdict.py` (self-contained) | YES (`fixtures/gmut-out/`) | **PASS** `GLOBALMUT=6/6` | YES |
| `gates/gate_guard_fallthrough.py` | Pods `pods_error()` guard-fallthrough bypass | `guard_fallthrough_verdict.py` (self-contained) | YES (`fixtures/guard-out/`) | **PASS** `GUARD_FALLTHROUGH=6/6` | YES |
| `gates/gate_malicious_npm.py` | Install-exfil dependency-confusion shape (MAL-2026-14356) | `malicious_npm_verdict.py` (self-contained) | YES (`fixtures/mal-fixture/`, `fixtures/mal-out/`) | **PASS** `MALICIOUS_NPM=13/13` | YES |
| `gates/gate_serialize_dos.py` | Unleash `JSON.stringify` crash, CWE-674 | `serialize_dos_verdict.py` (self-contained) | YES (`fixtures/ser-out/`) | **PASS** `SERIALIZE_DOS=9/9` | YES |
| `gates/gate_validation_bypass.py` | Elementor Pro `Upload::validation()` loop-control divergence | `validation_bypass_verdict.py` (self-contained) | YES (`fixtures/loop-out/`) | **PASS** `VALIDATION_BYPASS=6/6` | YES |
| `gates/gate_r38.py` | Cross-mount Express/Koa middleware dataflow, real Corpus D shape | `gates/app_mount_flow.py` -> Component B (`context_state_flow.py`, `framework_registration.py`) — **real cross-component dependency, confirmed working** | YES (`fixtures/r38-out/`, `fixtures/r38-fixture/`) | **PASS** `JS_PROV_R38=10/10` | YES |
| `gates/gate_r39.py` | Router-composition relation measured on real Corpus D (koa-knex-realworld-example) | Same as R38 | YES (`fixtures/r39-out/`) | **PASS** (reproduced from real Corpus D; see update below) | YES |
| `gates/gate_r40.py` | Nested/multi-hop export-member resolution, closes R39's export-side blocker | Same as R38 | YES (`fixtures/r40-out` symlink to byte-identical `r39-out`) | **PASS** (reproduced from real Corpus D; see update below) | YES |
| `tchecker-property-adjudicator/adjudicator/gate_llm_input.py` | LLM01/LLM02 prompt-injection and insecure-output-handling gate | `llm_input_verdict.py`, Joern, and `producers/export_llm_facts.sc` | **SOURCE ONLY** (`fixtures/llm_input/`); required TSVs are not pre-generated | **REQUIRES FACT GENERATION** — follow RUNBOOK §5; missing TSVs are a hard error | Code and source fixture YES; generated facts NO |
| `tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_bridge.py` | Bounded `WEBEXT_TAB_URL_INPUT` to SSRF-property integration, plus real Mozilla no-sink holdout | `portable_ssrf_source_bridge.py`, `export_ssrf_integ.sc`, frozen live-run facts | YES (`fixtures/webext_ssrf_bridge/`) | **PASS** `WEBEXT_SSRF_BRIDGE=9/9` | YES |
| `tchecker-property-adjudicator/adjudicator/gate_webext_external_ssrf_bridge.py` | Exact external-message payload bridge with inline/named handler controls | same bridge and frozen facts | YES (`fixtures/webext_ssrf_bridge/external_controlled/`) | **PASS** `WEBEXT_EXTERNAL_SSRF_BRIDGE=10/10` | YES |
| `tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_llm_handoff.py` | `OPEN` external-message SSRF path through two unknown transforms, with complete manual-review context | SSRF property facts, canonical code-context exporter, frozen real LLM packet | YES (`fixtures/webext_ssrf_transform/`) | **PASS** `WEBEXT_SSRF_LLM_HANDOFF=10/10` | YES |

**12 of 13 gates run from bundled fact fixtures. The LLM-input gate bundles source fixtures but
requires Joern fact generation first; RUNBOOK §5 documents the exact command and `outDir` parameter.**

## 2. Documentation and historical scripts found and added this pass

13 milestone `.md` files (design history for the exact mechanisms bundled: `PATH_CODE_CONTEXT`,
`PATH_FLOW_CONTEXT`, `SOURCE_TO_SINK_PATH` rendering, transform identity, property propagation,
etc.) → `tchecker-property-adjudicator/docs/milestones/`.

15 Python scripts (`build_evidence*.py`, `build_customs_*.py`, `resolver_*.py`, `make_ablation.py`,
`path_transform_identity.py`, `triage_pkg.py`) → `tchecker-property-adjudicator/historical/`.
Checked against every currently-bundled, working script's imports: **none of them are imported by
anything that currently runs**. Their docstrings ("Fourth semantic shape," "PROOF adapter...
Validates the four-part architecture," "Proves the STATE MACHINE") read as earlier design/proof
iterations superseded by the consolidated `adjudicate_js.py`. Included anyway, not deleted, per
the instruction that forgetting is worse than an extra file — but labeled `historical/`, not
presented as currently-active code.

2 shell utilities: `gates/scan_pkg.sh` (the real fixture-regeneration pipeline for the 6
self-contained gates — genuinely useful, but NOT self-contained in this bundle's directory layout,
see `gates/SCAN_PKG_NOT_SELF_CONTAINED.md`) and `joern-install.sh` (bundle root — a real,
permission-aware Joern installer, more robust than the plain `curl`+`unzip` in RUNBOOK.md).

## 3. Full accounting

```
TOTAL_RELEVANT_WORKSPACE_FILES = 102   (top-level .py/.sc/.json/.md/.sh in the source workspace)
TOTAL_BUNDLED                  = 102   (all accounted for -- see below)
TOTAL_INTENTIONALLY_EXCLUDED   = 0     (nothing top-level was found and deliberately left out)
  TOTAL_MISSING_HISTORICAL       = 0     (r39 facts bundled; r40 is the intentional r39-out symlink)
TOTAL_GATES                    = 12
  GATES_RUN_FROM_BUNDLED_FACTS   = 11    (6 detector gates + r38/r39/r40 + two WebExtension SSRF bridges)
  GATES_REQUIRE_FACT_GENERATION  = 1     (gate_llm_input; source fixture and producer are bundled)
CROSS_COMPONENT_DEPENDENCIES   = 5     (see CROSS_COMPONENT_DEPENDENCIES.md)
UNACCOUNTED_RELEVANT_FILES     = 0
```

All 30 files initially found "not yet bundled" by the filename diff were individually resolved:
13 milestone docs (bundled), 15 historical scripts (bundled, labeled), 2 shell utilities (bundled,
one honestly marked non-self-contained). The 3 apparent JSON "misses" in the first diff pass were
false positives from an incomplete comparison (already bundled under `property_configs/` with
identical filenames) — corrected before this document was written, not left as an open question.

## 4. What "TOTAL_BUNDLED = 102" does NOT claim

It does not claim every one of the 48 milestone identifiers in `MILESTONE_INDEX.md` was
individually deep-dived — most are design increments inside already-bundled Component B files,
accounted for by the file being present, not by a separate per-milestone investigation. It does
not claim `scan_pkg.sh` or the 15 historical scripts run correctly out of the box — both
limitations are stated plainly in their respective files, not smoothed over. It claims: every
top-level file in the source workspace matching the search terms has been found, classified, and
either bundled or explicitly excluded with a stated reason. That is what closure means here.

## 6. UPDATE 2026-08-24 (final) — Java core integrated, full engine suite verified

The missing Java core (PortableProvenanceEngine / ProgramGraphLoader) arrived in two
user-provided archives (commit ef05d8a, then a later full-bundle snapshot) and is now
merged into portable-engine-full-review-package/. VERIFY_FABLE=PASS. The later snapshot
independently reproduced the r39/r40 fixtures -- every regenerated fact file matches
this session's regeneration byte-for-byte (sorted), and it identified the original
char->raw typedecls producer (tests/gates/js-prov-r08/export_callsites.sc), confirming
the bridge derived here from r38-out ground truth. One truncated file
(FieldDeclarationEnvironment.java, 0 bytes in earlier snapshots) was restored from the
repo. Engine canonical suite: all executed gates PASS with JDK 21 + Joern 4.0.608,
including GUARD-R01 6/6 after regenerating its operator-maintained /tmp fixtures
(see tests/gates/guard-r01/FIXTURE_NOTE.md for the stale-fixture root cause).

## 7. UPDATE 2026-08-24 — third-party removal and deduplication
Per operator request: (a) all files byte-identical to upstream octopus-platform/joern
(286 files) and 4 Maven Central jars removed from engine/legacy-detector; only the 29
locally-modified/added sources remain, with a verifiable restore manifest at
detector/THIRD_PARTY_REMOVED.md. (b) joern-install.sh removed (see ENVIRONMENT.md for
the pinned-download note; Joern 4.0.608 itself was never locally modified). (c)
gates/fixtures/r40-out is now a symlink to r39-out (they were byte-identical by
construction). (d) The recovered serialize-dos snapshot was pruned to content unique
to it (61 exact duplicates removed). (e) Joern cpg.bin.tmp runtime twins deleted.
Completeness re-verified: every file of the authoritative snapshot is present by
content except the intentional removals above and gate runtime artifacts regenerated
by this session's verified-green suite runs.
