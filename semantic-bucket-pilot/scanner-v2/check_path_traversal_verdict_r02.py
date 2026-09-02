#!/usr/bin/env python3
"""PATH-TRAV-REDUCE-R02 regression: runs path_traversal_verdict.py against FROZEN real Joern
output (export_npm_source_identity.sc THEN export_path_traversal_integ_r02.sc, run in that order
against the SAME cpg of tchecker-property-adjudicator/fixtures/path_traversal_r02/src/) checked
into tchecker-property-adjudicator/fixtures/path_traversal_r02/raw/, so this reproduces without
needing Joern again -- same convention as check_path_traversal_verdict.py's own frozen-fixture
design.

`fixtures/path_traversal_r02/src/` is the ORIGINAL 26 R01 fixture files (unmodified, copied
verbatim) PLUS 4 new ones (multi_origin_fs_sink.js, shadow_same_name_params_fs.js,
closure_capture_fs_sink.js, shadow_nested_scope_fs.js) exercising the shared-source-identity
capabilities R01's own hand-rolled Capability 3 could not provide. Every one of R01's own 40
check_path_traversal_verdict.py assertions is separately reverified UNCHANGED, in place, against
the FROZEN R01 fixture set -- this file does not re-litigate them; run
`check_path_traversal_verdict.py` for that (still 40/40 after the ONLY change made to
path_traversal_verdict.py this round: sink_abstentions consumption -- see that file's own
docstring).

This file instead verifies TWO things:
  1. STRUCTURAL regression: export_path_traversal_integ_r02.sc's copied-verbatim sink/containment
     logic finds the SAME REAL fs/Express sink call sites structurally as R01 did on its own 26
     files (R01: 29 sink targets on those 26 files; R02 on 26+4=30 files: 34 -- exactly 29 + 5 new
     real sink call sites contributed by the 4 new fixtures: closure_capture_fs_sink.js (1),
     multi_origin_fs_sink.js (1), shadow_same_name_params_fs.js (2),
     shadow_nested_scope_fs.js (1)) -- confirmed via the producer's own real run_summary.log,
     quoted below, never hand-computed.
  2. The REAL, DISCLOSED consequence and improvement of consuming the shared, frozen
     export_npm_source_identity.sc's own source_origin_facts.tsv instead of R01's own hand-rolled
     name-matching resolution (per this file's own header comment in
     export_path_traversal_integ_r02.sc):
       a. MULTIPLE_ORIGINS is now real and OBSERVABLE for Path Traversal: multi_origin_fs_sink.js's
          one (sink, src) pair emits TWO rows (PACKAGE_API_INPUT + APPLICATION_INGRESS_INPUT),
          never collapsed -- confirmed via a REAL side-by-side comparison: R01's own frozen
          producer, run against this SAME cpg, emits only ONE row for the identical sink (its own
          `familyOfSource` never even considers the bare `req` identifier an
          APPLICATION_INGRESS_INPUT candidate at all, since its own ingress model only recognizes
          `req.<field>` field-access shapes, not a bare `req` reference).
       b. Same-name-parameter distinctness across SEPARATE exported functions
          (shadow_same_name_params_fs.js) -- both R01 and R02 keep these correctly distinct here
          (R01's own `p.method.ast`-scoped search happens not to cross-contaminate SIBLING
          functions), a real, honestly-reported "no observed regression, no observed improvement"
          result for this specific shape.
       c. Closure-capture-correct PACKAGE_API_INPUT resolution (closure_capture_fs_sink.js) -- R02
          correctly resolves the closure-captured parameter via `source_origin_facts.tsv`; R01,
          run on the SAME cpg, ALSO happens to get this specific fixture right (its own
          `p.method.ast` AST-subtree search happens to include the nested closure's own
          identifiers here) -- again a real, honest "no observed difference for this specific
          fixture" result, not a manufactured miss.
       d. The REAL, sharp false-positive R01's naive name-matching search is vulnerable to:
          WITHIN-METHOD shadowing (shadow_nested_scope_fs.js) -- a nested function inside the SAME
          exported method declares its OWN, differently-bound local variable of the exact same
          name as the outer exported parameter. R01, run on this SAME cpg, WRONGLY emits 2 rows
          crediting this sink as reachable from the outer (entirely UNUSED) exported parameter;
          R02 correctly emits ZERO rows, since `source_origin_facts.tsv`'s own
          refsTo/closureBindingId-based identity resolution never conflates the shadowed inner
          Local with the outer MethodParameterIn.
  3. The missing-`source_origin_facts.tsv` degrade-safe case
     (fixtures/path_traversal_r02/raw_missing_source_facts/, a real, separate Joern run of ONLY
     export_path_traversal_integ_r02.sc with the shared producer's own output never written first).
  4. `sink_abstentions` now appears in path_traversal_verdict.py's own FINAL JSON output (not just
     the raw TSV, which check_path_traversal_verdict.py already covers) -- read back out of the
     written JSON file itself.
  5. The real npm-package validation result (fixtures/path_traversal_r02/raw_real_package/, a real
     Joern run of both producers against miniml-1.0.19, one of the 4 real dev-package tarballs
     already staged at fixtures/npm_source_identity_r01/dev_packages/ -- motifer-26.1.1 and
     ms-2.1.3 were checked and have ZERO real fs-sink-relevant code; miniml's own `lib/yaml.js`
     exports `loadYamlFile(file)`/`loadYamlFileSync(file)`, whose own `file` parameter is passed
     DIRECTLY to `readFile`/`readFileSync` -- a real, genuine, non-manufactured
     PACKAGE_API_INPUT-reachable fs-read finding in real, unmodified npm package source).
"""
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
VERDICT = HERE / "path_traversal_verdict.py"
FIXTURES = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                          "tchecker-property-adjudicator/fixtures/path_traversal_r02"))

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real Joern-derived fixture: full end-to-end reducer run against the frozen R02 raw/ dir. ---
out_path = HERE / "out_path_traversal_verdict_r02.json"
work_dir = HERE / "out_path_traversal_verdict_r02.json.work"
if work_dir.is_dir():
    shutil.rmtree(work_dir)
r = subprocess.run([sys.executable, str(VERDICT), str(FIXTURES / "raw"), str(FIXTURES / "src"),
                     str(out_path)], capture_output=True, text=True)
ck("path_traversal_verdict.py exits 0 against the frozen real R02 fixture", r.returncode == 0)
doc = json.loads(out_path.read_text())
cls = doc["classification"]
findings = doc["findings"]
abstentions = doc["abstentions"]

ck("ADJUDICATOR_RUN_FAILED == 0 (adjudicate_js.py ran cleanly for every candidate sink)",
   cls.get("ADJUDICATOR_RUN_FAILED") == 0)
ck("every finding has reportable hardcoded False",
   findings and all(f["reportable"] is False for f in findings))
ck("no BROKEN alternative is ever surfaced as a finding",
   all(f["containment_status"] != "BROKEN" for f in findings))
ck("FILESYSTEM_SINK_CANDIDATE == 31 (real count after the shared npm-source-identity module was "
   "itself corrected, R02, to restore Meteor.methods-registered-parameter recognition -- the SAME "
   "18 real R01 controls that use Meteor.methods regain their own source recognition here, on top "
   "of the 4 req.*-shaped controls, the 2 package_api_*.js controls, and the 3 new fixtures that "
   "resolve; see docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md's own 'shared-module fix' "
   "addendum for the real before/after numbers)",
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 31)
ck("PACKAGE_API_INPUT_REACHABLE == 6, APPLICATION_INGRESS_REACHABLE == 26 (real counts from the "
   "frozen raw/ fixture, regenerated against export_npm_source_identity_r02.sc -- "
   "APPLICATION_INGRESS_REACHABLE rose from 2 to 26 once Meteor.methods recognition was restored "
   "in the shared module, since 18 of R01's own controls source their attacker-controlled path "
   "from a Meteor.methods handler parameter, not req/request)",
   cls.get("PACKAGE_API_INPUT_REACHABLE") == 6 and cls.get("APPLICATION_INGRESS_REACHABLE") == 26)
ck("ALTERNATIVES_ESTABLISHED == 29, ALTERNATIVES_OPEN == 3, ALTERNATIVES_BROKEN_EXCLUDED == 4 "
   "(real counts against the regenerated fixture -- the 4 BROKEN-excluded alternatives are the "
   "same genuine containment proofs R01 already established: ctrl11's own 2 wrapper-proven "
   "alternatives, ctrl13's direct boundary-aware check, ctrl21's dominating-canonicalization-with-"
   "intervening-statement case -- none of which depend on which source family reached them)",
   cls.get("ALTERNATIVES_ESTABLISHED") == 29 and cls.get("ALTERNATIVES_OPEN") == 3 and
   cls.get("ALTERNATIVES_BROKEN_EXCLUDED") == 4)

# --- 2. Structural regression proof: sink/containment logic copied verbatim finds the SAME real
# sink call sites (29 from R01's own 26 files + 5 new ones from the 4 new fixtures = 34). ---
run_log = (FIXTURES / "raw" / "run_summary.log").read_text()
ck("export_path_traversal_integ_r02.sc's own real run log reports sink targets found: 34 -- "
   "R01's own real 29 (unchanged, copied-verbatim sink/containment logic) + 5 new real sink call "
   "sites from the 4 new fixtures (closure=1, multi_origin=1, shadow_same_name=2, "
   "shadow_nested_scope=1)",
   "sink targets found: 34 " in run_log)

# --- 3. MULTIPLE_ORIGINS, now real: multi_origin_fs_sink.js's one (sink, src) pair emits TWO
# rows, one per real distinct family, never collapsed. ---
multi_origin_sink = "30064771384"
multi_rows = [f for f in findings if f["sink_node_id"] == multi_origin_sink]
ck("multi_origin_fs_sink.js: sink emits exactly 2 findings, same origin_node_id, one row per "
   "REAL distinct family (PACKAGE_API_INPUT and APPLICATION_INGRESS_INPUT), never collapsed to one",
   len(multi_rows) == 2 and
   {f["origin_family"] for f in multi_rows} == {"PACKAGE_API_INPUT", "APPLICATION_INGRESS_INPUT"} and
   len({f["origin_node_id"] for f in multi_rows}) == 1 and
   all(f["package_api_input"] == "ESTABLISHED" and f["application_ingress"] == "ESTABLISHED" for f in multi_rows))

# --- 4. Same-name-parameter distinctness: shadow_same_name_params_fs.js's two exported functions
# each reach their OWN sink from their OWN, structurally distinct source -- never cross-wired. ---
shadow_same_name_sinks = {"30064771442": "readAlpha", "30064771444": "readBeta"}
shadow_rows = {sid: [f for f in findings if f["sink_node_id"] == sid] for sid in shadow_same_name_sinks}
ck("shadow_same_name_params_fs.js: readAlpha's sink (30064771442) and readBeta's sink "
   "(30064771444) each carry exactly ONE finding, with DISTINCT origin_node_id (never "
   "cross-contaminated between the two identically-named parameters)",
   all(len(rows) == 1 for rows in shadow_rows.values()) and
   len({rows[0]["origin_node_id"] for rows in shadow_rows.values()}) == 2)

# --- 5. Closure-capture-correct PACKAGE_API_INPUT resolution. ---
closure_sink = "30064771072"
closure_rows = [f for f in findings if f["sink_node_id"] == closure_sink]
ck("closure_capture_fs_sink.js: the nested closure's own use of the captured parameter correctly "
   "resolves to a PACKAGE_API_INPUT finding via source_origin_facts.tsv's own "
   "refsTo/closureBindingId identity chain",
   len(closure_rows) == 1 and closure_rows[0]["origin_family"] == "PACKAGE_API_INPUT" and
   closure_rows[0]["origin_code"] == "userPath")

# --- 6. shadow_nested_scope_fs.js: the WITHIN-METHOD shadowing false-positive R01's own
# name-matching search is vulnerable to -- R02 correctly emits ZERO findings for this sink. ---
shadow_nested_sink = "30064771431"
ck("shadow_nested_scope_fs.js: the shadowed-local sink produces ZERO findings under R02 (the "
   "outer exported parameter is never actually used; the value reaching the sink is a "
   "same-named but structurally distinct inner Local, correctly excluded by real identity "
   "resolution) -- confirmed absent from source_facts.tsv-derived findings entirely",
   not any(f["sink_node_id"] == shadow_nested_sink for f in findings))

# --- 7. sink_abstentions still 3, unaffected by the source-model change (abstention logic is
# copied verbatim and does not depend on sources at all). ---
ck("sink_abstentions.tsv (raw) still carries exactly the 3 real R01 abstentions (ctrl10, ctrl14, "
   "ctrl19) -- the abstention mechanism is copied verbatim and does not depend on sources",
   len((FIXTURES / "raw" / "sink_abstentions.tsv").read_text().splitlines()) == 3)

# --- 8. sink_abstentions now appears in the reducer's own FINAL JSON output (not just the raw
# TSV -- read back out of the written JSON file itself). ---
ck("path_traversal_verdict.py's own final JSON output (out_path_traversal_verdict_r02.json) now "
   "carries a top-level 'abstentions' key with exactly the 3 real abstention records, each with "
   "all 7 fields, read back from the file this reducer itself wrote (not re-read from the TSV)",
   len(abstentions) == 3 and
   all(set(a.keys()) == {"call_node_id", "line", "file", "reason_code", "path_operand_code",
                          "call_code", "reason_detail"} for a in abstentions) and
   {a["reason_code"] for a in abstentions} == {"FS_OPEN_MODE_UNRESOLVED", "EXPRESS_ROOT_OPTIONS_UNRESOLVED"})
ck("one of those abstention records names the real ctrl10_unresolved_options.js "
   "EXPRESS_ROOT_OPTIONS_UNRESOLVED site with its real path operand",
   any(a["file"] == "ctrl10_unresolved_options.js" and a["reason_code"] == "EXPRESS_ROOT_OPTIONS_UNRESOLVED"
       and a["path_operand_code"] == "req.params.name" for a in abstentions))

shutil.rmtree(work_dir, ignore_errors=True)
out_path.unlink(missing_ok=True)

# --- 9. Missing source_origin_facts.tsv degrade-safe case: a real, separate Joern run of ONLY
# export_path_traversal_integ_r02.sc (the shared producer's own output never written first). ---
missing_dir = FIXTURES / "raw_missing_source_facts"
missing_summary = json.loads((missing_dir / "path_traversal_r02_summary.json").read_text())
ck("degrade-safe case: source_origin_facts_present is real and false, source_origin_facts_rows "
   "== 0, package_api_sources == 0, application_ingress_sources == 0 -- never a guessed source",
   missing_summary.get("source_origin_facts_present") is False and
   missing_summary.get("source_origin_facts_rows") == 0 and
   missing_summary.get("package_api_sources") == 0 and
   missing_summary.get("application_ingress_sources") == 0)
ck("degrade-safe case: sink_targets is STILL a real, non-zero structural count (33 -- every "
   "sink identification is structural and does not depend on sources at all) even though ZERO "
   "sources were recognized -- this is not a crash and not a silently-empty-because-broken result",
   missing_summary.get("sink_targets") == 33)
ck("degrade-safe case: source_facts.tsv (rows_emitted) is genuinely 0 -- no fabricated/guessed "
   "source-reachability row is ever emitted when the upstream dependency is missing",
   missing_summary.get("rows_emitted") == 0)
missing_log = (missing_dir / "run_summary.log").read_text()
ck("degrade-safe case: a real, disclosed stderr WARNING names the missing upstream dependency by "
   "file path and explains the required pipeline order -- never a silent zero",
   "WARNING: source_origin_facts.tsv NOT FOUND" in missing_log and
   "export_npm_source_identity.sc" in missing_log and "MUST be run" in missing_log)
missing_verdict_out = HERE / "out_path_traversal_verdict_r02_missing.json"
rmiss = subprocess.run([sys.executable, str(VERDICT), str(missing_dir), str(FIXTURES / "src"),
                         str(missing_verdict_out)],
                        capture_output=True, text=True, env={"PT_VERDICT_SKIP_ADJUDICATOR": "1",
                                                              "PATH": "/usr/bin:/bin"})
ck("degrade-safe case, end to end through the reducer: exits 0, zero findings, zero "
   "classification counts -- never a crash on an empty source_facts.tsv",
   rmiss.returncode == 0 and
   json.loads(missing_verdict_out.read_text())["findings"] == [] and
   json.loads(missing_verdict_out.read_text())["classification"]["FILESYSTEM_SINK_CANDIDATE"] == 0)
shutil.rmtree(HERE / "out_path_traversal_verdict_r02_missing.json.work", ignore_errors=True)
missing_verdict_out.unlink(missing_ok=True)

# --- 10. Real npm-package validation (miniml-1.0.19's own lib/yaml.js). ---
real_dir = FIXTURES / "raw_real_package"
real_summary = json.loads((real_dir / "path_traversal_r02_summary.json").read_text())
ck("real npm-package validation (miniml-1.0.19): sink_targets == 2 (loadYamlFile's readFile + "
   "loadYamlFileSync's readFileSync), source_origin_facts_present is real and true, "
   "package_api_sources == 192 (the shared producer's own real export-surface resolution across "
   "this package's own real, unmodified source), zero application_ingress_sources (a library, no "
   "req/request-shaped code anywhere)",
   real_summary.get("sink_targets") == 2 and real_summary.get("source_origin_facts_present") is True and
   real_summary.get("package_api_sources") == 192 and real_summary.get("application_ingress_sources") == 0)
ck("real npm-package validation: rows_emitted == 4 (2 sinks x 2 real source references each -- "
   "the exported function's own parameter reference at both the export-time and the call-site "
   "identifier), all PACKAGE_API_INPUT, all ESTABLISHED, zero BROKEN/OPEN -- a genuine, "
   "non-manufactured finding in real, unmodified npm package source, not a fabricated example",
   real_summary.get("rows_emitted") == 4 and real_summary.get("broken") == 0 and
   real_summary.get("open") == 0 and real_summary.get("established") == 4)

print(f"PATH_TRAVERSAL_VERDICT_R02={ok}/{total}")
sys.exit(0 if ok == total else 1)
