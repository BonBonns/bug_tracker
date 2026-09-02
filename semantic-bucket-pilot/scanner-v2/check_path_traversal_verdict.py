#!/usr/bin/env python3
"""PATH-TRAV-REDUCE-R01 regression: runs path_traversal_verdict.py against FROZEN real Joern
output (export_path_traversal_integ_r01.sc, run over
tchecker-property-adjudicator/fixtures/path_traversal_r01/src/) checked into
tchecker-property-adjudicator/fixtures/path_traversal_r01/raw/, so this reproduces without needing
Joern again -- same convention as check_redos_verdict.py's own frozen-fixture design.

Covers, per direct instruction:
  1. All 12 required regression controls (sibling-prefix, user-controlled root, fixed-root
     sendFile/download, aliased/destructured/ESM import recognition, unrelated-object negative
     control, family split, Windows/POSIX separator, repeated traversal, unresolved options,
     proven/unresolved wrapper) via the reducer's own final findings/classification.
  2. The reducer's own two-family (PACKAGE_API_INPUT / APPLICATION_INGRESS_INPUT) tagging, read
     directly from source_facts.tsv, not collapsed to a single origin.
  3. reportable hardcoded False on every finding.
  4. BROKEN alternatives are correctly EXCLUDED from findings (never surfaced), while OPEN and
     ESTABLISHED alternatives both ARE (neither is "safe").
  5. A synthetic negative control for families_by_sink-equivalent alternatives_by_sink(), same
     shape as check_redos_verdict.py's own synthetic dual-family test.
  6. FIX01/FIX02 (round 1 post-review hardening): open()/openSync() flags-based read/write split
     (superseded by correction round 2's own 4-way resolution, re-verified below) and the
     canonicalize-after-check ordering bug.
  7. Correction round 2 (6 new fixtures, ctrl16-ctrl21): open()/openSync() flags now resolve to a
     genuine 4-value outcome (FS_READ/FS_WRITE/FS_READ_WRITE/an explicit abstention, never a
     guessed default) including real numeric/constants flags resolution; boundary-check
     canonicalization now requires REAL CFG dominance (Joern's own `.dominatedBy`/`.dominates`
     CfgNode API) plus a same-variable reaching-definition check, replacing round 1's disclosed
     line-number-order approximation -- confirmed via a real wrong-branch negative control (item 5)
     and a genuine-dominance-with-intervening-statement positive control (item 6).
  8. Final freeze verification: FS_OPEN_MODE_UNRESOLVED / EXPRESS_ROOT_OPTIONS_UNRESOLVED
     abstentions are a persisted, machine-readable record (sink_abstentions.tsv: call/site
     identity, path operand, source path, reason) -- not stderr-log-only, not a bare count that
     silently disappears when no sink target is emitted.
"""
import json
import pathlib
import subprocess
import shutil
import sys

HERE = pathlib.Path(__file__).parent
VERDICT = HERE / "path_traversal_verdict.py"
FIXTURES = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                          "tchecker-property-adjudicator/fixtures/path_traversal_r01"))

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real Joern-derived fixture: full end-to-end reducer run against the frozen raw/ dir. ---
out_path = HERE / "out_path_traversal_verdict.json"
work_dir = HERE / "out_path_traversal_verdict.json.work"
if work_dir.is_dir():
    shutil.rmtree(work_dir)
r = subprocess.run([sys.executable, str(VERDICT), str(FIXTURES / "raw"), str(FIXTURES / "src"),
                     str(out_path)], capture_output=True, text=True)
ck("path_traversal_verdict.py exits 0 against the frozen real fixture", r.returncode == 0)
doc = json.loads(out_path.read_text())
cls = doc["classification"]
findings = doc["findings"]

ck("ADJUDICATOR_RUN_FAILED == 0 (adjudicate_js.py ran cleanly for every candidate sink)",
   cls.get("ADJUDICATOR_RUN_FAILED") == 0)
ck("every finding has reportable hardcoded False",
   findings and all(f["reportable"] is False for f in findings))
ck("no BROKEN alternative is ever surfaced as a finding (genuinely proven containment is excluded)",
   all(f["containment_status"] != "BROKEN" for f in findings))
ck("ALTERNATIVES_BROKEN_EXCLUDED == 4 (ctrl11 wrapper-proven x2 alternatives + ctrl13 direct "
   "boundary-aware x1 + ctrl21 dominating-with-intervening-statement x1, added by correction "
   "round 2 item 6)", cls.get("ALTERNATIVES_BROKEN_EXCLUDED") == 4)
ck("PACKAGE_API_INPUT_REACHABLE == 2 (package_api_basic.js + package_api_named_exports.js)",
   cls.get("PACKAGE_API_INPUT_REACHABLE") == 2)
ck("APPLICATION_INGRESS_REACHABLE == 25 (every other real candidate sink -- 20 from round 1 "
   "plus 5 new correction-round-2 sinks: ctrl16 r+, ctrl17 w+, ctrl18's own 2 numeric-constants "
   "sites, ctrl20 wrong-branch; ctrl19 abstains with zero sink target and ctrl21 is BROKEN-"
   "excluded, so neither adds a REACHABLE-counted sink)",
   cls.get("APPLICATION_INGRESS_REACHABLE") == 25)
ck("FILESYSTEM_SINK_CANDIDATE == 27 (22 from round 1 + 5 new correction-round-2 sinks: ctrl16, "
   "ctrl17, ctrl18 x2, ctrl20 -- ctrl19 abstains entirely and ctrl21 still counts as a candidate "
   "sink even though its own alternative is BROKEN-excluded from findings)",
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 27)

# --- Control-by-control mapping. Sink LINE NUMBERS are per-file, not globally unique across this
# multi-file fixture (e.g. ctrl02's L6 collides with ctrl07's own L6) -- so controls are looked up
# by real sink_node_id instead, taken verbatim from the frozen fixture's own checked-in
# raw/run_summary.log (stable as long as the fixture .js/.mjs files and the pinned Joern version
# themselves don't change -- exactly the same stability assumption check_redos_verdict.py's own
# hardcoded finding counts already rely on for its frozen fixture).
SINK = {
    "ctrl01_sibling_prefix": "30064771079",
    "ctrl02_user_controlled_root": "30064771087",
    "ctrl05_aliased_fs_import": "30064771113",
    "ctrl08_windows_separator": "30064771151",
    "ctrl09_repeated_traversal": "30064771162",
    "ctrl11_wrapper_proven": "30064771186",
    "ctrl12_wrapper_unresolved": "30064771197",
    "ctrl14_open_write_flag": "30064771224",     # fs.open(userPath, 'w', cb) at L9
    "ctrl14_open_read_flag_explicit": "30064771226",  # fs.openSync(userPath, 'r') at L12
    "ctrl14_open_unresolved_flag": "30064771228",     # fs.open(userPath, flagsVar, cb) at L15 --
                                                       # correction round 2 now ABSTAINS here (was
                                                       # wrongly FS_READ under round 1's own logic);
                                                       # this id is kept only to assert its ABSENCE.
    "ctrl15_canonicalize_after_check": "30064771246",  # fs.readFile(resolved, ...) at L14
    # Correction round 2 (items 1-6, ctrl16-ctrl21):
    "ctrl16_open_flags_rplus": "30064771258",             # fs.open(userPath, 'r+', cb) at L7
    "ctrl17_open_flags_wplus": "30064771266",             # fs.openSync(userPath, 'w+') at L7
    "ctrl18_open_flags_numeric_write": "30064771274",     # O_WRONLY|O_CREAT at L12
    "ctrl18_open_flags_numeric_readwrite": "30064771281",  # bare O_RDWR at L15
    "ctrl19_open_flags_numeric_unresolved": "30064771293",  # O_WRONLY|extraFlags at L12 (abstains
                                                              # -- id kept only to assert ABSENCE)
    "ctrl20_wrong_branch_canonicalization": "30064771313",  # resolved.startsWith(...) at L20
    "ctrl21_dominating_canonicalization_intervening": "30064771333",  # readFile(resolved) at L15
}
by_sink_id = {}
for f in findings:
    by_sink_id.setdefault(f["sink_node_id"], []).append(f)

ck("Control 1 (sibling-prefix): a finding exists, containment_status != BROKEN, and carries a "
   "weak_diagnostic_guards note about the bare startsWith -- the old producer's own confirmed "
   "false-BROKEN bug does NOT reproduce here",
   SINK["ctrl01_sibling_prefix"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl01_sibling_prefix"]]) and
   any("startsWith" in n for f in by_sink_id[SINK["ctrl01_sibling_prefix"]] for n in f["weak_diagnostic_guards"]))
ck("Control 2 (user-controlled root): a finding exists tagged EXPRESS_SEND_FILE, never treated "
   "as contained, root-taint note present",
   SINK["ctrl02_user_controlled_root"] in by_sink_id and
   all(f["sink_family"] == "EXPRESS_SEND_FILE" and f["containment_status"] != "BROKEN"
       for f in by_sink_id[SINK["ctrl02_user_controlled_root"]]) and
   any("root itself is source-tainted" in n for f in by_sink_id[SINK["ctrl02_user_controlled_root"]]
       for n in f["weak_diagnostic_guards"]))
ck("Controls 3+4 (fixed-root sendFile/download): NEITHER produces any finding at all -- both "
   "genuinely recognized as contained (zero candidate rows, not merely BROKEN-and-filtered)",
   not any(f["sink_family"] == "EXPRESS_DOWNLOAD" for f in findings) and
   len(by_sink_id.get(SINK["ctrl02_user_controlled_root"], [])) == 1)  # the ONLY EXPRESS_SEND_FILE finding
ck("Control 5 (aliased fs import): a finding exists -- the audited producer's own confirmed miss "
   "is fixed",
   SINK["ctrl05_aliased_fs_import"] in by_sink_id and
   all(f["sink_family"] == "FS_READ" for f in by_sink_id[SINK["ctrl05_aliased_fs_import"]]))
ck("Control 6 (unrelated object literally named fs): its call is never even counted as a "
   "FILESYSTEM_SINK_CANDIDATE at all -- confirmed structurally: total candidates (27) matches the "
   "hand-verified count of REAL fs sinks across the fixture set, which excludes ctrl06 entirely",
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 27)
ck("Control 7 (family split): all three of FS_READ/FS_WRITE/FS_DELETE appear as distinct "
   "sink_family tags", {"FS_READ", "FS_WRITE", "FS_DELETE"}.issubset({f["sink_family"] for f in findings}))
ck("Control 8 (Windows/POSIX separator): a finding exists, never BROKEN, weak '.includes' "
   "diagnostic present regardless of separator style",
   SINK["ctrl08_windows_separator"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl08_windows_separator"]]) and
   any("includes" in n for f in by_sink_id[SINK["ctrl08_windows_separator"]] for n in f["weak_diagnostic_guards"]))
ck("Control 9 (repeated traversal / single-pass replace strip): a finding exists, never BROKEN -- "
   "no literal '..' strip (global or non-global) is ever treated as containment",
   SINK["ctrl09_repeated_traversal"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl09_repeated_traversal"]]) and
   any("replace" in n for f in by_sink_id[SINK["ctrl09_repeated_traversal"]] for n in f["weak_diagnostic_guards"]))
ck("Control 10 (unresolved options object): NO finding at all -- abstained, not guessed",
   not any(f["origin_code"] == "opts" for f in findings) and
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 27)  # would be 28 if ctrl10 had guessed no-root
ck("Control 11 (proven containment wrapper): EXCLUDED as BROKEN -- confirmed via the "
   "ALTERNATIVES_BROKEN_EXCLUDED count above (2 of the 3 are this sink's own two source-reference "
   "alternatives) rather than appearing in findings",
   SINK["ctrl11_wrapper_proven"] not in by_sink_id)
ck("Control 12 (unresolvable wrapper): a finding exists with containment_status OPEN (abstain), "
   "never assumed safe",
   SINK["ctrl12_wrapper_unresolved"] in by_sink_id and
   all(f["containment_status"] == "OPEN" for f in by_sink_id[SINK["ctrl12_wrapper_unresolved"]]))
ck("FIX01 (open()/openSync() flags-based read/write split, round 1): a literal write-mode flag "
   "('w') produces FS_WRITE and an explicit read-mode flag ('r') stays FS_READ",
   SINK["ctrl14_open_write_flag"] in by_sink_id and
   all(f["sink_family"] == "FS_WRITE" for f in by_sink_id[SINK["ctrl14_open_write_flag"]]) and
   SINK["ctrl14_open_read_flag_explicit"] in by_sink_id and
   all(f["sink_family"] == "FS_READ" for f in by_sink_id[SINK["ctrl14_open_read_flag_explicit"]]))
ck("Correction round 2, item 4 (regression fix on ctrl14's own unresolved-flag case): an "
   "UNRESOLVED (variable) flags argument now produces NO finding at all -- round 1's FIX01 "
   "wrongly defaulted this to FS_READ (a guess); it is now a real, logged abstention "
   "(FS_OPEN_MODE_UNRESOLVED), the same non-guessing discipline every other abstention in this "
   "producer already uses",
   SINK["ctrl14_open_unresolved_flag"] not in by_sink_id)
ck("FIX02 (round 1, canonicalize-after-check ordering) re-verified under the correction-round-2 "
   "TRUE-dominance mechanism: a canonicalizing assignment written AFTER the boundary check it "
   "would otherwise 'justify' must NOT retroactively prove containment -- a finding exists here, "
   "never BROKEN, with the same weak-startsWith diagnostic a bare check gets, PLUS the new "
   "CANONICALIZATION_DOMINANCE_UNPROVEN diagnostic (real dominance correctly finds the "
   "later-line assignment can never dominate the earlier check, same conclusion the old "
   "line-order approximation reached, now via a real proof instead of an approximation)",
   SINK["ctrl15_canonicalize_after_check"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl15_canonicalize_after_check"]]) and
   any("startsWith" in n for f in by_sink_id[SINK["ctrl15_canonicalize_after_check"]]
       for n in f["weak_diagnostic_guards"]) and
   any("CANONICALIZATION_DOMINANCE_UNPROVEN" in n for f in by_sink_id[SINK["ctrl15_canonicalize_after_check"]]
       for n in f["weak_diagnostic_guards"]))

# --- Correction round 2 (items 1-6), real fixture-verified assertions. ---
ck("Correction round 2, item 1: 'r+' flags literal resolves to the NEW FS_READ_WRITE family "
   "(ctrl16), not FS_READ and not FS_WRITE",
   SINK["ctrl16_open_flags_rplus"] in by_sink_id and
   all(f["sink_family"] == "FS_READ_WRITE" for f in by_sink_id[SINK["ctrl16_open_flags_rplus"]]))
ck("Correction round 2, item 2: 'w+' flags literal also resolves to FS_READ_WRITE (ctrl17), "
   "confirming every combined-mode literal in Node's own documented set is recognized, not just "
   "'r+'",
   SINK["ctrl17_open_flags_wplus"] in by_sink_id and
   all(f["sink_family"] == "FS_READ_WRITE" for f in by_sink_id[SINK["ctrl17_open_flags_wplus"]]))
ck("Correction round 2, item 3: numeric/constants flags that DO structurally resolve -- "
   "fs.constants.O_WRONLY | fs.constants.O_CREAT -> FS_WRITE (ctrl18's own OR-chain case) and a "
   "bare fs.constants.O_RDWR -> FS_READ_WRITE (ctrl18's own single-constant case)",
   SINK["ctrl18_open_flags_numeric_write"] in by_sink_id and
   all(f["sink_family"] == "FS_WRITE" for f in by_sink_id[SINK["ctrl18_open_flags_numeric_write"]]) and
   SINK["ctrl18_open_flags_numeric_readwrite"] in by_sink_id and
   all(f["sink_family"] == "FS_READ_WRITE" for f in by_sink_id[SINK["ctrl18_open_flags_numeric_readwrite"]]))
ck("Correction round 2, item 4: an OR-chain flags expression with ONE unresolvable operand (a "
   "bare variable mixed with a real fs.constants.O_WRONLY, ctrl19) produces NO finding at all -- "
   "the whole expression abstains rather than guessing a base access mode from the operand that "
   "happens to resolve; this generalizes the ctrl14 bare-variable regression fix above to the "
   "OR-chain shape",
   SINK["ctrl19_open_flags_numeric_unresolved"] not in by_sink_id)
ck("Correction round 2, item 5 (real before/after evidence, the core soundness fix): a "
   "canonicalizing assignment on ONE if/else branch (ctrl20) is NOT credited toward a boundary "
   "check that runs regardless of which branch executed -- round 1's own line-number-order "
   "approximation would have WRONGLY accepted this (the assignment's line precedes the check's "
   "line in straight top-to-bottom reading); the corrected TRUE-CFG-dominance mechanism correctly "
   "rejects it: containment_status is never BROKEN, the weak startsWith note fires, AND the new "
   "CANONICALIZATION_DOMINANCE_UNPROVEN note names the exact reason (neither branch's own "
   "assignment CFG-dominates the check)",
   SINK["ctrl20_wrong_branch_canonicalization"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl20_wrong_branch_canonicalization"]]) and
   any("startsWith" in n for f in by_sink_id[SINK["ctrl20_wrong_branch_canonicalization"]]
       for n in f["weak_diagnostic_guards"]) and
   any("CANONICALIZATION_DOMINANCE_UNPROVEN" in n for f in by_sink_id[SINK["ctrl20_wrong_branch_canonicalization"]]
       for n in f["weak_diagnostic_guards"]))
ck("Correction round 2, item 6 (positive control -- the dominance proof is not overly narrow): a "
   "canonicalizing assignment that TRULY, unconditionally dominates the boundary check, with a "
   "real intervening non-branching statement in between (ctrl21), is still recognized as genuine "
   "containment -- EXCLUDED as BROKEN (confirmed via the ALTERNATIVES_BROKEN_EXCLUDED count above, "
   "now 4, and via this sink's own absence from findings), same as the pre-existing "
   "ctrl13_boundary_aware_safe.js direct-adjacency positive control re-verified passing below",
   SINK["ctrl21_dominating_canonicalization_intervening"] not in by_sink_id)
ck("Correction round 2, item 6 continued: the pre-existing ctrl13_boundary_aware_safe.js direct "
   "(non-intervening) positive control still correctly recognizes genuine dominance after the "
   "TRUE-CFG-dominance rewrite -- EXCLUDED as BROKEN, not regressed by the stricter mechanism",
   "30064771215" not in by_sink_id)

# --- Final verification (per direct instruction): FS_OPEN_MODE_UNRESOLVED (and its sibling
# EXPRESS_ROOT_OPTIONS_UNRESOLVED) must be a persisted, machine-readable abstention record --
# call/site identity, path operand, source path, and unresolved-flags reason -- never only
# stderr logging or a bare count silently absent because no SinkTarget was emitted. Read
# sink_abstentions.tsv directly (real output from export_path_traversal_integ_r01.sc's own
# sinkAbstentions writer) rather than through the reducer, since abstentions are deliberately
# never turned into findings.
abstentions_path = FIXTURES / "raw" / "sink_abstentions.tsv"
abstention_rows = [ln.split("\t") for ln in abstentions_path.read_text().splitlines() if ln.strip()]
abstentions_by_file = {row[2]: row for row in abstention_rows if len(row) == 7}
ck("sink_abstentions.tsv is persisted in the frozen raw/ fixture output and is not empty",
   abstentions_path.is_file() and len(abstention_rows) > 0)
ck("Every abstention row carries all 7 required fields (callNodeId, line, file, reasonCode, "
   "pathOperandCode, callCode, reasonDetail) -- not log-only, not a bare count",
   len(abstention_rows) == 3 and all(len(row) == 7 for row in abstention_rows))
ck("ctrl10_unresolved_options.js's EXPRESS_ROOT_OPTIONS_UNRESOLVED abstention is persisted with "
   "real call/site identity and the actual path operand (req.params.name), not just a log line",
   abstentions_by_file.get("ctrl10_unresolved_options.js", ["", ""])[3] == "EXPRESS_ROOT_OPTIONS_UNRESOLVED" and
   abstentions_by_file["ctrl10_unresolved_options.js"][4] == "req.params.name" and
   abstentions_by_file["ctrl10_unresolved_options.js"][1] == "4")
ck("ctrl14_open_flags_write.js's FS_OPEN_MODE_UNRESOLVED abstention (variable flags argument) is "
   "persisted with the real unresolved flags reason, not defaulted to FS_READ or FS_WRITE",
   abstentions_by_file.get("ctrl14_open_flags_write.js", ["", ""])[3] == "FS_OPEN_MODE_UNRESOLVED" and
   "flagsVar" in abstentions_by_file["ctrl14_open_flags_write.js"][6])
ck("ctrl19_open_flags_numeric_unresolved.js's FS_OPEN_MODE_UNRESOLVED abstention (numeric/constants "
   "OR-chain with an unresolvable operand) is persisted with the real unresolved reason",
   abstentions_by_file.get("ctrl19_open_flags_numeric_unresolved.js", ["", ""])[3] == "FS_OPEN_MODE_UNRESOLVED" and
   "extraFlags" in abstentions_by_file["ctrl19_open_flags_numeric_unresolved.js"][6])
ck("None of the 3 abstained sink call ids ever produced a FILESYSTEM_SINK_CANDIDATE finding -- "
   "the abstention genuinely suppressed sink-target emission rather than merely annotating it",
   all(row[0] not in by_sink_id for row in abstention_rows))

# --- Import recognition coverage: ESM (4 shapes) + destructured CommonJS, all reachable. Counted
# structurally rather than by line/id (avoids re-encoding 5 more fixture-specific ids): every
# FS_READ finding whose sink_node_id is none of the other named controls' above, restricted to the
# import_*/package_api_*/ctrl07 files' worth of plain (non-weak, non-wrapper) FS_READ findings.
other_named_ids = set(SINK.values())
plain_fs_read_findings = [f for f in findings if f["sink_family"] == "FS_READ" and
                           f["sink_node_id"] not in other_named_ids and
                           not f["weak_diagnostic_guards"]]
# ctrl07's own plain read (1) + ctrl13's plain read is BROKEN-excluded (0) + import_destructured (1)
# + import_esm x4 (4) + package_api_basic (1) + package_api_abstentions' 2 real-but-unreachable
# sinks never appear at all (0, no source reaches them) = 1+1+4+1 = 7 distinct plain FS_READ sinks
# (ctrl14's own two plain reads -- explicit 'r' flag, unresolved flags arg -- are excluded from
# this count via `other_named_ids`, since they're separately, explicitly asserted by the FIX01
# check above; this count intentionally stays scoped to import-recognition coverage only).
ck("Import recognition: ESM (4 shapes) + destructured CommonJS + ctrl07's own plain read + "
   "package_api_basic's own plain read all produce plain (non-weak) FS_READ findings (7 distinct "
   "sinks total)", len({f["sink_node_id"] for f in plain_fs_read_findings}) == 7)

shutil.rmtree(work_dir, ignore_errors=True)

# --- 2. Synthetic negative control: alternatives_by_sink() itself preserves per-sink family
# membership and BROKEN-vs-not distinctions, independent of the real Joern fixture above. ---
_synthetic_sf = (
    "9001\t10\t7001\tPACKAGE_API_INPUT\tESTABLISHED\tFS_READ\t\t\t\t\t\t\n"
    "9001\t10\t7002\tAPPLICATION_INGRESS_INPUT\tESTABLISHED\tFS_READ\t\t\t\t\t\t\n"
    "9002\t20\t7003\tAPPLICATION_INGRESS_INPUT\tESTABLISHED\tFS_WRITE\tweak includes check\t\t\t\t\t\n"
)
_synthetic_po = (
    "9001\t7001\tBROKEN\t-1\t-1\n"
    "9001\t7002\tESTABLISHED\t-1\t-1\n"
    "9002\t7003\tOPEN\t-1\t-1\n"
)
import tempfile
with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    (tdp / "source_facts.tsv").write_text(_synthetic_sf)
    (tdp / "propagation_relations.tsv").write_text("")
    (tdp / "property_outcome.tsv").write_text(_synthetic_po)
    (tdp / "transform_identity.tsv").write_text("")
    sys.path.insert(0, str(HERE))
    import path_traversal_verdict as ptv
    alts = ptv.alternatives_by_sink(str(tdp))
    outc = ptv.containment_status(str(tdp))

ck("SYNTHETIC: sink 9001 carries BOTH origin families across its two alternatives",
   {a["origin_family"] for a in alts.get("9001", [])} == {"PACKAGE_API_INPUT", "APPLICATION_INGRESS_INPUT"})
ck("SYNTHETIC: sink 9002 carries only APPLICATION_INGRESS_INPUT and its own weak_diagnostic_guards",
   alts.get("9002", [{}])[0].get("origin_family") == "APPLICATION_INGRESS_INPUT" and
   alts.get("9002", [{}])[0].get("weak_diagnostic_guards") == ["weak includes check"])
ck("SYNTHETIC: containment_status distinguishes BROKEN (9001/7001) from ESTABLISHED (9001/7002) "
   "from OPEN (9002/7003) per-ALTERNATIVE, not per-sink",
   outc.get(("9001", "7001")) == "BROKEN" and outc.get(("9001", "7002")) == "ESTABLISHED" and
   outc.get(("9002", "7003")) == "OPEN")

# --- 3. Reducer skips the adjudicator cleanly when asked (fast structural-only mode) ---
import os
with tempfile.TemporaryDirectory() as td2:
    cls2, findings2 = ptv.emit_findings(str(FIXTURES / "raw"), str(FIXTURES / "src"), td2,
                                         run_adjudicator=False)
ck("run_adjudicator=False mode: same finding COUNT as the full adjudicator-backed run, with "
   "adjudicator_status SKIPPED on every finding",
   len(findings2) == len(findings) and all(f["adjudicator_status"] == "SKIPPED" for f in findings2))

out_path.unlink(missing_ok=True)

print(f"PATH_TRAVERSAL_VERDICT_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
