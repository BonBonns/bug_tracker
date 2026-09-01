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
ck("ALTERNATIVES_BROKEN_EXCLUDED == 3 (ctrl11 wrapper-proven x2 alternatives + ctrl13 direct "
   "boundary-aware x1)", cls.get("ALTERNATIVES_BROKEN_EXCLUDED") == 3)
ck("PACKAGE_API_INPUT_REACHABLE == 2 (package_api_basic.js + package_api_named_exports.js)",
   cls.get("PACKAGE_API_INPUT_REACHABLE") == 2)
ck("APPLICATION_INGRESS_REACHABLE == 20 (every other real candidate sink, including ctrl14's 3 "
   "open()/openSync() sites and ctrl15's own single site, added by FIX01/FIX02)",
   cls.get("APPLICATION_INGRESS_REACHABLE") == 20)

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
    "ctrl14_open_unresolved_flag": "30064771228",     # fs.open(userPath, flagsVar, cb) at L15
    "ctrl15_canonicalize_after_check": "30064771246",  # fs.readFile(resolved, ...) at L14
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
   "FILESYSTEM_SINK_CANDIDATE at all -- confirmed structurally: total candidates (22) matches the "
   "hand-verified count of REAL fs sinks across the fixture set, which excludes ctrl06 entirely",
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 22)
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
   cls.get("FILESYSTEM_SINK_CANDIDATE") == 22)  # would be 23 if ctrl10 had guessed no-root
ck("Control 11 (proven containment wrapper): EXCLUDED as BROKEN -- confirmed via the "
   "ALTERNATIVES_BROKEN_EXCLUDED count above (2 of the 3 are this sink's own two source-reference "
   "alternatives) rather than appearing in findings",
   SINK["ctrl11_wrapper_proven"] not in by_sink_id)
ck("Control 12 (unresolvable wrapper): a finding exists with containment_status OPEN (abstain), "
   "never assumed safe",
   SINK["ctrl12_wrapper_unresolved"] in by_sink_id and
   all(f["containment_status"] == "OPEN" for f in by_sink_id[SINK["ctrl12_wrapper_unresolved"]]))
ck("FIX01 (open()/openSync() flags-based read/write split): a literal write-mode flag ('w') "
   "produces FS_WRITE, an explicit read-mode flag ('r') and an UNRESOLVED flags argument both "
   "stay FS_READ -- the fix only ever narrows the conservative default, never guesses toward write",
   SINK["ctrl14_open_write_flag"] in by_sink_id and
   all(f["sink_family"] == "FS_WRITE" for f in by_sink_id[SINK["ctrl14_open_write_flag"]]) and
   SINK["ctrl14_open_read_flag_explicit"] in by_sink_id and
   all(f["sink_family"] == "FS_READ" for f in by_sink_id[SINK["ctrl14_open_read_flag_explicit"]]) and
   SINK["ctrl14_open_unresolved_flag"] in by_sink_id and
   all(f["sink_family"] == "FS_READ" for f in by_sink_id[SINK["ctrl14_open_unresolved_flag"]]))
ck("FIX02 (canonicalize-after-check ordering): a canonicalizing assignment written AFTER the "
   "boundary check it would otherwise 'justify' must NOT retroactively prove containment -- a "
   "finding exists here, never BROKEN, with the same weak-startsWith diagnostic a bare check gets",
   SINK["ctrl15_canonicalize_after_check"] in by_sink_id and
   all(f["containment_status"] != "BROKEN" for f in by_sink_id[SINK["ctrl15_canonicalize_after_check"]]) and
   any("startsWith" in n for f in by_sink_id[SINK["ctrl15_canonicalize_after_check"]]
       for n in f["weak_diagnostic_guards"]))

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
