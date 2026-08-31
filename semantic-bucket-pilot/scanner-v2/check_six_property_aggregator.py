#!/usr/bin/env python3
"""SIX-PROP-AGG-R01 (task #47) controls. Covers: Resource Guard always included/trusted;
staged-enabled properties correctly summarized; OOB_COMPARE always DISABLED with its real reason
recorded; the hard invariant (a disabled property must never carry a reportable finding) both
holds on real data and is verified to actually FIRE when deliberately violated; and a real small
smoke test against TWO already-existing real evidence bundles from the completed
overnight-diagnostic-100 run (no new corpus run) -- SKIPs gracefully if that run's own bundles
aren't present in this environment.
"""
import json
import os
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import six_property_aggregator as agg
import reachability_tier as rt
import staged_enablement as se

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def mk(reportable):
    return {"reportable": reportable}

# --- Resource Guard: always included, never gated by staged_enablement's own set ---
record1 = {"r04_findings": [mk(True)], "r05_findings": [mk(False)], "r06_findings": [mk(True)]}
summary1 = agg.aggregate_record(record1, enabled_properties=frozenset())
ck("Resource Guard (r04/r05/r06_findings) always enabled=True in the aggregate, regardless of "
   "the passed-in enabled_properties set",
   all(summary1[k]["enabled"] is True for k in agg.RESOURCE_GUARD_KEYS))
ck("Resource Guard's own reportable_count is read directly, never recomputed",
   summary1["r04_findings"]["reportable_count"] == 1
   and summary1["r05_findings"]["reportable_count"] == 0
   and summary1["r06_findings"]["reportable_count"] == 1)

# --- staged property enabled via the passed-in set ---
record2 = {"lock_balance_findings": [mk(True), mk(False)]}
summary2 = agg.aggregate_record(record2, enabled_properties=frozenset({"lock_balance_findings"}))
ck("a staged property present in enabled_properties: enabled=True, raw/reportable counts real",
   summary2["lock_balance_findings"]["enabled"] is True
   and summary2["lock_balance_findings"]["raw_count"] == 2
   and summary2["lock_balance_findings"]["reportable_count"] == 1)

# --- staged property NOT in the passed-in set (not disabled-by-design, just not enabled yet) ---
record2b = {"protected_field_findings": [mk(False)]}
summary2b = agg.aggregate_record(record2b, enabled_properties=frozenset())
ck("a staged property absent from enabled_properties: enabled=False, a real (non-None) reason "
   "is still recorded, never silently blank",
   summary2b["protected_field_findings"]["enabled"] is False
   and bool(summary2b["protected_field_findings"]["disabled_reason"]))

# --- OOB_COMPARE: ALWAYS disabled, with its real recorded reason, regardless of what's passed in
record3 = {"oob_compare_candidates": [mk(False), mk(False)]}
summary3 = agg.aggregate_record(
    record3, enabled_properties=frozenset({"oob_compare_candidates"}))  # even if "enabled" is
                                                                          # passed in, it's DISABLED
ck("OOB_COMPARE is ALWAYS disabled=False, even if the caller's enabled_properties set "
   "(wrongly) includes it -- this module does not trust the caller on this specific property",
   summary3["oob_compare_candidates"]["enabled"] is False)
ck("OOB_COMPARE's disabled_reason is the real, specific task #33 citation, not a generic string",
   "task #33" in summary3["oob_compare_candidates"]["disabled_reason"]
   and "corpus survey" in summary3["oob_compare_candidates"]["disabled_reason"])

# --- hard invariant: OOB_COMPARE with a real reportable finding MUST raise, never silently pass
record4 = {"oob_compare_candidates": [mk(True)]}  # a real finding with reportable=True --
                                                    # deliberately simulates staged_enablement's
                                                    # own gate having failed
raised = False
try:
    agg.aggregate_record(record4, enabled_properties=frozenset())
except AssertionError as e:
    raised = True
    err_text = str(e)
ck("*** HARD INVARIANT FIRES: a DISABLED property (OOB_COMPARE) with a reportable=True "
   "finding raises AssertionError, never silently absorbed into a totals count ***", raised)
ck("the raised error names the real property key and the real violation, not a generic message",
   raised and "oob_compare_candidates" in err_text and "INVARIANT VIOLATION" in err_text)

# --- totals are a real sum, not fabricated ---
record5 = {"r04_findings": [mk(True)], "lock_balance_findings": [mk(True), mk(False)],
           "oob_compare_candidates": [mk(False)]}
summary5 = agg.aggregate_record(record5, enabled_properties=frozenset({"lock_balance_findings"}))
ck("_totals.total_raw is the real sum across all 9 keys",
   summary5["_totals"]["total_raw"] == 1 + 2 + 1)
ck("_totals.total_reportable is the real sum of reportable_count across all 9 keys",
   summary5["_totals"]["total_reportable"] == 1 + 1 + 0)

# --- format_summary: real rendering, not a second source of truth ---
rendered = agg.format_summary(summary5)
ck("format_summary renders every one of the 9 real keys plus a TOTAL line",
   all(k in rendered for k in agg.ALL_PROPERTY_KEYS) and "TOTAL:" in rendered)

# =====================================================================================
# REAL SMOKE TEST (task #47's own instruction: "a small smoke test before any new corpus
# run") -- TWO already-existing real evidence bundles from the completed
# overnight-diagnostic-100 run. No new corpus run is launched here.
# =====================================================================================
BUNDLE_DIR = ("/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus/"
              "overnight_100/evidence_bundles_100")
SMOKE_PACKAGES = ["re2@1.26.1.tar.gz", "node-crc16@2.0.7.tar.gz"]

OUT_JSON_TO_KEY = {
    "r04_out.json": "r04_findings", "r05_out.json": "r05_findings",
    "lock_balance_out.json": "lock_balance_findings",
    "protected_field_out.json": "protected_field_findings",
    "oob_write_out.json": "oob_write_candidates",
    "oob_index_write_out.json": "oob_index_write_candidates",
    "oob_read_out.json": "oob_read_candidates",
    "oob_compare_out.json": "oob_compare_candidates",
}


def load_bundle_record(bundle_path):
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(bundle_path) as tf:
            tf.extractall(td)
        record = {}
        for fname, key in OUT_JSON_TO_KEY.items():
            p = os.path.join(td, fname)
            if os.path.isfile(p):
                doc = json.load(open(p))
                record[key] = doc.get("findings", doc.get("candidates", doc if isinstance(doc, list) else []))
        record["r06_findings"] = []  # this run's own bundles predate task #41's r06 wiring into
                                       # run_pipeline_one.py -- real, disclosed, not fabricated
        js = json.load(open(os.path.join(td, "js_facts.json")))
        cpp = json.load(open(os.path.join(td, "cpp_facts.json")))
        return record, js, cpp


smoke_ran = 0
for pkg in SMOKE_PACKAGES:
    path = os.path.join(BUNDLE_DIR, pkg)
    if not os.path.isfile(path):
        continue
    record, js, cpp = load_bundle_record(path)
    # real, disclosed baseline: these raw scanner outputs never went through
    # provenance.enrich_record() when the bundle was built, so seed scanner_candidate=True /
    # reportable=True per PROPERTY_CANDIDATE_RULES's own unconditional-True properties, exactly
    # matching what a real pipeline run would compute at this stage, rather than fabricating a
    # formula result.
    for key in ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
                "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates"):
        for f in record.get(key) or []:
            f["reportable"] = True
            f.setdefault("provenance", {"resolved": True})
            f["applicability_status"] = "NOT_YET_DETERMINED"
    rt.classify_record_reachability(record, js, cpp)
    se.enforce_staged_enablement(record)
    summary = agg.aggregate_record(record, enabled_properties=se.ENABLED_PROPERTIES)
    smoke_ran += 1
    pkgname = pkg.split("@")[0]
    ck(f"SMOKE ({pkgname}): aggregate_record() runs cleanly over real evidence, no exception",
       True)  # reaching this line without the AssertionError above already proves it
    ck(f"SMOKE ({pkgname}): OOB_COMPARE's reportable_count is 0 (the hard invariant held on "
       "real data, not just the synthetic control above)",
       summary["oob_compare_candidates"]["reportable_count"] == 0)
    ck(f"SMOKE ({pkgname}): OOB_COMPARE is enabled=False with its real reason recorded",
       summary["oob_compare_candidates"]["enabled"] is False
       and bool(summary["oob_compare_candidates"]["disabled_reason"]))
    print(f"--- SMOKE ({pkgname}) real aggregate summary ---")
    print(agg.format_summary(summary))

if smoke_ran == 0:
    print("SKIP: overnight-diagnostic-100's evidence bundles not present in this environment -- "
          "real smoke test skipped, all synthetic controls above still ran")
else:
    ck(f"SMOKE: ran against {smoke_ran}/{len(SMOKE_PACKAGES)} real evidence bundles "
       "(a small smoke test, not a new corpus run)", smoke_ran >= 1)

print(f"SIX_PROPERTY_AGGREGATOR_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
