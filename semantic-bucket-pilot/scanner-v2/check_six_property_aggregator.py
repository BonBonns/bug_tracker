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

# --- ReDoS (roadmap step 8): always included/trusted, same as Resource Guard/Nan, never gated
# by staged_enablement's own set. redos_verdict.py hardcodes reportable=False on every finding
# it emits -- exercise that real shape (not a synthetic reportable=True) so this control also
# proves the "trust its own reportable field" design is sound in the one real case that occurs.
record1b = {"redos_findings": [mk(False), mk(False)]}
summary1b = agg.aggregate_record(record1b, enabled_properties=frozenset())
ck("redos_findings is in ALL_PROPERTY_KEYS", "redos_findings" in agg.ALL_PROPERTY_KEYS)
ck("redos_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1b["redos_findings"]["enabled"] is True
   and summary1b["redos_findings"]["disabled_reason"] is None)
ck("redos_findings raw/reportable counts are read directly, never recomputed -- both findings "
   "carry redos_verdict.py's own real hardcoded reportable=False",
   summary1b["redos_findings"]["raw_count"] == 2
   and summary1b["redos_findings"]["reportable_count"] == 0)

# --- redos_findings: the common case is zero findings for most packages -- must still produce a
# correct, non-crashing summary (an absent key, exactly like a package with no ReDoS candidate) ---
record1c = {"r04_findings": [mk(True)]}  # no "redos_findings" key at all, the common real case
summary1c = agg.aggregate_record(record1c, enabled_properties=frozenset())
ck("a record with no redos_findings key at all (the common case for most packages) still "
   "produces a correct, non-crashing summary: enabled=True, raw=0, reportable=0",
   summary1c["redos_findings"]["enabled"] is True
   and summary1c["redos_findings"]["raw_count"] == 0
   and summary1c["redos_findings"]["reportable_count"] == 0)

# --- Path Traversal (roadmap step 8, second JS/TS class): same discipline as redos_findings --
# always enabled, never gated by staged_enablement.py. path_traversal_verdict.py also hardcodes
# reportable=False on every finding it emits.
record1d = {"path_traversal_findings": [mk(False), mk(False), mk(False)]}
summary1d = agg.aggregate_record(record1d, enabled_properties=frozenset())
ck("path_traversal_findings is in ALL_PROPERTY_KEYS", "path_traversal_findings" in agg.ALL_PROPERTY_KEYS)
ck("path_traversal_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1d["path_traversal_findings"]["enabled"] is True
   and summary1d["path_traversal_findings"]["disabled_reason"] is None)
ck("path_traversal_findings raw/reportable counts are read directly, never recomputed -- all "
   "three findings carry path_traversal_verdict.py's own real hardcoded reportable=False",
   summary1d["path_traversal_findings"]["raw_count"] == 3
   and summary1d["path_traversal_findings"]["reportable_count"] == 0)
record1e = {"r04_findings": [mk(True)]}  # no "path_traversal_findings" key at all, the common case
summary1e = agg.aggregate_record(record1e, enabled_properties=frozenset())
ck("a record with no path_traversal_findings key at all still produces a correct, non-crashing "
   "summary: enabled=True, raw=0, reportable=0",
   summary1e["path_traversal_findings"]["enabled"] is True
   and summary1e["path_traversal_findings"]["raw_count"] == 0
   and summary1e["path_traversal_findings"]["reportable_count"] == 0)

# --- Serialize DoS (roadmap step 8, third JS/TS class): same discipline as redos_findings/
# path_traversal_findings -- always enabled, never gated by staged_enablement.py.
# serialize_dos_r03.py's own derive() also hardcodes reportable=False on every finding it emits.
record1f = {"serialize_dos_findings": [mk(False), mk(False), mk(False), mk(False)]}
summary1f = agg.aggregate_record(record1f, enabled_properties=frozenset())
ck("serialize_dos_findings is in ALL_PROPERTY_KEYS", "serialize_dos_findings" in agg.ALL_PROPERTY_KEYS)
ck("serialize_dos_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1f["serialize_dos_findings"]["enabled"] is True
   and summary1f["serialize_dos_findings"]["disabled_reason"] is None)
ck("serialize_dos_findings raw/reportable counts are read directly, never recomputed -- all "
   "four findings carry serialize_dos_r03.py's own real hardcoded reportable=False",
   summary1f["serialize_dos_findings"]["raw_count"] == 4
   and summary1f["serialize_dos_findings"]["reportable_count"] == 0)
record1g = {"r04_findings": [mk(True)]}  # no "serialize_dos_findings" key at all, the common case
summary1g = agg.aggregate_record(record1g, enabled_properties=frozenset())
ck("a record with no serialize_dos_findings key at all still produces a correct, non-crashing "
   "summary: enabled=True, raw=0, reportable=0",
   summary1g["serialize_dos_findings"]["enabled"] is True
   and summary1g["serialize_dos_findings"]["raw_count"] == 0
   and summary1g["serialize_dos_findings"]["reportable_count"] == 0)

# --- LLM-input: same discipline as redos_findings/path_traversal_findings/serialize_dos_findings
# -- always enabled, never gated by staged_enablement.py. Unlike those, llm_input_verdict.py's
# own derive() does NOT hardcode reportable itself (run_pipeline_one_r06.py's own wiring sets it
# after calling derive()) -- these findings simulate that already-set state, matching what the
# real pipeline record actually contains by the time it reaches this aggregator.
record1h = {"llm_input_findings": [mk(False), mk(False), mk(False)]}
summary1h = agg.aggregate_record(record1h, enabled_properties=frozenset())
ck("llm_input_findings is in ALL_PROPERTY_KEYS", "llm_input_findings" in agg.ALL_PROPERTY_KEYS)
ck("llm_input_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1h["llm_input_findings"]["enabled"] is True
   and summary1h["llm_input_findings"]["disabled_reason"] is None)
ck("llm_input_findings raw/reportable counts are read directly, never recomputed -- all three "
   "findings carry reportable=False (as the real pipeline wiring sets it)",
   summary1h["llm_input_findings"]["raw_count"] == 3
   and summary1h["llm_input_findings"]["reportable_count"] == 0)
record1i = {"r04_findings": [mk(True)]}  # no "llm_input_findings" key at all, the common case
summary1i = agg.aggregate_record(record1i, enabled_properties=frozenset())
ck("a record with no llm_input_findings key at all still produces a correct, non-crashing "
   "summary: enabled=True, raw=0, reportable=0",
   summary1i["llm_input_findings"]["enabled"] is True
   and summary1i["llm_input_findings"]["raw_count"] == 0
   and summary1i["llm_input_findings"]["reportable_count"] == 0)

# --- NoSQLi: same discipline as redos_findings/path_traversal_findings/serialize_dos_findings/
# llm_input_findings -- always enabled, never gated by staged_enablement.py. Unlike LLM-input,
# nosqli_verdict.py's own emit_findings() DOES hardcode reportable=False itself (matching ReDoS/
# Path Traversal/Serialize DoS, not LLM-input's own predates-the-convention shape) -- these
# findings simulate that already-set state, matching what the real reducer's own output actually
# contains.
record1j = {"nosqli_findings": [mk(False), mk(False)]}
summary1j = agg.aggregate_record(record1j, enabled_properties=frozenset())
ck("nosqli_findings is in ALL_PROPERTY_KEYS", "nosqli_findings" in agg.ALL_PROPERTY_KEYS)
ck("nosqli_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1j["nosqli_findings"]["enabled"] is True
   and summary1j["nosqli_findings"]["disabled_reason"] is None)
ck("nosqli_findings raw/reportable counts are read directly, never recomputed -- both findings "
   "carry reportable=False (as nosqli_verdict.py itself hardcodes)",
   summary1j["nosqli_findings"]["raw_count"] == 2
   and summary1j["nosqli_findings"]["reportable_count"] == 0)
record1k = {"r04_findings": [mk(True)]}  # no "nosqli_findings" key at all, the common case
summary1k = agg.aggregate_record(record1k, enabled_properties=frozenset())
ck("a record with no nosqli_findings key at all still produces a correct, non-crashing "
   "summary: enabled=True, raw=0, reportable=0",
   summary1k["nosqli_findings"]["enabled"] is True
   and summary1k["nosqli_findings"]["raw_count"] == 0
   and summary1k["nosqli_findings"]["reportable_count"] == 0)

# --- SSRF: same discipline as the other roadmap-step-8 JS/TS properties -- always enabled, never
# gated by staged_enablement.py. ssrf_verdict.py hardcodes reportable=False itself, matching
# ReDoS/Path Traversal/Serialize DoS/NoSQLi, not LLM-input's own predates-the-convention shape.
record1l = {"ssrf_findings": [mk(False)]}
summary1l = agg.aggregate_record(record1l, enabled_properties=frozenset())
ck("ssrf_findings is in ALL_PROPERTY_KEYS", "ssrf_findings" in agg.ALL_PROPERTY_KEYS)
ck("ssrf_findings always enabled=True in the aggregate, regardless of the passed-in "
   "enabled_properties set (never routed through staged_enablement.py)",
   summary1l["ssrf_findings"]["enabled"] is True
   and summary1l["ssrf_findings"]["disabled_reason"] is None)
ck("ssrf_findings raw/reportable counts are read directly, never recomputed -- the one finding "
   "carries reportable=False (as ssrf_verdict.py itself hardcodes)",
   summary1l["ssrf_findings"]["raw_count"] == 1
   and summary1l["ssrf_findings"]["reportable_count"] == 0)
record1m = {"r04_findings": [mk(True)]}  # no "ssrf_findings" key at all, the common case
summary1m = agg.aggregate_record(record1m, enabled_properties=frozenset())
ck("a record with no ssrf_findings key at all still produces a correct, non-crashing "
   "summary: enabled=True, raw=0, reportable=0",
   summary1m["ssrf_findings"]["enabled"] is True
   and summary1m["ssrf_findings"]["raw_count"] == 0
   and summary1m["ssrf_findings"]["reportable_count"] == 0)

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
ck("_totals.total_raw is the real sum across all real keys (ALL_PROPERTY_KEYS)",
   summary5["_totals"]["total_raw"] == 1 + 2 + 1)
ck("_totals.total_reportable is the real sum of reportable_count across all real keys (ALL_PROPERTY_KEYS)",
   summary5["_totals"]["total_reportable"] == 1 + 1 + 0)

# --- format_summary: real rendering, not a second source of truth ---
rendered = agg.format_summary(summary5)
ck("format_summary renders every one of the real ALL_PROPERTY_KEYS plus a TOTAL line",
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
        record["redos_findings"] = []  # this run's own bundles predate roadmap step 8's redos
                                         # wiring into run_pipeline_one_r06.py -- real, disclosed,
                                         # not fabricated (record1b/record1c above already cover
                                         # a real non-empty and a real absent-key redos_findings
                                         # case directly)
        record["path_traversal_findings"] = []  # same reason -- these bundles predate roadmap
                                         # step 8's path traversal wiring (record1d/record1e above
                                         # already cover a real non-empty and a real absent-key
                                         # path_traversal_findings case directly)
        record["serialize_dos_findings"] = []  # same reason -- these bundles predate roadmap
                                         # step 8's serialize DoS wiring (record1f/record1g above
                                         # already cover a real non-empty and a real absent-key
                                         # serialize_dos_findings case directly)
        record["llm_input_findings"] = []  # same reason -- these bundles predate the LLM-input
                                         # wiring (record1h/record1i above already cover a real
                                         # non-empty and a real absent-key llm_input_findings
                                         # case directly)
        record["nosqli_findings"] = []  # same reason -- these bundles predate the NoSQLi wiring
                                         # (record1j/record1k above already cover a real non-empty
                                         # and a real absent-key nosqli_findings case directly)
        record["ssrf_findings"] = []  # same reason -- these bundles predate the SSRF wiring
                                         # (record1l/record1m above already cover a real non-empty
                                         # and a real absent-key ssrf_findings case directly)
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
