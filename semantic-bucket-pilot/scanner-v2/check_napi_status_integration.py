#!/usr/bin/env python3
"""NAPI-STATUS-INTEGRATION-R01 gate: proves, over FROZEN real Joern facts, the exact
review-mandated integration properties:

  - CANDIDATE VOCABULARY: both candidate identifiers -- STATUS_GUARD_MISSING
    (intraprocedural) and its caller-side STATUS_DISCARDED_OUTPUT_USED_IN_CALLER --
    are candidates and CAN become reportable through the real pipeline stages;
    an unrecognized sub_reason fails closed LOUDLY (never dropped, never admitted).
  - ABSTENTIONS/NEGATIVES CANNOT: RocksDB's real escape abstention, established
    guards, no-use records, optional-NULL/required-NULL records, the ambiguous-caller
    abstention, and unsupported napi_create_external_buffer (which produces no record
    at all) can never become reportable.
  - EFFECTIVE CALLER IDENTITY: caller-side findings resolve provenance and
    reachability through the CALLER function.
  - DIAGNOSTIC-ONLY ENABLEMENT: after the full pipeline, enforce_napi_status_
    enablement forces every reportable back to False with the disclosed stage label,
    and the r02 aggregator's invariant raises if that step is bypassed.
  - AGGREGATOR REVISION: the six frozen properties' sub-summary is byte-identical to
    six_property_aggregator.aggregate_record's own output (task #34 schema untouched).

Every expectation is pipeline mechanics over API-handling classifications; nothing
here is a vulnerability or impact claim.
"""
import copy
import json
import os
import pathlib
import subprocess
import sys
from collections import defaultdict

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import napi_status_integration as integ  # noqa: E402
import provenance  # noqa: E402
import six_property_aggregator as agg6  # noqa: E402
import staged_enablement as se  # noqa: E402

STUDY = HERE / "study" / "napi_status"
CAP = HERE / "napi_status_verdict_r02.py"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run_scanner(rawdir, outname):
    outpath = STUDY / outname
    subprocess.run([sys.executable, str(CAP), str(STUDY / rawdir), str(outpath)],
                   check=True, stdout=subprocess.DEVNULL)
    return json.loads(outpath.read_text())


def build_fixture_manifest_and_pkgdir(rawdir, fixture_basename):
    """Builds a REAL provenance manifest for a fixture run: reads the file path the
    frozen methods.tsv actually records, and roots pkg_dir so that path resolves to
    the real fixture source file."""
    mfm = provenance.load_method_file_map(str(STUDY / rawdir))
    file_fields = {v for v in mfm.values() if v and fixture_basename in v}
    assert len(file_fields) == 1, file_fields
    field = file_fields.pop()
    if os.path.isabs(field):
        pkg_dir = os.path.dirname(field)
    else:
        pkg_dir = str(STUDY)
    manifest = provenance.build_source_manifest(pkg_dir, b"", "fixture-pkg", "0.0.0")
    return manifest, pkg_dir


def one(findings, fn, derived=False):
    recs = [f for f in findings
            if f["method_name"] == fn and ("derived_from" in f) == derived]
    return recs[0] if len(recs) == 1 else {}


# =========================================================================
# 1. Full pipeline over the R02 fixture facts.
# =========================================================================
r = run_scanner("raw_synthetic_r02", "out_integration_r02fix.json")
record = {"napi_status_findings": copy.deepcopy(r["findings"])}
manifest, pkg_dir = build_fixture_manifest_and_pkgdir("raw_synthetic_r02",
                                                       "fixture_r02.c")
unrecognized = integ.enrich_napi_status(record, str(STUDY / "raw_synthetic_r02"),
                                          manifest, pkg_dir)
F = record["napi_status_findings"]

ck("vocabulary: zero CANDIDATE_VOCABULARY_UNRECOGNIZED over the real fixture output",
   unrecognized == 0)
ck("vocabulary: intraprocedural STATUS_GUARD_MISSING (w05/STATUS_DISCARDED) is a "
   "candidate", one(F, "w05_null_optout").get("scanner_candidate") is True)
ck("vocabulary: caller-side STATUS_DISCARDED_OUTPUT_USED_IN_CALLER (w_fill) is a "
   "candidate -- the strongest caller-side finding is never discarded",
   one(F, "w_fill").get("scanner_candidate") is True
   and one(F, "w_fill").get("sub_reason") == "STATUS_DISCARDED_OUTPUT_USED_IN_CALLER")
ck("vocabulary: derived caller candidate (w02) is a candidate too",
   one(F, "w02_caller_unchecked", derived=True).get("scanner_candidate") is True)
ck("vocabulary: escape abstention (w_convert) is a NON-candidate",
   one(F, "w_convert").get("scanner_candidate") is False
   and one(F, "w_convert").get("candidate_vocabulary") == "NON_CANDIDATE")
ck("vocabulary: established (w01 derived), propagated (w_make), known-callers-clean "
   "(w_ignore), required-NULL abstain (w06), no-caller-facts (w07) are all "
   "NON-candidates",
   all(one(F, n, derived=d).get("scanner_candidate") is False
       for n, d in (("w01_caller_checked", True), ("w_make", False),
                    ("w_ignore", False), ("w06_null_required", False),
                    ("w07_orphan", False))))

ck("provenance: caller-side finding (w_fill) resolves through the CALLER function "
   "(w03_caller_uses), source path = the real fixture file",
   one(F, "w_fill").get("caller_method_id") is not None
   and integ.effective_function_id(one(F, "w_fill"))
   == one(F, "w_fill").get("caller_method_id")
   and (one(F, "w_fill").get("provenance") or {}).get("resolved") is True
   and "fixture_r02.c" in (one(F, "w_fill")["provenance"].get("source_path") or ""))
ck("provenance: intraprocedural candidate (w05) resolved with a real content hash",
   (one(F, "w05_null_optout").get("provenance") or {}).get("resolved") is True
   and one(F, "w05_null_optout")["provenance"].get("content_hash"))
ck("provenance alone never implies reportable (applicability not yet applied)",
   all(f.get("reportable") is False for f in F))

# --- reachability wiring: empty facts -> UNRESOLVED on the EFFECTIVE function ---
integ.apply_napi_status_reachability(record, {}, {})
ck("reachability: with no js/cpp facts every finding gets REACHABILITY_UNRESOLVED "
   "(never a silent pass)",
   all(f.get("reachability_status") == "REACHABILITY_UNRESOLVED" for f in F))

# --- applicability: nothing applies while reachability is unresolved ---
applied = integ.apply_napi_status_applicability(record)
ck("applicability: zero findings APPLICABLE while reachability is UNRESOLVED",
   applied == 0 and all(f.get("applicability_status") != "APPLICABLE" for f in F))

# --- mechanism controls: grant an allowed tier, re-apply ---
for f in F:
    f["reachability_status"] = "TIER_JS_CALL_PROVEN"
applied = integ.apply_napi_status_applicability(record)
w05, wfill = one(F, "w05_null_optout"), one(F, "w_fill")
w02 = one(F, "w02_caller_unchecked", derived=True)
ck("mechanism: with provenance resolved + allowed tier, BOTH candidate identifiers "
   "become APPLICABLE and reportable=True (intraprocedural w05, caller-side w_fill, "
   "derived w02)",
   all(x.get("applicability_status") == "APPLICABLE" and x.get("reportable") is True
       for x in (w05, wfill, w02)))
ck("mechanism: RocksDB-shaped escape abstention (w_convert) STILL cannot become "
   "reportable under the same maximal grants",
   one(F, "w_convert").get("applicability_status") != "APPLICABLE"
   and one(F, "w_convert").get("reportable") is False)
ck("mechanism: established/propagated/no-use/required-NULL records all stay "
   "non-reportable under the same grants",
   all(one(F, n, derived=d).get("reportable") is False
       for n, d in (("w01_caller_checked", True), ("w_make", False),
                    ("w_ignore", False), ("w06_null_required", False),
                    ("w07_orphan", False))))

# --- adjudication: empty registry is a no-op; an exact-match entry vetoes ---
applied = integ.apply_napi_status_adjudications(record, "fixture-pkg", "0.0.0")
ck("adjudication: the registry section is EMPTY -> zero applied, nothing changed",
   applied == 0 and integ.NAPI_STATUS_KNOWN_ADJUDICATIONS == {}
   and wfill.get("reportable") is True)
_key = ("fixture-pkg", "0.0.0", integ.NAPI_STATUS_KEY, wfill.get("site_id"))
integ.NAPI_STATUS_KNOWN_ADJUDICATIONS[_key] = {
    "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
    "citation": "synthetic gate control -- removed immediately",
    "reason": "mechanism control only"}
try:
    applied = integ.apply_napi_status_adjudications(record, "fixture-pkg", "0.0.0")
    ck("adjudication: an EXACT-match entry applies and vetoes reportable via the one "
       "formula", applied == 1 and wfill.get("reportable") is False
       and wfill.get("adjudication_status") == "CONFIRMED_FALSE_POSITIVE")
finally:
    del integ.NAPI_STATUS_KNOWN_ADJUDICATIONS[_key]
wfill["adjudication_status"] = "NOT_ADJUDICATED"
provenance.finalize_reportability(wfill, wfill.get("scanner_candidate", False))

# --- enablement: diagnostic-only forces everything back down, disclosed ---
integ.enforce_napi_status_enablement(record)
ck("enablement: DIAGNOSTIC-ONLY -- every finding forced reportable=False with "
   "stage_status STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY",
   integ.NAPI_STATUS_ENABLED is False
   and all(f.get("reportable") is False for f in F)
   and all(f.get("stage_status") == "STAGE_NOT_ENABLED_DIAGNOSTIC_ONLY" for f in F))

# --- aggregator revision ---
summary = integ.aggregate_record_r02(record, se.ENABLED_PROPERTIES)
six_only = agg6.aggregate_record(record, se.ENABLED_PROPERTIES)
ck("aggregator r02: six frozen properties' sub-summary is IDENTICAL to "
   "six_property_aggregator's own output (schema untouched)",
   all(summary[k] == six_only[k] for k in agg6.ALL_PROPERTY_KEYS))
ck("aggregator r02: napi_status row present, diagnostic-only, 0 reportable, "
   "disclosed reason",
   summary["napi_status_findings"]["enabled"] is False
   and summary["napi_status_findings"]["reportable_count"] == 0
   and summary["napi_status_findings"]["raw_count"] == len(F)
   and "diagnostic-only" in summary["napi_status_findings"]["disabled_reason"])
ck("aggregator r02: totals include the napi row and the revision tag is recorded",
   summary["_totals"]["total_raw"]
   == six_only["_totals"]["total_raw"] + len(F)
   and summary["_aggregator_revision"] == integ.AGGREGATOR_REVISION)
bad_record = copy.deepcopy(record)
bad_record["napi_status_findings"][0]["reportable"] = True
raised = False
try:
    integ.aggregate_record_r02(bad_record, se.ENABLED_PROPERTIES)
except AssertionError:
    raised = True
ck("aggregator r02: HARD INVARIANT -- a reportable napi finding while diagnostic-"
   "only RAISES (never silently absorbed)", raised)

# =========================================================================
# 2. Vocabulary fail-closed control (synthetic unknown sub_reason).
# =========================================================================
synth = {"napi_status_findings": [{
    "verdict": "STATUS_GUARD_MISSING", "sub_reason": "SOME_FUTURE_SUB_REASON",
    "method_id": None, "method_name": "synthetic", "file": "x.c", "line": "1",
    "creation_call_name": "napi_create_buffer"}]}
n_unrec = integ.enrich_napi_status(synth, str(STUDY / "raw_synthetic_r02"),
                                     manifest, pkg_dir)
sf = synth["napi_status_findings"][0]
ck("vocabulary fail-closed: unknown sub_reason -> CANDIDATE_VOCABULARY_UNRECOGNIZED, "
   "counted loudly, not a candidate, never reportable",
   n_unrec == 1 and sf["candidate_vocabulary"] == "CANDIDATE_VOCABULARY_UNRECOGNIZED"
   and sf.get("scanner_candidate") is False and sf.get("reportable") is False)

# =========================================================================
# 3. RocksDB real regression through the full integration pipeline.
# =========================================================================
r = run_scanner("raw_blind_rocksdb", "out_integration_rocksdb.json")
rec_rdb = {"napi_status_findings": copy.deepcopy(r["findings"])}
rdb_manifest = {"package_name": "@farcaster/rocksdb", "version": "5.5.0",
                "tarball_sha256": "cdc0e3e6", "source_tree_sha256": None,
                "files": {}}
integ.enrich_napi_status(rec_rdb, str(STUDY / "raw_blind_rocksdb"), rdb_manifest,
                          "/nonexistent")
for f in rec_rdb["napi_status_findings"]:
    f["reachability_status"] = "TIER_JS_CALL_PROVEN"  # maximal grant, deliberately
integ.apply_napi_status_applicability(rec_rdb)
integ.apply_napi_status_adjudications(rec_rdb, "@farcaster/rocksdb", "5.5.0")
integ.enforce_napi_status_enablement(rec_rdb)
conv = rec_rdb["napi_status_findings"][0]
ck("rocksdb: the real escape abstention is a NON-candidate and cannot become "
   "reportable even under a maximal reachability grant",
   conv.get("verdict") == "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED"
   and conv.get("scanner_candidate") is False and conv.get("reportable") is False
   and conv.get("applicability_status") != "APPLICABLE")
summary = integ.aggregate_record_r02(rec_rdb, se.ENABLED_PROPERTIES)
ck("rocksdb: aggregates as 1 raw, 0 reportable under the r02 aggregator",
   summary["napi_status_findings"] == {
       "raw_count": 1, "reportable_count": 0, "enabled": False,
       "disabled_reason": summary["napi_status_findings"]["disabled_reason"]}
   and summary["napi_status_findings"]["disabled_reason"] is not None)

# =========================================================================
# 4. Unsupported napi_create_external_buffer: no record exists to integrate.
# =========================================================================
r = run_scanner("raw_synthetic", "out_integration_r01fix.json")
ck("external-buffer: the R01 fixture's c09 site still contributes NO record at all "
   "(nothing for any pipeline stage to even consider)",
   not any(f["method_name"] == "c09_external_buffer" for f in r["findings"])
   and r["classification"].get("SUPPORTED_CREATION_CALL_FOUND") == 17)

print(f"NAPI_STATUS_INTEGRATION_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
