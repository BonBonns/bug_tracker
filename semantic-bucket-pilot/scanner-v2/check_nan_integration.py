#!/usr/bin/env python3
"""NAN-INTEGRATION-R01 controls (task #34 roadmap step 1): the frozen, standalone Nan Resource
Guard capability (resource_guard_verdict_nan.py, 30/30 of its own unit controls,
study/nan_capability/NAN_CAPABILITY_FREEZE.md) is wired into the live pipeline (run_pipeline_
one.py, run_pipeline_one_r06.py), provenance.py, applicability_gate.py, adjudication_registry.py,
and six_property_aggregator.py. Covers the wiring itself with synthetic controls, then validates
end to end against the SAME 8 real packages the capability's own freeze rests on (node-snap7's
3 real candidates + the 6 independently-verified real negative controls), through the NOW-FULLY-
INTEGRATED live pipeline -- not the standalone dev/test harness used during capability design."""
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import provenance  # noqa: E402
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import six_property_aggregator as agg  # noqa: E402

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


# =====================================================================================
# 1. provenance.PROPERTY_CANDIDATE_RULES["nan_findings"]: exact-match on the two real
#    contract_id strings, never a same-prefixed abstention verdict.
# =====================================================================================
rule = provenance.PROPERTY_CANDIDATE_RULES["nan_findings"]
ck("candidate: NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
   rule({"verdict": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION"}))
ck("candidate: NAN_COPYBUFFER_SOURCE_CAPACITY",
   rule({"verdict": "NAN_COPYBUFFER_SOURCE_CAPACITY"}))
for abstention in ("NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_ARITY_UNRECOGNIZED",
                   "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_SOURCE_BOUNDARY_UNRESOLVED",
                   "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_NOT_JS_REGISTERED",
                   "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_JS_CALL_UNRESOLVED",
                   "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_UPPER_BOUND_CHECK_PRESENT",
                   "NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED"):
    ck(f"NOT a candidate: {abstention}", not rule({"verdict": abstention}))
ck("NOT a candidate: missing verdict entirely", not rule({}))

# =====================================================================================
# 2. provenance.enrich_record() picks up "nan_findings" (id_field="method_id") -- real fixture
#    reused from the R04/R05/R06 controls (same real, resolvable method_id).
# =====================================================================================
fixture_dir = os.path.join(HERE, "study", "resource_guard", "raw_c01_missing_check")
method_map = provenance.load_method_file_map(fixture_dir)
real_method_id = next(iter(method_map))
real_claimed_filename = method_map[real_method_id]
scratch = "/tmp/_nan_integration_scratch"
shutil.rmtree(scratch, ignore_errors=True)
os.makedirs(scratch)
shutil.copy(os.path.join(fixture_dir, "fixture_source.cpp"),
            os.path.join(scratch, real_claimed_filename))
manifest = provenance.build_source_manifest(scratch, b"placeholder", "test-pkg", "1.0.0")
nan_record = {"nan_findings": [
    {"method_id": real_method_id, "verdict": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
     "js_reachability_tier": "confirmed_call"},
]}
# cpp_raw_dir=fixture_dir (the real raw facts/methods.tsv), pkg_dir=scratch (where the real
# source file actually lives, matching the manifest built from scratch above) -- these are two
# real, DIFFERENT directories, never conflated.
provenance.enrich_record(nan_record, fixture_dir, manifest, scratch)
f0 = nan_record["nan_findings"][0]
ck("enrich_record: nan_findings' real provenance resolves", f0["provenance"]["resolved"] is True)
ck("enrich_record: nan_findings' scanner_candidate=True for the real candidate verdict",
   f0["scanner_candidate"] is True)
ck("enrich_record: nan_findings' reportable stays False (no applicability yet)",
   f0["reportable"] is False)
shutil.rmtree(scratch, ignore_errors=True)

# =====================================================================================
# 3. applicability_gate.apply_applicability(): the real Nan rule (candidate + resolved +
#    js_reachability_tier in the real allowlist).
# =====================================================================================
applied = ag.apply_applicability(nan_record)
ck("applicability: real candidate with confirmed_call tier becomes APPLICABLE",
   applied == 1 and f0["applicability_status"] == "APPLICABLE")
ck("applicability: reportable=True now (candidate + resolved + APPLICABLE + not adjudicated)",
   f0["reportable"] is True)

weak_tier_record = {"nan_findings": [
    {"method_id": real_method_id, "verdict": "NAN_COPYBUFFER_SOURCE_CAPACITY",
     "js_reachability_tier": "exported_registration",
     "provenance": {"resolved": True}, "scanner_candidate": True}]}
n = ag.apply_applicability(weak_tier_record)
ck("applicability: the WEAKER exported_registration tier is ALSO accepted (real, disclosed, "
   "still-structural tier -- not a relaxation)",
   n == 1 and weak_tier_record["nan_findings"][0]["applicability_status"] == "APPLICABLE")

bad_tier_record = {"nan_findings": [
    {"method_id": real_method_id, "verdict": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
     "js_reachability_tier": "some_future_unvetted_tier",
     "provenance": {"resolved": True}, "scanner_candidate": True}]}
n = ag.apply_applicability(bad_tier_record)
ck("applicability: an UNRECOGNIZED js_reachability_tier value never grants APPLICABLE (belt-"
   "and-braces -- this must never silently pass even if resource_guard_verdict_nan.py were to "
   "someday emit a new, unvetted tier value)",
   n == 0 and bad_tier_record["nan_findings"][0].get("applicability_status") != "APPLICABLE")

not_candidate_record = {"nan_findings": [
    {"method_id": real_method_id, "verdict": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_JS_CALL_UNRESOLVED",
     "provenance": {"resolved": True}, "scanner_candidate": False}]}
n = ag.apply_applicability(not_candidate_record)
ck("applicability: a real abstention (scanner_candidate=False) never becomes APPLICABLE",
   n == 0)

# =====================================================================================
# 4. adjudication_registry.apply_known_adjudications(): nan_findings shares the SAME
#    (package,version,method_name,source_path) table as R04/R05/R06 -- a synthetic entry proves
#    the loop reaches nan_findings at all (no real Nan adjudication exists yet -- none of
#    node-snap7's 3 real candidates have been manually reviewed as part of this integration
#    step; that is explicitly step 2 of the roadmap's own scope for LOCK_BALANCE/OOB, never
#    claimed done here for Nan).
# =====================================================================================
ar.KNOWN_ADJUDICATIONS[("synthetic-nan-pkg", "1.0.0", "SyntheticMethod", "src/synthetic.cc")] = {
    "adjudication_status": "CONFIRMED_FALSE_POSITIVE",
    "citation": "synthetic, this control only",
    "reason": "synthetic control reason",
}
try:
    synth_record = {"package_name": "synthetic-nan-pkg", "version": "1.0.0", "nan_findings": [
        {"method_name": "SyntheticMethod", "verdict": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
         "scanner_candidate": True, "applicability_status": "APPLICABLE",
         "adjudication_status": "NOT_ADJUDICATED", "reportable": True,
         "provenance": {"resolved": True, "source_path": "src/synthetic.cc"}}]}
    n = ar.apply_known_adjudications(synth_record)
    ck("adjudication: nan_findings reached by the shared R04/R05/R06/nan loop, exact match "
       "applies", n == 1)
    ck("adjudication: reportable forced False by the veto",
       synth_record["nan_findings"][0]["reportable"] is False)
finally:
    del ar.KNOWN_ADJUDICATIONS[("synthetic-nan-pkg", "1.0.0", "SyntheticMethod", "src/synthetic.cc")]

# =====================================================================================
# 5. six_property_aggregator.py: nan_findings is in ALL_PROPERTY_KEYS, always "enabled" (never
#    gated by staged_enablement.py), and contributes to the combined totals.
# =====================================================================================
ck("aggregator: nan_findings is in ALL_PROPERTY_KEYS", "nan_findings" in agg.ALL_PROPERTY_KEYS)
agg_record = {"nan_findings": [
    {"reportable": True}, {"reportable": False}, {"reportable": True}]}
summary = agg.aggregate_record(agg_record, enabled_properties=set())
ck("aggregator: nan_findings always enabled=True (never depends on staged_enablement's "
   "ENABLED_PROPERTIES, which was never passed a nan entry above)",
   summary["nan_findings"]["enabled"] is True)
ck("aggregator: nan_findings raw_count/reportable_count computed correctly",
   summary["nan_findings"]["raw_count"] == 3 and summary["nan_findings"]["reportable_count"] == 2)
ck("aggregator: nan_findings' 2 reportable findings contribute to _totals",
   summary["_totals"]["total_reportable"] >= 2)

# =====================================================================================
# 6. REAL SMOKE TEST: the SAME 8 real packages the capability's own freeze rests on, through the
#    NOW-FULLY-INTEGRATED live pipeline (run_pipeline_one.py's run_one() -- real c2cpg+jssrc2cpg,
#    real provenance.enrich_record(), real adjudication_registry.apply_known_adjudications(),
#    all wired in above), with applicability_gate.apply_applicability() and
#    six_property_aggregator.aggregate_record() applied on top (the post-processing stage, same
#    as every other property). No bundle replay -- js_raw was never preserved in the 100-package
#    bundles, so this REQUIRES a fresh live run, exactly like every other Nan validation to date.
# =====================================================================================
RUN_LIVE = os.environ.get("NAN_INTEGRATION_LIVE_SMOKE", "1") != "0"
if RUN_LIVE:
    npm_corpus = os.path.join(HERE, "npm_corpus")
    sys.path.insert(0, npm_corpus)
    # NAN-FINALIZE-TASK1 fix: root-caused directly (real per-stage timing, not guessed) --
    # @confluentinc/kafka-javascript's own real bottleneck is `cpp_normalize` (330.1s on its
    # exceptionally large bundled deps/librdkafka C library), NOT resource_guard_verdict_nan.py's
    # own scan logic (9.7s, unremarkable at this size) -- the same class of large-bundled-
    # codebase normalize cost already known from re2 (127.6s), just further along that spectrum,
    # past the DEFAULT NORMALIZE_TIMEOUT=180s margin. Raised ONLY for this smoke test's own
    # subprocess calls (an env var scoped to this process) -- the production
    # NPM_CORPUS_TIMEOUT_MULTIPLIER default (used by the real corpus-wide pipeline) is
    # deliberately left untouched here; that is a separate, repo-wide capacity/cost decision for
    # the eventual 494-package run (roadmap step 9), not one to smuggle in via one negative
    # control's own gate. See NAN_INTEGRATION_RESULTS.md's own "Task 1" update for the full
    # real-evidence account (real successful ANALYZED run, 2 raw findings, 0 reportable,
    # confirmed byte-for-byte matching NAN_REPLAY_TASK4_RESULTS.md's own independent bundle-
    # replay result for the same package).
    os.environ.setdefault("NPM_CORPUS_TIMEOUT_MULTIPLIER", "6")
    import run_pipeline_one as P  # noqa: E402

    eligible = {}
    with open(os.path.join(npm_corpus, "eligible_packages.tsv")) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            eligible[(parts[idx["package_name"]], parts[idx["version"]])] = parts[idx["tarball_url"]]

    POSITIVE_PKG = ("node-snap7", "1.0.9")
    NEGATIVE_PKGS = [
        ("murmurhash-native", "3.5.1"), ("msgpack", "1.0.3"),
        ("@confluentinc/kafka-javascript", "1.10.0"), ("scrypt", "6.0.3"),
        ("libpq", "1.11.0"), ("phplike", "2.5.12"),
    ]
    EXPECTED_POSITIVE_METHODS = {"ReadArea", "Upload", "FullUpload"}

    def run_live(pkg, version):
        url = eligible.get((pkg, version))
        if url is None:
            print(f"SKIP real smoke: {pkg}@{version} not in eligible_packages.tsv")
            return None
        work_root = f"/tmp/check_nan_integration_{pkg.replace('/', '_')}"
        shutil.rmtree(work_root, ignore_errors=True)
        t0 = time.time()
        rec = P.run_one(pkg, version, url, None, work_root)
        print(f"  {pkg}@{version}: {rec.get('status')} in {time.time()-t0:.1f}s", file=sys.stderr)
        shutil.rmtree(work_root, ignore_errors=True)
        return rec

    pos_rec = run_live(*POSITIVE_PKG)
    if pos_rec is not None:
        ck(f"REAL SMOKE: {POSITIVE_PKG[0]}'s real live run reaches ANALYZED",
           pos_rec.get("status") == "ANALYZED")
        nan_findings = pos_rec.get("nan_findings") or []
        candidate_findings = [f for f in nan_findings
                               if f.get("verdict") in ("NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
                                                        "NAN_COPYBUFFER_SOURCE_CAPACITY")]
        found_methods = {f.get("method_name") for f in candidate_findings}
        ck(f"REAL SMOKE: {POSITIVE_PKG[0]} reproduces exactly the 3 frozen real candidates "
           f"(ReadArea, Upload, FullUpload) -- found: {sorted(found_methods)}",
           found_methods == EXPECTED_POSITIVE_METHODS)
        for f in candidate_findings:
            ck(f"REAL SMOKE: {POSITIVE_PKG[0]}'s real {f.get('method_name')} finding: "
               "provenance.resolved=True", f.get("provenance", {}).get("resolved") is True)
            ck(f"REAL SMOKE: {POSITIVE_PKG[0]}'s real {f.get('method_name')} finding: "
               "scanner_candidate=True", f.get("scanner_candidate") is True)
        applied = ag.apply_applicability(pos_rec)
        ck(f"REAL SMOKE: applicability_gate grants APPLICABLE to all 3 real candidates "
           f"(applied={applied})", applied == 3)
        for f in candidate_findings:
            ck(f"REAL SMOKE: {POSITIVE_PKG[0]}'s real {f.get('method_name')}: reportable=True "
               "end to end (no adjudication exists for it -- a real, novel candidate, not yet "
               "manually reviewed, exactly as expected at this integration step)",
               f.get("reportable") is True)
        summary = agg.aggregate_record(pos_rec, enabled_properties=set())
        ck(f"REAL SMOKE: {POSITIVE_PKG[0]}'s own six_property_aggregator summary counts all 3 "
           "as reportable in nan_findings",
           summary["nan_findings"]["reportable_count"] == 3)

    for pkg, version in NEGATIVE_PKGS:
        neg_rec = run_live(pkg, version)
        if neg_rec is None:
            continue
        ck(f"REAL SMOKE: {pkg}'s real live run reaches ANALYZED", neg_rec.get("status") == "ANALYZED")
        nan_findings = neg_rec.get("nan_findings") or []
        candidate_findings = [f for f in nan_findings
                               if f.get("verdict") in ("NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
                                                        "NAN_COPYBUFFER_SOURCE_CAPACITY")]
        ck(f"REAL SMOKE: {pkg} (negative control) produces ZERO real Nan candidates end to end "
           f"-- 0 false positives, matching NAN_CAPABILITY_FREEZE.md's own real result, now "
           f"reconfirmed through the fully-integrated live pipeline", len(candidate_findings) == 0)
else:
    print("SKIP: real live smoke tests disabled (NAN_INTEGRATION_LIVE_SMOKE=0) -- all synthetic "
          "controls above still ran")

print(f"NAN_INTEGRATION_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
