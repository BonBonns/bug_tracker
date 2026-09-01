#!/usr/bin/env python3
"""ADJUDICATION-REGISTRY-R01 controls. Synthetic behavior + a real smoke test against
node-libcurl's own real R06 finding, reusing task #34's own already-preserved bundle evidence
(no new Joern run, no download)."""
import json
import os
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adjudication_registry as ar  # noqa: E402
import provenance  # noqa: E402

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)

# --- synthetic: exact match applies the adjudication and forces reportable False -----------
matching = {
    "package_name": "node-libcurl", "version": "5.1.2",
    "r06_findings": [{
        "method_name": "ReadFunction", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
        "scanner_candidate": True, "applicability_status": "APPLICABLE",
        "adjudication_status": "NOT_ADJUDICATED", "reportable": True,
        "provenance": {"resolved": True, "source_path": "src/Easy.cc"},
    }],
}
n = ar.apply_known_adjudications(matching)
ck("exact match applies exactly 1 adjudication", n == 1)
f = matching["r06_findings"][0]
ck("adjudication_status set to CONFIRMED_FALSE_POSITIVE", f["adjudication_status"] == "CONFIRMED_FALSE_POSITIVE")
ck("a real citation is recorded (the actual review document, not a generic string)",
   f.get("adjudication_citation") == "study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md")
ck("a real, specific reason is recorded (not blank, not generic)",
   bool(f.get("adjudication_reason")) and "libcurl" in f["adjudication_reason"])
ck("*** reportable is FORCED False by the veto, even though it was True (candidate=True, "
   "resolved=True, applicability=APPLICABLE) before adjudication was applied ***",
   f["reportable"] is False)

# --- synthetic: same method_name/source_path, DIFFERENT version -- must NOT match (exact match
#     on all four fields, never a partial one) ------------------------------------------------
different_version = {
    "package_name": "node-libcurl", "version": "5.2.0",  # a real, plausible future version --
                                                            # never assumed to carry the same fix
    "r06_findings": [{
        "method_name": "ReadFunction", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
        "scanner_candidate": True, "applicability_status": "APPLICABLE",
        "reportable": True, "provenance": {"resolved": True, "source_path": "src/Easy.cc"},
    }],
}
n2 = ar.apply_known_adjudications(different_version)
ck("a different VERSION of the same package/method/path does NOT match (exact-match "
   "discipline, never assumed to carry forward)", n2 == 0)
ck("un-adjudicated finding's reportable stays whatever it already was (True here) -- this "
   "module never touches a non-matching finding at all", different_version["r06_findings"][0]["reportable"] is True)

# --- synthetic: same package/version, DIFFERENT method_name -- must NOT match ---------------
different_method = {
    "package_name": "node-libcurl", "version": "5.1.2",
    "r06_findings": [{
        "method_name": "SomeOtherFunction", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
        "scanner_candidate": True, "applicability_status": "APPLICABLE",
        "reportable": True, "provenance": {"resolved": True, "source_path": "src/Easy.cc"},
    }],
}
n3 = ar.apply_known_adjudications(different_method)
ck("a different method_name in the same file does NOT match", n3 == 0)

# --- synthetic: r04_findings/r05_findings keys are ALSO checked (not R06-only) --------------
r05_matching = {
    "package_name": "node-libcurl", "version": "5.1.2",
    "r05_findings": [{
        "method_name": "ReadFunction", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
        "scanner_candidate": True, "applicability_status": "APPLICABLE",
        "reportable": True, "provenance": {"resolved": True, "source_path": "src/Easy.cc"},
    }],
}
n4 = ar.apply_known_adjudications(r05_matching)
ck("R05's own real finding at the same exact site is ALSO matched (the registry is keyed by "
   "site identity, not by which Resource Guard lineage version produced the finding)", n4 == 1)
ck("R05's own matched finding also gets reportable forced False",
   r05_matching["r05_findings"][0]["reportable"] is False)

# =====================================================================================
# REAL SMOKE TEST: node-libcurl's own real R06 finding, from task #34's own already-
# preserved bundle evidence (no new Joern run, no download).
# =====================================================================================
BUNDLE_DIR = os.path.join(HERE, "npm_corpus", "overnight_100", "evidence_bundles_100")
REPLAY_RECORDS = os.path.join(HERE, "study", "task34_replay", "results", "replay_records.jsonl")

smoke_ran = False
if os.path.isfile(REPLAY_RECORDS):
    with open(REPLAY_RECORDS) as fh:
        for line in fh:
            d = json.loads(line)
            if d.get("package_name") == "node-libcurl" and d.get("outcome") == "REPLAYED":
                real_r06 = [f for f in (d.get("r06_findings") or [])
                            if f.get("method_name") == "ReadFunction"]
                ck("SMOKE: node-libcurl's real R06 ReadFunction finding is present in task "
                   "#34's own replay output", len(real_r06) == 1)
                if real_r06:
                    rf = dict(real_r06[0])  # copy -- this smoke test must not mutate the
                                              # committed replay_records.jsonl in place
                    rf["provenance"] = dict(rf["provenance"])
                    ck("SMOKE: before adjudication, adjudication_status is the real, unset "
                       "default (NOT_ADJUDICATED) -- confirms this was genuinely never applied "
                       "during the original replay", rf.get("adjudication_status") == "NOT_ADJUDICATED")
                    record = {"package_name": "node-libcurl", "version": "5.1.2",
                              "r06_findings": [rf]}
                    applied = ar.apply_known_adjudications(record)
                    ck("SMOKE: exactly 1 real adjudication applied to node-libcurl's real "
                       "finding", applied == 1)
                    ck("SMOKE: real finding's adjudication_status is now CONFIRMED_FALSE_POSITIVE",
                       rf["adjudication_status"] == "CONFIRMED_FALSE_POSITIVE")
                    ck("SMOKE: real finding's reportable stays False -- was already False (the "
                       "applicability gap), now ALSO correctly vetoed by a real, cited, "
                       "affirmative adjudication, not just an open precondition",
                       rf["reportable"] is False)
                smoke_ran = True
                break
if not smoke_ran:
    print("SKIP: task #34's own replay_records.jsonl not present in this environment -- real "
          "smoke test skipped, all synthetic controls above still ran")

print(f"ADJUDICATION_REGISTRY_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
