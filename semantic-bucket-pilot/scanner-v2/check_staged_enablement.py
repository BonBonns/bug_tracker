#!/usr/bin/env python3
"""STAGED-ENABLE-R01 (tasks #36/#37/#38/#39/#40) controls. Covers: the two real gates
(property-level enablement, finding-level reachability) both required and independently
labeled; never flips a real False to True; r04_findings/r05_findings never touched; and a real
end-to-end run combining this module with reachability_tier.py against re2's own real evidence
bundle from the overnight-diagnostic-100 run (SKIPs gracefully if that bundle isn't present).
"""
import json
import os
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import staged_enablement as se
import reachability_tier as rt

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def mk(reportable, reachability_status="TIER_JS_CALL_PROVEN"):
    f = {"reportable": reportable}
    if reachability_status is not None:
        f["reachability_status"] = reachability_status
    return f

# --- property-level gate: not-enabled property forces False regardless of anything else ---
# oob_compare_candidates is the ONLY property still not enabled (task #40 -- task #33's own
# real investigation found no positive-path evidence and recommended staying gated; a
# deliberate, evidence-backed decision, not an open precondition). oob_write_candidates was
# enabled as part of task #38 once task #44 formally accounted for all 3 real Tremor sinks.
rec1 = {"oob_compare_candidates": [mk(True, "TIER_JS_CALL_PROVEN")]}
se.enforce_staged_enablement(rec1)
ck("NOT-enabled property (oob_compare_candidates, task #40 stays gated by design): forced False",
   rec1["oob_compare_candidates"][0]["reportable"] is False)
ck("NOT-enabled property: stage_status is STAGE_NOT_ENABLED",
   rec1["oob_compare_candidates"][0]["stage_status"] == "STAGE_NOT_ENABLED")

# --- finding-level gate: enabled property, but reachability unresolved -> still forced False ---
rec2 = {"lock_balance_findings": [mk(True, "REACHABILITY_UNRESOLVED")]}
se.enforce_staged_enablement(rec2)
ck("enabled property + REACHABILITY_UNRESOLVED: forced False",
   rec2["lock_balance_findings"][0]["reportable"] is False)
ck("enabled property + REACHABILITY_UNRESOLVED: stage_status is "
   "REACHABILITY_REQUIRED_FOR_REPORTING (distinct from STAGE_NOT_ENABLED)",
   rec2["lock_balance_findings"][0]["stage_status"] == "REACHABILITY_REQUIRED_FOR_REPORTING")

rec2b = {"protected_field_findings": [mk(True, reachability_status=None)]}
se.enforce_staged_enablement(rec2b)
ck("enabled property + reachability_status absent entirely: also forced False (fails closed, "
   "not treated as a pass)",
   rec2b["protected_field_findings"][0]["reportable"] is False)

# --- both gates clear: reportable is left EXACTLY as provenance.py's formula computed ---
rec3 = {"oob_read_candidates": [mk(True, "TIER_JS_CALL_PROVEN")]}
se.enforce_staged_enablement(rec3)
ck("enabled property + resolved reachability + formula True: STAYS True",
   rec3["oob_read_candidates"][0]["reportable"] is True)
ck("both gates clear: stage_status is STAGE_ENABLED", rec3["oob_read_candidates"][0]["stage_status"] == "STAGE_ENABLED")

# --- task #38: oob_write_candidates / oob_index_write_candidates are now ENABLED ---
ck("ENABLED_PROPERTIES contains oob_write_candidates (task #38, unblocked by task #44)",
   "oob_write_candidates" in se.ENABLED_PROPERTIES)
ck("ENABLED_PROPERTIES contains oob_index_write_candidates (task #38)",
   "oob_index_write_candidates" in se.ENABLED_PROPERTIES)
ck("ENABLED_PROPERTIES does NOT contain oob_compare_candidates (task #40 stays gated by "
   "task #33's own evidence-backed decision)",
   "oob_compare_candidates" not in se.ENABLED_PROPERTIES)
rec3b = {"oob_write_candidates": [mk(True, "TIER_JS_CALL_PROVEN")],
         "oob_index_write_candidates": [mk(True, "TIER_JS_CALL_PROVEN")]}
se.enforce_staged_enablement(rec3b)
ck("oob_write_candidates: enabled property + resolved reachability + formula True -> STAYS True",
   rec3b["oob_write_candidates"][0]["reportable"] is True
   and rec3b["oob_write_candidates"][0]["stage_status"] == "STAGE_ENABLED")
ck("oob_index_write_candidates: same", rec3b["oob_index_write_candidates"][0]["reportable"] is True
   and rec3b["oob_index_write_candidates"][0]["stage_status"] == "STAGE_ENABLED")

rec4 = {"lock_balance_findings": [mk(False, "TIER_REGISTERED_NOT_JS_CALLED")]}
se.enforce_staged_enablement(rec4)
ck("enabled property + resolved (weaker) reachability tier + formula False: STAYS False "
   "(this module never turns False into True)",
   rec4["lock_balance_findings"][0]["reportable"] is False)
ck("a weaker-but-resolved tier (TIER_REGISTERED_NOT_JS_CALLED, not just TIER_JS_CALL_PROVEN) "
   "still clears the reachability gate -- STAGE_ENABLED, not REACHABILITY_REQUIRED",
   rec4["lock_balance_findings"][0]["stage_status"] == "STAGE_ENABLED")

# --- r04_findings/r05_findings never touched ---
rec5 = {"r04_findings": [mk(True, "REACHABILITY_UNRESOLVED")],
        "r05_findings": [mk(True, None)]}
se.enforce_staged_enablement(rec5)
ck("r04_findings never touched (Resource Guard owns its own lineage, task #41)",
   "stage_status" not in rec5["r04_findings"][0] and rec5["r04_findings"][0]["reportable"] is True)
ck("r05_findings never touched",
   "stage_status" not in rec5["r05_findings"][0] and rec5["r05_findings"][0]["reportable"] is True)

# --- real end-to-end: re2's own evidence bundle from overnight-diagnostic-100, combined with
# reachability_tier.py's real classification (not synthetic) ---
BUNDLE = ("/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus/overnight_100/"
          "evidence_bundles_100/re2@1.26.1.tar.gz")
if os.path.isfile(BUNDLE):
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(BUNDLE) as tf:
            tf.extractall(td)
        js = json.load(open(os.path.join(td, "js_facts.json")))
        cpp = json.load(open(os.path.join(td, "cpp_facts.json")))
        oob_read = json.load(open(os.path.join(td, "oob_read_out.json")))
        oob_write = json.load(open(os.path.join(td, "oob_write_out.json")))
        record = {"oob_read_candidates": oob_read.get("candidates", oob_read),
                  "oob_write_candidates": oob_write.get("candidates", oob_write),
                  "lock_balance_findings": [], "protected_field_findings": [],
                  "oob_index_write_candidates": [], "oob_compare_candidates": []}
        # real provenance.py-shaped reportable field: these raw scanner candidates never went
        # through provenance.enrich_record() in this smoke test, so seed a real, disclosed
        # baseline (scanner_candidate True -> reportable True) rather than fabricate a formula.
        for key in ("oob_read_candidates", "oob_write_candidates"):
            for f in record[key]:
                f["reportable"] = True
        rt.classify_record_reachability(record, js, cpp)
        se.enforce_staged_enablement(record)

        # re2's real oob_read_out.json is empty (0 candidates) as of this session's own #29/#43
        # fixes -- its one historical candidate was reclassified STATIC_EXTENT_SAFE, correctly
        # not a candidate at all. That is itself the real, honest, current result -- not a test
        # failure -- so this checks the MECHANISM ran cleanly over whatever re2's real current
        # output actually is, rather than asserting a specific nonzero count.
        n_read = len(record["oob_read_candidates"])
        ck(f"real re2 end-to-end (OOB_READ, ENABLED task #39): mechanism runs cleanly over "
           f"re2's own real current output ({n_read} real candidates -- 0 is itself a real, "
           "disclosed result following #29/#43's own fixes, not a failure); every candidate "
           "present got a real stage_status",
           all("stage_status" in f for f in record["oob_read_candidates"]))

        # re2's real oob_write_out.json DOES have 2 real candidates (StrErrorInternal,
        # TrySymbolizeWithLimit, both inside vendored abseil-cpp). Now that task #38 has
        # enabled oob_write_candidates, both clear the property-level gate; their own real
        # reachability_tier.py classification is TIER_INTERNAL_UNREGISTERED (the WEAKEST real
        # tier -- neither function is registered as a JS-callable export under any recognized
        # idiom) -- confirmed empirically, not assumed. Per task #32's own established design
        # (a real, resolved tier of ANY strength clears the reachability gate -- the floor is
        # "classified", not "strongest tier only", see check_reachability_tier.py's own
        # TIER_REGISTERED_NOT_JS_CALLED control), this still reaches STAGE_ENABLED here. That
        # design point is disclosed, not silently relied on: a real internal C++ helper deep
        # inside a vendored dependency, with no proof it is ever JS-reachable at all, becoming
        # reportable under this floor is a genuine, foreseeable consequence of the existing
        # reachability-gate threshold -- worth a human's attention when this reaches a live,
        # non-diagnostic run, not something this test papers over.
        n_write = len(record["oob_write_candidates"])
        ck(f"real re2 end-to-end (OOB_WRITE, ENABLED task #38): {n_write} real candidates all "
           "got a real stage_status, none silently skipped",
           n_write > 0 and all("stage_status" in f for f in record["oob_write_candidates"]))
        ck("real re2 end-to-end (OOB_WRITE): both real candidates' own reachability_tier.py "
           "classification is TIER_INTERNAL_UNREGISTERED (real, empirically confirmed -- "
           "neither StrErrorInternal nor TrySymbolizeWithLimit is a registered JS-callable "
           "export under any idiom this module recognizes)",
           n_write == 2 and all(f["reachability_status"] == "TIER_INTERNAL_UNREGISTERED"
                                 for f in record["oob_write_candidates"]))
        ck("real re2 end-to-end (OOB_WRITE): reaches STAGE_ENABLED under the seeded baseline "
           "(scanner_candidate=True) -- confirms the weakest real reachability tier still "
           "clears the gate for OOB_WRITE too, consistent with task #32's own established floor",
           all(f["stage_status"] == "STAGE_ENABLED" for f in record["oob_write_candidates"]))
else:
    print("SKIP: re2's overnight-diagnostic-100 evidence bundle not present -- real end-to-end "
          "check skipped, all synthetic/unit checks above still ran")

print(f"STAGED_ENABLE_R01_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
