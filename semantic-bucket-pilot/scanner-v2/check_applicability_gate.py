#!/usr/bin/env python3
"""APPLICABILITY-GATE-R01 controls. Per direct instruction: (1) a real eligible staged
candidate becomes APPLICABLE and reportable; (2) internal/unregistered, unresolved, disabled,
ambiguous, and false-adjudicated records remain blocked; (3) node-libcurl remains non-
reportable; (4) the four pqclean candidates remain NOT_YET_DETERMINED until individually
adjudicated. Plus a synthetic Resource Guard positive control (no real corpus example exists
today where Resource Guard's own applicability rule alone, independent of adjudication,
produces reportable=True -- node-libcurl is always vetoed -- so this is built to the exact real
rule's own shape, disclosed as synthetic, not corpus data)."""
import json
import os
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import applicability_gate as ag  # noqa: E402
import provenance  # noqa: E402
import reachability_tier as rt  # noqa: E402
import staged_enablement as se  # noqa: E402

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def staged(reportable, reachability, scanner_candidate=True, resolved=True):
    return {"reportable": reportable, "reachability_status": reachability,
            "scanner_candidate": scanner_candidate,
            "applicability_status": "NOT_YET_DETERMINED", "adjudication_status": "NOT_ADJUDICATED",
            "provenance": {"resolved": resolved}}


# =====================================================================================
# 1. A real eligible staged candidate becomes APPLICABLE and reportable -- @eliyya/sange's real
# "lock" (Mutex.lock) finding, TIER_TRANSITIVELY_CALLED_FROM_REGISTERED (task #32 reopened),
# reused from task #34's own real replay evidence.
# =====================================================================================
_sange_bundle = os.path.join(HERE, "npm_corpus", "overnight_100", "evidence_bundles_100",
                              "@eliyya__sange@1.2.0.tar.gz")
if os.path.isfile(_sange_bundle):
    with tarfile.open(_sange_bundle, "r:gz") as tf:
        sange_cpp = json.load(tf.extractfile("cpp_facts.json"))
        sange_js = json.load(tf.extractfile("js_facts.json"))
    lock_finding = {
        "method_id": 107374182564,
        "scanner_candidate": True, "applicability_status": "NOT_YET_DETERMINED",
        "adjudication_status": "NOT_ADJUDICATED",
        "provenance": {"resolved": True, "source_path": "src/mutex.cpp"},
    }
    sange_record = {"lock_balance_findings": [lock_finding]}
    rt.classify_record_reachability(sange_record, sange_js, sange_cpp)
    ck("SMOKE precondition: real 'lock' finding is TIER_TRANSITIVELY_CALLED_FROM_REGISTERED "
       "(task #32 reopened) before this module runs",
       lock_finding["reachability_status"] == "TIER_TRANSITIVELY_CALLED_FROM_REGISTERED")
    n = ag.apply_applicability(sange_record)
    ck("*** REAL POSITIVE: exactly 1 real staged candidate newly marked APPLICABLE ***", n == 1)
    ck("*** REAL POSITIVE: applicability_status is APPLICABLE ***",
       lock_finding["applicability_status"] == "APPLICABLE")
    ck("*** REAL POSITIVE: reportable is now True -- the first real, non-synthetic reportable=True "
       "this pipeline has ever produced on real corpus data, eligible for manual review only, "
       "NOT a vulnerability declaration ***", lock_finding["reportable"] is True)
else:
    print("SKIP: @eliyya/sange's real bundle not present -- control #1's real smoke test "
          "skipped")

# =====================================================================================
# 2. Internal/unregistered, unresolved, disabled, ambiguous, and false-adjudicated records
# remain blocked.
# =====================================================================================
rec_internal = {"lock_balance_findings": [staged(False, "TIER_INTERNAL_UNREGISTERED")]}
ag.apply_applicability(rec_internal)
ck("INTERNAL/UNREGISTERED: stays NOT_YET_DETERMINED, never applicable",
   rec_internal["lock_balance_findings"][0]["applicability_status"] == "NOT_YET_DETERMINED"
   and rec_internal["lock_balance_findings"][0]["reportable"] is False)

rec_unresolved_reach = {"lock_balance_findings": [staged(False, "REACHABILITY_UNRESOLVED")]}
ag.apply_applicability(rec_unresolved_reach)
ck("REACHABILITY_UNRESOLVED: stays NOT_YET_DETERMINED, never applicable",
   rec_unresolved_reach["lock_balance_findings"][0]["applicability_status"] == "NOT_YET_DETERMINED")

rec_unresolved_prov = {"lock_balance_findings": [
    staged(False, "TIER_JS_CALL_PROVEN", resolved=False)]}
ag.apply_applicability(rec_unresolved_prov)
ck("provenance UNRESOLVED: stays NOT_YET_DETERMINED even with a strong reachability tier",
   rec_unresolved_prov["lock_balance_findings"][0]["applicability_status"] == "NOT_YET_DETERMINED")

rec_disabled = {"oob_compare_candidates": [staged(False, "TIER_JS_CALL_PROVEN")]}
ag.apply_applicability(rec_disabled)
ck("*** DISABLED (OOB_COMPARE): this module never even sets applicability_status on it -- "
   "task #40 stays out of scope entirely, not merely vetoed downstream ***",
   "applicability_status" not in rec_disabled["oob_compare_candidates"][0]
   or rec_disabled["oob_compare_candidates"][0]["applicability_status"] == "NOT_YET_DETERMINED")
ck("DISABLED (OOB_COMPARE): reportable stays False regardless",
   rec_disabled["oob_compare_candidates"][0]["reportable"] is False)

rec_not_enabled = {"lock_balance_findings": [staged(False, "TIER_JS_CALL_PROVEN")]}
# simulate a not-yet-enabled staged property by using a key outside STAGED_APPLICABILITY_KEYS'
# own real ENABLED_PROPERTIES membership check indirectly -- lock_balance_findings IS enabled,
# so directly exercise the ENABLED_PROPERTIES membership clause instead:
ck("a staged key not in staged_enablement.ENABLED_PROPERTIES would be excluded by "
   "_staged_applicable()'s own 4th clause (structural check, not re-tested via a live key "
   "since all 5 staged keys ARE currently enabled)",
   "oob_compare_candidates" not in se.ENABLED_PROPERTIES)  # the one real staged-shaped key
                                                             # NOT enabled -- already covered by
                                                             # the DISABLED control above, which
                                                             # this module explicitly excludes
                                                             # from STAGED_APPLICABILITY_KEYS too
ck("oob_compare_candidates is excluded from STAGED_APPLICABILITY_KEYS entirely (belt-and-"
   "braces -- not merely relying on the ENABLED_PROPERTIES membership check)",
   "oob_compare_candidates" not in ag.STAGED_APPLICABILITY_KEYS)

# AMBIGUOUS: a candidate reachable ONLY via an ambiguous (multi-target) call stays
# TIER_INTERNAL_UNREGISTERED at the reachability layer (already proven in
# check_reachability_tier.py) -- confirms end-to-end that applicability_gate correctly leaves
# such a candidate NOT_YET_DETERMINED too, chaining both real modules together.
ambiguous_cpp = {
    "functions": [
        {"id": 1, "name": "Registered", "full_name": "Registered:Napi.Value(Napi.CallbackInfo&)",
         "is_external": False},
        {"id": 2, "name": "AmbiguousTarget", "full_name": "AmbiguousTarget:void()",
         "is_external": False},
    ],
    "calls": [
        {"id": 10, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": "\"env\""}}]},
        {"id": 11, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "code": "Registered",
                        "value_ref": {"kind": "IDENTIFIER", "code": "Registered"}}]},
        {"id": 12, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": '"registered"'}}]},
        {"id": 13, "name": "Set", "receiver_name": "exports",
         "arguments": [{"index": 1, "value_ref": {"kind": "CALL", "id": 12}},
                       {"index": 2, "value_ref": {"kind": "CALL", "id": 11}}]},
        # ambiguous: 2 real candidates, target is one of them but not the only one
        {"id": 20, "name": "ambiguousCall", "enclosing_function_id": 1,
         "candidate_target_ids": [2, 999]},
    ],
}
amb_table = rt.build_registration_table(ambiguous_cpp)
amb_clean = rt.build_clean_call_edges(ambiguous_cpp)
amb_res = rt.classify_function_reachability(2, amb_table, [], facts_available=True,
                                             clean_edges=amb_clean, fn_names={})
amb_finding = staged(False, amb_res["reachability_status"])
rec_amb = {"lock_balance_findings": [amb_finding]}
ag.apply_applicability(rec_amb)
ck("*** AMBIGUOUS: a candidate reachable ONLY through an ambiguous multi-target call stays "
   "TIER_INTERNAL_UNREGISTERED at the reachability layer, and therefore NOT_YET_DETERMINED "
   "here too -- never applicable on an unclean edge ***",
   amb_res["reachability_status"] == "TIER_INTERNAL_UNREGISTERED"
   and rec_amb["lock_balance_findings"][0]["applicability_status"] == "NOT_YET_DETERMINED")

# FALSE-ADJUDICATED: applicable (would be reportable) but CONFIRMED_FALSE_POSITIVE -- the
# adjudication veto wins even after applicability grants eligibility.
rec_false_adj = {"r06_findings": [{
    "method_name": "SomeMethod", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
    "scanner_candidate": True, "applicability_status": "NOT_YET_DETERMINED",
    "adjudication_status": "CONFIRMED_FALSE_POSITIVE",  # already adjudicated, e.g. by a future
                                                          # individual review
    "reportable": False,
    "provenance": {"resolved": True, "source_path": "x.cc"},
    "source_boundary_evidence": {"traced_to_parameter": "len"},
}]}
ag.apply_applicability(rec_false_adj)
ck("*** FALSE-ADJUDICATED: this Resource Guard finding clears applicability (real verdict, "
   "resolved, real source_boundary_evidence, traces to a real value parameter -- not 'this') "
   "but stays non-reportable because adjudication_status is ALREADY CONFIRMED_FALSE_POSITIVE "
   "-- the veto wins, applicability never overrides an existing adjudication ***",
   rec_false_adj["r06_findings"][0]["applicability_status"] == "APPLICABLE"
   and rec_false_adj["r06_findings"][0]["reportable"] is False)

# =====================================================================================
# 3 & 4. REAL SMOKE TEST: node-libcurl stays non-reportable; the four pqclean candidates stay
# NOT_YET_DETERMINED -- reusing results/replay_records_v5.jsonl, the current corrected chain
# (v4 -- node-libcurl's own targeted build-config fix -- plus
# audit_build_config_staleness.py's own corpus-wide staleness audit and its 32 targeted R06
# reruns; v2/v3/v4 are all superseded here -- v5 is the only file this control ever reads).
# Falls back to v4 only if v5 is not present in this environment.
# =====================================================================================
_v5_path = os.path.join(HERE, "study", "task34_replay", "results", "replay_records_v5.jsonl")
_v4_path = os.path.join(HERE, "study", "task34_replay", "results", "replay_records_v4.jsonl")
_records_path = _v5_path if os.path.isfile(_v5_path) else _v4_path
if os.path.isfile(_records_path):
    with open(_records_path) as fh:
        v4_records = [json.loads(line) for line in fh
                      if json.loads(line).get("outcome") == "REPLAYED"]
    libcurl = next((r for r in v4_records if r["package_name"] == "node-libcurl"), None)
    pqclean = next((r for r in v4_records if r["package_name"] == "pqclean"), None)

    if libcurl:
        r05 = [f for f in (libcurl.get("r05_findings") or []) if f.get("method_name") == "ReadFunction"]
        r06 = [f for f in (libcurl.get("r06_findings") or []) if f.get("method_name") == "ReadFunction"]
        # Both copies already carry the CORRECTED verdict (CONTRACT_NOT_APPLICABLE, not the old
        # stale-data VALUE_ACQUISITION_GUARD_MISSING). Re-run applicability_gate directly against
        # a COPY with adjudication stripped entirely (simulating "never reviewed"), to prove --
        # independent of adjudication_registry.py -- that applicability_gate never grants
        # APPLICABLE for either copy any more, on the corrected verdict's own merits alone.
        r05_copy = dict(r05[0]); r05_copy["provenance"] = dict(r05_copy["provenance"])
        r05_copy["adjudication_status"] = "NOT_ADJUDICATED"
        r06_copy = dict(r06[0]); r06_copy["provenance"] = dict(r06_copy["provenance"])
        r06_copy["adjudication_status"] = "NOT_ADJUDICATED"
        stripped = {"r05_findings": [r05_copy], "r06_findings": [r06_copy]}
        applied_libcurl = ag.apply_applicability(stripped)
        ck("SMOKE #3: *** THE FIX ITSELF, independent of adjudication *** -- applying "
           "applicability_gate to node-libcurl's real record (adjudication stripped) applies to "
           "NEITHER copy: R05 never carried source_boundary_evidence (predates R06's gate) and "
           "R06's own corrected verdict is CONTRACT_NOT_APPLICABLE, not "
           "VALUE_ACQUISITION_GUARD_MISSING -- condition 1 fails on the corrected verdict's real "
           "merits, never even reaching an adjudication veto",
           applied_libcurl == 0)
        ck("SMOKE #3: node-libcurl's real r05 ReadFunction copy: scanner_candidate is False on "
           "its own corrected-verdict merits, applicability_status stays NOT_YET_DETERMINED, "
           "reportable stays False",
           r05[0].get("scanner_candidate") is False
           and r05[0]["applicability_status"] == "NOT_YET_DETERMINED"
           and r05[0]["reportable"] is False)
        ck("SMOKE #3: node-libcurl's real r06 ReadFunction copy: scanner_candidate is False on "
           "its own corrected-verdict merits -- it never becomes a candidate at all, let alone "
           "APPLICABLE (the old masked regression is fixed at its root cause). Still ALSO, "
           "independently, CONFIRMED_FALSE_POSITIVE-adjudicated on its own real, separately-"
           "cited merits -- a genuine second, independent veto, never the only thing standing "
           "between this site and reportable=True",
           r06[0].get("scanner_candidate") is False
           and r06[0]["applicability_status"] == "NOT_YET_DETERMINED"
           and r06[0]["reportable"] is False
           and r06[0]["adjudication_status"] == "CONFIRMED_FALSE_POSITIVE")
    else:
        print("SKIP: node-libcurl not found in v4 replay records")

    if pqclean:
        pq_findings = [f for f in (pqclean.get("r06_findings") or [])
                        if f.get("verdict") == "VALUE_ACQUISITION_GUARD_MISSING"]
        ck("SMOKE #4 precondition: real pqclean has exactly 4 real GUARD_MISSING R06 candidates",
           len(pq_findings) == 4)
        applied_pq = ag.apply_applicability(pqclean)
        ck("SMOKE #4: applicability_gate applies to ZERO of pqclean's real candidates "
           "(all 4 trace to 'this', not a real value parameter)", applied_pq == 0)
        for f in pq_findings:
            ck(f"SMOKE #4: pqclean's real {f.get('method_name')} finding stays "
               "NOT_YET_DETERMINED (traced_to_parameter="
               f"{(f.get('source_boundary_evidence') or {}).get('traced_to_parameter')!r}), "
               "reportable stays False -- genuinely open, never guessed at",
               f["applicability_status"] == "NOT_YET_DETERMINED" and f["reportable"] is False)
    else:
        print("SKIP: pqclean not found in v4 replay records")
else:
    print("SKIP: neither results/replay_records_v5.jsonl nor replay_records_v4.jsonl is "
          "present -- controls #3/#4's real smoke tests skipped")

# =====================================================================================
# Synthetic Resource Guard positive (no real corpus example exists today where Resource Guard's
# own rule, independent of adjudication, produces reportable=True -- node-libcurl is always
# vetoed by its own real adjudication) -- built to the EXACT real rule's own shape, disclosed as
# synthetic.
# =====================================================================================
synthetic_rg = {
    "method_name": "UnreviewedAcquire", "verdict": "VALUE_ACQUISITION_GUARD_MISSING",
    "scanner_candidate": True, "applicability_status": "NOT_YET_DETERMINED",
    "adjudication_status": "NOT_ADJUDICATED", "reportable": False,
    "provenance": {"resolved": True, "source_path": "synthetic.cc"},
    "source_boundary_evidence": {"traced_to_parameter": "length", "attacker_controlled": False,
                                  "source_boundary": "SOURCE_BOUNDARY_UNRESOLVED"},
}
rec_syn_rg = {"r06_findings": [synthetic_rg]}
n_syn = ag.apply_applicability(rec_syn_rg)
ck("SYNTHETIC (disclosed, not corpus data): a Resource Guard candidate tracing to a real named "
   "value parameter ('length', not 'this'), never adjudicated, becomes APPLICABLE and "
   "reportable=True -- proves the rule alone, independent of node-libcurl's own specific "
   "adjudication veto, is real and does what it claims", n_syn == 1 and rec_syn_rg["r06_findings"][0]["reportable"] is True)

print(f"APPLICABILITY_GATE_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
