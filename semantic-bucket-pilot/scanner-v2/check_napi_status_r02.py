#!/usr/bin/env python3
"""NAPI-STATUS-R02 regression gate. Three frozen-fact suites, all real Joern v4.0.608
output (regeneration recipe: check_napi_status.py's docstring):

  1. R01-FIXTURE INVARIANCE: study/napi_status/raw_synthetic must classify IDENTICALLY
     under R02 (full 17-row verdict/sub-reason table) -- R02's deltas may only change
     behavior where an escape/opt-out/derived shape is actually present.
  2. R02 CONTROLS: study/napi_status/raw_synthetic_r02 (fixture_r02.c) -- optional
     vs required roles, NULL opt-outs, escape handling, one-level caller analysis,
     derived proven-wrapper sites (the real positive-path machinery).
  3. ROCKSDB REGRESSION: study/napi_status/raw_blind_rocksdb -- the REAL blind-run
     facts from @farcaster/rocksdb@5.5.0 (pinned tarball verified; parse scope per
     REAL_PACKAGE_RESULTS.md). R01 reported the Convert site NO_OUTPUT_USE; the
     required `napi_value* result` output escapes through a caller-provided pointer,
     so the honest classification is the explicit caller-analysis abstention this
     suite pins.

Every expectation is an API-handling classification; none is a vulnerability or
impact claim.
"""
import json
import pathlib
import subprocess
import sys
from collections import defaultdict

HERE = pathlib.Path(__file__).parent
CAP = HERE / "napi_status_verdict_r02.py"
STUDY = HERE / "study" / "napi_status"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname):
    outpath = STUDY / outname
    subprocess.run([sys.executable, str(CAP), str(STUDY / rawdir), str(outpath)],
                   check=True)
    return json.loads(outpath.read_text())


def table(r, derived):
    return {(f["method_name"], f["creation_call_id"]):
            (f["verdict"], f.get("sub_reason") or f.get("reason"))
            for f in r["findings"] if ("derived_from" in f) == derived}


def one(r, fn, derived=False):
    recs = [f for f in r["findings"]
            if f["method_name"] == fn and ("derived_from" in f) == derived]
    return recs[0] if len(recs) == 1 else {}


# --- 1. R01-fixture invariance ---------------------------------------------------------
r01_expected = {
    "c01_unchecked_use": ("STATUS_GUARD_MISSING", "NO_RELATED_CHECK"),
    "c02_checked_terminating": ("STATUS_GUARD_ESTABLISHED", None),
    "c03_check_after_use": ("STATUS_GUARD_MISSING", "RELATED_CHECK_AFTER_USE"),
    "c04_unrelated_status": ("STATUS_GUARD_MISSING", "UNRELATED_CHECK_ONLY"),
    "c05_nonterminating_failure": ("STATUS_GUARD_MISSING",
                                    "NON_TERMINATING_OR_BYPASSED_FAILURE_PATH"),
    "c06_propagates": ("STATUS_PROPAGATED_BEFORE_USE",
                        "STATUS_RETURNED_OUTPUTS_UNUSED_LOCALLY"),
    "c06b_propagates_direct": ("STATUS_PROPAGATED_BEFORE_USE",
                                "CREATION_CALL_RETURNED_DIRECTLY"),
    "c07_use_in_success_branch": ("STATUS_GUARD_ESTABLISHED", None),
    "c08_ambiguous_output": ("ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED",
                              "OUT_ARG_NOT_A_RESOLVABLE_VARIABLE"),
    "c10_known_wrapper": ("STATUS_GUARD_ESTABLISHED", None),
    "c11_unknown_wrapper": ("ABSTAIN_WRAPPER_UNRESOLVED",
                             "STATUS_CONSUMED_BY_UNPROVEN_CALLEE_BEFORE_USE"),
    "p02_copy_unchecked": ("STATUS_GUARD_MISSING", "STATUS_DISCARDED"),
    "p03_known_terminating_wrapper": ("STATUS_GUARD_ESTABLISHED", None),
    "p04_compound_and": ("STATUS_GUARD_ESTABLISHED", None),
    "p05_compound_or_ambiguous": ("ABSTAIN_BRANCH_POLARITY_UNRESOLVED",
                                   "RELATED_CHECK_PRESENT_BUT_POLARITY_UNPROVEN"),
    "p06_no_use": ("NO_OUTPUT_USE", None),
    "p07_wrong_arity": ("ABSTAIN_CALL_IDENTITY_UNRESOLVED",
                         "ARITY_OR_DISPATCH_MISMATCH"),
}
r = run("raw_synthetic", "out_synthetic_r02.json")
got = {fn: v for (fn, _), v in table(r, derived=False).items()}
mismatch = [fn for fn, exp in r01_expected.items()
            if got.get(fn, (None, None))[0] != exp[0]
            or (exp[1] is not None and got.get(fn, (None, None))[1] != exp[1])]
ck("R01-fixture invariance: all 17 sites classify identically under R02 "
   f"(mismatches: {mismatch})", not mismatch and len(got) == 17)
ck("R01-fixture: c06/c06b register as proven propagating wrappers (no callers, so "
   "no derived sites)",
   set(r["proven_propagating_wrappers"]) == {"c06_propagates", "c06b_propagates_direct"}
   and not table(r, derived=True))

# --- 2. R02 controls -------------------------------------------------------------------
r = run("raw_synthetic_r02", "out_synthetic_r02fix.json")

ck("w_make: proven propagating wrapper, own site STATUS_PROPAGATED_BEFORE_USE",
   one(r, "w_make").get("verdict") == "STATUS_PROPAGATED_BEFORE_USE"
   and r["proven_propagating_wrappers"] == ["w_make"])
ck("w01: derived caller site with CHECKED status -> STATUS_GUARD_ESTABLISHED "
   "(positive-path caller machinery)",
   one(r, "w01_caller_checked", derived=True).get("verdict")
   == "STATUS_GUARD_ESTABLISHED"
   and one(r, "w01_caller_checked", derived=True).get("derived_from")
   == "napi_create_buffer")
ck("w02: derived caller site with DISCARDED status -> STATUS_GUARD_MISSING / "
   "STATUS_DISCARDED",
   one(r, "w02_caller_unchecked", derived=True).get("verdict")
   == "STATUS_GUARD_MISSING"
   and one(r, "w02_caller_unchecked", derived=True).get("sub_reason")
   == "STATUS_DISCARDED")
ck("w03 (via w_fill): dead status + escaping output + resolved caller use -> "
   "STATUS_GUARD_MISSING / STATUS_DISCARDED_OUTPUT_USED_IN_CALLER",
   one(r, "w_fill").get("verdict") == "STATUS_GUARD_MISSING"
   and one(r, "w_fill").get("sub_reason") == "STATUS_DISCARDED_OUTPUT_USED_IN_CALLER"
   and one(r, "w_fill").get("caller_method") == "w03_caller_uses")
ck("w04 (via w_convert): caller passes its own parameter (2nd-level escape) -> "
   "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED / CALLER_MAPPING_UNRESOLVED",
   one(r, "w_convert").get("verdict") == "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED"
   and one(r, "w_convert").get("reason") == "CALLER_MAPPING_UNRESOLVED"
   and any(u["why"] == "SECOND_LEVEL_ESCAPE_VIA_CALLER_PARAMETER"
           for u in one(r, "w_convert").get("unresolved_callers", [])))
w05 = one(r, "w05_null_optout")
ck("w05: NULL opt-out of OPTIONAL result_data recorded; required result still "
   "tracked -> STATUS_GUARD_MISSING / STATUS_DISCARDED",
   w05.get("verdict") == "STATUS_GUARD_MISSING"
   and w05.get("sub_reason") == "STATUS_DISCARDED"
   and any(t.get("opted_out") and t["role"] == "result_data"
           for t in w05.get("output_targets", []))
   and all(t.get("variable") != "NULL" for t in w05.get("output_targets", [])))
ck("w06: NULL in the REQUIRED result role -> ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED / "
   "REQUIRED_OUTPUT_NULL",
   one(r, "w06_null_required").get("verdict") == "ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED"
   and one(r, "w06_null_required").get("reason") == "REQUIRED_OUTPUT_NULL")
ck("w07: dead status + escaping output + zero TU-visible callers -> "
   "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED / NO_CALLER_FACTS",
   one(r, "w07_orphan").get("verdict") == "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED"
   and one(r, "w07_orphan").get("reason") == "NO_CALLER_FACTS")
ck("w08 (via w_ignore): all TU-visible callers resolved and clean -> "
   "NO_OUTPUT_USE_IN_KNOWN_CALLERS (TU-scoped, distinct from NO_OUTPUT_USE)",
   one(r, "w_ignore").get("verdict") == "NO_OUTPUT_USE_IN_KNOWN_CALLERS")
ck("R02 controls: claims-boundary lint (no vulnerability language in the output)",
   "vulnerab" not in json.dumps(r).lower())

# --- 3. RocksDB regression (real blind-run facts, corrected expectation) --------------
r = run("raw_blind_rocksdb", "out_blind_rocksdb_r02.json")
conv = one(r, "Convert")
ck("rocksdb: exactly one supported site (Convert / napi_create_buffer_copy)",
   r["classification"].get("SUPPORTED_CREATION_CALL_FOUND") == 1
   and conv.get("creation_call_name") == "napi_create_buffer_copy")
ck("rocksdb: the R01 NO_OUTPUT_USE result is CORRECTED to "
   "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED (required result escapes via the "
   "caller-provided pointer; callers unresolvable from these facts)",
   conv.get("verdict") == "OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED"
   and conv.get("escaping_roles") == ["result"])
ck("rocksdb: NULL for the optional result_data role recorded as an opt-out, "
   "not a tracked variable",
   any(t.get("opted_out") and t["role"] == "result_data"
       for t in conv.get("output_targets", []))
   and all(t.get("variable") != "NULL" for t in conv.get("output_targets", [])))
ck("rocksdb: zero STATUS_GUARD_MISSING findings (the abstention is not a finding)",
   r["classification"].get("STATUS_GUARD_MISSING") is None)

print(f"NAPI_STATUS_R02={ok}/{total}")
sys.exit(0 if ok == total else 1)
