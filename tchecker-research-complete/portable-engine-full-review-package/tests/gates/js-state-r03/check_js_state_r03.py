#!/usr/bin/env python3
"""JS-STATE-R03/R05 gate check.

Verifies sink-reachability classification against the shared fixture.
Expectations, per case, from JS-STATE-R01's independently-written per-case
report (SECURITY_SENSITIVE_USE column), reduced to this module's honest
two-value vocabulary (SENSITIVE only when the example profile matches;
everything else UNKNOWN, never a proven "not sensitive"):

  case2, case8, case9   -> reach authenticate()   -> SENSITIVE
  case7, case10, case11, case12 -> reach unrelatedSink() -> UNKNOWN
  case4b -> reaches authenticate() -> SENSITIVE (the null-sentinel erasure case)
  case13 -> reaches authenticate() ONLY inside the guard's own true-branch
            (JS-STATE-R04) -> UNKNOWN
  case14 -> reaches authenticate() but only AFTER an intervening reassignment
            of the guarded local (JS-STATE-R05) -> UNKNOWN

case1/3/4/5/6 never produce an erasure candidate fact in the first place
(JS-STATE-R02), so there is nothing for this gate to classify for them.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from security_sensitive_reachability import derive  # noqa: E402

EXPECTED_SENSITIVE = {
    "case2_transformBeforeGuard",
    "case4b_nullSentinelErasedByCoercion",
    "case8_bitwiseCoercionBeforeGuard",
    "case9_unaryPlusBeforeGuard",
}
EXPECTED_UNKNOWN = {
    "case7_erasedButNoSensitiveSink",
    "case10_stringCoercionBeforeGuard",
    "case11_booleanCoercionBeforeGuard",
    "case12_parseIntCoercionBeforeGuard",
    "case13_sinkOnlyInGuardTrueBranch",
    "case14_reassignedBeforeSink",
}


def main():
    raw = sys.argv[1]
    result = derive(raw)
    facts = result["facts"]
    by_method = {f["method_name"]: f for f in facts}

    checks = []
    def ck(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    for name in sorted(EXPECTED_SENSITIVE):
        f = by_method.get(name)
        ck(f"{name} classified SENSITIVE", f and f["security_sensitive_use"] == "SENSITIVE", f)
    for name in sorted(EXPECTED_UNKNOWN):
        f = by_method.get(name)
        ck(f"{name} classified UNKNOWN (not proven safe, just unmatched)",
           f and f["security_sensitive_use"] == "UNKNOWN", f)

    # The SENSITIVE cases must specifically match on `authenticate`, not on
    # anything else, and the category must come through from the profile.
    for name in sorted(EXPECTED_SENSITIVE):
        f = by_method.get(name)
        matches = f["sink_matches"] if f else []
        ck(f"{name} sink match is authenticate/AUTHENTICATION",
           any(m["callee_name"] == "authenticate" and m["category"] == "AUTHENTICATION" for m in matches),
           matches)

    # The UNKNOWN cases must have empty sink_matches (no false positive match).
    # case7/10/11/12 reach unrelatedSink (absent from the profile, so it stays
    # UNKNOWN with a real reaching call recorded for audit). case13 is the
    # branch-aware exclusion case: its only same-function reaching call
    # (authenticate) is inside the guard's own true-branch, so reaching_calls
    # is correctly EMPTY and the exclusion shows up in
    # excluded_then_branch_calls instead -- checked separately below.
    for name in sorted(EXPECTED_UNKNOWN - {"case13_sinkOnlyInGuardTrueBranch", "case14_reassignedBeforeSink"}):
        f = by_method.get(name)
        ck(f"{name} has zero sink_matches (unrelatedSink correctly unmatched)",
           f and f["sink_matches"] == [], f)
        ck(f"{name} still records the reaching call for audit (reaching_calls nonempty)",
           f and len(f["reaching_calls"]) >= 1, f)

    # case13: the branch-aware exclusion case (JS-STATE-R04). Its only
    # same-function reaching call (authenticate) sits inside the guard's own
    # true-branch, so it must be EXCLUDED, not merely unmatched -- verify the
    # exclusion mechanism fired specifically, not just that the case happens to
    # land on UNKNOWN for some other reason.
    c13 = by_method.get("case13_sinkOnlyInGuardTrueBranch")
    ck("case13 has zero sink_matches", c13 and c13["sink_matches"] == [], c13)
    ck("case13 has zero reaching_calls (the only candidate was excluded)",
       c13 and c13["reaching_calls"] == [], c13)
    ck("case13's authenticate() call is recorded in excluded_then_branch_calls",
       c13 and any(m["callee_name"] == "authenticate" for m in c13.get("excluded_then_branch_calls", [])),
       c13)

    # case14: the reassignment-aware exclusion case (JS-STATE-R05). The guarded
    # local is reassigned to 42 before authenticate(id14) runs, so the erased
    # value never reaches the sink. Verify the exclusion mechanism fired
    # specifically (excluded_reassigned_calls), not just that the case happens
    # to land on UNKNOWN some other way.
    c14 = by_method.get("case14_reassignedBeforeSink")
    ck("case14 has zero sink_matches", c14 and c14["sink_matches"] == [], c14)
    ck("case14 has zero reaching_calls (the only candidate was excluded)",
       c14 and c14["reaching_calls"] == [], c14)
    ck("case14's authenticate() call is recorded in excluded_reassigned_calls",
       c14 and any(m["callee_name"] == "authenticate" for m in c14.get("excluded_reassigned_calls", [])),
       c14)
    ck("case14's authenticate() call is NOT in excluded_then_branch_calls (different exclusion reason)",
       c14 and not any(m["callee_name"] == "authenticate" for m in c14.get("excluded_then_branch_calls", [])),
       c14)

    # Vocabulary discipline: this module must never emit anything other than
    # SENSITIVE or UNKNOWN -- no NOT_SENSITIVE, no vulnerability verdict.
    ck("no fact uses a value other than SENSITIVE/UNKNOWN for security_sensitive_use",
       all(f["security_sensitive_use"] in ("SENSITIVE", "UNKNOWN") for f in facts))

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" :: {detail}" if detail and not ok else ""))

    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"JS_STATE_R03={passed}/{len(checks)}")

    print("\n--- emitted facts (full dump, for audit) ---")
    print(json.dumps(result, indent=2))

    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
