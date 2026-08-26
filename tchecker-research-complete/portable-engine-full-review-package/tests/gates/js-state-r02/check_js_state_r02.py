#!/usr/bin/env python3
"""JS-STATE-R02 gate check.

Verifies FailureStateErasureCandidateFact derivation against the fixture
(state_erasure.ts, 14 case functions -- case13 was added in the JS-STATE-R04
path-sensitivity follow-up). This is a real gate: it runs failure_state_facts.py
against real Joern-exported facts and checks results, not stored/pre-computed
output.

Expected: candidate facts fire for exactly the cases where JS-STATE-R01's
per-case report said GUARD_SUBJECT=TRANSFORMED and TRANSFORMATION_SEMANTICS=
ERASES (case2, case4b, case7, case8, case9, case10, case11, case12), plus
case13 (added later: same Number()-before-instanceof-Error erasure shape as
case2 -- R02 correctly flags it as an erasure candidate regardless of where the
sink call sits, since branch-awareness is JS-STATE-R04's job, not R02's). Facts
do NOT fire for case1 (guard before transform), case3 (no transform), case4 (no
transform), case5 (transform is identity(), not in the closed erasing set --
this module makes no PRESERVES claim, it just correctly stays silent), or case6
(transform is an unmodeled external function, not in the closed erasing set --
correct abstention, not a false negative: this module never claims to cover
UNKNOWN transformations).
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from failure_state_facts import derive  # noqa: E402

EXPECTED_FLAGGED = {
    "case2_transformBeforeGuard",
    "case4b_nullSentinelErasedByCoercion",
    "case7_erasedButNoSensitiveSink",
    "case8_bitwiseCoercionBeforeGuard",
    "case9_unaryPlusBeforeGuard",
    "case10_stringCoercionBeforeGuard",
    "case11_booleanCoercionBeforeGuard",
    "case12_parseIntCoercionBeforeGuard",
    "case13_sinkOnlyInGuardTrueBranch",
    "case14_reassignedBeforeSink",
}
EXPECTED_NOT_FLAGGED = {
    "case1_safeGuardBeforeTransform",
    "case3_discriminatedUnionSafe",
    "case4_nullSentinelSafe",
    "case5_preservingTransform",
    "case6_unknownTransformAbstain",
}


def main():
    raw = sys.argv[1]
    result = derive(raw)
    facts = result["facts"]

    flagged_methods = {f["method_name"] for f in facts}

    checks = []
    def ck(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    for name in sorted(EXPECTED_FLAGGED):
        ck(f"{name} flagged as candidate", name in flagged_methods)
    for name in sorted(EXPECTED_NOT_FLAGGED):
        ck(f"{name} NOT flagged (correct abstention/silence)", name not in flagged_methods)

    # Exactly one fact per flagged case in this fixture (each has one guard).
    for name in sorted(EXPECTED_FLAGGED):
        n = sum(1 for f in facts if f["method_name"] == name)
        ck(f"{name} has exactly one candidate fact", n == 1, f"got {n}")

    # No fact ever asserts a security-sensitive-use verdict -- this module must
    # never emit anything beyond FailureStateErasureCandidateFact.
    ck("no fact carries a security/vulnerability verdict field",
       all(set(f.keys()) <= {
           "method_id", "method_name", "control_structure_id", "condition_id",
           "condition_code", "guard_identifier_id", "guard_local_id",
           "transformation_call_id", "transformation_name", "transformation_code",
           "resolution", "derivation",
       } for f in facts))

    # Every emitted fact's resolution is ERASES -- this module has no other
    # resolution value, by construction (see failure_state_facts.py docstring).
    ck("every fact has resolution=ERASES", all(f["resolution"] == "ERASES" for f in facts))

    # Unrecognized/off-fixture noise check: total fact count should equal
    # exactly the flagged-case count (no double-counting, no stray facts from
    # unrelated methods like `create`/`identity`/`authenticate` themselves).
    ck("total fact count equals expected flagged-case count",
       len(facts) == len(EXPECTED_FLAGGED), f"got {len(facts)} facts: {sorted(flagged_methods)}")

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" :: {detail}" if detail and not ok else ""))

    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"JS_STATE_R02={passed}/{len(checks)}")

    print("\n--- emitted facts (full dump, for audit) ---")
    print(json.dumps(result, indent=2))

    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
