#!/usr/bin/env python3
"""JS-STATE-R07 gate check.

Verifies the four-way isolation matrix (from JS-STATE-R06) plus the retained
null|number case, against a real Joern run. This is a permanent regression
gate, not a one-off characterization probe.

Expected outcomes, transcribed from JS-STATE-R06's characterization BEFORE
this implementation was written (see JS_STATE_R06_CHARACTERIZATION.md's
"Combined (A AND B required)" table):

  truePositive_unionReturnInstanceofGuard        A=yes B=ESTABLISHED -> EMIT
  <lambda>0 (falsePositive_plainFieldDedupKey)    A=no  B=UNKNOWN    -> no emit
  isolation_guardShapeOnlyNoReturnContract        A=yes B=UNKNOWN    -> no emit
  isolation_returnContractOnlyNonComparisonGuard  A=no  B=ESTABLISHED -> no emit
  nullNumber_survivesMalformedReturnType          A=yes B=ESTABLISHED -> EMIT
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from js_state_r07 import derive  # noqa: E402

EXPECTED = {
    "truePositive_unionReturnInstanceofGuard": {
        "emit": True, "guard_shape": True, "return_contract": "ESTABLISHED",
    },
    "<lambda>0": {
        "emit": False, "guard_shape": False, "return_contract": "UNKNOWN",
    },
    "isolation_guardShapeOnlyNoReturnContract": {
        "emit": False, "guard_shape": True, "return_contract": "UNKNOWN",
    },
    "isolation_returnContractOnlyNonComparisonGuard": {
        "emit": False, "guard_shape": False, "return_contract": "ESTABLISHED",
    },
    "nullNumber_survivesMalformedReturnType": {
        "emit": True, "guard_shape": True, "return_contract": "ESTABLISHED",
    },
}


def main():
    raw = sys.argv[1]
    result = derive(raw)
    by_method = {f["method_name"]: f for f in result["all_facts"]}

    checks = []
    def ck(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    ck("exactly 5 total facts produced (no fixture drift)", len(result["all_facts"]) == 5,
       [f["method_name"] for f in result["all_facts"]])

    for name, exp in EXPECTED.items():
        f = by_method.get(name)
        ck(f"{name} present", f is not None)
        if f is None:
            continue
        ck(f"{name} r07_emit == {exp['emit']}", f["r07_emit"] == exp["emit"],
           f["r07_emit"])
        ck(f"{name} guard_shape_established == {exp['guard_shape']}",
           f["r07_guard_shape_established"] == exp["guard_shape"],
           f["r07_guard_shape_established"])
        ck(f"{name} return_contract == {exp['return_contract']}",
           f["r07_return_contract"] == exp["return_contract"],
           f["r07_return_contract"])
        # Item 4 (guard subject = transformed value) must be recorded as
        # already-satisfied on every fact, per R02's construction.
        ck(f"{name} guard_subject_is_transformed_value recorded True",
           f["r07_guard_subject_is_transformed_value"] is True)

    # Exactly 2 candidates should be emitted: the true positive and the
    # retained null|number case. Not 0, not 3+.
    ck("exactly 2 candidates emitted (truePositive + nullNumber)",
       len(result["candidates"]) == 2,
       [c["method_name"] for c in result["candidates"]])
    ck("emitted candidates are exactly the expected two, nothing else",
       {c["method_name"] for c in result["candidates"]} ==
       {"truePositive_unionReturnInstanceofGuard", "nullNumber_survivesMalformedReturnType"},
       [c["method_name"] for c in result["candidates"]])

    # The specific FxA-shaped false positive must show BOTH signals failing,
    # not just one -- this is the exact verification requested: "RETURN
    # CONTRACT: NOT ESTABLISHED, FAILURE GUARD: NOT ESTABLISHED -> excluded".
    fp = by_method.get("<lambda>0")
    ck("FxA-shaped false positive: FAILURE GUARD not established",
       fp and not fp["r07_guard_shape_established"], fp)
    ck("FxA-shaped false positive: RETURN CONTRACT not established (UNKNOWN, not proven-safe)",
       fp and fp["r07_return_contract"] != "ESTABLISHED", fp)
    ck("FxA-shaped false positive: excluded overall",
       fp and not fp["r07_emit"], fp)

    for name, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f" :: {detail}" if detail and not ok else ""))

    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"JS_STATE_R07={passed}/{len(checks)}")

    print("\n--- full fact dump (for audit) ---")
    print(json.dumps(result, indent=2))

    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
