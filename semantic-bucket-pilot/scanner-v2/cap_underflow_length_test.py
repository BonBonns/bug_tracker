#!/usr/bin/env python3
"""Regression/control harness for the underflow-fed-length capability
(cap_underflow_length.py). Scans the synthetic control corpus with the FROZEN
pipeline and asserts the guard-crediting behavior described in
dev_controls/UNDERFLOW_CAPABILITY_DESIGN.md, plus a no-regression check (0 ops
on a subtraction-free file). NO model calls.

Usage: cap_underflow_length_test.py   (requires REPO env + scan_c_frozen.sh + joern)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cap_underflow_length as C


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "underflow"))
    ops = {}
    for o in C.analyze_underflow_length(cpp):
        ops.setdefault(o["function"], []).append(o)
    def one(fn): return (ops.get(fn) or [{}])[0]
    checks = [
        ("guarded: real dominating+controlling guard -> credited deterministic_complete",
         one("guarded").get("disposition") == "deterministic_complete"
         and one("guarded").get("resolution") == "one_hop_local"),
        ("unguarded: no guard at all -> open_candidate",
         one("unguarded").get("disposition") == "open_candidate"
         and one("unguarded").get("reason") == "subtraction_may_underflow"),
        ("wrongpair: guard on the WRONG operand pair -> not falsely credited",
         one("wrongpair").get("disposition") == "open_candidate"),
        ("compoundguard: compound adjustment (headerLen - 4 < mdBlockSize) never credited",
         one("compoundguard").get("disposition") == "open_candidate"),
        ("directguard: inline subtraction (no local hop), real guard -> credited",
         one("directguard").get("disposition") == "deterministic_complete"
         and one("directguard").get("resolution") == "direct"),
        ("idxunguarded: subtraction feeds array index, no guard -> open_candidate",
         one("idxunguarded").get("disposition") == "open_candidate"
         and one("idxunguarded").get("use_kind") == "array_index"),
        ("idxguarded: subtraction feeds array index, guarded -> credited",
         one("idxguarded").get("disposition") == "deterministic_complete"
         and one("idxguarded").get("use_kind") == "array_index"),
        ("assertonly: assert-only guard (compiled out in release) -> NOT credited",
         one("assertonly").get("disposition") == "open_candidate"),
        ("every open_candidate carries llm_eligible=True and route=range_arithmetic_review",
         all(o.get("llm_eligible") is True and o.get("route") == "range_arithmetic_review"
             for fn in ("unguarded", "wrongpair", "compoundguard", "idxunguarded", "assertonly")
             for o in ops.get(fn, []))),
        ("every deterministic_complete carries llm_eligible=False and no route",
         all(o.get("llm_eligible") is False and o.get("route") is None
             for fn in ("guarded", "directguard", "idxguarded")
             for o in ops.get(fn, []))),
    ]
    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c

    # no-regression: a file with a subtraction that feeds NEITHER a sink width
    # arg nor an array index (e.g. it's just printed) -> 0 ops.
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "typedef unsigned int uint;\n"
        "int f(uint a, uint b) { uint c = a - b; return (int)c; }\n")
    n = len(C.analyze_underflow_length(scan(bare)))
    print(("PASS" if n == 0 else "FAIL"), f"no-regression: 0 ops when subtraction feeds no sink/index (got {n})")
    ok = ok and n == 0

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
