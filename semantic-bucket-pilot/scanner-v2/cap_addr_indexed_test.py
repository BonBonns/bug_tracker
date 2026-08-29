#!/usr/bin/env python3
"""Regression/control harness for capability 1 (address-of indexed destination).
Scans the synthetic control corpus with the FROZEN pipeline and asserts the general model's
behavior, plus a no-regression check (0 ops on a bare-local file). Run before accepting any
change to cap_addr_indexed.py. NO model calls.

Usage: cap_addr_indexed_test.py   (requires REPO env + scan_c_frozen.sh + joern)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cap_addr_indexed as C


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap1"))
    ops = {}
    for o in C.analyze_addr_indexed(cpp):
        ops.setdefault(o["function"], []).append(o)
    def one(fn): return (ops.get(fn) or [{}])[0]
    checks = [
        ("POS1 recognized, offset10 remaining90", one("pos1").get("offset") == 10 and one("pos1").get("remaining_capacity") == 90),
        ("POS2 symbolic offset -> abstain", one("pos2").get("reason") == "offset_not_numeric"),
        ("POS3 overflow at offset (remaining15 < 40)", one("pos3").get("disposition") == "proven_oversized"),
        ("NEG1 read not recognized", "neg1" not in ops),
        ("NEG2 bare-local not handled", "neg2" not in ops),
        ("NEG3 addr-of-nonindexed not handled", "neg3" not in ops),
        ("SNDSHAPE struct-field base recognized + capacity unresolved", one("sndshape").get("reason") == "capacity_of_base_unresolved"),
        ("UNIT int-array element units (remaining8, ok)", one("unitcase").get("remaining_capacity") == 8 and one("unitcase").get("disposition") == "deterministic_complete"),
        ("NONARRAY pointer param -> no false bind", one("nonarray").get("reason") == "capacity_of_base_unresolved"),
        ("AMBIG shadowed decls -> abstain", all(o.get("reason") == "conflicting_base_decls" for o in ops.get("ambig", [{}]))),
        # safety-critical edge controls: 'remaining capacity' must never be treated as
        # established while pointer validity or index arithmetic is unresolved.
        ("NEGIDX negative index -> abstain (no cap+1)", one("negidx").get("reason") == "negative_offset_pointer_validity_unresolved" and one("negidx").get("remaining_capacity") is None),
        ("ONEPASTEND offset==cap -> remaining0, positive write not 'safe'", one("onepast").get("remaining_capacity") == 0 and one("onepast").get("disposition") != "deterministic_complete"),
        ("SYMARITH symbolic index arithmetic -> abstain", one("symarith").get("reason") == "offset_not_numeric"),
        ("SIDEEFFECT side-effecting index -> abstain", one("sideeffect").get("reason") == "side_effecting_index"),
        ("UNITMISMATCH byte width vs element array -> abstain", one("unitmismatch").get("disposition") == "relationship_unresolved" and one("unitmismatch").get("route") != "deterministic_complete"),
    ]
    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c
    # no-regression: on a bare-local-only file, cap1 emits ZERO ops
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    n = len(C.analyze_addr_indexed(scan(bare)))
    print(("PASS" if n == 0 else "FAIL"), f"no-regression: 0 cap1 ops on bare-local file (got {n})")
    ok = ok and n == 0
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
