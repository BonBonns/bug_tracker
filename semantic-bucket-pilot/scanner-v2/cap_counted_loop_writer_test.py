#!/usr/bin/env python3
"""Control/regression harness for the counted-writer/loop summary model. Scans synthetic
controls + the REAL SSL004 ascii2ebcdic body with the FROZEN pipeline (joern 4.0.608) and
asserts each distinct proof obligation, additive-ness, model separation from the
delegation wrapper, and no-regression. NO model calls.

Usage: cap_counted_loop_writer_test.py   (requires REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cap_counted_loop_writer as C
import cap_wrapper_summary as W
import oob_runtime_capacity_v2 as v2


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap_loop"))
    ops, summ = C.analyze_counted_writers(cpp)
    by = {}
    for o in ops:
        by.setdefault((o["callee"], o["count"]), o)

    checks = [
        # summary inference from body
        ("SUMM cw counted writer (dest0, counter2, unsigned, advance 1)",
         summ.get("cw", {}).get("dest_param_index") == 0 and summ["cw"]["counter_param"] == "count"
         and summ["cw"]["counter_signed"] is False and summ["cw"]["advance_per_iteration"] == 1),
        ("SIGNEDNESS recorded: cw_signed counter is signed",
         summ.get("cw_signed", {}).get("counter_signed") is True),
        # each proof-obligation NEGATIVE -> no summary
        ("POINTER ADVANCEMENT: single-slot no_advance -> NO summary", "no_advance" not in summ),
        ("ADVANCE MULTIPLICITY: double_advance (2/iter) -> NO summary", "double_advance" not in summ),
        ("ALIAS IDENTITY: alien_walk (unrelated local) -> NO summary", "alien_walk" not in summ),
        ("CONFLICTING PATHS: two_dests -> NO summary", "two_dests" not in summ),
        # call-site routing
        ("POS cw(big,32) literal fits -> deterministic_complete",
         by.get(("cw", "32"), {}).get("disposition") == "deterministic_complete"),
        ("POS cw(small,40) literal over -> proven_oversized",
         by.get(("cw", "40"), {}).get("disposition") == "proven_oversized"),
        ("ZERO COUNT cw(big,0) -> proven safe, never false overflow",
         by.get(("cw", "0"), {}).get("disposition") == "deterministic_complete"),
        ("UNSIGNED symbolic cw(big,n) -> count_bound_not_established, capacity bound",
         by.get(("cw", "n"), {}).get("reason") == "count_bound_not_established"
         and by[("cw", "n")]["dest_capacity"] == 64),
        ("SIGNED symbolic cw_signed(big,sn) -> count_sign_unresolved, no false safe",
         by.get(("cw_signed", "sn"), {}).get("reason") == "count_sign_unresolved"
         and by[("cw_signed", "sn")]["disposition"] != "deterministic_complete"),
        ("extent is a sound UPPER bound flag set", all(o.get("extent_is_upper_bound") for o in ops)),
        # ARGUMENT POSITION: non-standard param order (dest arg1, counter arg0)
        ("ARG-POSITION cw_reordered binds dest=1/counter=0",
         summ.get("cw_reordered", {}).get("dest_param_index") == 1
         and summ["cw_reordered"]["counter_param_index"] == 0),
        ("ARG-POSITION cw_reordered(16,big,src) routes 16<=64 -> deterministic_complete",
         by.get(("cw_reordered", "16"), {}).get("disposition") == "deterministic_complete"),
        # EARLY EXIT: a break still yields a sound summary (count is upper bound)
        ("EARLY-EXIT cw_break summarized (single advance, one counter)",
         summ.get("cw_break", {}).get("form") == "counted_loop_writer"),
        ("EARLY-EXIT cw_break(20,big) routes 20<=64 -> deterministic_complete (upper bound)",
         by.get(("cw_break", "20"), {}).get("disposition") == "deterministic_complete"),
    ]

    # additive-ness: disjoint from the frozen v1 runtime scanner ops
    v1_recs = v2.V1.analyze_operations(cpp) if hasattr(v2, "V1") else []
    frozen_lines = {(r.get("function"), r.get("line")) for r in v1_recs}
    loop_lines = {(o["function"], o["line"]) for o in ops}
    checks.append(("ADDITIVE: counted-writer call sites disjoint from frozen scanner ops",
                   frozen_lines.isdisjoint(loop_lines)))

    # MODEL SEPARATION: the counted-loop callees are NOT delegation wrapper summaries
    _, wsumm = W.analyze_wrapper_calls(cpp)
    checks.append(("SEPARATION: cw/cw_signed are NOT transparent-wrapper summaries",
                   "cw" not in wsumm and "cw_signed" not in wsumm))

    # Magma SSL004: MODEL-LEVEL recovery on an EXTRACTED real ascii2ebcdic body
    # (reconstructed caller; complete target NOT built, original site NOT through c2cpg).
    mcpp = scan(os.path.join(HERE, "cap_controls", "cap2_magma"))
    mops, msumm = C.analyze_counted_writers(mcpp)
    m_by = {o["callee"]: o for o in mops}
    checks += [
        ("MAGMA SSL004 ascii2ebcdic summarized as counted writer (extracted real body)",
         msumm.get("ascii2ebcdic", {}).get("form") == "counted_loop_writer"
         and msumm["ascii2ebcdic"]["advance_per_iteration"] == 1),
        ("MAGMA SSL004 call recognized, cap 1024 bound, correct abstention (unsigned count)",
         m_by.get("ascii2ebcdic", {}).get("dest_capacity") == 1024
         and m_by["ascii2ebcdic"]["disposition"] == "relationship_unresolved"),
        ("SEPARATION: _TIFFmemcpy delegation is NOT a counted-writer summary",
         "_TIFFmemcpy" not in msumm),
    ]

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c

    # no-regression: a bare direct-memcpy file -> ZERO counted-writer ops/summaries
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    bops, bsumm = C.analyze_counted_writers(scan(bare))
    print(("PASS" if not bops and not bsumm else "FAIL"),
          f"no-regression: 0 counted-writer summaries/ops on bare-memcpy file (got {len(bsumm)}/{len(bops)})")
    ok = ok and not bops and not bsumm

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
