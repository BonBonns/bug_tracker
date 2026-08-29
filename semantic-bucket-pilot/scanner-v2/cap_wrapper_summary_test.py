#!/usr/bin/env python3
"""Control/regression harness for capability 2 (transparent wrapper summaries).
Scans synthetic controls + the REAL-source Magma dev-sites with the FROZEN pipeline and
asserts the general model's behavior, the body-not-name discipline, additive-ness (the
frozen scanner emits nothing on these wrapper call sites), and no-regression on a bare
direct-memcpy file. Run before accepting any change to cap_wrapper_summary.py. NO model calls.

Usage: cap_wrapper_summary_test.py   (requires REPO env + scan_c_frozen.sh + joern)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cap_wrapper_summary as C
import oob_runtime_capacity_v2 as v2


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap2"))
    ops, summ = C.analyze_wrapper_calls(cpp)
    ops_by_callee = {}
    for o in ops:
        ops_by_callee.setdefault(o["callee"], []).append(o)

    def only(callee):
        return (ops_by_callee.get(callee) or [{}])[0]

    checks = [
        # summaries inferred from BODY (delegation positives), abstentions get no summary
        ("SUMM deleg (delegation, dest0/len2)",
         summ.get("deleg", {}).get("dest_param_index") == 0 and summ["deleg"]["length_param"] == "n"
         and summ["deleg"]["form"] == "delegation"),
        ("SUMM deleg_alias via local alias of dest param",
         summ.get("deleg_alias", {}).get("dest_param") == "d"),
        # a counted loop is NOT a transparent delegation wrapper -> no wrapper summary here
        ("SEPARATION: loop 'walk' is NOT a wrapper-summary (handled by counted-loop model)",
         "walk" not in summ),
        # body-not-name discipline + soundness abstentions -> NO summary at all
        ("NEG name-only copy_into has NO summary", "copy_into" not in summ),
        ("NEG dest-not-param writes_local has NO summary", "writes_local" not in summ),
        ("NEG fixed-length (not a param) has NO summary", "fixed_len" not in summ),
        ("NEG conflicting sinks -> NO summary", "conflict" not in summ),
        # call-site routing via the frozen comparison
        ("POS deleg(big,32) literal fits -> deterministic_complete",
         any(o["dest"] == "big" and o["length"] == "32" and o["disposition"] == "deterministic_complete"
             for o in ops_by_callee.get("deleg", []))),
        ("POS deleg(small,40) literal over -> proven_oversized",
         any(o["dest"] == "small" and o["disposition"] == "proven_oversized"
             for o in ops_by_callee.get("deleg", []))),
        ("POS deleg_alias(big,n) symbolic -> unresolved, capacity bound",
         only("deleg_alias").get("disposition") == "relationship_unresolved"
         and only("deleg_alias").get("dest_capacity") == 64),
        # ARGUMENT POSITION: non-standard param order bound correctly (dest arg1, len arg0)
        ("ARG-POSITION deleg_reordered binds dest=1/len=0",
         summ.get("deleg_reordered", {}).get("dest_param_index") == 1
         and summ["deleg_reordered"]["length_param_index"] == 0),
        ("ARG-POSITION deleg_reordered(32,big,src) routes 32<=64 -> deterministic_complete",
         only("deleg_reordered").get("dest") == "big"
         and only("deleg_reordered").get("disposition") == "deterministic_complete"),
        # non-summarized callees produce ZERO call-site ops
        ("NEG no ops for name-only/dest-local/fixed/conflict/loop callees",
         not any(c in ops_by_callee for c in ("copy_into", "writes_local", "fixed_len", "conflict", "walk"))),
    ]

    # additive-ness: the frozen v1/v2 runtime scanner emits NOTHING on these wrapper
    # call sites (its contracts are library sinks only) -> cap2 cannot move any verdict.
    v1_recs = v2.V1.analyze_operations(cpp) if hasattr(v2, "V1") else []
    frozen_lines = {(r.get("function"), r.get("line")) for r in v1_recs}
    cap2_lines = {(o["function"], o["line"]) for o in ops}
    checks.append(("ADDITIVE: cap2 call sites disjoint from frozen scanner ops",
                   frozen_lines.isdisjoint(cap2_lines)))

    # Magma dev-site: MODEL-LEVEL recovery on an EXTRACTED real _TIFFmemcpy body (reduced
    # caller; complete libtiff target NOT built, original site NOT through c2cpg). cap2
    # abstention (symbolic length), no false capacity claim. (SSL004 ascii2ebcdic is the
    # counted-loop model's dev-site, asserted in cap_counted_loop_writer_test.py -- it
    # must NOT be a wrapper summary here.)
    mcpp = scan(os.path.join(HERE, "cap_controls", "cap2_magma"))
    mops, msumm = C.analyze_wrapper_calls(mcpp)
    m_by = {o["callee"]: o for o in mops}
    checks += [
        ("MAGMA TIF013 _TIFFmemcpy summarized (extracted real delegation body)",
         msumm.get("_TIFFmemcpy", {}).get("form") == "delegation"),
        ("MAGMA TIF013 call recognized, cap 512 bound, correct abstention",
         m_by.get("_TIFFmemcpy", {}).get("dest_capacity") == 512
         and m_by["_TIFFmemcpy"]["disposition"] == "relationship_unresolved"),
        ("SEPARATION: ascii2ebcdic loop is NOT a wrapper summary",
         "ascii2ebcdic" not in msumm),
    ]

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c

    # no-regression: a bare direct-memcpy file (no user wrappers) -> ZERO cap2 ops/summaries
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    bops, bsumm = C.analyze_wrapper_calls(scan(bare))
    print(("PASS" if not bops and not bsumm else "FAIL"),
          f"no-regression: 0 cap2 summaries/ops on bare-memcpy file (got {len(bsumm)}/{len(bops)})")
    ok = ok and not bops and not bsumm

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
