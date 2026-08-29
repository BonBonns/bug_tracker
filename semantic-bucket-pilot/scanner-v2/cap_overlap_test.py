#!/usr/bin/env python3
"""Overlap control for the capability-2 / capability-3 boundary. Ensures ONE underlying
physical write does not become TWO experimental operations when both a cap2 call-site
summary and a cap3 direct recognition refer to it. NO model calls.

Usage: cap_overlap_test.py   (requires REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cap_counted_loop_writer as CL
import cap_wrapper_summary as W
import cap_write_site_dedup as D


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "overlap"))

    c_ops, _ = CL.analyze_counted_writers(cpp)     # cap2 call-site summaries
    w_ops, _ = W.analyze_wrapper_calls(cpp)        # (none expected here)
    direct = D.direct_walk_write_sites(cpp)        # cap3 primitive: direct write sites

    # the counted-writer call-site op in f_caller, referring to g_writer's physical write
    cap2 = [o for o in c_ops if o["callee"] == "g_writer"]
    # the direct pointer-walk write inside g_writer's body
    g_direct = [o for o in direct if o["function"] == "g_writer"]

    checks = [
        ("cap2 produced a call-site summary for g_writer (in f_caller)",
         len(cap2) == 1 and cap2[0]["function"] == "f_caller"
         and cap2[0]["attribution"] == "call_site_summary"),
        ("cap2 record carries underlying_write pointing into g_writer",
         cap2 and cap2[0].get("underlying_write", {}).get("line") is not None),
        ("cap3 primitive found exactly ONE direct pointer-walk write in g_writer",
         len(g_direct) == 1 and g_direct[0]["attribution"] == "direct"),
        ("cap2.underlying_write and cap3.direct resolve to the SAME write-site key",
         cap2 and g_direct and D.write_site_key(cap2[0]) == D.write_site_key(g_direct[0])),
    ]

    merged = D.dedup(c_ops + w_ops + direct)
    g_merged = [m for m in merged if m["write_site"]["file"].endswith("overlap.c")
                and m["provenance"] and any(p["function"] == "g_writer" for p in m["provenance"])]

    checks += [
        # THE overlap guarantee: one underlying write -> ONE operation, not two
        ("ONE underlying write -> ONE merged operation (not two)", len(g_merged) == 1),
        ("merged op carries BOTH provenance paths (direct + call_site_summary)",
         g_merged and g_merged[0]["n_provenance_paths"] == 2
         and {p["attribution"] for p in g_merged[0]["provenance"]} == {"direct", "call_site_summary"}),
        ("PRECEDENCE: canonical attribution is the DIRECT (cap3) recognition",
         g_merged and g_merged[0]["canonical_attribution"] == "direct"
         and g_merged[0]["canonical_capability"] == "pointer_walk_direct"),
        # total distinct write sites in this fixture is 1 (no double counting anywhere)
        ("no write site in overlap.c is counted more than once",
         all(m["n_provenance_paths"] >= 1 for m in merged)
         and len([m for m in merged if m["write_site"]["file"].endswith("overlap.c")]) == 1),
    ]

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
