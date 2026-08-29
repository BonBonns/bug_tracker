#!/usr/bin/env python3
"""Capability-2 / capability-3 write-site boundary controls. Verifies the ROBUST physical
write identity: (a) same basename+line in different directories stay separate; (b) two
writes on one line stay separate; (c) a cap2 call-site summary and a cap3 direct record for
the SAME physical write merge once and preserve both provenances. NO model calls.

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
    checks = []

    # ---- (c) MERGE: cap2 summary + cap3 direct for the SAME physical write -------------
    cpp = scan(os.path.join(HERE, "cap_controls", "overlap"))
    c_ops, _ = CL.analyze_counted_writers(cpp)
    w_ops, _ = W.analyze_wrapper_calls(cpp)
    direct = D.direct_walk_write_sites(cpp)
    cap2 = [o for o in c_ops if o["callee"] == "g_writer"]
    g_direct = [o for o in direct if o["function"] == "g_writer"]
    checks += [
        ("cap2 call-site summary for g_writer carries a robust underlying_write identity",
         len(cap2) == 1 and cap2[0].get("underlying_write") is not None
         and cap2[0]["underlying_write"].get("dest_decl") is not None),
        ("cap3 primitive finds exactly ONE direct write in g_writer",
         len(g_direct) == 1),
        ("cap2 and cap3 resolve the SAME physical write to the SAME robust identity key",
         cap2 and g_direct and D.identity_key(cap2[0]) == D.identity_key(g_direct[0])),
    ]
    merged = D.dedup(c_ops + w_ops + direct)
    g_merged = [m for m in merged
                if any(p["function"] == "g_writer" for p in m["provenance"])]
    checks += [
        ("MERGE: one underlying write -> ONE operation (not two)", len(g_merged) == 1),
        ("MERGE: both provenance paths preserved (direct + call_site_summary)",
         g_merged and g_merged[0]["n_provenance_paths"] == 2
         and {p["attribution"] for p in g_merged[0]["provenance"]} == {"direct", "call_site_summary"}),
        ("MERGE: precedence -> canonical is the DIRECT (cap3) recognition",
         g_merged and g_merged[0]["canonical_attribution"] == "direct"),
    ]

    # ---- (a) same basename+line, different dirs; (b) two writes on one line ------------
    icpp = scan(os.path.join(HERE, "cap_controls", "idcollide"))
    idirect = D.direct_walk_write_sites(icpp)
    wa = [o for o in idirect if o["function"] == "wa"]
    wb = [o for o in idirect if o["function"] == "wb"]
    two = [o for o in idirect if o["function"] == "two_writes"]

    checks += [
        ("(a) wa/wb writes exist in different-directory same-basename files (dirA/dirB w.c)",
         len(wa) == 1 and len(wb) == 1
         and wa[0]["identity"]["file"] != wb[0]["identity"]["file"]
         and wa[0]["identity"]["file"].endswith("w.c")
         and wb[0]["identity"]["file"].endswith("w.c")),
        ("(a) same basename + same line in different dirs -> DIFFERENT identity keys",
         wa and wb and wa[0]["identity"]["line"] == wb[0]["identity"]["line"]
         and D.identity_key(wa[0]) != D.identity_key(wb[0])),
        ("(a) dedup keeps wa and wb SEPARATE (not collapsed)",
         len({D.identity_key(x) for x in (wa + wb)}) == 2
         and len(D.dedup(wa + wb)) == 2),
        ("(b) two_writes has TWO physical writes on the SAME line",
         len(two) == 2 and two[0]["identity"]["line"] == two[1]["identity"]["line"]),
        ("(b) two writes on one line -> DIFFERENT identity keys (ordinal/write/dest_decl)",
         len({D.identity_key(x) for x in two}) == 2),
        ("(b) dedup keeps both same-line writes SEPARATE (not collapsed)",
         len(D.dedup(two)) == 2),
    ]

    # ---- (d) TWIN: two IDENTICAL writes on one line, cross-run stable --------------------
    # Two INDEPENDENT Joern rescans of the same source (separate c2cpg builds).
    adv1 = scan(os.path.join(HERE, "cap_controls", "idadv"))
    adv2 = scan(os.path.join(HERE, "cap_controls", "idadv"))
    tw1 = [o for o in D.direct_walk_write_sites(adv1) if o["function"] == "twin"]
    tw2 = [o for o in D.direct_walk_write_sites(adv2) if o["function"] == "twin"]
    kset1 = {D.identity_key(o) for o in tw1}
    kset2 = {D.identity_key(o) for o in tw2}
    checks += [
        ("(d) twin: two identical-text writes on one line -> TWO distinct identities",
         len(tw1) == 2 and len(kset1) == 2),
        ("(d) twin identity uses SOURCE COLUMN (not node id / appearance rank)",
         all(o["identity"]["site"] and o["identity"]["site"][0] == "col" for o in tw1)),
        ("(d) two independent Joern rescans -> the SAME two identities",
         kset1 == kset2 and len(kset2) == 2),
        ("(d) dedup does NOT collapse the two identical-line writes",
         len(D.dedup(tw1)) == 2),
    ]

    # ---- (e) SHADOW: same-name locals in nested scopes on one line ----------------------
    sh = [o for o in D.direct_walk_write_sites(adv1) if o["function"] == "shadow"]
    xdecls = [r for r in D.local_declaration_identities(adv1)
              if r["function"] == "shadow" and r["name"] == "x"]
    sh_decls = {tuple(o["identity"]["dest_decl"]) for o in sh}
    checks += [
        ("(e) shadowed same-line locals x -> TWO distinct DECLARATION identities",
         len(xdecls) == 2 and len({D.decl_identity_key(r) for r in xdecls}) == 2
         and all(r["verifiable"] for r in xdecls)),
        ("(e) writes through shadowed same-line locals -> TWO distinct identities",
         len(sh) == 2 and len({D.identity_key(o) for o in sh}) == 2),
        ("(e) each shadow write binds a distinct local decl (via ref-target, ordinals 0/1)",
         all(dd[0] == "local" for dd in sh_decls)
         and {dd[-1] for dd in sh_decls} == {0, 1}),
        ("(e) dedup keeps both shadowed-local writes SEPARATE",
         len(D.dedup(sh)) == 2),
    ]

    # ---- (f) OUTER-SHADOW: later write to outer x after inner block ends ----------------
    # ref-target must bind to the OUTER decl (earlier line), NOT the nearer inner decl.
    osh = [o for o in D.direct_walk_write_sites(adv1) if o["function"] == "outer_shadow"]
    xdecl_lines = sorted(r["line"] for r in D.local_declaration_identities(adv1)
                         if r["function"] == "outer_shadow" and r["name"] == "x")
    # the later write is the one on the LARGEST line (after the inner block closes)
    later = max(osh, key=lambda o: o["identity"]["line"]) if osh else None
    inner = min(osh, key=lambda o: o["identity"]["line"]) if osh else None
    checks += [
        ("(f) outer_shadow has two x decls on different lines and two writes",
         len(xdecl_lines) == 2 and len(osh) == 2),
        ("(f) REF-TARGET binds the later write to the OUTER decl (earliest decl line)",
         later and later["identity"]["dest_decl"][0] == "local"
         and later["identity"]["dest_decl"][3] == xdecl_lines[0]),
        ("(f) the inner write binds to the INNER decl (later decl line) -- not merged",
         inner and inner["identity"]["dest_decl"][3] == xdecl_lines[1]
         and D.identity_key(later) != D.identity_key(inner)),
        ("(f) a nearest-preceding-name heuristic would MISbind (outer decl line < inner)",
         xdecl_lines[0] < xdecl_lines[1] and later["identity"]["line"] > xdecl_lines[1]),
    ]

    # ---- (g) FAIL CLOSED: source unavailable -> identity_unverifiable, never merged ------
    import json as _json
    dd = _json.load(open(adv1))
    dd["metadata"][0]["root"] = "/nonexistent-source-root-xyz"   # source now unreadable
    ui = D.build_index(dd)
    tw_calls = [c for c in dd["calls"]
                if c.get("name") == "<operator>.assignment"
                and (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "").startswith("*")]
    uverif = [D.physical_write_identity(c, ui)[0] for c in tw_calls]
    urecs = [{"attribution": "direct", "capability": "pointer_walk_direct",
              "identity": idn, "node_id": i} for i, idn in enumerate(uverif)]
    checks += [
        ("(g) source unavailable -> writes are identity_unverifiable (fail closed)",
         uverif and all(v["verifiable"] is False and v["site"] == ["unverifiable"]
                        for v in uverif)),
        ("(g) unverifiable records are NEVER merged (each stays a separate op, flagged)",
         all(op["identity_unverifiable"] for op in D.dedup(urecs))
         and len(D.dedup(urecs)) == len(urecs)),
    ]

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
