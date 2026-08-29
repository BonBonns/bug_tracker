#!/usr/bin/env python3
"""Control/regression harness for capability 3 (advancing-pointer struct-member walks).
Synthetic positive + adversarial controls, the PNG003 extracted dev body, family grouping,
additive-ness (nothing outside the new domain), and separation from the frozen cursor
producer. NO model calls. Uses Magma/PNG003 as DEVELOPMENT evidence only; the frozen
held-out corpus is NOT referenced.

Usage: cap_member_pointer_walk_test.py   (REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_member_pointer_walk as C
import cap_write_site_dedup as WSD
import cap3_domain_audit as AUD


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap3_member"))
    by = {o["function"]: o for o in C.analyze_member_walks(cpp)}

    def route(fn):
        return by.get(fn, {}).get("route")

    def reason(fn):
        return by.get(fn, {}).get("reason")

    checks = [
        # positive
        ("POS mw_open -> open_candidate / write_count_bound_not_established",
         route("mw_open") == "open_candidate"
         and reason("mw_open") == "write_count_bound_not_established"),
        ("FAMILY: mw_open is ONE op over 3 member writes, ONE family_id, 3 DISTINCT sites",
         by["mw_open"]["n_member_writes"] == 3
         and len(by["mw_open"]["member_writes"]) == 3
         and len({WSD.identity_key({"identity": m}) for m in by["mw_open"]["member_writes"]}) == 3
         and len(set(by["mw_open"]["member_write_nodes"])) == 3
         and isinstance(by["mw_open"]["family_id"], str)
         and len([o for o in by.values() if o["function"] == "mw_open"]) == 1),
        ("CAPACITY established from static array (256), not assumed",
         by["mw_open"]["base_capacity"] == 256
         and by["mw_open"]["base_prov"] == "stack_fixed_array"),
        ("STRUCTURAL PROOF: advance in for-UPDATE, writes in for-BODY (AST, not lines)",
         by["mw_open"].get("proof", {}).get("advance_in_update") is True
         and by["mw_open"]["proof"].get("writes_in_body") is True),
        # multiline header + same-line body increment: the AST fix's key regressions
        ("MULTILINE for-header -> recognized (open_candidate) via AST, not line coincidence",
         route("mw_multiline") == "open_candidate"
         and by["mw_multiline"]["n_member_writes"] == 3),
        ("SAME-LINE body increment -> abstain (in body, not update); line heuristic would MISread",
         reason("mw_sameline") == "cursor_advance_in_loop_body_not_update"),
        # literal (sound without a guard proof)
        ("LITERAL fits (100<=256) -> deterministic_complete",
         route("mw_fits") == "deterministic_complete"),
        ("LITERAL over (300>256) -> proven_oversized",
         by.get("mw_over", {}).get("disposition") == "proven_oversized"),
        # GUARDED symbolic bound: conservatively an OPEN CANDIDATE (no false safe without a
        # rigorous guard-dominance/polarity/non-invalidation proof -- deferred).
        ("GUARDED symbolic bound -> open_candidate (no unproven safe claim)",
         route("mw_guarded") == "open_candidate"),
        # adversarial abstentions (each a distinct trajectory failure)
        ("CONDITIONAL increment -> abstain (in loop body, not update)",
         route("mw_cond") == "additional_evidence_required"
         and reason("mw_cond") == "cursor_advance_in_loop_body_not_update"),
        ("MULTIPLE increments -> abstain (advance ambiguous)",
         reason("mw_multi") == "cursor_advance_ambiguous"),
        ("POINTER RESET -> abstain (trajectory reset)",
         reason("mw_reset") == "cursor_trajectory_reset"),
        ("ALIAS CONFLICT -> abstain (destination identity ambiguous)",
         reason("mw_alias") == "destination_identity_ambiguous"),
        ("ONE-PAST (body advance before write) -> abstain (in loop body, not update)",
         reason("mw_onepast") == "cursor_advance_in_loop_body_not_update"),
        ("EARLY EXIT -> open_candidate (count is upper bound, no false safe)",
         route("mw_break") == "open_candidate"),
        ("UNKNOWN LIFETIME / param base -> abstain (capacity unresolved)",
         reason("mw_param") == "capacity_of_base_unresolved"
         and by["mw_param"].get("base_capacity") is None),
        # SYMBOLIC/signed bound never yields a false safe (max(0,num) semantics noted)
        ("SYMBOLIC bound never deterministic_complete (open candidate flag)",
         by["mw_open"]["disposition"] == "relationship_unresolved"),
        # ITERATION COUNT proofs (bound token != iteration count) --------------------------
        # i=0; i<=256 -> 257 writes -> oversized (NOT safe just because token==capacity).
        ("ITER i=0;i<=256 OFF-BY-ONE -> proven_oversized (257 writes)",
         by.get("mw_le256", {}).get("disposition") == "proven_oversized"
         and by.get("mw_le256", {}).get("iteration_count") == 257),
        # i=1; i<=256 -> 256 writes -> fits exactly (nonzero init handled).
        ("ITER i=1;i<=256 NONZERO-INIT -> deterministic_complete (256 writes)",
         route("mw_init1") == "deterministic_complete"
         and by["mw_init1"]["iteration_count"] == 256),
        # i=256; i>0; i-- -> 256 writes -> fits (decrementing counter handled).
        ("ITER i=256;i>0;i-- DECREMENT -> deterministic_complete (256 writes)",
         route("mw_dec") == "deterministic_complete"
         and by["mw_dec"]["iteration_count"] == 256),
        # i=0; i<256; i+=2 -> 128 writes -> fits (literal step drives the count, not step 1).
        ("ITER i+=2 STEP -> deterministic_complete (128 writes, not 256)",
         route("mw_step2") == "deterministic_complete"
         and by["mw_step2"]["iteration_count"] == 128),
        # counter mutated in the body -> count not header-determined -> conservative open.
        ("ITER counter modified in body -> open_candidate (counter_modified_in_body)",
         route("mw_bodymod") == "open_candidate"
         and by["mw_bodymod"]["bound_shape"] == "counter_modified_in_body"),
        # cursor = array + 100, 200 writes -> reaches index 299 >= 256 -> oversized.
        ("ITER cursor=array+offset -> proven_oversized (offset 100 counted)",
         by.get("mw_offset", {}).get("disposition") == "proven_oversized"
         and by["mw_offset"]["cursor_start_offset"] == 100
         and by["mw_offset"]["iteration_count"] == 200),
        # NO DoS: a 2e9 literal bound resolved by O(1) closed form (this test returns instantly).
        ("NO-DoS huge literal bound -> proven_oversized via closed form (2e9 writes, O(1))",
         by.get("mw_huge", {}).get("disposition") == "proven_oversized"
         and by["mw_huge"]["iteration_count"] == 2000000000
         and by["mw_huge"]["bound_shape"] == "literal_count"),
        # C SEMANTICS: signed overflow at the boundary -> cannot promote (open, not fits).
        ("SIGNED-OVERFLOW boundary -> open_candidate (counter_overflow_unproven, not fits)",
         route("mw_ovf") == "open_candidate"
         and by["mw_ovf"]["bound_shape"] == "counter_overflow_unproven"),
        # C SEMANTICS: unsigned decrement wraps past 0 -> cannot prove count -> open.
        ("UNSIGNED-WRAP decrement -> open_candidate (counter_overflow_unproven)",
         route("mw_wrap") == "open_candidate"
         and by["mw_wrap"]["bound_shape"] == "counter_overflow_unproven"),
        # negatives: outside the domain -> NO cap3 op
        ("NEG non-advancing single member write -> no cap3 op", "mw_single" not in by),
        ("NEG byte *p++ deref (cursor domain) -> no cap3 op", "mw_byte" not in by),
    ]

    # FAIL CLOSED: without control-structure facts, cap3 must NOT recognize (abstain).
    fc = {o["function"]: o for o in C.analyze_member_walks(cpp, for_struct=None)}
    checks.append(
        ("FAIL CLOSED: no for-structure facts -> mw_open abstains (for_structure_unavailable)",
         fc.get("mw_open", {}).get("route") == "additional_evidence_required"
         and fc["mw_open"]["reason"] == "for_structure_unavailable"))

    # PNG003 extracted development body (Magma dev evidence only)
    png = scan(os.path.join(HERE, "cap_controls", "audit"))  # a6_png003.c lives here
    pops = [o for o in C.analyze_member_walks(png)
            if o["function"] == "png_handle_PLTE_devsite"]
    checks += [
        ("PNG003 dev body -> ONE open_candidate over 3 writes, capacity 256",
         len(pops) == 1 and pops[0]["route"] == "open_candidate"
         and pops[0]["n_member_writes"] == 3 and pops[0]["base_capacity"] == 256),
    ]

    # separation + additive: cap3 emits nothing in the cursor producer's domain, and its
    # sites are disjoint from the frozen cursor producer's recognized sites.
    cur = AUD.cursor_sites(cpp)
    cur_keys = {WSD.identity_key(o) for o in cur}
    cap3_member_keys = set()
    for o in by.values():
        for m in o.get("member_writes", []):
            cap3_member_keys.add(WSD.identity_key({"identity": m}))
    audit_cpp = scan(os.path.join(HERE, "cap_controls", "audit"))
    cap3_on_deref = [o for o in C.analyze_member_walks(audit_cpp)
                     if o["function"] in ("a1_raw", "a2_off", "a4_arr", "a5_heap")]
    checks += [
        ("ADDITIVE: cap3 emits NOTHING on the cursor-domain deref fixtures (a1/a2/a4/a5)",
         len(cap3_on_deref) == 0),
        ("SEPARATION: cap3 member-write sites are disjoint from cursor-recognized sites",
         cap3_member_keys.isdisjoint(cur_keys)),
    ]

    # CPP<->CPG BINDING FAIL-CLOSED: a for_structure whose witness code no longer matches
    # the cpp.json (node ids are only meaningful within one CPG generation) must be rejected.
    fs = C.load_for_structure(cpp)
    tampered = {"by_method": fs["by_method"], "cpg_sha": fs["cpg_sha"],
                "cpp_sha": fs["cpp_sha"],
                "witnesses": [(wid, wcode + " /*STALE*/") for (wid, wcode) in fs["witnesses"]]}
    mm = {o["function"]: o for o in C.analyze_member_walks(cpp, for_struct=tampered)}
    checks.append(
        ("BINDING MISMATCH (witness): tampered node witness -> fail closed",
         len(fs["witnesses"]) > 0
         and reason("mw_open") == "write_count_bound_not_established"   # sanity: real run ok
         and mm.get("mw_open", {}).get("reason") == "for_structure_cpp_cpg_mismatch"
         and mm["mw_open"]["route"] == "additional_evidence_required"))

    # TWO-FILE MANIFEST: a cpp.json hash that does not match the manifest -> fail closed, even
    # though the node witnesses are intact (this is the check the witnesses alone cannot make).
    bad_cpp_sha = dict(fs); bad_cpp_sha["cpp_sha"] = "0" * 64
    mh = {o["function"]: o for o in C.analyze_member_walks(cpp, for_struct=bad_cpp_sha)}
    checks.append(
        ("BINDING MISMATCH (manifest): wrong cpp.json hash -> fail closed",
         mh.get("mw_open", {}).get("reason") == "for_structure_cpp_cpg_mismatch"
         and mh["mw_open"]["route"] == "additional_evidence_required"))

    # MULTIPLE UNVERIFIABLE records remain DISTINCT: dedup must not merge them, and must give
    # each a monotonic per-run index (NOT object id()) as its "never merge" guarantee.
    unver = [{"attribution": "direct", "capability": "member_pointer_walk",
              "function": "fA", "node_id": None,
              "identity": {"verifiable": False, "file": "x.c",
                           "function": ["fA", 1, 9], "write": ["=", "p->f"]}},
             {"attribution": "direct", "capability": "member_pointer_walk",
              "function": "fB", "node_id": None,
              "identity": {"verifiable": False, "file": "x.c",
                           "function": ["fB", 1, 9], "write": ["=", "q->f"]}}]
    dd = WSD.dedup(unver)
    un_ops = [o for o in dd if o.get("identity_unverifiable")]
    # Both unverifiable records collapse to the SAME identity_key (("UNVERIFIABLE", None)):
    # that is exactly why the monotonic per-run index -- not the key, not object id() -- is
    # the thing guaranteeing they are never merged.
    same_key = WSD.identity_key(unver[0]) == WSD.identity_key(unver[1]) == ("UNVERIFIABLE", None)
    checks.append(
        ("MULTIPLE UNVERIFIABLE: 2 records -> 2 distinct never-merged ops, monotonic index",
         len(un_ops) == 2 and same_key
         and sorted(o["unverifiable_index"] for o in un_ops) == [0, 1]
         and all(o["n_provenance_paths"] == 1 for o in un_ops)))

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c

    # no-regression: cap3 emits 0 ops on a bare direct-memcpy file
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    n = len(C.analyze_member_walks(scan(bare)))
    print(("PASS" if n == 0 else "FAIL"), f"no-regression: 0 cap3 ops on bare-memcpy file (got {n})")
    ok = ok and n == 0

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
