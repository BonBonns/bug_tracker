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
        ("FAMILY: mw_open is ONE operation over 3 member writes, ONE family_id",
         by["mw_open"]["n_member_writes"] == 3
         and len(by["mw_open"]["member_writes"]) == 3
         and isinstance(by["mw_open"]["family_id"], str)
         and len([o for o in C.analyze_member_walks(cpp) if o["function"] == "mw_open"]) == 1),
        ("CAPACITY established from static array (256), not assumed",
         by["mw_open"]["base_capacity"] == 256
         and by["mw_open"]["base_prov"] == "stack_fixed_array"),
        # guarded / literal
        ("GUARDED clamp -> deterministic_complete",
         route("mw_guarded") == "deterministic_complete"),
        ("LITERAL fits (100<=256) -> deterministic_complete",
         route("mw_fits") == "deterministic_complete"),
        ("LITERAL over (300>256) -> proven_oversized",
         by.get("mw_over", {}).get("disposition") == "proven_oversized"),
        # adversarial abstentions (each a distinct trajectory failure)
        ("CONDITIONAL increment -> abstain (per-iteration not proven)",
         route("mw_cond") == "additional_evidence_required"
         and reason("mw_cond") == "cursor_advance_not_proven_per_iteration"),
        ("MULTIPLE increments -> abstain (advance ambiguous)",
         reason("mw_multi") == "cursor_advance_ambiguous"),
        ("POINTER RESET -> abstain (trajectory reset)",
         reason("mw_reset") == "cursor_trajectory_reset"),
        ("ALIAS CONFLICT -> abstain (destination identity ambiguous)",
         reason("mw_alias") == "destination_identity_ambiguous"),
        ("ONE-PAST (body advance before write) -> abstain (one past)",
         reason("mw_onepast") == "cursor_one_past_write"),
        ("EARLY EXIT -> open_candidate (count is upper bound, no false safe)",
         route("mw_break") == "open_candidate"),
        ("UNKNOWN LIFETIME / param base -> abstain (capacity unresolved)",
         reason("mw_param") == "capacity_of_base_unresolved"
         and by["mw_param"].get("base_capacity") is None),
        # SYMBOLIC/negative bound never yields a false safe
        ("SYMBOLIC bound never deterministic_complete (open candidate flag)",
         by["mw_open"]["disposition"] == "relationship_unresolved"),
        # negatives: outside the domain -> NO cap3 op
        ("NEG non-advancing single member write -> no cap3 op", "mw_single" not in by),
        ("NEG byte *p++ deref (cursor domain) -> no cap3 op", "mw_byte" not in by),
    ]

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
