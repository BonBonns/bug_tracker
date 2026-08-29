#!/usr/bin/env python3
"""Capability-3 domain-overlap audit against the frozen cursor producer.
NO model calls. Runs BOTH the frozen `oob_cursor_write_verdict` producer and the
`cap_write_site_dedup.direct_walk_write_sites` primitive on six representation shapes,
classifies every physical write site by robust identity into:
  * existing_cursor_domain  -- recognized by the frozen cursor producer;
  * new_capability_3_domain -- a pointer-walk write the cursor producer does NOT model
                               (member-through-advancing-pointer / non-byte element);
  * overlap_domain          -- recognized by BOTH (dedup must collapse to ONE op,
                               cursor precedence, both provenances preserved).
Emits study/magma/CAP3_DOMAIN_AUDIT.json and prints a per-fixture table.

Usage: cap3_domain_audit.py   (requires REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import json, os, re, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_write_site_dedup as WSD
import oob_cursor_write_verdict as CW

# member-write target through a pointer: `base->field` or `base.field` (the assignment
# LHS `code` is the target expression alone, without the `=`).
MEMBER_WRITE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*[A-Za-z_]\w*\s*$")


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def cursor_sites(cpp):
    """Physical write sites the FROZEN cursor producer recognizes, with robust identity."""
    d = json.load(open(cpp))
    index = WSD.build_index(d)
    recs = [r for r in CW.analyze_operations(cpp)
            if r.get("recognized_operation") == "cursor_write"]
    out = []
    for r in recs:
        for c in d.get("calls", []):
            f = index["funcs"].get(c.get("enclosing_function_id"), {})
            if f.get("name") != r.get("function") or c.get("line") != r.get("line"):
                continue
            tgt = WSD.write_target(c)
            if tgt is None or WSD._root_ident(tgt) != r.get("dest"):
                continue
            ident, node = WSD.physical_write_identity(c, index)
            out.append({"attribution": "cursor_producer", "capability": "oob_cursor_write",
                        "function": f.get("name"), "identity": ident, "node_id": node,
                        "cursor_status": r.get("analysis_status"),
                        "cursor_reason": r.get("reason_code")})
            break
    return out


def member_walk_sites(cpp):
    """CHARACTERIZATION of the cap3-target shape: a `base->field`/`base.field` write whose
    base pointer is advanced (++ / +=) somewhere in the function. Identifies the uncovered
    domain; NOT the capability-3 implementation (that comes after this audit)."""
    d = json.load(open(cpp))
    index = WSD.build_index(d)
    adv = {}
    for c in d.get("calls", []):
        if c.get("name") in ("<operator>.postIncrement", "<operator>.preIncrement",
                             "<operator>.assignmentPlus") and c.get("arguments"):
            r = WSD._root_ident(c["arguments"][0].get("code") or "")
            if r:
                adv.setdefault(c.get("enclosing_function_id"), set()).add(r)
    out = []
    for c in d.get("calls", []):
        if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
            continue
        tgt = (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "")
        m = MEMBER_WRITE.match(tgt)
        if not m:
            continue
        base = m.group(1)
        if base not in adv.get(c.get("enclosing_function_id"), set()):
            continue     # not an advancing-pointer member walk
        f = index["funcs"].get(c.get("enclosing_function_id"), {})
        out.append({"attribution": "direct", "capability": "pointer_walk_member_direct",
                    "function": f.get("name"), "line": c.get("line"),
                    "target": WSD._norm_code(tgt), "base": base, "node_id": c.get("id")})
    return out


# fixture -> the enclosing function name whose sites belong to that fixture
FIXTURES = {"a1_raw_deref": "a1_raw", "a2_offset_deref": "a2_off",
            "a3_struct_member": "a3_struct", "a4_array_backed": "a4_arr",
            "a5_heap_backed": "a5_heap", "a6_png003": "png_handle_PLTE_devsite"}


def main():
    # scan the whole audit DIRECTORY once (so metadata.root is a dir and `file` is relative,
    # enabling the source-column identity; a single .c file as root breaks source lookup).
    cpp = scan(os.path.join(HERE, "cap_controls", "audit"))
    cur_all = cursor_sites(cpp)
    direct_all = WSD.direct_walk_write_sites(cpp)
    member_all = member_walk_sites(cpp)

    audit = {}
    print(f"{'fixture':<18} {'cursor':>7} {'direct*p++':>11} {'overlap':>8} {'member-walk(cap3)':>18}")
    for name, fn in FIXTURES.items():
        cur = [o for o in cur_all if o["function"] == fn]
        direct = [o for o in direct_all if o["function"] == fn]
        member = [o for o in member_all if o["function"] == fn]
        ckeys = {WSD.identity_key(o) for o in cur}
        dkeys = {WSD.identity_key(o) for o in direct}
        overlap = ckeys & dkeys
        cursor_only = ckeys - dkeys
        direct_only = dkeys - ckeys
        audit[name] = {
            "cursor_recognized": len(cur), "direct_pptr_recognized": len(direct),
            "overlap_sites": len(overlap), "cursor_only_sites": len(cursor_only),
            "direct_only_sites": len(direct_only),
            "member_walk_sites_cap3_target": len(member),
            "cursor_reasons": sorted({o["cursor_reason"] for o in cur if o["cursor_reason"]}),
        }
        print(f"{name:<18} {len(cur):>7} {len(direct):>11} {len(overlap):>8} {len(member):>18}")

        # dedup/precedence demonstration on the overlap fixtures
        if overlap:
            merged = WSD.dedup(cur + direct)
            ov = [m for m in merged if len(m["provenance"]) > 1]
            audit[name]["overlap_merges_to_one_op"] = bool(ov)
            audit[name]["overlap_canonical"] = ov[0]["canonical_attribution"] if ov else None
            audit[name]["overlap_provenances"] = sorted(
                {p["attribution"] for p in ov[0]["provenance"]}) if ov else []

    # freeze
    frozen = {
        "FROZEN": True, "model_calls": 0, "frontend": "joern-c2cpg v4.0.608",
        "existing_cursor_domain": "pointer-DEREFERENCE writes on byte buffers with a "
            "resolvable capacity: *p = x, *p++ = x, *(p+n) = x (oob_cursor_write_verdict, "
            "frozen; regexes INCR_WRITE_RE / DEREF_WRITE_RE / OFFSET_DEREF_WRITE_RE). Base "
            "identity chained through p=arr and q=p; static byte arrays and literal-constant "
            "malloc/PORT_Alloc capacity. Does NOT model member writes (p->field), non-byte "
            "element buffers, or call-argument sinks.",
        "new_capability_3_domain": "pointer-walk writes the cursor producer MISSES: a write "
            "through an ADVANCING pointer whose target is a STRUCT/UNION MEMBER (base->field "
            "/ base.field) and/or whose element is a non-byte aggregate (e.g. png_color[]). "
            "The PNG003 png_handle_PLTE palette walk (pal_ptr->red/green/blue = buf[..], "
            "pal_ptr++) is the canonical case (scanner_ok=false in the frozen Magma screen).",
        "overlap_domain": "raw *p++ / array-backed *p++ / heap-backed *p++ on byte buffers "
            "-- recognized by BOTH the cursor producer and the direct pointer-walk primitive. "
            "Capability 3 must NOT emit an independent operation here.",
        "dedup_precedence_rule": "Deduplicate by robust physical-write identity "
            "(cap_write_site_dedup). PRECEDENCE cursor_producer > direct (cap3) > "
            "call_site_summary (cap2). For a site in the overlap domain the FROZEN cursor "
            "producer is canonical; capability 3 enriches its evidence or abstains and is "
            "retained only as PROVENANCE -- it never emits a second operation. Both producer "
            "provenances are preserved on the merged operation. Capability 3 OWNS only the "
            "new_capability_3_domain sites (cursor recognizes nothing there).",
        "per_fixture": audit,
    }
    outp = os.path.join(HERE, "study", "magma", "CAP3_DOMAIN_AUDIT.json")
    json.dump(frozen, open(outp, "w"), indent=2, sort_keys=True)
    print("\nfrozen ->", outp)

    # invariants (make the audit a re-runnable gate)
    pf = audit
    checks = [
        ("overlap: raw *p++ recognized by BOTH cursor and direct",
         pf["a1_raw_deref"]["overlap_sites"] == 1),
        ("overlap: array-backed *p++ recognized by BOTH",
         pf["a4_array_backed"]["overlap_sites"] == 1),
        ("overlap: heap-backed *p++ recognized by BOTH",
         pf["a5_heap_backed"]["overlap_sites"] == 1),
        ("overlap merges to ONE op, cursor canonical, both provenances (a1/a4/a5)",
         all(pf[k]["overlap_merges_to_one_op"] and pf[k]["overlap_canonical"] == "cursor_producer"
             and pf[k]["overlap_provenances"] == ["cursor_producer", "direct"]
             for k in ("a1_raw_deref", "a4_array_backed", "a5_heap_backed"))),
        ("cursor-only: *(p+n) offset-deref recognized by cursor, NOT by direct pptr",
         pf["a2_offset_deref"]["cursor_recognized"] >= 1
         and pf["a2_offset_deref"]["direct_pptr_recognized"] == 0),
        ("cap3-new: struct-member walk MISSED by cursor AND direct pptr",
         pf["a3_struct_member"]["cursor_recognized"] == 0
         and pf["a3_struct_member"]["direct_pptr_recognized"] == 0),
        ("cap3-new: struct-member walk sites present (cap3 target shape)",
         pf["a3_struct_member"]["member_walk_sites_cap3_target"] == 3),
        ("cap3-new: PNG003 palette walk MISSED by cursor (matches scanner_ok=false)",
         pf["a6_png003"]["cursor_recognized"] == 0
         and pf["a6_png003"]["member_walk_sites_cap3_target"] == 3),
    ]
    ok = True
    print()
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c
    print("\nCAP3_DOMAIN_AUDIT=PASS" if ok else "\nCAP3_DOMAIN_AUDIT=FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
