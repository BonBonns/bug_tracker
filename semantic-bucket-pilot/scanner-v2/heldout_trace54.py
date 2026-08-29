#!/usr/bin/env python3
"""Seven-field trace for the 54 held-out sites that reached the producers as MAPPED confirmed
destination-writes (39 missing-capacity + 8 capacity-established + 7 emitted). ANALYSIS ONLY;
reads the cached cpp.json (no re-scan, no scanner change). The key column is EMITTED: whether any
producer emitted a record for the labeled operation (with its reason/route) or SILENTLY DROPPED
it (no record at all)."""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_write_site_dedup as WSD
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
import heldout_run as HR
import cap_addr_indexed as C1, cap_wrapper_summary as C2W, cap_counted_loop_writer as C2L
import cap_decoder_contract as C4

CACHE = os.path.join(HERE, "study", "heldout_diagnosis", "cache")
COPY = {"memcpy": 2, "memmove": 2, "memset": 2, "strncpy": 2, "strlcpy": 2, "strncat": 2,
        "snprintf": 1, "scnprintf": 1, "copy_from_user": 2, "copy_to_user": 2, "bcopy": 2}
MEMB = re.compile(r"^[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*")
INT = re.compile(r"^\s*[+-]?\d+\s*$")


def _norm(s): return re.sub(r"\s+", " ", (s or "").strip())


def emitted_records_at(cpp, fn, L):
    """Every producer record emitted for the labeled op (function fn, line L), with reason."""
    recs = []
    for pname, m in HR.PROD.items():
        for r in m.analyze_operations(cpp):
            if r.get("line") == L and r.get("function") == fn:
                recs.append((pname, r.get("reason_code"), r.get("recommended_route")))
    for r in C1.analyze_addr_indexed(cpp):
        if r.get("line") == L and r.get("function") == fn:
            recs.append(("cap1", r.get("reason"), r.get("route")))
    ops, _ = C2W.analyze_wrapper_calls(cpp)
    for r in ops:
        if r.get("line") == L and r.get("function") == fn:
            recs.append(("cap2_wrapper", r.get("reason"), r.get("route")))
    cl = C2L.analyze_counted_writers(cpp); cl = cl[0] if isinstance(cl, tuple) else cl
    for r in cl:
        if r.get("line") == L and r.get("function") == fn:
            recs.append(("cap2_loop", r.get("reason"), r.get("route")))
    for r in C4.analyze_decoder_calls(cpp):
        if r.get("line") == L and r.get("function") == fn:
            recs.append(("cap4", r.get("reason"), r.get("route")))
    return recs


def trace_site(row):
    cpp = os.path.join(CACHE, row["site_id"] + ".cpp.json")
    if not os.path.exists(cpp):
        return None
    cj = json.load(open(cpp)); index = WSD.build_index(cj)
    stack = v2.compute_stack_fixed_array_extents(cj); heap = AE.compute_allocation_extents(cj)
    L = row.get("labeled_line"); dest = row.get("write_dest") or ""
    base = WSD._root_ident(dest)
    calls_at_L = [c for c in cj.get("calls", []) if c.get("line") == L]
    node = next((c for c in calls_at_L if base and base in (c.get("code") or "")), None)
    fid = node.get("enclosing_function_id") if node else None
    fn = index["funcs"].get(fid, {}).get("name") if fid else row.get("func_name")
    pf = row.get("producer_facts", {})
    # 1 target identity
    decl_kind = pf.get("dest_decl_kind")
    # 2 write form
    sink = next((c["name"] for c in calls_at_L if c.get("name") in COPY), None)
    form = ("copy_sink:" + sink if sink else row.get("write_shape"))
    # 3 destination identity established
    dest_id = decl_kind not in (None, "unresolved")
    # 4 capacity established
    cap = pf.get("dest_extent_established")
    # 5 write length established (copy sinks: the size arg literal/symbolic; else n/a)
    length = "n/a"
    if sink:
        sc = next((c for c in calls_at_L if c.get("name") == sink), None)
        wi = COPY[sink]
        args = sorted(sc.get("arguments", []), key=lambda a: a.get("index", 0)) if sc else []
        if wi < len(args):
            lc = _norm(args[wi].get("code"))
            length = "literal:" + lc if INT.match(lc) else "symbolic:" + lc[:24]
    # 6 relationship established = capacity AND length both concrete
    rel = bool(cap) and isinstance(length, str) and length.startswith("literal")
    # 7 emitted
    emitted = emitted_records_at(cpp, fn, L)
    return {"site": row.get("func_name"), "vuln": row["is_vulnerable"], "kind": row.get("write_kind"),
            "target": "%s(%s)" % (dest, decl_kind), "form": form,
            "dest_identity_established": dest_id, "capacity_established": cap or False,
            "write_length_established": length, "relationship_established": rel,
            "emitted": emitted if emitted else "SILENT_DROP"}


def main():
    rows = [json.loads(l) for l in open(os.path.join(HERE, "study", "heldout_diagnosis",
                                                     "raw_diagnosis.jsonl"))]
    dw = lambda r: r.get("label_class") == "destination_write"
    mapped = [r for r in rows if r.get("mapped") and dw(r)]
    def gate(r): return r.get("producer_facts", {}).get("failing_gate", "")
    cap_missing = [r for r in mapped if gate(r).startswith("destination_capacity_not_established")]
    cap_ok = [r for r in mapped if gate(r).startswith("capacity_established_but_relation")]
    emitted = [r for r in mapped if r.get("recognized")]
    out = {"missing_capacity": [trace_site(r) for r in cap_missing],
           "capacity_established_no_relation": [trace_site(r) for r in cap_ok],
           "emitted": [trace_site(r) for r in emitted]}
    for k in out:
        out[k] = [t for t in out[k] if t]
    json.dump(out, open(os.path.join(HERE, "study", "heldout_diagnosis", "trace54.json"), "w"),
              indent=1)
    # summaries
    for group, ts in out.items():
        drops = sum(1 for t in ts if t["emitted"] == "SILENT_DROP")
        print(f"\n### {group} (n={len(ts)}): SILENT_DROP={drops}  emitted-a-record={len(ts)-drops}")
        for t in ts[:60]:
            e = "SILENT_DROP" if t["emitted"] == "SILENT_DROP" else ",".join(
                "%s/%s" % (p, rc) for p, rc, _ in t["emitted"])
            print(f"   {t['site'][:22]:22} form={str(t['form'])[:16]:16} destID={int(t['dest_identity_established'])} "
                  f"cap={str(t['capacity_established']):18} len={str(t['write_length_established'])[:14]:14} "
                  f"rel={int(t['relationship_established'])} -> {e}")


if __name__ == "__main__":
    main()
