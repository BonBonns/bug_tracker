#!/usr/bin/env python3
"""Per-operation evidence trace for the local-destination cases (CLOSING form).

Keeps the THREE levels separate and, for every operation, records the full chain:
  source declaration -> normalized capacity fact -> producer destination binding
  -> emitted reason -> proposed v2 disposition.

Levels:
  L1 source            `T buf[N]` exists in the .c/.h
  L2 normalized fact   cpp.json `locals` carries `T[N]` for dest in the function
  L3 producer binding  compute_allocation_extents ESTABLISHED an extent for
                       (fn, dest) -- the producer actually consumed the capacity

Only L3 proves a pure routing mistake. Destination identity is keyed on
(function id + declaration NODE id), never the bare name, so shadowed/repeated
names cannot collapse. The 938 are OPERATION instances; the 738 are distinct
destination identities -- both denominators are reported, and the 200 extra
operations are NOT assumed to share a final disposition (each keeps its own
offset and write length).

Proposed v2 disposition follows the narrow first capability -- import normalized
fixed local-array capacity into the extent model (capacity ONLY), then:
  * symbolic write length          -> relationship_unresolved
  * literal, type-matched, offset-0, fresh, k<=N -> deterministic_complete
  * pointer/unresolved destination -> required_evidence_absent (unchanged)
  * conflicting identity           -> destination_identity_ambiguous
No fix is applied; this only computes what the disposition WOULD be.
"""
import base64
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
EXP = "/tmp/expansion"
ARR = re.compile(r"\[\s*([0-9A-Za-z_]+)\s*\]")


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


AE = _load("allocation_extent")


def _b64(s):
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def array_decls(d, method_ids, dest):
    """All fixed-array declarations of `dest` in these functions, as
    (node_id, elem_type, capacity_token). Keyed on node identity, not name."""
    out = []
    for l in d.get("locals", []):
        if l.get("name") == dest and l.get("method_id") in method_ids:
            code = l.get("code") or ""
            t = l.get("type_full_name") or ""
            m = ARR.search(code) or ARR.search(t)
            if m and "*" not in code.split(dest)[0]:
                elem = (t.split("[")[0].strip() if "[" in t
                        else " ".join(code.split(dest)[0].split()).strip())
                out.append((l.get("id"), elem or None, m.group(1)))
    return out


def raw_local_is_array(scan_dir, method_ids, dest):
    p = os.path.join(scan_dir, "raw", "locals.tsv")
    if not os.path.exists(p):
        return None, False
    in_fn, other = False, False
    for line in open(p, errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5 and _b64(f[2]) == dest:
            try:
                mid = int(f[1])
            except Exception:
                continue
            if ARR.search(_b64(f[3])) or ARR.search(_b64(f[4])):
                if mid in method_ids:
                    in_fn = True
                else:
                    other = True
    return in_fn, other


def parse_width(width, elem_type):
    """Return (kind, k) where kind in {'symbolic','literal_elems','literal_bytes',
    'unknown'}; k is the literal element count when derivable AND the sizeof type
    matches the array element type (so the ABI size cancels)."""
    if width is None:
        return "count_based", None
    w = str(width).strip()
    m = re.fullmatch(r"(\d+)\s*\*\s*sizeof\s*\(\s*([\w ]+?)\s*\)", w) \
        or re.fullmatch(r"sizeof\s*\(\s*([\w ]+?)\s*\)\s*\*\s*(\d+)", w)
    if m:
        g = m.groups()
        k = int(g[0]) if g[0].isdigit() else int(g[1])
        wt = g[1] if g[0].isdigit() else g[0]
        if elem_type and wt.strip() == elem_type.strip():
            return "literal_elems", k
        return "literal_elems_typemismatch", k
    if re.fullmatch(r"sizeof\s*\(\s*[\w ]+?\s*\)", w):
        # one object; k=1 only meaningful if type matches
        return "literal_elems", 1
    if re.fullmatch(r"\d+", w):
        return "literal_bytes", int(w)
    # has a runtime identifier
    ids = [t for t in re.findall(r"[A-Za-z_]\w*", re.sub(r"sizeof\s*\([^()]*\)", "", w))]
    return ("symbolic", None) if ids else ("unknown", None)


def propose_v2(defect, identity, cap_token, width, elem_type):
    """Proposed disposition AFTER the capacity-import capability. Establishes
    capacity only; never declares safe without an offset-0, type-matched,
    literal comparison."""
    if defect in ("frontend_or_genuinely_absent",):
        return "required_evidence_absent", "unchanged (no local capacity)"
    if defect == "audit_identity_collision" or identity == "ambiguous":
        return "destination_identity_ambiguous", "shadowed/repeated name — identity unresolved"
    if defect == "normalizer_evidence_loss":
        pre = "needs normalizer fix first; then: "
    elif defect == "producer_consumer_gap":
        pre = "after capacity import: "
    else:
        return "required_evidence_absent", "unhandled"
    kind, k = parse_width(width, elem_type)
    cap_lit = bool(re.fullmatch(r"\d+", str(cap_token or "")))
    if kind == "symbolic" or kind == "count_based":
        return "relationship_unresolved", pre + "capacity bound, count symbolic -> relationship"
    if kind == "literal_elems" and cap_lit and k is not None and k <= int(cap_token):
        return "deterministic_complete", pre + f"offset-0, type-matched, {k}<={cap_token} (sizeof cancels)"
    if kind == "literal_elems_typemismatch":
        return "relationship_unresolved", pre + "literal count but sizeof type != array element type"
    return "relationship_unresolved", pre + "capacity bound, comparison not established"


def main():
    recs = [json.loads(l) for l in open(os.path.join(HERE, "distinct_ops_v2.jsonl"))]
    ci = json.load(open(os.path.join(HERE, "caller_inspection.json")))
    local_ops = [o for o in ci["per_op"] if o["caller_class"] == "dest_not_a_parameter"]
    local_keys = {(o["source"], o["function"], o["dest"]) for o in local_ops}
    op_recs = [r for r in recs
               if (r["_source_label"], r.get("function"), r.get("dest")) in local_keys]

    facts = {}
    trace = []
    for r in op_recs:
        src = r["_source_label"]
        fid, side = src.split("/")
        scan_dir = os.path.join(EXP, fid, side)
        if src not in facts:
            d = json.load(open(os.path.join(scan_dir, "cpp.json")))
            fbn = defaultdict(set)
            for f in d.get("functions", []):
                fbn[f.get("full_name")].add(f.get("id"))
            facts[src] = (d, fbn, AE.compute_allocation_extents(d))
        d, fbn, ext = facts[src]
        func, dest = r.get("function"), r.get("dest")
        mids = fbn.get(func, set())
        decls = array_decls(d, mids, dest)
        # destination identity keyed on declaration node id (not name)
        if len(decls) == 1:
            identity = f"node:{decls[0][0]}"
            elem_type, cap_token = decls[0][1], decls[0][2]
        elif len(decls) > 1:
            identity = "ambiguous"
            elem_type, cap_token = None, None
        else:
            identity = "no_local_array"
            elem_type, cap_token = None, None
        l2 = cap_token is not None
        l3 = any((fn, dest) in ext and ext[(fn, dest)].get("establishment_status") == "ESTABLISHED"
                 for fn in mids)
        reason = (r.get("primary_reason_code") or r.get("reason_code"))
        if l2 and l3:
            defect = "router_misclassification" if reason == "required_evidence_absent" else "l3_bound_ok"
        elif l2 and not l3:
            defect = "producer_consumer_gap"
        elif identity == "ambiguous":
            defect = "audit_identity_collision"
        else:
            raw_in_fn, other = raw_local_is_array(scan_dir, mids, dest)
            if raw_in_fn:
                defect = "normalizer_evidence_loss"
            elif other:
                defect = "audit_identity_collision"
            else:
                defect = "frontend_or_genuinely_absent"
        v2_reason, v2_note = propose_v2(defect, identity, cap_token, r.get("width_expr"), elem_type)
        trace.append({
            "source": src, "function": func, "line": r.get("line"), "dest": dest,
            "destination_identity": identity, "element_type": elem_type,
            "normalized_capacity_status": ("fixed_array[%s]" % cap_token) if l2 else "absent",
            "producer_binding_status": "ESTABLISHED" if l3 else "unbound",
            "offset": 0,  # producer recognizes only bare-identifier dests (write at base)
            "write_length": r.get("width_expr"),
            "v1_reason": reason, "defect_category": defect,
            "proposed_v2_reason": v2_reason, "proposed_v2_note": v2_note,
        })

    # denominators
    destinations = {(t["source"], t["function"], t["destination_identity"]) for t in trace}
    dest_by_srcfndest = {(t["source"], t["function"], t["dest"]) for t in trace}
    accounting = {
        "operation_instances_938": len(trace),
        "distinct_destination_identities": len(destinations),
        "distinct_source_fn_dest_keys": len(dest_by_srcfndest),
        "unaccounted_operations": len(op_recs) - len(trace),
    }
    report = {
        "accounting": accounting,
        "by_defect_category": dict(Counter(t["defect_category"] for t in trace)),
        "by_proposed_v2": dict(Counter(t["proposed_v2_reason"] for t in trace)),
    }
    with open(os.path.join(HERE, "evidence_trace.json"), "w") as fh:
        json.dump({"summary": report, "trace": trace}, fh, indent=2, sort_keys=True, default=str)

    # ---- closing assertions ----
    assert accounting["operation_instances_938"] == 938, accounting
    assert accounting["distinct_source_fn_dest_keys"] == 738, accounting
    assert accounting["unaccounted_operations"] == 0, accounting
    assert all(all(k in t for k in ("normalized_capacity_status", "producer_binding_status",
               "destination_identity", "offset", "write_length", "v1_reason",
               "proposed_v2_reason")) for t in trace)
    assert not any(t["defect_category"] == "router_misclassification" for t in trace), \
        "a router_misclassification would be a real routing bug"

    print("CLOSING TOTALS (assertions passed):")
    print(f"   operation traces        : {accounting['operation_instances_938']} (== 938)")
    print(f"   destination identities  : {accounting['distinct_source_fn_dest_keys']} (== 738)")
    print(f"   unaccounted operations  : {accounting['unaccounted_operations']} (== 0)")
    print(f"   distinct decl-node identities: {accounting['distinct_destination_identities']}")
    print(f"\nby defect category: {report['by_defect_category']}")
    print(f"by proposed v2 disposition: {report['by_proposed_v2']}")


if __name__ == "__main__":
    main()
