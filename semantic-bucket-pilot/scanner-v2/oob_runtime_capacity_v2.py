#!/usr/bin/env python3
"""Capability 1 (v2): consume normalized stack fixed-array capacity.

Frozen v1 is NOT modified. This v2 producer runs v1's analysis and, ONLY for
operations v1 abstained on with `required_evidence_absent`, tries to bind a
`stack_fixed_array` extent to the sink and re-classify. Boundaries (all enforced):

  * new extent provenance `stack_fixed_array`, keyed by (function id, DECLARATION
    NODE id) -- never (function, variable name);
  * the sink destination reference must resolve UNIQUELY to that declaration
    (dest arg `value_ref.kind == LOCAL` whose id is a single fixed-array local);
  * accept only fixed, COMPILE-TIME array capacities `T[N]` with literal N;
  * exclude VLAs (non-literal N), multidimensional arrays, member accesses,
    aliases, casts, pointer params, and unresolved/offset destinations (their
    dest arg resolves to CALL/PARAM/ANY, not a LOCAL array decl);
  * preserve element type; element counts are compared as counts, never
    conflated with byte counts;
  * stack extents NEVER override or merge with heap extents -- v2 only touches
    ops that had NO heap extent (v1 abstained);
  * symbolic write length -> relationship_unresolved (never guessed safe);
  * deterministic_complete requires the full type-matched, offset-0 comparison
    k <= N; a literal k > N is a distinguished `proven_oversized` finding, never
    called safe.

Heap-allocation behavior is unchanged (those records pass through untouched).
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)

BYTE_TYPES = {"char", "unsigned char", "signed char", "uint8_t", "int8_t",
              "PRUint8", "PRInt8", "JOCTET", "CK_BYTE"}
ARR1 = re.compile(r"^\s*([A-Za-z_][\w ]*?)\s*\[\s*(\d+)\s*\]\s*$")   # single-dim, literal N
ARRX = re.compile(r"\[")  # any bracket (to detect multidim)


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


V1 = _load("oob_runtime_capacity_verdict")
AE = _load("allocation_extent")


def compute_stack_fixed_array_extents(d):
    """{(function_id, decl_node_id): extent} for single-dimension, literal-sized
    local arrays. Excludes VLAs (non-literal N) and multidimensional arrays."""
    out = {}
    for l in d.get("locals", []):
        t = (l.get("type_full_name") or "").strip()
        code = (l.get("code") or "").strip()
        if t.count("[") > 1 or code.count("[") > 1:
            continue  # multidimensional -> excluded
        m = ARR1.match(t)
        if not m:
            continue  # not `T[<literal>]` -> excludes pointers, VLAs, non-arrays
        elem_type, n = m.group(1).strip(), int(m.group(2))
        nid = l.get("id")
        out[(l.get("method_id"), nid)] = {
            "provenance": "stack_fixed_array",
            "decl_node": nid, "function_id": l.get("method_id"),
            "element_type": elem_type, "element_count": n,
            "capacity_expr": f"{n}*sizeof({elem_type})",
            "decl_line": l.get("line"), "lifetime": "function_scope",
        }
    return out


def resolve_sink_decl(call, dest_index):
    """Return (decl_node_id, 'ok') if the dest argument resolves UNIQUELY to a
    LOCAL declaration node; else (None, reason). Offsets/casts/aliases/params
    do not have value_ref.kind == LOCAL and are excluded here."""
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if dest_index >= len(args):
        return None, "no_dest_arg"
    da = args[dest_index]
    vr = da.get("value_ref") or {}
    if vr.get("kind") != "LOCAL":
        return None, f"dest_not_local:{vr.get('kind')}"   # CALL(at+4)/PARAM/ANY -> excluded
    return vr.get("id"), "ok"


_WIDTH_KSIZEOF = re.compile(r"^\s*(\d+)\s*\*\s*sizeof\s*\(\s*([\w ]+?)\s*\)\s*$")
_WIDTH_SIZEOFK = re.compile(r"^\s*sizeof\s*\(\s*([\w ]+?)\s*\)\s*\*\s*(\d+)\s*$")
_WIDTH_SIZEOF1 = re.compile(r"^\s*sizeof\s*\(\s*([\w ]+?)\s*\)\s*$")
_WIDTH_LIT = re.compile(r"^\s*(\d+)\s*$")


def parse_width(width):
    """(kind, k, wtype). kind in {k_sizeof, literal_bytes, symbolic, unknown}."""
    if width is None:
        return "symbolic", None, None   # count-based / no width -> relationship
    w = str(width).strip()
    m = _WIDTH_KSIZEOF.match(w) or _WIDTH_SIZEOFK.match(w)
    if m:
        g = m.groups()
        k = int(g[0]) if g[0].isdigit() else int(g[1])
        wt = g[1] if g[0].isdigit() else g[0]
        return "k_sizeof", k, wt.strip()
    if _WIDTH_SIZEOF1.match(w):
        return "k_sizeof", 1, _WIDTH_SIZEOF1.match(w).group(1).strip()
    if _WIDTH_LIT.match(w):
        return "literal_bytes", int(w), None
    return "symbolic", None, None


# reason-specific routing for an unresolved relationship
_COUNT_SIZEOF = re.compile(r"^\s*([A-Za-z_][\w.\->\[\] ]*?)\s*\*\s*sizeof\s*\(\s*([\w ]+?)\s*\)\s*$")


def _relationship_route(width, T):
    """Route an unresolved capacity relationship by WHAT is missing:
      range_arithmetic_review  -- a numeric bound on a count is missing
      semantic_relationship_review -- the code meaning of the length is unclear
      additional_evidence_required -- no length expression at all (count-based)."""
    if width is None:
        return "additional_evidence_required", "numeric_count_bound", "no width expression (count-based)"
    m = _COUNT_SIZEOF.match(str(width))
    if m and m.group(2).strip() == T:
        return ("range_arithmetic_review", "numeric_count_bound",
                f"length is count*sizeof({T}); needs a numeric bound count<=N")
    if m:  # count*sizeof(other) -- type meaning must be reconciled first
        return ("semantic_relationship_review", "length_meaning",
                f"length uses sizeof({m.group(2).strip()}) != element {T}; meaning unresolved")
    return ("semantic_relationship_review", "length_meaning",
            "length expression meaning unresolved")


def compare(ext, width):
    """Type-matched, offset-0 comparison of the WRITE LENGTH against the
    DESTINATION capacity only. Offset is 0 by construction (sink resolved to a
    bare LOCAL array decl). Returns (disposition, route, unresolved_property,
    note). This establishes ONLY write_length_within_destination_capacity; it
    says nothing about source length, pointer validity, or lifetime."""
    N, T = ext["element_count"], ext["element_type"]
    kind, k, wt = parse_width(width)
    if kind == "symbolic":
        route, prop, note = _relationship_route(width, T)
        return "relationship_unresolved", route, prop, "capacity bound; " + note
    if kind == "k_sizeof":
        if wt != T:
            return ("relationship_unresolved", "semantic_relationship_review", "length_meaning",
                    f"sizeof({wt}) != element type {T} (not simplified)")
        if k <= N:
            return ("deterministic_complete", None, "write_length_within_destination_capacity",
                    f"{k}<={N} elems, offset 0, type-matched (sizeof cancels)")
        return ("proven_oversized", "range_arithmetic_review", "write_length_within_destination_capacity",
                f"{k}>{N} elems into {T}[{N}] -- provable destination overflow")
    if kind == "literal_bytes":
        if T in BYTE_TYPES:      # sizeof(T) == 1 -> bytes == elements
            if k <= N:
                return ("deterministic_complete", None, "write_length_within_destination_capacity",
                        f"{k} bytes <= {N} (byte array), offset 0")
            return ("proven_oversized", "range_arithmetic_review", "write_length_within_destination_capacity",
                    f"{k} bytes > {N} (byte array)")
        return ("relationship_unresolved", "range_arithmetic_review", "numeric_count_bound",
                "literal byte count vs non-byte array (needs ABI size)")
    return ("relationship_unresolved", "semantic_relationship_review", "length_meaning",
            "capacity bound; comparison not established")


def _recognized_calls(d):
    """(function_id, line) -> (call, dest_index, width_code) for the memcpy-family
    contracts v1 recognizes."""
    idx = {}
    for c in d.get("calls", []):
        name = c.get("name") or ""
        contract = V1.CALLEE_CONTRACTS.get(name) if hasattr(V1, "CALLEE_CONTRACTS") else None
        if contract is None:
            continue
        di = contract.get("dest_arg")
        wi = contract.get("width_arg")
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if di is None or wi is None or wi >= len(args):
            continue
        idx[(c.get("enclosing_function_id"), c.get("line"))] = (c, di, (args[wi].get("code") or "").strip())
    return idx


def analyze_operations_v2(prefix):
    _v1, out, transitions = _analyze_both(prefix)
    return out, transitions


def analyze_operations_v1_and_v2(prefix):
    """Return (v1_runtime_records, v2_runtime_records, transitions) from a SINGLE
    V1.analyze_operations pass — the runtime producer is the slow one, so callers
    needing both populations (e.g. the transition matrix) must not run it twice."""
    return _analyze_both(prefix)


def _analyze_both(prefix):
    d = json.load(open(prefix))
    v1_records = [dict(r) for r in V1.analyze_operations(prefix)]
    v1_frozen = [dict(r) for r in v1_records]
    stack_ext = compute_stack_fixed_array_extents(d)
    calls = _recognized_calls(d)
    fn_ids = {}
    for f in d.get("functions", []):
        fn_ids.setdefault(f.get("full_name"), set()).add(f.get("id"))

    out, transitions = [], []
    for r in v1_records:
        reason = r.get("primary_reason_code") or r.get("reason_code")
        if not (r.get("analysis_status") == "abstained" and reason == "required_evidence_absent"):
            out.append(r)   # heap / other -> unchanged
            continue
        # locate the call for this op and resolve the sink to a declaration node
        call = None
        for fid in fn_ids.get(r.get("function"), set()):
            if (fid, r.get("line")) in calls:
                call, di, width = calls[(fid, r.get("line"))]
                break
        if call is None:
            out.append(r)
            continue
        decl_id, why = resolve_sink_decl(call, di)
        key = (call.get("enclosing_function_id"), decl_id)
        ext = stack_ext.get(key) if decl_id is not None else None
        if ext is None:
            r["_v2_note"] = f"no stack extent bound ({why if decl_id is None else 'decl not a fixed array'})"
            out.append(r)
            continue
        disp, route, prop, note = compare(ext, width)
        before = {"status": r["analysis_status"], "reason": reason,
                  "route": r.get("recommended_route")}
        r2 = dict(r)
        r2["_v2_evidence"] = {"provenance": "stack_fixed_array", "decl_node": ext["decl_node"],
                              "element_type": ext["element_type"], "element_count": ext["element_count"],
                              "capacity_expr": ext["capacity_expr"], "width": width,
                              "established_property": prop, "note": note}
        if disp == "deterministic_complete":
            for k in ("reason_code", "primary_reason_code", "all_reason_codes", "uncertainty_bucket",
                      "recommended_route", "unresolved_property", "llm_eligible"):
                r2.pop(k, None)
            # deterministic ONLY for the destination-capacity property; NOT a claim
            # that the memcpy/operation is safe (source length, pointer validity,
            # lifetime are separate, unaddressed properties).
            r2["analysis_status"] = "deterministic_complete"
            r2["capacity_basis"] = "stack_fixed_array"
            r2["establishment_status"] = "ESTABLISHED"
            r2["established_property"] = "write_length_within_destination_capacity"
            r2["unaddressed_properties"] = ["source_length_sufficiency", "pointer_validity", "lifetime"]
        elif disp == "relationship_unresolved":
            r2["analysis_status"] = "open_candidate"
            r2["reason_code"] = r2["primary_reason_code"] = "capacity_relation_not_established"
            r2["all_reason_codes"] = ["capacity_relation_not_established"]
            r2["uncertainty_bucket"] = "relationship_unresolved"
            r2["recommended_route"] = route
            r2["unresolved_property"] = prop
            r2["llm_eligible"] = (route == "semantic_relationship_review")
        elif disp == "proven_oversized":
            r2["analysis_status"] = "open_candidate"
            r2["reason_code"] = r2["primary_reason_code"] = "write_exceeds_stack_capacity"
            r2["all_reason_codes"] = ["write_exceeds_stack_capacity"]
            r2["uncertainty_bucket"] = "relationship_unresolved"
            r2["recommended_route"] = route
            r2["llm_eligible"] = False
            r2["proven_oversized"] = True
        r2["_v2_disposition"] = disp
        r2["_v2_route"] = route
        transitions.append({"function": r.get("function"), "line": r.get("line"), "dest": r.get("dest"),
                            "source": r.get("_source_label"), "from": before, "to_status": r2["analysis_status"],
                            "disposition": disp, "route": route, "established_property": prop,
                            "evidence": r2["_v2_evidence"]})
        out.append(r2)
    return v1_frozen, out, transitions


if __name__ == "__main__":
    for p in sys.argv[1:]:
        recs, tr = analyze_operations_v2(p)
        print(f"{p}: {len(tr)} stack-capacity transitions")
        from collections import Counter
        print("  by disposition:", dict(Counter(t["disposition"] for t in tr)))
