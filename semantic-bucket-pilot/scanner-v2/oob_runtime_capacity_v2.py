#!/usr/bin/env python3
"""Capability 1 (v2): consume normalized stack fixed-array capacity, AND adjudicate
V1's `delegated_to_stack_capacity_v2` handoffs for non-bare (struct-member array,
address-of-scalar, array+offset) destinations.

Frozen v1 is NOT modified. This v2 producer runs v1's analysis and refines two
distinct populations, through the SAME arithmetic (`compare()` -- one unit-aware
implementation, never a second copy):

  1. Bare destinations V1 abstained on with `required_evidence_absent`: bind a
     `stack_fixed_array` extent to the sink (dest arg `value_ref.kind == LOCAL`)
     and re-classify.
  2. Non-bare destinations V1 rerouted with `delegated_to_stack_capacity_v2`: V1
     already CPG-resolved the destination's structure (element type, element
     count, offset, raw width expression) via reference-target resolution; V2
     does not re-walk the CPG, it only runs the resolved structure through
     `compare()`. V1 NEVER computes or finalizes this comparison itself -- see
     `oob_runtime_capacity_verdict.diagnose_nonbare_destination`.

Boundaries (all enforced, both populations):

  * new extent provenance `stack_fixed_array` / `stack_or_scalar_object`, keyed
    by CPG declaration identity (bare: DECLARATION NODE id; non-bare: V1's own
    reference-target resolution) -- never by variable name;
  * accept only fixed, COMPILE-TIME sizes: `T[N]` with literal N, or a modeled
    scalar (element_count=1); exclude VLAs, multidimensional arrays, pointer
    params/members, and unresolved destinations;
  * preserve element type; element counts are compared as counts, never
    conflated with byte counts (`compare()`'s BYTE_TYPES / k_sizeof handling is
    the ONLY place a byte-vs-element or sizeof(T) relationship is decided --
    never assumed elsewhere, never an ABI byte count for `&scalar`);
  * a symbolic or negative offset (non-bare) or symbolic write length (either
    population) -> relationship_unresolved / identity_ambiguous, never guessed
    safe or clamped to 0;
  * stack/object extents NEVER override or merge with heap extents -- v2 only
    touches ops V1 itself abstained/rerouted on for a non-heap reason;
  * deterministic_complete requires the full type-matched comparison k <= N at
    the resolved offset; a literal k > N (or an offset itself past the object)
    is a distinguished `proven_oversized` finding, never called safe.

Heap-allocation behavior and every other V1 reason (identity-ambiguous,
unknown-allocator-contract, free-dominates-sink, ...) are unchanged (those
records pass through untouched).
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


def _finalize_disposition(r2, disp, route, prop):
    """Map a compare() disposition to the final output fields. The ONE place that
    decides what deterministic_complete / relationship_unresolved / proven_oversized
    MEAN in terms of analysis_status/reason_code -- shared by the bare-destination
    stack-array path and the delegated (non-bare) stack/object path, so the two
    populations can never drift into inconsistent output shapes for the same
    disposition."""
    r2.pop("candidate_class", None)   # only meaningful on the pre-adjudication rerouted record
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
    return r2


def _adjudicate_delegated(r):
    """Finalize a V1 `delegated_to_stack_capacity_v2` handoff -- a non-bare
    destination (struct-member array, address-of-scalar, or array+offset) whose
    CPG structure V1 already resolved but never adjudicated. The ONLY arithmetic
    here is `compare()`, the SAME function the bare-destination path uses: one
    unit-aware implementation for both, never a second, independently-maintained
    copy (the drift risk the delegation itself exists to avoid).

    A symbolic or non-numeric offset means pointer validity into the object is
    unresolved -- abstain, exactly like the bare-destination path abstains on a
    symbolic width, and exactly like cap_addr_indexed.py abstains on a symbolic
    `&(base[index])` offset rather than guessing. A negative offset means the
    pointer is before the object (never treat capacity+|offset| as available,
    same posture as cap_addr_indexed.py's own negative-offset abstention). An
    offset at or past the object's own extent is a distinguished proven-oversized
    finding -- the destination pointer itself is out of bounds, before the write
    width is even considered."""
    facts = (r.get("established_facts") or [{}])[0]
    elem_type = facts.get("element_type")
    elem_count = facts.get("element_count")
    off = facts.get("offset_elements")
    width = facts.get("width_expr")
    r2 = dict(r)
    r2["_v2_evidence"] = {"provenance": "stack_or_scalar_object", "element_type": elem_type,
                          "element_count": elem_count, "offset_elements": off, "width": width}

    if not isinstance(elem_count, int) or off == "sym" or not isinstance(off, int):
        # Symbolic offset: pointer validity into the object is unresolved, exactly
        # the same "relationship_unresolved" disposition compare() itself returns
        # for a symbolic WIDTH -- route through the SAME finalizer so the two
        # symbolic cases (offset vs. width) land on the identical, consistent
        # output shape (open_candidate, never abstained -- relationship_unresolved
        # is a candidate-review bucket everywhere else in this module).
        return _finalize_disposition(r2, "relationship_unresolved",
                                     "semantic_relationship_review",
                                     "write_length_within_capacity")

    if off < 0:
        r2.pop("candidate_class", None)
        r2["analysis_status"] = "abstained"
        r2.update(reason_code="destination_identity_ambiguous",
                  primary_reason_code="destination_identity_ambiguous",
                  all_reason_codes=["destination_identity_ambiguous"],
                  uncertainty_bucket="identity_ambiguous",
                  recommended_route="additional_evidence_required",
                  unresolved_property="destination_object_identity", llm_eligible=False)
        r2["_v2_disposition"] = "identity_ambiguous"
        r2["_v2_route"] = "additional_evidence_required"
        return r2

    remaining = elem_count - off
    if remaining < 0:
        r2.pop("candidate_class", None)
        r2["analysis_status"] = "open_candidate"
        r2.update(reason_code="write_exceeds_stack_capacity",
                  primary_reason_code="write_exceeds_stack_capacity",
                  all_reason_codes=["write_exceeds_stack_capacity"],
                  uncertainty_bucket="relationship_unresolved",
                  recommended_route="range_arithmetic_review", llm_eligible=False,
                  proven_oversized=True)
        r2["_v2_disposition"] = "proven_oversized"
        r2["_v2_route"] = "range_arithmetic_review"
        return r2

    disp, route, prop, note = compare({"element_count": remaining, "element_type": elem_type}, width)
    r2["_v2_evidence"]["remaining_capacity"] = remaining
    r2["_v2_evidence"]["established_property"] = prop
    r2["_v2_evidence"]["note"] = note
    return _finalize_disposition(r2, disp, route, prop)


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
        status = r.get("analysis_status")

        if status == "rerouted" and reason == "delegated_to_stack_capacity_v2":
            before = {"status": status, "reason": reason, "route": r.get("recommended_route")}
            r2 = _adjudicate_delegated(r)
            transitions.append({"function": r.get("function"), "line": r.get("line"), "dest": r.get("dest"),
                                "source": r.get("_source_label"), "from": before,
                                "to_status": r2["analysis_status"], "disposition": r2["_v2_disposition"],
                                "route": r2["_v2_route"], "evidence": r2["_v2_evidence"]})
            out.append(r2)
            continue

        if not (status == "abstained" and reason == "required_evidence_absent"):
            out.append(r)   # heap / other / any other V1 reason -> unchanged
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
        before = {"status": status, "reason": reason, "route": r.get("recommended_route")}
        r2 = dict(r)
        r2["_v2_evidence"] = {"provenance": "stack_fixed_array", "decl_node": ext["decl_node"],
                              "element_type": ext["element_type"], "element_count": ext["element_count"],
                              "capacity_expr": ext["capacity_expr"], "width": width,
                              "established_property": prop, "note": note}
        _finalize_disposition(r2, disp, route, prop)
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
