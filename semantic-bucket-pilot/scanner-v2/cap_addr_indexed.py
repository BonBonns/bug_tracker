#!/usr/bin/env python3
"""Capability 1 — address-of indexed destination `&(base[index])`  (NO model calls).

A GENERAL evidence model for one destination REPRESENTATION SHAPE, not a bug-specific
alias. It is ADDITIVE: it only fires on dest args of the form `&(base[index])` (which the
frozen scanner excludes as `dest_not_local`), so it cannot move any existing verdict. For a
recognized op it binds:
  * base identity (resolved to a real declaration / extent, never a name match),
  * offset (the index expression; numeric or symbolic),
  * element width (sizeof(element of base), kept symbolic),
  * REMAINING capacity = capacity(base) - offset,
and routes on the write length vs remaining capacity.

Capacity of the base is taken ONLY from independently-established evidence: a local
fixed-array declaration, or an ESTABLISHED heap allocation extent. Struct-field / realloc /
parameter bases are left UNRESOLVED (never assumed) -> additional_evidence_required.
Ambiguous base (shadowed decls) -> abstain (conflicting).

PHYSICAL-WRITE IDENTITY (added; previously absent). Every prior capability that shares
domain with another (cap2/cap3) is integrated with `cap_write_site_dedup`'s robust
cross-run physical-write identity so an accidentally-shared physical write collapses to
one operation instead of being silently double-counted in any pooled report
(`CAP2_CAP3_BOUNDARY_FROZEN.md`). Capability 1 was the one recognizer with NO identity at
all -- a real gap, not by design: `&(base[index])` passed to a copy-family call is exactly
`write_dest_arg`'s existing copy-sink branch (already correct for this shape; it descends
through `<operator>.addressOf` -> `<operator>.indirectIndexAccess` -> the base
IDENTIFIER the same way `_descend_to_identifier` already walks any argument-index-0 chain
-- no change to `cap_write_site_dedup.py` was needed). Every emitted record now carries
`identity`/`node_id`, `attribution="direct"` (recognized directly at the physical site,
the same tier as capability 3, not an interprocedural call-site summary). This changes NO
existing field/route/disposition -- purely additive, verified by the unchanged frozen
`cap_addr_indexed_test.py` controls.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS); sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
import cap_write_site_dedup as WSD

# copy-family destination/width argument positions (self-contained; not from bug analysis)
CONTRACTS = {"memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2), "wcsncpy": (0, 2),
             "strcpy": (0, None), "wcscpy": (0, None), "strcat": (0, None), "wcscat": (0, None)}

# &(base[index])  with optional parens/spaces; base is an lvalue (ident / field access)
_ADDR_IDX = re.compile(r"^\s*&\s*\(?\s*([A-Za-z_][\w]*(?:\s*(?:\.|->)\s*[A-Za-z_]\w*)*)"
                       r"\s*\[\s*(.+?)\s*\]\s*\)?\s*$")


def _int(expr):
    try:
        node = __import__("ast").parse(expr.strip(), mode="eval").body
    except Exception:
        return None
    import ast
    ok = (ast.Constant, ast.BinOp, ast.UnaryOp, ast.Add, ast.Sub, ast.Mult,
          ast.FloorDiv, ast.Mod, ast.UAdd, ast.USub)

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return n.value
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if a is None or b is None:
                return None
            return {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
                    ast.FloorDiv: lambda: a // b if b else None,
                    ast.Mod: lambda: a % b if b else None}.get(type(n.op), lambda: None)()
        if isinstance(n, ast.UnaryOp):
            v = ev(n.operand)
            return None if v is None else (v if isinstance(n.op, ast.UAdd) else -v)
        return None
    return ev(node)


def _locals_index(d):
    idx = {}
    for l in d.get("locals", []):
        idx.setdefault((l.get("method_id"), l.get("name")), []).append(l)
    return idx


def base_capacity(fn_id, base, stack_ext, heap_ext, locals_idx):
    """Independently-established capacity of `base`, or (None, reason). No assumptions."""
    decls = [x for x in locals_idx.get((fn_id, base), [])
             if "[" in (x.get("type_full_name") or x.get("code") or "")]
    if len(decls) > 1:
        return None, "conflicting_base_decls"
    if len(decls) == 1:
        e = stack_ext.get((fn_id, decls[0].get("id")))
        if e:
            return {"provenance": "stack_fixed_array", "element_count": e["element_count"],
                    "element_type": e["element_type"]}, "ok"
    hf = heap_ext.get((fn_id, base))
    if hf and hf.get("establishment_status") == "ESTABLISHED":
        return {"provenance": "heap_direct_allocation", "element_count": None,
                "size_expression": hf.get("size_expression")}, "ok"
    return None, "capacity_of_base_unresolved"   # struct-field / realloc / param -> never assume


def analyze_addr_indexed(cpp):
    d = json.load(open(cpp))
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    heap_ext = AE.compute_allocation_extents(d)
    locals_idx = _locals_index(d)
    fns = {f["id"]: f for f in d.get("functions", [])}
    wsd_index = WSD.build_index(d)
    ops = []
    for c in d.get("calls", []):
        contract = CONTRACTS.get(c.get("name"))
        if not contract:
            continue
        di, wi = contract
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if di >= len(args):
            continue
        dest_code = (args[di].get("code") or "").strip()
        m = _ADDR_IDX.match(dest_code)
        if not m:
            continue                     # only the &(base[index]) shape (additive)
        base, index_expr = m.group(1).replace(" ", ""), m.group(2)
        fn_id = c.get("enclosing_function_id")
        cap, why = base_capacity(fn_id, base, stack_ext, heap_ext, locals_idx)
        # A side-effecting index (++/--, embedded assignment, or a call) makes the offset
        # value AND pointer validity unresolved -- never compute a remaining capacity.
        side_effect = bool(re.search(r"\+\+|--|(?<![<>=!])=(?!=)|[A-Za-z_]\w*\s*\(", index_expr))
        offset = None if side_effect else _int(index_expr)
        width = (args[wi].get("code") or "").strip() if (wi is not None and wi < len(args)) else None
        rec = {"function": fns.get(fn_id, {}).get("name"), "line": c.get("line"),
               "capability": "addr_indexed", "dest": dest_code, "base": base,
               "index": index_expr, "offset": offset, "width_expr": width,
               "sink": c.get("name"), "remaining_capacity": None}
        if cap is None:
            rec.update(route="additional_evidence_required", reason=why)
        elif cap["provenance"] == "heap_direct_allocation" or not isinstance(cap.get("element_count"), int):
            rec.update(route="additional_evidence_required", reason="base_capacity_symbolic",
                       base_provenance=cap["provenance"])
        elif side_effect:
            rec.update(route="additional_evidence_required", reason="side_effecting_index",
                       base_capacity=cap["element_count"], base_provenance=cap["provenance"])
        elif offset is None:
            rec.update(route="additional_evidence_required", reason="offset_not_numeric",
                       base_capacity=cap["element_count"], base_provenance=cap["provenance"])
        elif offset < 0:
            # &base[-k] points before the buffer -> pointer validity unresolved; do NOT
            # treat capacity+|offset| as available. Abstain.
            rec.update(route="additional_evidence_required",
                       reason="negative_offset_pointer_validity_unresolved",
                       base_capacity=cap["element_count"], base_provenance=cap["provenance"])
        else:
            # 0 <= offset: the pointer &base[offset] is in-range for offset <= capacity
            # (offset == capacity is the one-past-the-end pointer -> remaining 0). Beyond
            # capacity the pointer itself is out of bounds -> oversized.
            remaining = cap["element_count"] - offset
            rec["remaining_capacity"] = remaining
            rec["base_capacity"] = cap["element_count"]
            rec["element_type"] = cap["element_type"]
            rec["base_provenance"] = cap["provenance"]
            if remaining < 0:
                rec.update(route="range_arithmetic_review", reason="offset_exceeds_capacity",
                           disposition="proven_oversized")
            else:
                disp, route, prop, note = v2.compare(
                    {"element_count": remaining, "element_type": cap["element_type"]}, width)
                rec.update(route=route or "deterministic_complete", reason=prop,
                           disposition=disp, note=note)
        identity, node_id = WSD.physical_write_identity(c, wsd_index)
        rec["attribution"] = "direct"
        rec["identity"] = identity
        rec["node_id"] = node_id
        ops.append(rec)
    return ops


if __name__ == "__main__":
    for r in analyze_addr_indexed(sys.argv[1]):
        print(json.dumps(r, sort_keys=True))
