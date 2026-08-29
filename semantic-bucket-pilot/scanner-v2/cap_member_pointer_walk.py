#!/usr/bin/env python3
"""Capability 3 -- advancing-pointer STRUCT-MEMBER writes  (NO model calls).

The uncovered remainder from CAP3_DOMAIN_AUDIT.md: a write through an ADVANCING pointer
whose target is a struct/union MEMBER (`p->field = ...` / `p.field = ...`) with the
pointer advanced separately (`p++` / `++p` / `p += 1`). This is the PNG003
`png_handle_PLTE` palette-population shape, which the frozen cursor producer
(`oob_cursor_write_verdict`, dereference-syntax + byte-buffer only) does not model.

SCOPE (deliberately narrow):
  * OWNS only advancing-pointer struct-member writes `p->field = x` / `p.field = x`.
    It does NOT claim general "non-byte aggregate writes" -- e.g. `*p++ = struct_value`
    (whole-aggregate cursor writes) are NOT handled here and would need their own model
    and controls.
  * The pointer's declaration is resolved through Joern reference-target
    (`cap_write_site_dedup.resolve_dest_declaration`), never by name.
  * Capacity is bound ONLY from an independently-established fixed-array or literal-count
    allocation extent (element count). Unknown struct-field / parameter / alias / realloc /
    symbolic-allocation capacity stays UNRESOLVED (abstain), never assumed.
  * The cursor trajectory is examined explicitly: a single base binding, a single unit
    advance, a loop counter+bound, write-before-advance (no one-past), no reset, no alias
    conflict. Anything else abstains with a specific reason.
  * All member writes through ONE cursor (e.g. PNG003 red/green/blue) are ONE operation
    with ONE capacity obligation and ONE proof family -- NOT three independent families.

Additive: emits `attribution="direct"` records that flow through
`cap_write_site_dedup.dedup`, where the frozen PRECEDENCE keeps the cursor producer
canonical on any site it already recognizes (cursor_producer > direct > call_site_summary).
Never emits VULNERABLE.
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
import cap_write_site_dedup as WSD

MEMBER_WRITE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*[A-Za-z_]\w*\s*$")
INC_OPS = ("<operator>.postIncrement", "<operator>.preIncrement")
PLUS_OPS = ("<operator>.assignmentPlus",)
LT_OPS = ("<operator>.lessThan", "<operator>.lessEqualsThan")
GT_OPS = ("<operator>.greaterThan", "<operator>.greaterEqualsThan")
INT_RE = re.compile(r"^\s*\d+\s*$")
UNSIGNED_HINTS = ("unsigned", "size_t", "uint")


def _resolve(idid, ident_by_id):
    ident = ident_by_id.get(idid)
    refs = (ident.get("ref_target_ids") if ident else None) or []
    return refs[0] if len(refs) == 1 else None


def _decl_of_name_use(call, index):
    """Resolve the identifier at a call's arg0 root to its declaration node via ref-target."""
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if not args:
        return None
    idid = WSD._descend_to_identifier(args[0], index["call_by_id"])
    return _resolve(idid, index["ident_by_id"])


def _base_capacity(base_decl_node, base_binding_call, index, d, stack_ext, heap_ext):
    """Independently-established capacity (element count) of the cursor's base, or
    (None, reason). Only fixed arrays and literal-count allocations qualify."""
    # base binding RHS: cursor = <X>
    args = sorted(base_binding_call.get("arguments", []), key=lambda a: a.get("index", 0))
    if len(args) < 2:
        return None, "base_binding_unreadable"
    rhs = args[1]
    rhs_code = (rhs.get("code") or "").strip()
    # X an identifier referencing a fixed array local?
    rid = WSD._descend_to_identifier(rhs, index["call_by_id"])
    rdecl = _resolve(rid, index["ident_by_id"]) if rid else None
    fid = base_binding_call.get("enclosing_function_id")
    if rdecl is not None and (fid, rdecl) in stack_ext:
        e = stack_ext[(fid, rdecl)]
        return {"element_count": e["element_count"], "element_type": e["element_type"],
                "provenance": "stack_fixed_array"}, "ok"
    # X a literal-count allocation bound to the cursor's base name?
    he = heap_ext.get((fid, WSD._root_ident(rhs_code)))
    if he and he.get("establishment_status") == "ESTABLISHED" and isinstance(he.get("element_count"), int):
        return {"element_count": he["element_count"], "element_type": he.get("element_type"),
                "provenance": "heap_literal_allocation"}, "ok"
    # struct-field / parameter / alias / realloc / symbolic alloc -> unresolved
    return None, "capacity_of_base_unresolved"


def _is_unsigned(bound_code, index, fid):
    """Is the loop bound provably non-negative (unsigned type)?"""
    for f in [index["funcs"].get(fid, {})]:
        for p in (f.get("parameters") or []):
            if p.get("name") == bound_code:
                t = (p.get("type_full_name") or "").lower()
                return any(h in t for h in UNSIGNED_HINTS)
    for l in index["locals_by_id"].values():
        if l.get("method_id") == fid and l.get("name") == bound_code:
            t = (l.get("type_full_name") or "").lower()
            return any(h in t for h in UNSIGNED_HINTS)
    return False


def analyze_member_walks(cpp):
    d = json.load(open(cpp))
    index = WSD.build_index(d)
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    heap_ext = AE.compute_allocation_extents(d)
    calls_by_fn = defaultdict(list)
    for c in d.get("calls", []):
        calls_by_fn[c.get("enclosing_function_id")].append(c)
    fns = index["funcs"]

    # 1. member-write calls grouped by (function, resolved cursor decl node)
    groups = defaultdict(list)
    for c in d.get("calls", []):
        if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
            continue
        tgt = (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "")
        if not MEMBER_WRITE.match(tgt):
            continue
        cursor_decl = _decl_of_name_use(c, index)
        if cursor_decl is None:
            continue
        groups[(c.get("enclosing_function_id"), cursor_decl)].append(c)

    ops = []
    for (fid, cursor_decl), writes in groups.items():
        body = calls_by_fn[fid]
        cursor_name = WSD._root_ident(
            (sorted(writes[0]["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or ""))

        # 2. advances of THIS cursor (resolved via ref-target)
        advances = []
        for c in body:
            if c.get("name") in INC_OPS + PLUS_OPS and c.get("arguments"):
                if _decl_of_name_use(c, index) == cursor_decl:
                    advances.append(c)
        # 3. base bindings: cursor = X  (LHS ref-> cursor_decl, not a member/deref target)
        base_bindings = []
        for c in body:
            if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
                continue
            a = sorted(c["arguments"], key=lambda x: x.get("index", 0))
            lhs = (a[0].get("code") or "").strip()
            if lhs == cursor_name and _decl_of_name_use(c, index) == cursor_decl:
                base_bindings.append(c)

        member_ids = [WSD.physical_write_identity(c, index)[0] for c in writes]
        member_nodes = [c.get("id") for c in writes]
        # family: ONE per cursor obligation (base shape x bound shape), NOT per member write
        rec = {"capability": "member_pointer_walk", "attribution": "direct",
               "function": fns.get(fid, {}).get("name"), "cursor": cursor_name,
               "cursor_decl_node": cursor_decl,
               "member_writes": member_ids, "n_member_writes": len(writes),
               "member_write_nodes": member_nodes,
               "line": min(c.get("line") for c in writes)}

        def emit(route, reason, disposition=None, **extra):
            sig = f"member_pointer_walk|{extra.get('base_prov','?')}|{extra.get('bound_shape','?')}"
            rec.update(route=route, reason=reason, disposition=disposition,
                       family_signature=sig,
                       family_id="fam_" + hashlib.sha256(sig.encode()).hexdigest()[:12],
                       **extra)
            ops.append(rec)

        # ---- trajectory gates (abstain with a specific reason) ---------------------------
        # No advance at all -> a single struct-member write, NOT a pointer WALK -> outside
        # capability 3's domain entirely; emit nothing (additive).
        if len(advances) == 0:
            continue
        if len({(_decl_of_name_use(bb, index)) for bb in base_bindings}) == 0:
            emit("additional_evidence_required", "capacity_of_base_unresolved",
                 base_prov="no_base_binding"); continue
        distinct_bases = {WSD._norm_code(
            sorted(bb["arguments"], key=lambda a: a.get("index", 0))[1].get("code") or "")
            for bb in base_bindings}
        if len(base_bindings) > 1 and len(distinct_bases) > 1:
            emit("additional_evidence_required", "destination_identity_ambiguous",
                 detail="cursor base bound from multiple distinct sources (alias conflict/reset)")
            continue
        if len(base_bindings) > 1:
            emit("additional_evidence_required", "cursor_trajectory_reset",
                 detail="cursor re-based more than once"); continue
        if len(advances) != 1:
            emit("additional_evidence_required", "cursor_advance_ambiguous",
                 detail=f"{len(advances)} advance sites (multiple/conditional increments)")
            continue
        adv = advances[0]
        # unit stride only: p++ / ++p, or p += 1
        if adv.get("name") in PLUS_OPS:
            aargs = sorted(adv["arguments"], key=lambda a: a.get("index", 0))
            stride = (aargs[1].get("code") or "").strip() if len(aargs) > 1 else "?"
            if stride != "1":
                emit("additional_evidence_required", "cursor_advance_non_unit",
                     detail=f"stride {stride}"); continue

        # capacity of the base (established array / literal allocation only)
        cap, why = _base_capacity(cursor_decl, base_bindings[0], index, d, stack_ext, heap_ext)
        if cap is None:
            emit("additional_evidence_required", why, base_prov="unresolved"); continue

        # loop counter + bound: a DIFFERENT incremented var compared via < / <= to a bound.
        # header_line = the loop-header line (where that comparison sits).
        counters = {WSD._root_ident(c["arguments"][0].get("code") or "")
                    for c in body if c.get("name") in INC_OPS and c.get("arguments")}
        counters.discard(cursor_name)
        bound_code, header_line = None, None
        for c in body:
            if c.get("name") in LT_OPS and c.get("arguments"):
                a = sorted(c["arguments"], key=lambda x: x.get("index", 0))
                lhs = WSD._root_ident(a[0].get("code") or "")
                if lhs in counters and len(a) > 1:
                    bound_code = (a[1].get("code") or "").strip()
                    header_line = c.get("line")
                    break

        # Advance placement -- the trajectory is PROVEN per-iteration only for a for-UPDATE
        # advance (on the loop-header line, runs once after each body execution). A BODY
        # advance is not proven unconditional/per-iteration without CFG dominance:
        #   * a body advance BEFORE the member write -> possible one-past  -> abstain;
        #   * any other body advance -> per-iteration not proven (conditional?) -> abstain.
        aln = adv.get("line")
        wln = min(c.get("line") for c in writes)
        if aln is not None and header_line is not None and aln != header_line:
            if wln > aln:
                emit("additional_evidence_required", "cursor_one_past_write",
                     base_prov=cap["provenance"],
                     detail="body advance precedes the member write (possible one-past)")
            else:
                emit("additional_evidence_required", "cursor_advance_not_proven_per_iteration",
                     base_prov=cap["provenance"],
                     detail="advance is in the body, not the for-update; per-iteration "
                            "execution not provable without CFG dominance (e.g. conditional)")
            continue

        if bound_code is None:
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap["element_count"], bound_shape="no_loop_bound"); continue

        # guard: bound compared via > / >= AND clamped (reassigned) -> capacity-bounded
        gt = any(c.get("name") in GT_OPS and any(
            WSD._root_ident(x.get("code") or "") == bound_code for x in c.get("arguments", []))
            for c in body)
        clamp = any(c.get("name") == "<operator>.assignment" and c.get("arguments")
                    and (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "").strip() == bound_code
                    for c in body)
        guarded = gt and clamp

        cap_n = cap["element_count"]
        if INT_RE.match(bound_code):
            k = int(bound_code)
            if k <= cap_n:
                emit("deterministic_complete", "write_count_within_destination_capacity",
                     disposition="deterministic_complete", base_prov=cap["provenance"],
                     base_capacity=cap_n, bound_shape="literal",
                     note=f"{k} elems (loop bound) <= capacity {cap_n}")
            else:
                emit("range_arithmetic_review", "write_count_within_destination_capacity",
                     disposition="proven_oversized", base_prov=cap["provenance"],
                     base_capacity=cap_n, bound_shape="literal",
                     note=f"{k} > capacity {cap_n}")
        elif guarded:
            emit("deterministic_complete", "write_count_within_destination_capacity",
                 disposition="deterministic_complete", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="symbolic_guarded",
                 note="loop bound clamped to capacity by a visible guard")
        else:
            # symbolic, unguarded bound: the count-vs-capacity relationship is NOT
            # established (a large positive count would overflow) -> OPEN CANDIDATE (flag),
            # never a safety claim. Sign is recorded but does not make it safe: a negative
            # signed value merely means 0 iterations, which does not resolve the relation.
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap_n,
                 bound_shape=("symbolic_unsigned" if _is_unsigned(bound_code, index, fid)
                              else "symbolic_signed"))
    return ops


if __name__ == "__main__":
    for o in analyze_member_walks(sys.argv[1]):
        print(json.dumps({k: o[k] for k in o if k != "member_writes"}, sort_keys=True))
