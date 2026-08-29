#!/usr/bin/env python3
"""Counted-writer / loop summary  (NO model calls).

A GENERAL evidence model for a DIFFERENT interprocedural shape than the transparent
delegation wrapper (cap_wrapper_summary.py): a user-defined callee that writes through an
INCREMENTED pointer in a loop bounded by a counter, e.g.

    void *ascii2ebcdic(void *dest, const void *srce, size_t count) {
        unsigned char *udest = dest; const unsigned char *usrce = srce;
        while (count-- != 0) *udest++ = TBL[*usrce++];
        return dest;
    }

A counted loop is NOT a transparent wrapper: writing through an advancing pointer under a
counter has its own proof obligations, and each is a control here:

  * pointer advancement -- the write must go through an ADVANCING pointer (`*p++`); a
    single-slot `*p =` written repeatedly is extent 1, not `count`.
  * alias identity     -- the advancing pointer must resolve to the dest PARAMETER (via
    local aliasing), not to some unrelated local.
  * advancement multiplicity -- exactly ONE advance of the walked pointer per body; two
    advances mean extent 2*count, so a single-`count` summary would be unsound -> abstain.
  * signedness         -- a SIGNED counter may be negative (=> wrap / huge loop); the
    summary records signedness and the call-site router refuses to prove a bound for a
    signed, not-provably-nonnegative count.
  * zero count         -- count==0 writes nothing; a literal 0 at a call site is proven
    safe, never a false overflow.
  * early exits        -- a break/return inside the loop only writes FEWER than count
    elements, so `count` is a sound UPPER bound and early exits cannot cause an
    underestimate of capacity need. The model never widens beyond `count`; combined with
    the advance-multiplicity gate below (which rejects any per-iteration write that could
    exceed one element), no path writes MORE than `count`. (The normalized fact schema
    carries no break/return nodes, so early exits are handled by this soundness argument,
    not by detecting the exit.)
  * conflicting paths  -- more than one walked dest param, or more than one distinct
    counter, is ambiguous -> abstain, no summary.

Summary emitted only when exactly one (dest_param, counter_param) with exactly one
advance is implied. ADDITIVE: fires only on calls to summarized user-defined functions,
which the frozen scanner never routes. Name is never consulted.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import cap_write_site_dedup as WSD

DEC_OPS = {"<operator>.postDecrement", "<operator>.preDecrement"}
INC_OPS = {"<operator>.postIncrement", "<operator>.preIncrement"}
_IDENT = re.compile(r"[A-Za-z_]\w*")
SIGNED_HINTS = ("unsigned", "size_t", "uint")   # negative test below is inverted


def _root_ident(expr):
    s = (expr or "").strip().lstrip("*&( \t")
    m = _IDENT.match(s)
    return m.group(0) if m else None


def _alias_map(fid, calls_by_fn, param_names):
    edges = []
    for c in calls_by_fn.get(fid, []):
        if c.get("name") != "<operator>.assignment":
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if len(args) < 2:
            continue
        tgt = (args[0].get("code") or "").strip()
        src = (args[1].get("code") or "").strip()
        if _IDENT.fullmatch(tgt) and _IDENT.fullmatch(src):
            edges.append((tgt, src))
    amap = {}
    for _ in range(len(edges) + 1):
        changed = False
        for tgt, src in edges:
            dst = src if src in param_names else amap.get(src)
            if dst and amap.get(tgt) != dst:
                amap[tgt] = dst
                changed = True
        if not changed:
            break
    return amap


def _to_param(ident, param_names, amap):
    return ident if ident in param_names else amap.get(ident)


def _is_signed(param):
    t = (param.get("type_full_name") or param.get("code") or "").lower()
    return not any(h in t for h in SIGNED_HINTS)   # int/long/short/char default -> signed


def summarize_counted_writer(f, calls_by_fn):
    params = sorted(f.get("parameters", []), key=lambda p: p.get("index", 0))
    ptr_params = {p["name"]: p for p in params
                  if "*" in (p.get("type_full_name") or p.get("code") or "")}
    len_params = {p["name"]: p for p in params
                  if "*" not in (p.get("type_full_name") or p.get("code") or "")}
    if not ptr_params or not len_params:
        return None
    param_names = set(ptr_params) | set(len_params)
    amap = _alias_map(f["id"], calls_by_fn, param_names)
    body = calls_by_fn.get(f["id"], [])

    # counter: a length param that is DECREMENTED (loop bound signal)
    counters = set()
    for c in body:
        if c.get("name") in DEC_OPS and c.get("arguments"):
            r = _to_param(_root_ident(c["arguments"][0].get("code") or ""), param_names, amap)
            if r in len_params:
                counters.add(r)

    # advancing-pointer writes: an assignment whose target is `* <ident> ++`, i.e. the
    # write goes through the SAME token that is post/pre-incremented in place.
    walk_dests = set()
    advance_counts = {}   # dest_param -> number of increments of the walked alias
    write_call_id = {}    # dest_param -> node id of the physical loop-write call in the callee
    # first, tally increments per identifier
    inc_by_ident = {}
    for c in body:
        if c.get("name") in INC_OPS and c.get("arguments"):
            i = _root_ident(c["arguments"][0].get("code") or "")
            if i:
                inc_by_ident[i] = inc_by_ident.get(i, 0) + 1
    for c in body:
        if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
            continue
        tgt = (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "").strip()
        # advancing write: leading '*' AND the written pointer token is incremented
        if not tgt.startswith("*"):
            continue
        walked = _root_ident(tgt)
        if walked is None:
            continue
        # advancement established either inline (`*p++`) or via a separate ++ on the token
        inline_adv = bool(re.match(r"^\*\s*" + re.escape(walked) + r"\s*(\+\+|--)", tgt))
        adv = inc_by_ident.get(walked, 0) + (1 if inline_adv and walked not in inc_by_ident else 0)
        if adv == 0:
            continue     # single-slot write, not a counted walk -> not this shape
        dp = _to_param(walked, param_names, amap)
        if dp in ptr_params:
            walk_dests.add(dp)
            advance_counts[dp] = max(advance_counts.get(dp, 0), adv)
            write_call_id[dp] = c.get("id")

    if len(counters) != 1 or len(walk_dests) != 1:
        return None       # zero/many counters or dests -> ambiguous, abstain
    dest = next(iter(walk_dests))
    L = next(iter(counters))
    if advance_counts.get(dest, 0) != 1:
        return None       # advancement multiplicity != 1 -> extent != count, abstain

    # `count` is a sound UPPER bound on writes: early exits only write fewer, and the
    # advance==1 gate guarantees no path writes more than one element per iteration.
    # underlying_write_call_id names the PHYSICAL write site inside the callee body; the
    # robust cap2/cap3 identity is computed from it in analyze_counted_writers.
    return {"callee": f["name"], "callee_id": f["id"],
            "dest_param_index": ptr_params[dest]["index"], "dest_param": dest,
            "counter_param_index": len_params[L]["index"], "counter_param": L,
            "counter_signed": _is_signed(len_params[L]),
            "advance_per_iteration": 1, "extent_is_upper_bound": True,
            "underlying_write_call_id": write_call_id.get(dest),
            "form": "counted_loop_writer"}


def _route_counted(ext, count_code, signed):
    """Route the counted write extent (=count elements) against dest capacity. A literal,
    non-negative count is compared element-wise; a signed not-provably-nonnegative or
    symbolic count abstains (capacity bound, extent not proven)."""
    N = ext["element_count"]
    m = re.fullmatch(r"\s*(\d+)\s*", count_code or "")
    if m:
        k = int(m.group(1))
        if k <= N:
            return ("deterministic_complete", None, "write_count_within_destination_capacity",
                    f"{k} elems (count) <= capacity {N}, advancing pointer, offset 0")
        return ("proven_oversized", "range_arithmetic_review", "write_count_within_destination_capacity",
                f"{k} elems (count) > capacity {N} -- provable destination overflow")
    if signed:
        return ("relationship_unresolved", "semantic_relationship_review", "count_sign_unresolved",
                "capacity bound; signed counter not proven non-negative (may wrap/huge loop)")
    return ("relationship_unresolved", "semantic_relationship_review", "count_bound_not_established",
            "capacity bound; symbolic count not proven <= capacity")


def analyze_counted_writers(cpp):
    d = json.load(open(cpp))
    calls_by_fn = {}
    call_by_id = {}
    for c in d.get("calls", []):
        calls_by_fn.setdefault(c.get("enclosing_function_id"), []).append(c)
        call_by_id[c.get("id")] = c
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    locals_idx = {}
    for l in d.get("locals", []):
        locals_idx.setdefault((l.get("method_id"), l.get("name")), []).append(l)
    index = WSD.build_index(d)   # robust physical-write identity index

    summaries = {}
    for f in d.get("functions", []):
        if f.get("is_external"):
            continue
        s = summarize_counted_writer(f, calls_by_fn)
        if s:
            summaries[f["name"]] = s

    fns = {f["id"]: f for f in d.get("functions", [])}
    ops = []
    for c in d.get("calls", []):
        s = summaries.get(c.get("name"))
        if not s:
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if s["dest_param_index"] >= len(args) or s["counter_param_index"] >= len(args):
            continue
        dest_code = (args[s["dest_param_index"]].get("code") or "").strip()
        cnt_code = (args[s["counter_param_index"]].get("code") or "").strip()
        fn_id = c.get("enclosing_function_id")
        wcall = call_by_id.get(s.get("underlying_write_call_id"))
        uw, uw_node = (WSD.physical_write_identity(wcall, index) if wcall else (None, None))
        rec = {"function": fns.get(fn_id, {}).get("name"), "line": c.get("line"),
               "capability": "counted_loop_writer", "callee": c.get("name"),
               "dest": dest_code, "count": cnt_code, "counter_signed": s["counter_signed"],
               "extent_is_upper_bound": s["extent_is_upper_bound"], "sink": c.get("name"),
               "attribution": "call_site_summary", "underlying_write": uw,
               "underlying_write_node_id": uw_node, "resolved_dest_param": s["dest_param"]}
        base = _root_ident(dest_code)
        decls = [x for x in locals_idx.get((fn_id, base), [])
                 if "[" in (x.get("type_full_name") or x.get("code") or "")]
        ext = stack_ext.get((fn_id, decls[0].get("id"))) if len(decls) == 1 else None
        if dest_code != base or len(decls) > 1 or ext is None:
            rec.update(route="additional_evidence_required",
                       reason="capacity_of_dest_unresolved")
        else:
            disp, route, prop, note = _route_counted(
                {"element_count": ext["element_count"], "element_type": ext["element_type"]},
                cnt_code, s["counter_signed"])
            rec.update(route=route or "deterministic_complete", reason=prop,
                       disposition=disp, note=note, dest_capacity=ext["element_count"],
                       dest_element_type=ext["element_type"])
        ops.append(rec)
    return ops, summaries


if __name__ == "__main__":
    ops, summ = analyze_counted_writers(sys.argv[1])
    for name, s in sorted(summ.items()):
        print("SUMMARY", json.dumps(s, sort_keys=True))
    for r in ops:
        print(json.dumps(r, sort_keys=True))
