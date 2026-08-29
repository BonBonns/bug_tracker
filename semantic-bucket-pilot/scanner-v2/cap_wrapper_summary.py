#!/usr/bin/env python3
"""Capability 2 — transparent wrapper summaries (delegation to a known write sink).
NO model calls.

A GENERAL evidence model for ONE interprocedural representation shape: a user-defined
callee that transparently DELEGATES a copy to a library write sink, writing its LENGTH
argument into its DESTINATION parameter. The summary is inferred from the callee BODY
ONLY -- never from the function name. It is ADDITIVE: it fires only on calls to
user-defined functions carrying such a summary, which the frozen scanner (library
copy-sink contracts only) never routes, so it cannot move any existing verdict.

Recognized body form (delegation only):
  the body calls a library copy sink (memcpy family) whose destination argument resolves
  -- through local aliasing -- to a POINTER parameter P, and whose length argument is a
  LENGTH parameter L.  e.g.  _TIFFmemcpy(d,s,c){ return memcpy(d,s,c); }

This model is deliberately DISTINCT from the counted-writer/loop model
(cap_counted_loop_writer.py). A counted loop through an incremented pointer
(`ascii2ebcdic`-shape) is NOT a transparent delegation wrapper: it has its own proof
obligations (zero count, signedness, early exits, alias identity, pointer advancement,
conflicting paths) and is handled by that separate model. The two proof models are not
merged just because both happen to be wrapper functions.

Soundness gates: a summary is emitted ONLY when exactly one (P, L) delegation is implied.
Multiple distinct sink destinations, multiple candidate lengths, a length not resolvable
to a single parameter, or a sink whose destination is a local (not a param) -> NO summary
(abstain). Name is never consulted.

At a call site to a summarized callee, the model binds the actual destination and length
arguments and routes with the SAME frozen comparison used elsewhere (v2.compare) ONLY
when the actual destination is a bare local fixed array of independently-established
capacity; otherwise the op is additional_evidence_required (capacity_of_dest_unresolved),
never a guess.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2

# library copy sinks with (dest_index, width_index); width_index None -> no length arg,
# cannot be a length-transparent summary. Self-contained, not from any bug analysis.
COPY_SINKS = {"memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2), "wcsncpy": (0, 2),
              "strncat": (0, 2), "wmemcpy": (0, 2), "bcopy": (1, 2)}
_IDENT = re.compile(r"[A-Za-z_]\w*")


def _root_ident(expr):
    """Leading identifier of a dest/target expression, stripping *, &, (, ++/--, [ ]."""
    s = expr.strip().lstrip("*&( \t")
    m = _IDENT.match(s)
    return m.group(0) if m else None


def _alias_map(fid, calls_by_fn, param_names):
    """local <- (param | alias) one-hop assignments, closed to a fixpoint. Maps a local
    identifier to the parameter it ultimately aliases."""
    edges = []
    for c in calls_by_fn.get(fid, []):
        if c.get("name") != "<operator>.assignment":
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if len(args) < 2:
            continue
        tgt = (args[0].get("code") or "").strip()
        src = (args[1].get("code") or "").strip()
        # only bare-identifier target initialised from a bare-identifier source
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
    if ident in param_names:
        return ident
    return amap.get(ident)


def summarize_callee(f, calls_by_fn):
    """Infer {dest_param_index, length_param_index} for one function, from body only.
    Returns dict or None."""
    params = sorted(f.get("parameters", []), key=lambda p: p.get("index", 0))
    ptr_params = {p["name"]: p["index"] for p in params
                  if "*" in (p.get("type_full_name") or p.get("code") or "")}
    len_params = {p["name"]: p["index"] for p in params
                  if "*" not in (p.get("type_full_name") or p.get("code") or "")}
    if not ptr_params or not len_params:
        return None
    param_names = set(ptr_params) | set(len_params)
    amap = _alias_map(f["id"], calls_by_fn, param_names)
    body = calls_by_fn.get(f["id"], [])

    cands = set()   # (dest_param_name, length_param_name)

    # delegation to a library copy sink whose dest resolves (through aliasing) to a
    # pointer param and whose length is a length param
    for c in body:
        sink = COPY_SINKS.get(c.get("name"))
        if not sink:
            continue
        di, wi = sink
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if wi is None or wi >= len(args) or di >= len(args):
            continue
        dparam = _to_param(_root_ident(args[di].get("code") or ""), param_names, amap)
        wcode = (args[wi].get("code") or "").strip()
        if dparam in ptr_params and wcode in len_params:
            cands.add((dparam, wcode))

    dests = {c[0] for c in cands}
    lens = {c[1] for c in cands}
    if len(dests) != 1 or len(lens) != 1:
        return None    # no delegation, or conflicting/ambiguous -> abstain, no summary
    dest, length = next(iter(dests)), next(iter(lens))
    return {"callee": f["name"], "callee_id": f["id"],
            "dest_param_index": ptr_params[dest], "dest_param": dest,
            "length_param_index": len_params[length], "length_param": length,
            "form": "delegation"}


def analyze_wrapper_calls(cpp):
    d = json.load(open(cpp))
    calls_by_fn = {}
    for c in d.get("calls", []):
        calls_by_fn.setdefault(c.get("enclosing_function_id"), []).append(c)
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    locals_idx = {}
    for l in d.get("locals", []):
        locals_idx.setdefault((l.get("method_id"), l.get("name")), []).append(l)

    summaries = {}
    for f in d.get("functions", []):
        if f.get("is_external"):
            continue
        s = summarize_callee(f, calls_by_fn)
        if s:
            summaries[f["name"]] = s

    fns = {f["id"]: f for f in d.get("functions", [])}
    ops = []
    for c in d.get("calls", []):
        s = summaries.get(c.get("name"))
        if not s:
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if s["dest_param_index"] >= len(args) or s["length_param_index"] >= len(args):
            continue
        dest_code = (args[s["dest_param_index"]].get("code") or "").strip()
        len_code = (args[s["length_param_index"]].get("code") or "").strip()
        fn_id = c.get("enclosing_function_id")
        rec = {"function": fns.get(fn_id, {}).get("name"), "line": c.get("line"),
               "capability": "wrapper_summary", "callee": c.get("name"),
               "summary_form": s["form"], "dest": dest_code, "length": len_code,
               "sink": c.get("name")}
        # capacity of the actual destination: independently-established stack array only
        base = _root_ident(dest_code)
        decls = [x for x in locals_idx.get((fn_id, base), [])
                 if "[" in (x.get("type_full_name") or x.get("code") or "")]
        ext = stack_ext.get((fn_id, decls[0].get("id"))) if len(decls) == 1 else None
        if dest_code != base or len(decls) > 1 or ext is None:
            rec.update(route="additional_evidence_required",
                       reason="capacity_of_dest_unresolved")
        else:
            disp, route, prop, note = v2.compare(
                {"element_count": ext["element_count"], "element_type": ext["element_type"]},
                len_code)
            rec.update(route=route or "deterministic_complete", reason=prop,
                       disposition=disp, note=note, dest_capacity=ext["element_count"],
                       dest_element_type=ext["element_type"])
        ops.append(rec)
    return ops, summaries


if __name__ == "__main__":
    ops, summ = analyze_wrapper_calls(sys.argv[1])
    for name, s in sorted(summ.items()):
        print("SUMMARY", json.dumps(s, sort_keys=True))
    for r in ops:
        print(json.dumps(r, sort_keys=True))
