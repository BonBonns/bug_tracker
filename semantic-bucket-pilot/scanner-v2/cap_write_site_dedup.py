#!/usr/bin/env python3
"""Capability 2 / Capability 3 write-site boundary: a ROBUST physical-write identity, plus
deduplication + precedence. NO model calls.

BOUNDARY DEFINITIONS (frozen; see CAP2_CAP3_BOUNDARY_FROZEN.md):
  * Capability 2 summarizes a CALLEE's write EFFECT at its CALL SITE (interprocedural); its
    record carries `underlying_write` = the identity of the callee's PHYSICAL write.
  * Capability 3 recognizes DIRECT pointer-walk writes WITHIN the analyzed function; its
    record IS at the physical write site.

WRITE IDENTITY (cross-run stable; `(basename, line)` is NOT used -- it collapses same-named
files in different directories and multiple writes on one line). A physical write is
identified by:
  * normalized REPOSITORY-RELATIVE file path (full path, not basename);
  * enclosing function identity + source span (name, line, line_end);
  * line + SITE ORDINAL within (function, line)  [no column in this schema];
  * normalized write statement + operator;
  * destination DECLARATION identity (param -> ("param", index); local -> ("local",
    decl_line, name)) -- a declaration site, never a bare name.
The write-call/node id is retained as WITHIN-RUN provenance only; it is NOT part of the
cross-run identity because node ids may change between runs.

Both cap2 and cap3 build their identities through THIS module's `physical_write_identity`,
so the same physical instruction yields the same identity from either path.
"""
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_IDENT = re.compile(r"[A-Za-z_]\w*")
COPY_SINKS = {"memcpy": 0, "memmove": 0, "strncpy": 0, "wcsncpy": 0,
              "strncat": 0, "wmemcpy": 0, "bcopy": 1}
INC_OPS = ("<operator>.postIncrement", "<operator>.preIncrement")
PRECEDENCE = {"direct": 0, "call_site_summary": 1}


def _norm_path(p):
    if not p:
        return p
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    while "//" in p:
        p = p.replace("//", "/")
    return p


def _norm_code(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def _root_ident(expr):
    s = (expr or "").strip().lstrip("*&( \t")
    m = _IDENT.match(s)
    return m.group(0) if m else None


def write_target(call):
    """Destination expression this call writes, or None if the call is not a write."""
    nm = call.get("name")
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if nm == "<operator>.assignment" and args:
        tgt = (args[0].get("code") or "").strip()
        return tgt if (tgt.startswith("*") or "[" in tgt) else None
    di = COPY_SINKS.get(nm)
    if di is not None and di < len(args):
        return (args[di].get("code") or "").strip()
    return None


def build_index(d):
    """Precompute function/param/local declarations and the per-(function,line) site
    ordinal over all write-like calls."""
    funcs = {f["id"]: f for f in d.get("functions", [])}
    params = {f["id"]: {p["name"]: p for p in (f.get("parameters") or [])}
              for f in d.get("functions", [])}
    localdecl = {}
    for l in d.get("locals", []):
        localdecl.setdefault(l.get("method_id"), {})[l.get("name")] = l
    byline = defaultdict(list)
    for i, c in enumerate(d.get("calls", [])):
        if write_target(c) is not None:
            byline[(c.get("enclosing_function_id"), c.get("line"))].append((i, c))
    ordinal = {}
    for _key, lst in byline.items():
        # deterministic, cross-run-stable order: normalized write text, then appearance
        ordered = sorted(lst, key=lambda ic: (_norm_code(write_target(ic[1])), ic[0]))
        for ordn, (_i, c) in enumerate(ordered):
            ordinal[c.get("id")] = ordn
    return {"funcs": funcs, "params": params, "localdecl": localdecl, "ordinal": ordinal}


def dest_decl_identity(call, index):
    """Declaration identity of the write's destination (NOT a bare name)."""
    fid = call.get("enclosing_function_id")
    root = _root_ident(write_target(call))
    p = index["params"].get(fid, {}).get(root)
    if p is not None:
        return ("param", p.get("index"))
    l = index["localdecl"].get(fid, {}).get(root)
    if l is not None:
        return ("local", l.get("line"), root)
    return ("unknown", root)


def physical_write_identity(call, index):
    """Robust cross-run identity of one physical write. Returns (identity_dict, node_id).
    node_id is within-run provenance only, excluded from the identity."""
    fid = call.get("enclosing_function_id")
    f = index["funcs"].get(fid, {})
    ident = {
        "file": _norm_path(f.get("file")),
        "function": [f.get("name"), f.get("line"), f.get("line_end")],
        "line": call.get("line"),
        "ordinal": index["ordinal"].get(call.get("id")),
        "write": [call.get("name"), _norm_code(write_target(call))],
        "dest_decl": list(dest_decl_identity(call, index)),
    }
    return ident, call.get("id")


def identity_key(rec_or_ident):
    """Hashable cross-run key. Accepts a raw identity dict, or a record carrying
    `underlying_write` (cap2) / being a direct record with `identity` (cap3)."""
    ident = rec_or_ident
    if "underlying_write" in rec_or_ident and rec_or_ident.get("underlying_write"):
        ident = rec_or_ident["underlying_write"]
    elif "identity" in rec_or_ident:
        ident = rec_or_ident["identity"]
    return (ident.get("file"), tuple(ident.get("function") or []), ident.get("line"),
            ident.get("ordinal"), tuple(ident.get("write") or []),
            tuple(ident.get("dest_decl") or []))


def direct_walk_write_sites(cpp):
    """Minimal Capability-3 PRIMITIVE: locate DIRECT pointer-walk writes (`*p++ = ...`)
    within each function. Identification only (no capacity routing). Each record carries
    the robust `identity` and the within-run `node_id` provenance."""
    d = json.load(open(cpp)) if isinstance(cpp, str) else cpp
    index = build_index(d)
    inc_by_fn = {}
    for c in d.get("calls", []):
        if c.get("name") in INC_OPS and c.get("arguments"):
            r = _root_ident(c["arguments"][0].get("code") or "")
            if r:
                inc_by_fn.setdefault(c.get("enclosing_function_id"), set()).add(r)
    out = []
    for c in d.get("calls", []):
        if c.get("name") != "<operator>.assignment":
            continue
        tgt = write_target(c)
        if not tgt or not tgt.startswith("*"):
            continue
        walked = _root_ident(tgt)
        fid = c.get("enclosing_function_id")
        inline_adv = bool(re.match(r"^\*\s*" + re.escape(walked or "") + r"\s*(\+\+|--)", tgt))
        if not (inline_adv or (walked in inc_by_fn.get(fid, set()))):
            continue
        ident, node_id = physical_write_identity(c, index)
        out.append({"attribution": "direct", "capability": "pointer_walk_direct",
                    "function": index["funcs"].get(fid, {}).get("name"),
                    "identity": ident, "node_id": node_id})
    return out


def dedup(records):
    """One operation per physical write identity. Canonical = highest-precedence
    attribution (direct > call_site_summary); all contributing records kept as provenance."""
    groups = defaultdict(list)
    for r in records:
        groups[identity_key(r)].append(r)
    ops = []
    for key, recs in sorted(groups.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        canonical = min(recs, key=lambda r: PRECEDENCE.get(r.get("attribution"), 9))
        ident = (canonical.get("underlying_write") or canonical.get("identity"))
        prov = [{"attribution": r.get("attribution"), "capability": r.get("capability"),
                 "function": r.get("function"), "node_id": r.get("node_id"),
                 "resolved_dest_param": r.get("resolved_dest_param")} for r in recs]
        ops.append({"identity": ident,
                    "canonical_capability": canonical.get("capability"),
                    "canonical_attribution": canonical.get("attribution"),
                    "n_provenance_paths": len(prov), "provenance": prov})
    return ops


if __name__ == "__main__":
    import cap_wrapper_summary as W
    import cap_counted_loop_writer as CL
    cpp = sys.argv[1]
    w_ops, _ = W.analyze_wrapper_calls(cpp)
    c_ops, _ = CL.analyze_counted_writers(cpp)
    direct = direct_walk_write_sites(cpp)
    for op in dedup(w_ops + c_ops + direct):
        print(json.dumps(op, sort_keys=True))
