#!/usr/bin/env python3
"""Capability 2 / Capability 3 write-site boundary: deduplication + precedence.
NO model calls.

BOUNDARY DEFINITIONS (frozen; see CAP2_CAP3_BOUNDARY_FROZEN.md):
  * Capability 2 summarizes a CALLEE's write EFFECT at its CALL SITE (interprocedural).
    The physical write instruction lives inside the callee; cap2 attributes the effect at
    each call site and records `underlying_write = {file, line, dest_param}` = that
    physical site.
  * Capability 3 recognizes DIRECT pointer-walk writes WITHIN the analyzed function
    (intraprocedural). Its record IS at the physical write site.

OVERLAP: when a callee G with a pointer-walk loop is in scope and F calls G, the SAME
physical write (G:line) is reachable two ways -- cap3 recognizes it directly in G's body,
and cap2 attributes G's effect at F's call site. That is ONE underlying write, not two
experimental operations.

RULE (frozen):
  * Write-site identity = (basename(file), line) of the PHYSICAL write instruction. For a
    cap2 record that is its `underlying_write`; for a cap3 record it is the record's own
    site.
  * Deduplicate by write-site identity. PRECEDENCE: a DIRECT (cap3) recognition is the
    canonical operation for a physical site; a cap2 CALL_SITE_SUMMARY of the same site is a
    propagated view, retained as PROVENANCE, not a second operation.
  * Both provenance paths are preserved on the merged operation (`provenance` list).
  * A cap2 call-site summary whose callee body is NOT in scope has no matching direct
    record and stands on its own as one operation (its underlying_write still names the
    site, so a later in-scope pass can merge it).
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_IDENT = re.compile(r"[A-Za-z_]\w*")
PRECEDENCE = {"direct": 0, "call_site_summary": 1}


def _base(p):
    return os.path.basename(p) if p else p


def write_site_key(rec):
    """(basename(file), line) of the physical write this record refers to."""
    if rec.get("attribution") == "call_site_summary":
        uw = rec.get("underlying_write") or {}
        return (_base(uw.get("file")), uw.get("line"))
    return (_base(rec.get("file")), rec.get("line"))


def direct_walk_write_sites(cpp):
    """Minimal Capability-3 PRIMITIVE: locate DIRECT pointer-walk write sites
    (`*p++ = ...`) within each analyzed function. Write-site identification only -- no
    capacity routing (that is capability 3 proper). Returns one record per physical site."""
    d = json.load(open(cpp))
    fns = {f["id"]: f for f in d.get("functions", [])}
    inc_by_fn = {}
    for c in d.get("calls", []):
        if c.get("name") in ("<operator>.postIncrement", "<operator>.preIncrement") and c.get("arguments"):
            m = _IDENT.match((c["arguments"][0].get("code") or "").lstrip("*&( "))
            if m:
                inc_by_fn.setdefault(c.get("enclosing_function_id"), {})[m.group(0)] = True
    out = []
    for c in d.get("calls", []):
        if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
            continue
        tgt = (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "").strip()
        if not tgt.startswith("*"):
            continue
        m = _IDENT.match(tgt.lstrip("*&( "))
        if not m:
            continue
        walked = m.group(0)
        fid = c.get("enclosing_function_id")
        inline_adv = bool(re.match(r"^\*\s*" + re.escape(walked) + r"\s*(\+\+|--)", tgt))
        if not (inline_adv or inc_by_fn.get(fid, {}).get(walked)):
            continue     # not an advancing pointer -> not a pointer-walk write
        f = fns.get(fid, {})
        out.append({"attribution": "direct", "capability": "pointer_walk_direct",
                    "function": f.get("name"), "file": f.get("file"),
                    "line": c.get("line"), "dest": walked})
    return out


def dedup(records):
    """Merge records that refer to the SAME physical write site. One operation per site;
    canonical = highest-precedence attribution (direct > call_site_summary); all
    contributing records kept as provenance."""
    groups = {}
    for r in records:
        groups.setdefault(write_site_key(r), []).append(r)
    ops = []
    for key, recs in sorted(groups.items(), key=lambda kv: (str(kv[0][0]), kv[0][1] or 0)):
        canonical = min(recs, key=lambda r: PRECEDENCE.get(r.get("attribution"), 9))
        prov = [{"attribution": r.get("attribution"), "capability": r.get("capability"),
                 "function": r.get("function"), "line": r.get("line")} for r in recs]
        ops.append({"write_site": {"file": key[0], "line": key[1]},
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
