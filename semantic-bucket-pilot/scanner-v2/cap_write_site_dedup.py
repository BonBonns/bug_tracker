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
  * line + SITE column (source column of the write; NOT fact-list order / node id);
  * normalized write statement + operator;
  * destination DECLARATION identity, built in TWO SEPARATE STEPS:
      1. RESOLVE the write target to its declaration node via Joern's reference-target
         edge (`identifiers[].ref_target_ids`) -- a semantic reference resolution, NOT a
         name/nearest-declaration heuristic. This binds correctly across nested scopes
         (an outer `x` used after an inner shadow's block ends resolves to the OUTER decl).
      2. SERIALIZE that resolved declaration node into a stable cross-run identity:
         relative file, enclosing function, declaration line, normalized declaration
         text/type, and a source-column DECLARATION ordinal (which only disambiguates
         same-name same-line declarations; it does NOT decide which declaration is meant).
The write-call/node id is retained as WITHIN-RUN provenance only; it is NOT part of the
cross-run identity because node ids may change between runs.

FAIL CLOSED: if the source text needed to serialize a site column or a same-line
declaration ordinal is unavailable, the identity is marked `identity_unverifiable`; such
records are NEVER merged by dedup and are excluded from trust decisions -- the fact-list
appearance order is NEVER used as a fallback identity.

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
# Precedence for the canonical operation at a shared physical-write identity: the frozen
# cursor producer owns the sites it recognizes; capability 3 (direct) owns only the
# remainder; cap2 (call_site_summary) is the interprocedural propagation. See
# CAP3_DOMAIN_AUDIT.json / CAP2_CAP3_BOUNDARY_FROZEN.md.
PRECEDENCE = {"cursor_producer": 0, "direct": 1, "call_site_summary": 2}


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


_MEMBER_TGT = re.compile(r"^[A-Za-z_]\w*\s*(?:->|\.)\s*[A-Za-z_]\w*$")


def write_target(call):
    """Destination expression this call writes, or None if the call is not a write. Covers
    pointer-dereference / indexed writes (`*p`, `p[i]`) AND struct-member writes
    (`p->field`, `p.field`) so capability 3's member writes get proper physical identities.
    (Only `*`-prefixed targets are treated as pointer-WALK writes by direct_walk_write_sites.)"""
    nm = call.get("name")
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if nm == "<operator>.assignment" and args:
        tgt = (args[0].get("code") or "").strip()
        if tgt.startswith("*") or "[" in tgt or _MEMBER_TGT.match(tgt):
            return tgt
        return None
    di = COPY_SINKS.get(nm)
    if di is not None and di < len(args):
        return (args[di].get("code") or "").strip()
    return None


def _line_text(root, file, line):
    """The source text of `file`:`line` (1-indexed), or None if unavailable."""
    if not root or not file or not line:
        return None
    try:
        with open(os.path.join(root, file), "r", errors="replace") as fh:
            for i, txt in enumerate(fh, 1):
                if i == line:
                    return txt.rstrip("\n")
    except Exception:
        return None
    return None


def _occurrence_columns(line_text, needle):
    """Start columns of `needle` (whitespace-flexible) in a source line, sorted."""
    if not line_text or not needle:
        return []
    toks = needle.split()
    pat = r"\s*".join(re.escape(t) for t in toks) if toks else re.escape(needle)
    return sorted(m.start() for m in re.finditer(pat, line_text))


def write_dest_arg(call):
    """The destination ARGUMENT node (carrying id/kind) this write targets, or None.
    Mirrors write_target: pointer-deref / indexed / struct-member assignment LHS, or a
    copy-sink destination argument."""
    nm = call.get("name")
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if nm == "<operator>.assignment" and args:
        tgt = (args[0].get("code") or "").strip()
        if tgt.startswith("*") or "[" in tgt or _MEMBER_TGT.match(tgt):
            return args[0]
        return None
    di = COPY_SINKS.get(nm)
    if di is not None and di < len(args):
        return args[di]
    return None


def _descend_to_identifier(argnode, call_by_id):
    """Walk down argument index 0 (the pointer base) until an IDENTIFIER node, return its id."""
    node = argnode
    for _ in range(32):
        if node is None:
            return None
        if node.get("kind") == "IDENTIFIER":
            return node.get("id")
        c = call_by_id.get(node.get("id"))
        if not c:
            return None
        a = sorted(c.get("arguments", []), key=lambda x: x.get("index", 0))
        if not a:
            return None
        node = a[0]
    return None


def _init_column(local, txt, d, call_by_id, ident_by_id):
    """Source column of a local's initializer on its decl line, located via the RHS text of
    the assignment whose LHS reference-targets this local. None if not locatable."""
    if txt is None:
        return None
    lid, mid, line = local.get("id"), local.get("method_id"), local.get("line")
    for c in d.get("calls", []):
        if (c.get("name") != "<operator>.assignment" or c.get("enclosing_function_id") != mid
                or c.get("line") != line):
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        if len(args) < 2:
            continue
        idid = _descend_to_identifier(args[0], call_by_id)
        ident = ident_by_id.get(idid)
        if not ident or lid not in (ident.get("ref_target_ids") or []):
            continue
        cols = _occurrence_columns(txt, (args[1].get("code") or "").strip())
        if len(cols) == 1:
            return cols[0]
        acols = _occurrence_columns(txt, _norm_code(c.get("code") or ""))
        return acols[0] if len(acols) >= 1 else None
    return None


def build_index(d):
    """Precompute declarations, reference-target edges, and SOURCE-DERIVED positions. NO
    positional component comes from fact-list order or node ids. Where the source text
    needed to serialize a position is unavailable, the affected node is marked UNVERIFIABLE
    (fail closed) rather than falling back to appearance order."""
    meta = (d.get("metadata") or [{}])[0]
    root = meta.get("root")
    funcs = {f["id"]: f for f in d.get("functions", [])}
    call_by_id = {c.get("id"): c for c in d.get("calls", [])}
    ident_by_id = {i.get("id"): i for i in d.get("identifiers", [])}
    params_by_id = {}
    for f in d.get("functions", []):
        for p in (f.get("parameters") or []):
            params_by_id[p.get("id")] = (f["id"], p)
    locals_by_id = {l.get("id"): l for l in d.get("locals", [])}

    # declaration ordinal per local node id (source-column rank; group size 1 -> 0; else via
    # initializer column). Fail closed (decl_unverifiable) when source/init not resolvable.
    local_groups = defaultdict(list)
    for l in d.get("locals", []):
        local_groups[(l.get("method_id"), _norm_code(l.get("code") or l.get("name")),
                      l.get("line"))].append(l)
    decl_ordinal = {}
    decl_unverifiable = set()
    for (mid, _code, line), decls in local_groups.items():
        if len(decls) == 1:
            decl_ordinal[decls[0].get("id")] = 0
            continue
        txt = _line_text(root, _norm_path(funcs.get(mid, {}).get("file")), line)
        colmap = {}
        for l in decls:
            col = _init_column(l, txt, d, call_by_id, ident_by_id)
            if col is None:
                break
            colmap[l.get("id")] = col
        if len(colmap) == len(decls) and len(set(colmap.values())) == len(decls):
            for rank, (nid, _col) in enumerate(sorted(colmap.items(), key=lambda kv: kv[1])):
                decl_ordinal[nid] = rank
        else:
            for l in decls:
                decl_unverifiable.add(l.get("id"))

    # site column per write call (pairs same-target writes on a line to their source columns)
    byline = defaultdict(list)
    for i, c in enumerate(d.get("calls", [])):
        if write_target(c) is not None:
            byline[(c.get("enclosing_function_id"), c.get("line"),
                    _norm_code(write_target(c)))].append((i, c))
    site_col = {}
    site_unverifiable = set()
    for (fid, line, tgt), lst in byline.items():
        lst.sort(key=lambda ic: ic[0])
        txt = _line_text(root, _norm_path(funcs.get(fid, {}).get("file")), line)
        cols = _occurrence_columns(txt, tgt)
        if txt is not None and len(cols) == len(lst):
            for (_i, c), col in zip(lst, cols):
                site_col[c.get("id")] = col
        else:
            for _i, c in lst:
                site_unverifiable.add(c.get("id"))

    return {"funcs": funcs, "root": root, "call_by_id": call_by_id,
            "ident_by_id": ident_by_id, "params_by_id": params_by_id,
            "locals_by_id": locals_by_id, "decl_ordinal": decl_ordinal,
            "decl_unverifiable": decl_unverifiable, "site_col": site_col,
            "site_unverifiable": site_unverifiable}


def resolve_dest_declaration(call, index):
    """STEP 1 -- resolve the write target to its declaration NODE via Joern's reference
    target (`ref_target_ids`). Returns a decl node id, or None if unresolved/ambiguous. This
    is a semantic resolution, NOT a name or nearest-declaration heuristic."""
    arg = write_dest_arg(call)
    if arg is None:
        return None
    idid = _descend_to_identifier(arg, index["call_by_id"])
    ident = index["ident_by_id"].get(idid)
    if not ident:
        return None
    refs = ident.get("ref_target_ids") or []
    return refs[0] if len(refs) == 1 else None


def serialize_declaration(decl_node_id, index):
    """STEP 2 -- serialize a RESOLVED declaration node into a stable cross-run identity.
    Returns (identity_tuple, verifiable_bool). Source position only serializes; it does not
    decide which declaration is meant (that was step 1)."""
    if decl_node_id is None:
        return ("unresolved_ref",), False
    if decl_node_id in index["params_by_id"]:
        fid, p = index["params_by_id"][decl_node_id]
        f = index["funcs"].get(fid, {})
        return ("param", _norm_path(f.get("file")), f.get("name"), p.get("line"),
                _norm_code(p.get("type_full_name") or ""), p.get("index")), True
    l = index["locals_by_id"].get(decl_node_id)
    if l is not None:
        f = index["funcs"].get(l.get("method_id"), {})
        if l.get("id") in index["decl_unverifiable"]:
            return ("local_unverifiable", _norm_path(f.get("file")), f.get("name"),
                    l.get("line")), False
        return ("local", _norm_path(f.get("file")), f.get("name"), l.get("line"),
                _norm_code(l.get("code") or l.get("name")),
                index["decl_ordinal"].get(l.get("id"), 0)), True
    return ("unresolved_ref",), False


def physical_write_identity(call, index):
    """Robust cross-run identity of one physical write. Returns (identity_dict, node_id).
    node_id is within-run provenance only, excluded from the identity."""
    fid = call.get("enclosing_function_id")
    f = index["funcs"].get(fid, {})
    cid = call.get("id")
    site_ok = cid in index["site_col"]
    site = ("col", index["site_col"][cid]) if site_ok else ("unverifiable",)
    decl_node = resolve_dest_declaration(call, index)
    dest_decl, decl_ok = serialize_declaration(decl_node, index)
    ident = {
        "file": _norm_path(f.get("file")),
        "function": [f.get("name"), f.get("line"), f.get("line_end")],
        "line": call.get("line"),
        "site": list(site),
        "write": [call.get("name"), _norm_code(write_target(call))],
        "dest_decl": list(dest_decl),
        "verifiable": bool(site_ok and decl_ok),
    }
    return ident, cid


def local_declaration_identities(cpp):
    """Declaration-level identities of every local (ref-target serialization). For the
    shadowed-locals control."""
    d = json.load(open(cpp)) if isinstance(cpp, str) else cpp
    index = build_index(d)
    out = []
    for nid, l in index["locals_by_id"].items():
        f = index["funcs"].get(l.get("method_id"), {})
        ser, ok = serialize_declaration(nid, index)
        out.append({"file": _norm_path(f.get("file")), "function": f.get("name"),
                    "name": l.get("name"), "line": l.get("line"),
                    "serialized": list(ser), "verifiable": ok})
    return out


def decl_identity_key(rec):
    return tuple(rec["serialized"])


def _ident_of(rec_or_ident):
    if "underlying_write" in rec_or_ident and rec_or_ident.get("underlying_write"):
        return rec_or_ident["underlying_write"]
    if "identity" in rec_or_ident:
        return rec_or_ident["identity"]
    return rec_or_ident


def is_verifiable(rec_or_ident):
    return bool(_ident_of(rec_or_ident).get("verifiable", True))


def identity_key(rec_or_ident):
    """Hashable cross-run key. FAIL CLOSED: an unverifiable identity gets a unique key so it
    can never be merged with anything (dedup also flags it and excludes it from trust)."""
    ident = _ident_of(rec_or_ident)
    if not ident.get("verifiable", True):
        node = (rec_or_ident.get("node_id")
                or rec_or_ident.get("underlying_write_node_id") or id(rec_or_ident))
        return ("UNVERIFIABLE", node)
    return (ident.get("file"), tuple(ident.get("function") or []), ident.get("line"),
            tuple(ident.get("site") or []), tuple(ident.get("write") or []),
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
    attribution (direct > call_site_summary); all contributing records kept as provenance.
    FAIL CLOSED: unverifiable records are never merged and are flagged
    identity_unverifiable=True so trust decisions can exclude them."""
    groups = defaultdict(list)
    unverifiable = []
    for r in records:
        if is_verifiable(r):
            groups[identity_key(r)].append(r)
        else:
            unverifiable.append(r)
    ops = []
    for key, recs in sorted(groups.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        canonical = min(recs, key=lambda r: PRECEDENCE.get(r.get("attribution"), 9))
        ident = _ident_of(canonical)
        prov = [{"attribution": r.get("attribution"), "capability": r.get("capability"),
                 "function": r.get("function"), "node_id": r.get("node_id"),
                 "resolved_dest_param": r.get("resolved_dest_param")} for r in recs]
        ops.append({"identity": ident, "identity_unverifiable": False,
                    "canonical_capability": canonical.get("capability"),
                    "canonical_attribution": canonical.get("attribution"),
                    "n_provenance_paths": len(prov), "provenance": prov})
    for r in unverifiable:
        ops.append({"identity": _ident_of(r), "identity_unverifiable": True,
                    "canonical_capability": r.get("capability"),
                    "canonical_attribution": r.get("attribution"),
                    "n_provenance_paths": 1,
                    "provenance": [{"attribution": r.get("attribution"),
                                    "capability": r.get("capability"),
                                    "function": r.get("function"),
                                    "node_id": r.get("node_id")}]})
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
