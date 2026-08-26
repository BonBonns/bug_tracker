#!/usr/bin/env python3
"""JS-PROV-R17 — TransformInputOriginFact.

FROZEN THREE-WAY DISTINCTION (JS-PROV-R16). These must never collapse:

    DERIVED_FROM_HTTP_BODY
        output provenance itself is established as derived from the HTTP body
    TRANSFORM_INPUT {HTTP_BODY, HTTP_QUERY}
        those origins entered the transformation, but OUTPUT provenance is
        NOT established
    UNKNOWN
        no useful origin evidence at all

An opaque transformation does not erase all provenance evidence: its output
origin may remain unestablished while the origins known to have ENTERED it
remain separately reportable.

Set-valued and open-world, per JS-PROV-R04: `input_origins` is a SET, and
`unconstrained_input` records that at least one argument's provenance could not
be resolved -- so `{HTTP_BODY}` is never implied to be exhaustive.

No third-party semantics are modelled. A call with no resolvable callee is a
transform boundary; a locally-defined value-preserving helper is NOT
distinguished from an arbitrary one (JS-PROV-R16 T8 vs T9).
"""
import json, sys
from pathlib import Path

_HTTP = [("request.body", "HTTP_BODY"), ("query", "HTTP_QUERY"),
         ("params", "HTTP_PATH_PARAM"), ("headers", "HTTP_HEADER"),
         ("cookies", "HTTP_COOKIE")]


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    return [x for x in (l.split("\t") for l in p.read_text().splitlines() if l.strip()) if len(x) == n]


def _direct_origin(code, ctx_names):
    """A direct `<ctx>.request.body`-style read. `ctx` is supplied POSITIONALLY
    by the caller (parameter index 1), never matched by name."""
    c = (code or "").strip()
    for cn in ctx_names:
        if c.startswith(cn + "."):
            rest = c[len(cn) + 1:]
            for pat, fam in _HTTP:
                if rest == pat or rest.startswith(pat + "."):
                    return fam
    return None


def build_exprs(raw):
    """JS-PROV-R18 — ArgumentValueRef targets keyed by NODE ID, never by code
    string. Code strings are not identities: two syntactically identical inline
    objects at different callsites are distinct nodes and must stay distinct."""
    out = {}
    for nid, label, spreads, code in _rows(Path(raw) / "expr_nodes.tsv", 4):
        out[nid] = {"label": label, "spreads": [x for x in spreads.split("|") if x],
                    "code": code}
    return out


def build(raw):
    defs = {}
    for m, name, lbl, kind, callee, ncal, spreads, cargs, code in _rows(Path(raw) / "local_defs.tsv", 9):
        defs.setdefault((m, name), {
            "label": lbl, "kind": kind, "callee": callee, "ncallee": int(ncal),
            "spreads": [s for s in spreads.split("|") if s],
            "args": [a for a in cargs.split("|") if a], "code": code})
    return defs


def resolve_ref(defs, exprs, method, ref, ctx_names, depth, seen):
    """Resolve an ArgumentValueRef: LOCAL:<name> | EXPRESSION_NODE:<id>."""
    if ref.startswith("LOCAL:"):
        return resolve(defs, method, ref[6:], ctx_names, depth + 1, seen, exprs)
    if ref.startswith("EXPRESSION_NODE:"):
        node = exprs.get(ref[16:])
        if node is None:
            return set(), True, None
        # An expression node may itself be a direct context read, e.g.
        # `opaque(ctx.request.body)` -- the argument node IS the field access.
        d = _direct_origin(node["code"], ctx_names)
        if d:
            return {d}, False, None
        # Otherwise ONLY this node's own direct spread sources are inspected.
        orgs, unc = set(), False
        if not node["spreads"]:
            return set(), True, None      # literal-only / unmodelled expression
        for src in node["spreads"]:
            o, u, _ = resolve(defs, method, src, ctx_names, depth + 1, seen, exprs)
            orgs |= o
            unc = unc or u
        return orgs, unc, None
    return set(), True, None


def resolve(defs, method, expr, ctx_names, depth=0, seen=None, exprs=None):
    """-> (origins:set, unconstrained:bool, transform:dict|None)"""
    seen = seen or set()
    if depth > 12 or not expr:
        return set(), True, None
    e = expr.strip()
    d = _direct_origin(e, ctx_names)
    if d:
        return {d}, False, None
    key = (method, e)
    if key in seen:
        return set(), True, None
    seen = seen | {key}
    rec = defs.get(key)
    if rec is None:
        return set(), True, None            # unresolved -> open-world

    # Object literal with spreads: union of the SOURCE operands.
    # GUARDED (JS-PROV-R17): only when the RHS is ITSELF an object literal.
    # A CALL's arguments may CONTAIN spreads -- e.g.
    #   await schema.validate({ ...ctx.request.body, ...ctx.query })
    # and harvesting those would report the CALL'S RESULT as established from
    # body+query, manufacturing provenance across an unmodelled transform.
    # That is precisely the error this milestone exists to prevent.
    if rec["spreads"] and rec["label"] != "CALL":
        orgs, unc = set(), False
        for s in rec["spreads"]:
            o, u, _ = resolve(defs, method, s, ctx_names, depth + 1, seen)
            orgs |= o
            unc = unc or u
        return orgs, unc, None

    kind = rec["kind"]
    if kind in ("<operator>.await",) and rec["args"]:
        return resolve_ref(defs, exprs or {}, method, rec["args"][0], ctx_names, depth, seen)
    if kind == "<operator>.fieldAccess" and len(rec["args"]) >= 1:
        # destructuring / member read: provenance of the BASE (R16 Q3)
        return resolve_ref(defs, exprs or {}, method, rec["args"][0], ctx_names, depth, seen)
    if kind == "IDENTIFIER":
        return resolve(defs, method, rec["code"], ctx_names, depth + 1, seen, exprs)
    if rec["label"] == "CALL" and not kind.startswith("<operator>."):
        # TRANSFORM BOUNDARY. No third-party semantics: output is NOT established.
        orgs, unc = set(), False
        for a in rec["args"]:
            o, u, _ = resolve_ref(defs, exprs or {}, method, a, ctx_names, depth, seen)
            orgs |= o
            unc = unc or u
        return set(), True, {"transform_call": rec["code"], "callee": rec["callee"],
                             "callee_resolvable": rec["ncallee"] > 0,
                             "input_origins": sorted(orgs), "unconstrained_input": unc,
                             "output_origin_established": False}
    return set(), True, None


def classify(defs, method, expr, ctx_names, exprs=None):
    orgs, unc, tr = resolve(defs, method, expr, ctx_names, exprs=exprs or {})
    if tr is not None:
        return {"origin_family": "UNKNOWN",
                "transform_input_origins": tr["input_origins"],
                "unconstrained_input": tr["unconstrained_input"],
                "transform": "UNMODELLED_CALL",
                "transform_call": tr["transform_call"],
                "output_origin_established": False}
    if orgs:
        fams = sorted(orgs)
        return {"origin_family": fams[0] if len(fams) == 1 else "MULTIPLE",
                "origin_families": fams, "transform_input_origins": [],
                "unconstrained_input": unc, "transform": None,
                "output_origin_established": True}
    return {"origin_family": "UNKNOWN", "transform_input_origins": [],
            "unconstrained_input": unc, "transform": None,
            "output_origin_established": False}


if __name__ == "__main__":
    defs = build(sys.argv[1])
    ctx = sys.argv[3].split(",") if len(sys.argv) > 3 else ["ctx"]
    print(json.dumps(classify(defs, sys.argv[2], sys.argv[4], ctx), indent=2))
