#!/usr/bin/env python3
"""JS-PROV-R21 — ExternalInputOriginFact (NestJS parameter-decorator producer).

The first path where `established = true` is defensible WITHOUT a third-party
semantics profile: the decorator states the source family at the controller
boundary, with no transform in between.

FROZEN MAPPING -- family level only, closed set:

    @Body()        -> HTTP_BODY
    @Query()       -> HTTP_QUERY
    @Param(...)    -> HTTP_PARAM
    @Headers(...)  -> HTTP_HEADERS

    evidence   = NESTJS_PARAMETER_DECORATOR
    established = true
    origin_key  = UNKNOWN     <-- ALWAYS. Never parsed from annotation code.

Any decorator outside the closed set (@Req, @Res, @GetUser, @UploadedFile,
custom application decorators) yields UNKNOWN. It is never guessed from its
name, and an undecorated parameter yields nothing at all -- no fallback to
identifier names, which JS-PROV-R20 proved would be wrong in four measured
cases (`@Query() body`, `@Body() query`, ...).

BOUNDARY vs DATAFLOW: this producer emits facts ONLY for decorated parameters.
Locals derived from them (`const x = body`) are NOT given fresh decorator
facts; they are reported as DERIVED, consuming the parameter's established
fact through ordinary dataflow. Framework evidence stays at the boundary.
"""
import json, sys
from pathlib import Path

_FAMILY = {"Body": "HTTP_BODY", "Query": "HTTP_QUERY",
           "Param": "HTTP_PARAM", "Headers": "HTTP_HEADERS"}
_ROUTE_VERBS = {"Get", "Post", "Put", "Delete", "Patch", "All", "Options", "Head"}


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    return [x for x in (l.split("\t") for l in p.read_text().splitlines() if l.strip()) if len(x) == n]


def derive(raw):
    raw = Path(raw)
    facts, unknown, derived = [], [], []

    decorated = {}   # (method, param_name) -> fact
    for cls, cann, meth, mann, idx, pname, pann in _rows(raw / "param_decorators.tsv", 7):
        cls_ann = set(a for a in cann.split("|") if a)
        meth_ann = set(a for a in mann.split("|") if a)
        # controller boundary: a @Controller class with a route-verb method
        if not any("Controller" in a for a in cls_ann):
            continue
        if not (meth_ann & _ROUTE_VERBS):
            continue
        names = [a for a in pann.split("|") if a]
        if not names:
            continue                       # undecorated -> NOTHING (no name fallback)
        fams = {_FAMILY[n] for n in names if n in _FAMILY}
        if not fams:
            unknown.append({"method": meth, "parameter_index": int(idx),
                            "parameter_name": pname, "decorators": names,
                            "origin_family": "UNKNOWN",
                            "reason": "DECORATOR_NOT_IN_CLOSED_SET"})
            continue
        if len(fams) > 1:
            unknown.append({"method": meth, "parameter_index": int(idx),
                            "parameter_name": pname, "decorators": names,
                            "origin_family": "UNKNOWN",
                            "reason": "MULTIPLE_CONFLICTING_FAMILIES"})
            continue
        f = {"value": {"method": meth, "parameter_index": int(idx),
                       "parameter_name": pname},
             "origin_family": next(iter(fams)),
             "origin_key": "UNKNOWN",
             "evidence": "NESTJS_PARAMETER_DECORATOR",
             "established": True}
        facts.append(f)
        decorated[(meth, pname)] = f

    # DERIVED: locals assigned from a decorated parameter consume the boundary
    # fact through ordinary dataflow; they never get a fresh decorator fact.
    for m, name, lbl, kind, callee, ncal, spreads, cargs, code in _rows(raw / "local_defs.tsv", 9):
        src = (code or "").strip()
        base = src.split(".")[0] if src else ""
        for cand in (src, base):
            src_fact = decorated.get((m, cand))
            if src_fact:
                derived.append({"method": m, "local": name,
                                "derived_from_parameter": cand,
                                "origin_family": src_fact["origin_family"],
                                "evidence": "DATAFLOW_FROM_ESTABLISHED_ORIGIN",
                                "established": True, "derivation": "ALIAS_OR_MEMBER"})
                break

    return {"schema": "portable-external-input-origin/0.1",
            "note": ("NestJS parameter-decorator producer. Family level only; "
                     "origin_key is ALWAYS UNKNOWN and never parsed from annotation "
                     "code. Decorators outside the closed set yield UNKNOWN, never a "
                     "name-based guess. Derived locals consume the boundary fact "
                     "rather than receiving fresh decorator facts."),
            "facts": facts, "unknown_decorators": unknown, "derived": derived}


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
