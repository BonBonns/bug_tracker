#!/usr/bin/env python3
"""v2 evidence capability: single-object-copy bounding (post-pass over frozen v1).

v1 is NOT modified. This wraps the frozen v1 producer and, for operations v1
ABSTAINED on with `required_evidence_absent`, applies ONE new capability:

  A write whose width is exactly one `sizeof(...)` with NO multiplier, writing
  into a destination that is provably a pointer to the sizeof'd object, writes
  exactly one pointee object. A valid pointer-to-T destination has capacity
  >= sizeof(T), so the write is deterministically bounded.

Only two SOUND forms are accepted (no naming-convention assumptions):
  A. width is `sizeof(*dest)` / `sizeof(dest[0])` — syntactic: the width is the
     pointee size of the exact destination. No type facts needed.
  B. width is `sizeof(T)` and the destination's exported type_full_name is a
     LITERAL pointer `T *` (ends in '*', pointee == T). External `X_PTR`
     typedefs whose alias is not resolvable from the facts are NOT accepted
     (they stay `required_evidence_absent`) — we never assume `X_PTR == X*`.

Never fires for `N * sizeof(T)` array writes (capacity genuinely unknown), and
never touches any non-abstained record, any warning candidate, or any other
reason code. Every promotion carries provenance: the destination type (or the
syntactic form) and the sizeof width that justified it, with
establishment_status ESTABLISHED.
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


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


_SIZEOF = re.compile(r"^\s*sizeof\s*(\(\s*(?P<paren>[^()]*)\s*\)|\s+(?P<bare>[*]?\s*[\w\[\]. >-]+))\s*$")


def _has_multiplier(width):
    """True if the width expression multiplies the sizeof by anything (array)."""
    stripped = re.sub(r"sizeof\s*\([^()]*\)", "SZ", str(width))
    stripped = re.sub(r"sizeof\s+\*?\s*[\w\[\].]+", "SZ", stripped)
    return "*" in stripped or "+" in stripped or "-" in stripped


def _sizeof_arg(width):
    """Return the single sizeof argument text, or None if width is not exactly
    one sizeof(...) with no surrounding arithmetic."""
    w = str(width).strip()
    if _has_multiplier(w):
        return None
    m = _SIZEOF.match(w)
    if not m:
        return None
    return (m.group("paren") if m.group("paren") is not None else m.group("bare")).strip()


def _pointee(type_full_name):
    """Pointee of a LITERAL pointer type, else None. 'Foo *' -> 'Foo';
    'Foo*' -> 'Foo'. A typedef name like 'CK_X_PTR' (no '*') returns None."""
    t = (type_full_name or "").strip()
    if not t.endswith("*"):
        return None
    return t[:-1].strip()


def _dest_types_in_function(d, function_full_name, dest):
    """Set of type_full_name values for identifiers named `dest` inside the
    function. Scoped to the function via method_id so a name reused across
    functions with different types does not leak."""
    fn_ids = {f["id"] for f in d.get("functions", [])
              if f.get("full_name") == function_full_name}
    types = set()
    for i in d.get("identifiers", []):
        if i.get("name") == dest and i.get("method_id") in fn_ids:
            t = i.get("type_full_name")
            if t and t not in ("ANY", "<empty>", ""):
                types.add(t)
    # also consider parameters (dest is often a pointer parameter)
    for p in d.get("parameters", []) if isinstance(d.get("parameters"), list) else []:
        if p.get("name") == dest and p.get("method_id") in fn_ids:
            t = p.get("type_full_name")
            if t and t not in ("ANY", "<empty>", ""):
                types.add(t)
    return types


def _single_object_evidence(rec, d):
    """Return an evidence dict if the abstained record is a bounded single-object
    write, else None."""
    width = rec.get("width_expr")
    dest = rec.get("dest")
    if width is None or not dest:
        return None
    arg = _sizeof_arg(width)
    if arg is None:
        return None
    # Form A: sizeof(*dest) / sizeof(dest[0]) -- syntactic, no type needed
    a = arg.replace(" ", "")
    if a == "*" + dest or a == dest + "[0]":
        return {"basis": "single_object_syntactic", "form": "sizeof(*dest)",
                "width_expr": width, "dest": dest}
    # Form B: sizeof(T) into a LITERAL T* destination
    T = arg.strip()
    for t in _dest_types_in_function(d, rec.get("function"), dest):
        p = _pointee(t)
        if p is not None and p == T:
            return {"basis": "single_object_typed", "form": "sizeof(T) into T*",
                    "dest_type": t, "pointee": p, "width_expr": width, "dest": dest}
    return None


def analyze_operations_v2(prefix, base_producer="oob_runtime_capacity_verdict"):
    """v1 records with single-object abstentions promoted to deterministic_complete.
    Returns (records, promotions) where promotions lists the changed operations."""
    v1 = _load(base_producer)
    d = json.load(open(prefix))
    records = [dict(r) for r in v1.analyze_operations(prefix)]
    promotions = []
    for r in records:
        if r.get("analysis_status") != "abstained":
            continue
        if (r.get("primary_reason_code") or r.get("reason_code")) != "required_evidence_absent":
            continue
        ev = _single_object_evidence(r, d)
        if ev is None:
            continue
        before = {"analysis_status": r["analysis_status"],
                  "reason_code": r.get("primary_reason_code") or r.get("reason_code"),
                  "route": r.get("recommended_route")}
        # promote: single-object write is deterministically bounded (proven safe)
        for k in ("reason_code", "primary_reason_code", "all_reason_codes",
                  "uncertainty_bucket", "recommended_route", "unresolved_property",
                  "llm_eligible"):
            r.pop(k, None)
        r["analysis_status"] = "deterministic_complete"
        r["recognized_operation"] = r.get("recognized_operation", "buffer_write")
        r["capacity_basis"] = "single_object_copy"
        r["establishment_status"] = "ESTABLISHED"
        r["evidence"] = ev
        r["v2_promoted"] = True
        promotions.append({
            "op_fingerprint": r.get("op_fingerprint"),
            "function": r.get("function"), "line": r.get("line"), "dest": r.get("dest"),
            "file": r.get("file"), "from": before,
            "to": {"analysis_status": "deterministic_complete"},
            "evidence": ev})
    return records, promotions


if __name__ == "__main__":
    for prefix in sys.argv[1:]:
        recs, proms = analyze_operations_v2(prefix)
        print(f"{prefix}: {len(proms)} single-object promotions")
        for p in proms[:20]:
            e = p["evidence"]
            print(f"   {p['function']}:{p['line']} dest={p['dest']} "
                  f"[{e['basis']}] {e.get('dest_type', e['form'])} width={e['width_expr']}")
