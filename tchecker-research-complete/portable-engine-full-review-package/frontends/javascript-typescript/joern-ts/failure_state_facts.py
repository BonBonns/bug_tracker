#!/usr/bin/env python3
"""JS-STATE-R02: FailureStateErasureCandidateFact derivation.

Implements ONLY the narrowest sound invariant JS-STATE-R01 identified as ready
to promote:

  A guard on instanceof/equality/relational comparison protects the exact value
  it structurally checks (via REF), and only that value. If the checked value's
  producing CALL is a member of a closed set of builtins/operators with
  spec-fixed, argument-shape-sensitive coercion semantics that are known to
  destroy a prior value's failure discriminator, the guard must not be credited
  as protecting the original callee result.

This module does NOT implement:
  - PRESERVES detection (structural passthrough proof) -- JS-STATE-R01 Q4 reason 2
  - UNKNOWN/abstain bookkeeping for arbitrary external calls -- already the
    correct default here, since anything not in the closed set is simply not
    reported (silence, not a false PRESERVES claim)
  - Any security-sensitive-sink classification -- JS-STATE-R01 Q5 found this is
    a downstream profile problem, not a core-provable fact, and deliberately out
    of scope for this module. Every fact this module emits is a
    FailureStateErasureCandidateFact, not a vulnerability, not a verdict.
  - Any use of identifier/function/variable NAMES as evidence, per the hard rule.
    The only names ever compared here are producing-CALL names against the
    closed builtin/operator set below, which is recognition of fixed language
    identifiers (the same category as recognizing "<operator>.instanceOf" by its
    canonical CPG name), not inference from programmer-chosen identifiers.

Neutral fact emitted:
  FailureStateErasureCandidateFact {
    method_id, method_name,
    control_structure_id, condition_id,
    guard_identifier_id, guard_local_id,
    transformation_call_id, transformation_name, transformation_code,
    resolution: "ERASES",
    derivation: { rule, source_node_ids }
  }
"""
import base64, json, sys
from pathlib import Path

def _d(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s

def _ids(s):
    return [int(x) for x in s.split(",") if x.strip()]

# Closed set of spec-fixed coercion builtins/operators whose semantics are known
# (from the ECMAScript spec, not from this program's code) to destroy an
# Error-shaped or null/undefined failure discriminator when applied to it.
# This is the ONLY classification table this module uses; nothing here reads a
# user-chosen identifier name.
#
# Global builtin functions (identified structurally: is_external=true,
# ast_parent_type=NAMESPACE_BLOCK, ast_parent_full_name=<global> -- see
# _is_global_builtin below, not just a bare name match).
_ERASING_GLOBAL_BUILTINS = {"Number", "String", "Boolean", "parseInt", "parseFloat"}

# Operators. Some names are shared with non-coercion uses (binary vs unary
# <operator>.plus), so arity is checked, not just the name.
_ERASING_UNARY_OPERATORS = {"<operator>.plus"}          # unary +x -> ToNumber
_ERASING_BINARY_BIT_OPERATORS = {"<operator>.or", "<operator>.and", "<operator>.xor"}  # x|0 etc -> ToInt32
_ERASING_CAST_TARGET_TYPES = {"number", "string", "boolean"}  # `x as number` etc, when x's runtime shape is Error/null
_ERASING_TEMPLATE_OPERATOR = "<operator>.formatString"    # `${x}` -> ToString


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) != n:
            raise ValueError(f"{p.name}: expected {n} cols, got {len(xs)}: {ln!r}")
        out.append(xs)
    return out


def _load(raw):
    raw = Path(raw)
    methods = {}
    for r in _rows(raw / "methods.tsv", 10):
        methods[int(r[0])] = {"id": int(r[0]), "name": _d(r[1]), "full_name": _d(r[2])}

    calls = {}
    for r in _rows(raw / "calls.tsv", 11):
        calls[int(r[0])] = {
            "id": int(r[0]), "method_id": int(r[1]), "name": _d(r[2]),
            "method_full_name": _d(r[3]), "code": _d(r[6]),
        }

    args = {}
    for r in _rows(raw / "arguments.tsv", 8):
        args.setdefault(int(r[1]), []).append({
            "node_id": int(r[0]), "index": int(r[2]), "code": _d(r[4]),
        })
    for v in args.values():
        v.sort(key=lambda a: a["index"])

    identifiers = {}
    for r in _rows(raw / "identifiers.tsv", 7):
        identifiers[int(r[0])] = {"id": int(r[0]), "method_id": int(r[1]), "refs": _ids(r[6])}

    control_structs = {}
    for r in _rows(raw / "control_structures.tsv", 6):
        cs_id = int(r[0])
        control_structs[cs_id] = {
            "id": cs_id, "method_id": int(r[1]), "type": _d(r[2]),
            "condition_id": int(r[3]) if r[3] else None,
            "condition_code": _d(r[4]), "line": r[5],
        }

    cond_idents = []  # (control_structure_id, condition_id, identifier_id, [ref_local_ids])
    for r in _rows(raw / "condition_identifiers.tsv", 4):
        cond_idents.append((int(r[0]), int(r[1]), int(r[2]), _ids(r[3])))

    return methods, calls, args, identifiers, control_structs, cond_idents


def _is_global_builtin_call(call, external_stub_names):
    return call["name"] in _ERASING_GLOBAL_BUILTINS and call["name"] in external_stub_names


def derive(raw):
    raw = Path(raw)
    methods, calls, args, identifiers, control_structs, cond_idents = _load(raw)

    # Which global-scope method stubs are external builtins, keyed by name.
    # (methods.tsv's ast_parent_full_name column isn't loaded above to keep this
    # module's surface small; recomputed here directly from the raw file.)
    external_builtin_names = set()
    for r in _rows(raw / "methods.tsv", 10):
        name = _d(r[1])
        ast_parent_full_name = _d(r[8])
        is_external = r[9].strip().lower() == "true"
        if is_external and ast_parent_full_name == "<global>" and name in _ERASING_GLOBAL_BUILTINS:
            external_builtin_names.add(name)

    # local_id -> producing CALL, derived from <operator>.assignment calls whose
    # LHS identifier's REF (identifiers.tsv column 6) names the local, and whose
    # RHS (argument index 2) is itself a CALL. No name comparison is used to
    # link LHS to RHS -- only argument position and REF ids.
    producing_call_by_local = {}
    for c in calls.values():
        if c["name"] != "<operator>.assignment":
            continue
        a = args.get(c["id"], [])
        if len(a) < 2:
            continue
        lhs_node_id = a[0]["node_id"]
        lhs_ident = identifiers.get(lhs_node_id)
        if not lhs_ident or not lhs_ident["refs"]:
            continue
        rhs_node_id = a[1]["node_id"]
        rhs_call = calls.get(rhs_node_id)
        if not rhs_call:
            continue
        for local_id in lhs_ident["refs"]:
            producing_call_by_local[local_id] = rhs_call

    facts = []
    for (cs_id, cond_id, ident_id, ref_local_ids) in cond_idents:
        cs = control_structs.get(cs_id)
        if cs is None:
            continue
        for local_id in ref_local_ids:
            producer = producing_call_by_local.get(local_id)
            if producer is None:
                continue  # not a direct-assignment target we can trace; abstain

            name = producer["name"]
            transformation_args = args.get(producer["id"], [])
            erases = False
            rule = None

            if _is_global_builtin_call(producer, external_builtin_names):
                erases = True
                rule = "GLOBAL_BUILTIN_COERCION"
            elif name in _ERASING_UNARY_OPERATORS and len(transformation_args) == 1:
                erases = True
                rule = "UNARY_COERCION_OPERATOR"
            elif name in _ERASING_BINARY_BIT_OPERATORS and len(transformation_args) == 2:
                erases = True
                rule = "BINARY_BITWISE_COERCION_OPERATOR"
            elif name == _ERASING_TEMPLATE_OPERATOR:
                erases = True
                rule = "TEMPLATE_STRING_COERCION"
            # NOTE: <operator>.cast is deliberately NOT included here. A TS
            # `as number` cast is a compile-time-only annotation with NO runtime
            # coercion effect -- it does not itself call ToNumber/ToString/etc.
            # Treating `as number` as erasing would be UNSOUND (a false claim
            # about runtime behavior). JS-STATE-R01's case8/case9 fixtures used
            # `as unknown as number` purely to satisfy the TypeScript compiler
            # before applying a REAL runtime operator (`| 0`, unary `+`); this
            # module correctly attributes the erasure to that real operator, not
            # to the cast, and cast-only chains with no runtime operator are
            # correctly NOT flagged by this implementation.

            if not erases:
                continue

            facts.append({
                "method_id": cs["method_id"],
                "method_name": methods.get(cs["method_id"], {}).get("name", ""),
                "control_structure_id": cs_id,
                "condition_id": cond_id,
                "condition_code": cs["condition_code"],
                "guard_identifier_id": ident_id,
                "guard_local_id": local_id,
                "transformation_call_id": producer["id"],
                "transformation_name": name,
                "transformation_code": producer["code"],
                "resolution": "ERASES",
                "derivation": {
                    "rule": rule,
                    "source_node_ids": [cs_id, cond_id, ident_id, local_id, producer["id"]],
                },
            })

    return {"schema": "portable-failure-state-erasure-candidate-facts/0.1", "facts": facts}


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
