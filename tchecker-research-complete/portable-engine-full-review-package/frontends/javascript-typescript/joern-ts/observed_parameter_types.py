#!/usr/bin/env python3
"""JS-PROV-R08 — ObservedParameterTypeFact derivation.

Implements EXACTLY the rule JS-PROV-R04 specified, gated by the safe-input
constraints JS-PROV-R05 measured. Nothing broader.

WHAT THIS IS
------------
For a call whose callee is resolved to exactly one method, bind the argument's
type at index i to the callee's parameter at index i -- as OBSERVATIONAL
evidence recorded in a separate fact, never by mutating parameter.typeFullName.

WHAT THIS IS NOT
----------------
This does NOT recover the concrete runtime type of a value. Per the guardrail
frozen in JS-PROV-R04/R05:

    Argument->parameter propagation may preserve the type evidence VISIBLE AT
    A CALLSITE; it must never be described as recovering the concrete runtime
    type of the value.

Accordingly the emitted resolution is CALLSITE_PROPAGATED and the fact carries
`declared_type` alongside, never replacing it.

JOIN SEMANTICS (JS-PROV-R04 Q2)
-------------------------------
`observed_types` is a SET, never last-writer-wins and never a collapsed
supertype -- both were explicitly forbidden, and R04 measured that genuine
conflicts ({Router, Db}) are observable and that downstream consumers (R11/R12)
need the alternatives separable.

`ANY` NEVER reduces to a concrete type (JS-STATE-R11 invariant: ANY is not a
domain, it is the absence of one). A callsite passing ANY sets
`unconstrained_callsite = True`, which downstream MUST read as "this
parameter's domain is not established" regardless of what else is in the set.

SAFE-INPUT GATES (JS-PROV-R05)
------------------------------
G1 callee resolved to exactly ONE method                       (R04 Q9)
G2 argument is a plain IDENTIFIER                              (R05: constructor
   calls type as BLOCK; casts type as ANY and are mutually indistinguishable)
G3 argument carries no `<operator>.cast` hint                  (R05 Q8)
G4 callee parameter's declared type is ANY                     (R04 Q3 -- a
   stronger declared contract is preserved automatically)
G5 parameter is not variadic/rest                              (R05/R04 Q5 --
   argument index maps to an array ELEMENT, not the parameter; the ANY-gate
   would abstain only incidentally, so this is checked explicitly)
G6 argument's type short-name is NOT ambiguous across the program (R05-2 --
   the confirmed import-alias mis-binding defect; abstain rather than trust a
   possibly-fabricated nominal type)
G7 callee is not a `<operator>.*` intrinsic  (operand slots are not bindings)

Failing any gate records an abstention with its reason rather than silently
dropping the callsite.
"""
import base64, json, sys
from pathlib import Path

_d = lambda s: (base64.b64decode(s).decode() if s else "")


def _short(t):
    """Short name of a type full name, for the G6 ambiguity guard."""
    if not t:
        return ""
    t = t.split(":<init>")[0]
    for sep in ("::program:", ":"):
        if sep in t:
            t = t.rsplit(sep, 1)[-1]
    return t


def _norm(t):
    """R05 Q1: one concept can have several spellings (`X` vs `X:<init>`).
    Strip only the constructor suffix -- deliberately NOT a general name
    normalization, which R05 showed would ALSO merge genuinely-distinct
    same-named classes from different modules."""
    return t[: -len(":<init>")] if t.endswith(":<init>") else t


def derive(raw):
    raw = Path(raw)

    typedecls = []
    for line in (raw / "typedecls.tsv").read_text().splitlines():
        if not line.strip():
            continue
        tid, name, full, ext = line.split("\t")
        typedecls.append({"id": int(tid), "name": name, "full": full,
                          "external": ext.strip().lower() == "true"})

    # G6: a short name is ambiguous if >1 NON-EXTERNAL decl declares it.
    # External stubs are excluded because R05 showed every type has a duplicate
    # stub, which would make every name look ambiguous.
    by_short = {}
    for td in typedecls:
        if not td["external"]:
            by_short.setdefault(td["name"], set()).add(td["full"])
    ambiguous_shorts = {n for n, fulls in by_short.items() if len(fulls) > 1}

    observed = {}     # (callee_id, param_index) -> fact under construction
    abstentions = []

    for line in (raw / "callsites.tsv").read_text().splitlines():
        if not line.strip():
            continue
        (call_id, callee_id, callee_full, argidx, kind, argtype, hints,
         pname, ptype, pvariadic, pcode) = line.split("\t")
        call_id, callee_id, argidx = int(call_id), int(callee_id), int(argidx)
        variadic = pvariadic.strip().lower() == "true"

        if argidx == 0:            # implicit `this` -- not a propagation target
            continue
        # G7: language-intrinsic operators are not propagation targets. Their
        # "parameters" are operand slots, not user-declared bindings, so binding
        # observed types into them produces noise, not evidence. This is a closed
        # set of language constructs (same category as R07's builtin table), not
        # a heuristic over user-chosen names.
        if callee_full.startswith("<operator>."):
            continue
        if pname == "":            # no matching parameter at this index
            continue

        key = (callee_id, argidx)
        rec = observed.setdefault(key, {
            "callee_method_id": callee_id,
            "callee_full_name": callee_full,
            "parameter_index": argidx,
            "parameter_name": pname,
            "declared_type": ptype,
            "observed_types": set(),
            "unconstrained_callsite": False,
            "source_call_ids": [],
            "abstained_call_ids": [],
        })

        def abstain(reason):
            abstentions.append({"call_id": call_id, "callee_full_name": callee_full,
                                "parameter_index": argidx, "reason": reason,
                                "arg_type": argtype})
            rec["abstained_call_ids"].append(call_id)

        # G4 -- stronger declared contract preserved
        if ptype != "ANY":
            abstain("G4_DECLARED_TYPE_PRESENT"); continue
        # G5 -- rest/variadic parameter: index maps to an ELEMENT, not the param
        if variadic or pcode.strip().startswith("..."):
            abstain("G5_VARIADIC_PARAMETER"); continue
        # G2 -- only plain identifiers carry a usable callsite type
        if kind != "IDENTIFIER":
            abstain(f"G2_ARG_NOT_IDENTIFIER({kind})"); continue
        # G3 -- cast-erased argument
        if "<operator>.cast" in hints:
            abstain("G3_CAST_ERASED_ARGUMENT"); continue

        # ANY never reduces to a concrete type (R11 invariant)
        if argtype == "ANY" or argtype == "":
            rec["unconstrained_callsite"] = True
            rec["source_call_ids"].append(call_id)
            continue

        # G6 -- short-name ambiguity guard (R05-2 confirmed defect)
        if _short(argtype) in ambiguous_shorts:
            abstain(f"G6_AMBIGUOUS_SHORT_NAME({_short(argtype)})"); continue

        rec["observed_types"].add(_norm(argtype))
        rec["source_call_ids"].append(call_id)

    facts = []
    for rec in observed.values():
        if not rec["observed_types"] and not rec["unconstrained_callsite"]:
            continue
        f = dict(rec)
        f["observed_types"] = sorted(rec["observed_types"])
        f["resolution"] = "CALLSITE_PROPAGATED"
        # Downstream contract: an unconstrained callsite means the parameter's
        # domain is NOT established, whatever else was observed.
        f["domain_established"] = (
            bool(f["observed_types"]) and not rec["unconstrained_callsite"]
        )
        facts.append(f)

    return {
        "schema": "portable-observed-parameter-types/0.1",
        "note": ("CALLSITE_PROPAGATED evidence about types VISIBLE AT CALLSITES. "
                 "NOT a recovery of concrete runtime types. observed_types is a SET; "
                 "unconstrained_callsite=True means the domain is NOT established "
                 "regardless of set contents. declared_type is carried alongside and "
                 "is never replaced."),
        "facts": facts,
        "abstentions": abstentions,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2, default=str))
