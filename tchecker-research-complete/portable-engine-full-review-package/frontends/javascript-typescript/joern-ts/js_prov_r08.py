#!/usr/bin/env python3
"""JS-PROV-R08 — Safe Receiver-Type Propagation.

Implements ONLY the propagation mechanism characterized in JS-PROV-R04, under
the reliability constraints measured in JS-PROV-R05. It does NOT touch
framework-registration logic (JS-PROV-R07), does NOT use candidate-callee
membership to compensate for a missing receiver, and does NOT write anything
into `parameter.typeFullName`.

## The open-world type-evidence lattice

Propagated evidence is deliberately TWO-dimensional. These four states are
distinguishable and must stay distinguishable, because "we observed Router"
is not the same claim as "the receiver is provably Router":

    observed_types={T},      unconstrained=False
        -> CLOSED_SINGLE: closed observed domain, one concrete type.
           The only state usable as positive proof for exclusive dispatch.

    observed_types={T},      unconstrained=True
        -> OPEN_SINGLE: T was observed, but at least one callsite passed an
           unconstrained value, so the domain remains OPEN. Insufficient for
           exclusive dispatch claims.

    observed_types={T,U,...},unconstrained=any
        -> CONFLICT: genuine multiple concrete observations. Insufficient for
           unique dispatch. NOT collapsed to a supertype, NOT last-win.

    observed_types={},       unconstrained=True
        -> NO_EVIDENCE: no useful receiver-domain proof.

This is an open-world lattice, not a Koa-specific trick: `unconstrained` is the
world-openness axis and `observed_types` is the observation axis. Per R11's
standing invariant, ANY is not a domain — it is the absence of one — so an ANY
callsite can only ever OPEN the world, never contribute a member.

## R05-derived safe-input constraints (all enforced, each independently)

  - callee resolved to exactly ONE method (R04 Q9)
  - argument is a plain IDENTIFIER (constructor calls export as BLOCK; casts
    export as ANY — R05 Q8)
  - argument's short name is UNIQUE program-wide (guards the R05-2
    imported-alias mis-binding, which cannot be detected any other way)
  - argument carries no `<operator>.cast` hint (R05 Q2/Q8)
  - target parameter's declared type is ANY (never overwrite a stronger
    declared contract — R04 Q3)
  - target parameter is NOT a rest parameter (R04 Q5; detected structurally
    from its `code`, not by relying on the ANY-gate coincidentally abstaining)

Anything failing a constraint contributes NOTHING — it does not silently
degrade into an unconstrained observation either, because a skipped callsite is
not evidence that the world is open; it is evidence we did not look.
EXCEPTION: an argument that IS analyzable and IS unconstrained (typed ANY) DOES
set unconstrained=True. That distinction is the point of constraint auditing.
"""
import base64, json, sys
from collections import defaultdict
from pathlib import Path

_d = lambda s: base64.b64decode(s).decode("utf-8", "replace") if s else ""


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) >= n:
            out.append(xs)
    return out


def canonicalize(t):
    """R04 Q1: collapse equivalent spellings of ONE type identity.

    Measured equivalences (JS-PROV-R04/R05):
      X               (declared-return spelling)
      X:<init>        (constructor spelling)
      X:<returnValue> (factory-return spelling)
    Returns None for types that carry no domain information.
    """
    if not t:
        return None
    if t in ("ANY", "", "<unknownFullName>"):
        return None
    for suffix in (":<init>", ":<returnValue>"):
        while t.endswith(suffix):
            t = t[: -len(suffix)]
    return t or None


def derive(raw):
    raw = Path(raw)

    methods = {}
    for r in _rows(raw / "methods.tsv", 10):
        methods[int(r[0])] = {"id": int(r[0]), "name": _d(r[1]), "full_name": _d(r[2])}

    # parameters, keyed (method_id, index); retain code for rest detection
    params = {}
    for r in _rows(raw / "parameters.tsv", 7):
        params[(int(r[1]), int(r[2]))] = {
            "id": int(r[0]), "method_id": int(r[1]), "index": int(r[2]),
            "name": _d(r[3]), "code": _d(r[4]), "declared_type": _d(r[5]),
        }

    calls = {}
    for r in _rows(raw / "calls.tsv", 11):
        calls[int(r[0])] = {
            "id": int(r[0]), "name": _d(r[2]),
            "callee_ids": [int(x) for x in r[9].split(",") if x.strip()],
        }

    args = defaultdict(list)
    for r in _rows(raw / "arguments.tsv", 8):
        args[int(r[1])].append({
            "node_id": int(r[0]), "index": int(r[2]), "kind": _d(r[3]),
            "code": _d(r[4]), "name": _d(r[5]), "type": _d(r[6]),
        })

    hints = defaultdict(list)
    for r in _rows(raw / "type_hints.tsv", 3):
        hints[int(r[1])].append(_d(r[2]))

    # R05-2 guard: short-name uniqueness across the whole program.
    # IMPORTANT (measured in R08): every locally-declared class ALSO has a
    # duplicate EXTERNAL STUB TYPE_DECL (R05 Q1). Counting stubs would mark
    # EVERY class-typed argument ambiguous and over-abstain to uselessness.
    # Only NON-EXTERNAL declarations can constitute a genuine collision.
    short_counts = defaultdict(set)
    for r in _rows(raw / "type_decls.tsv", 7):
        if r[5].strip().lower() == "true":
            continue                      # external stub — not a real declaration
        full = _d(r[2])
        if full:
            short_counts[_d(r[1])].add(full)
    ambiguous_short_names = {n for n, fulls in short_counts.items() if len(fulls) > 1}

    observations = defaultdict(lambda: {"types": set(), "unconstrained": False,
                                        "sources": [], "skipped": []})

    for call in calls.values():
        # CONSTRAINT: exactly one resolved callee
        if len(call["callee_ids"]) != 1:
            continue
        callee_id = call["callee_ids"][0]
        if callee_id not in methods:
            continue
        # CONSTRAINT: ordinary parameter callsites only. Operator lowerings
        # (<operator>.assignment/fieldAccess/...) are not ordinary functions;
        # propagating into their synthetic p0/p1 parameters produces facts with
        # no program meaning. Measured in R08's first run as pure noise.
        if methods[callee_id]["name"].startswith("<operator>."):
            continue

        for a in sorted(args.get(call["id"], []), key=lambda x: x["index"]):
            key = (callee_id, a["index"])
            p = params.get(key)
            if p is None:
                continue
            if p["name"] == "this":
                continue
            # CONSTRAINT: never overwrite a stronger declared contract
            if p["declared_type"] != "ANY":
                continue
            # CONSTRAINT: rest parameters excluded structurally
            if p["code"].startswith("..."):
                observations[key]["skipped"].append(
                    {"call_id": call["id"], "reason": "REST_PARAMETER"})
                continue

            rec = observations[key]

            # CONSTRAINT: argument must be a plain identifier
            if a["kind"] != "IDENTIFIER":
                rec["skipped"].append({"call_id": call["id"],
                                       "reason": f"ARG_NOT_IDENTIFIER:{a['kind']}"})
                continue
            # CONSTRAINT: no cast-erased argument
            if any("<operator>.cast" in h for h in hints.get(a["node_id"], [])):
                rec["skipped"].append({"call_id": call["id"], "reason": "CAST_ERASED"})
                continue

            canon = canonicalize(a["type"])

            if canon is None:
                # Analyzable AND unconstrained -> the world is genuinely open.
                rec["unconstrained"] = True
                rec["sources"].append({"call_id": call["id"], "arg": a["code"],
                                       "raw_type": a["type"], "canonical": None,
                                       "effect": "OPENS_WORLD"})
                continue

            # CONSTRAINT: R05-2 short-name ambiguity guard
            short = canon.rsplit(":", 1)[-1]
            if short in ambiguous_short_names:
                rec["skipped"].append({"call_id": call["id"],
                                       "reason": f"AMBIGUOUS_SHORT_NAME:{short}"})
                continue

            rec["types"].add(canon)
            rec["sources"].append({"call_id": call["id"], "arg": a["code"],
                                   "raw_type": a["type"], "canonical": canon,
                                   "effect": "OBSERVES_TYPE"})

    facts = []
    for (mid, idx), rec in sorted(observations.items()):
        if not rec["sources"]:
            continue
        p = params[(mid, idx)]
        types = sorted(rec["types"])
        unc = rec["unconstrained"]
        if len(types) > 1:
            state = "CONFLICT"
        elif len(types) == 1:
            state = "OPEN_SINGLE" if unc else "CLOSED_SINGLE"
        else:
            state = "NO_EVIDENCE"
        facts.append({
            "callee_method_id": mid,
            "callee_method_name": methods.get(mid, {}).get("name", ""),
            "parameter_index": idx,
            "parameter_name": p["name"],
            "parameter_value_id": p["id"],
            "declared_type": p["declared_type"],       # retained ALONGSIDE
            "observed_types": types,                   # SET, never collapsed
            "unconstrained_callsite": unc,
            "evidence_state": state,
            "usable_as_exclusive_dispatch_proof": state == "CLOSED_SINGLE",
            "source_call_ids": [s["call_id"] for s in rec["sources"]],
            "derivation": rec["sources"],              # inspectable provenance
            "skipped_callsites": rec["skipped"],
            "resolution": "CALLSITE_PROPAGATED",
        })

    return {
        "schema": "portable-observed-parameter-type-facts/0.1",
        "note": "Propagated observations are evidence about types VISIBLE AT "
                "CALLSITES, never a claim about the concrete runtime type. "
                "declared_type is retained separately and is never overwritten. "
                "Only evidence_state=CLOSED_SINGLE may support an exclusive "
                "dispatch claim.",
        "facts": facts,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
