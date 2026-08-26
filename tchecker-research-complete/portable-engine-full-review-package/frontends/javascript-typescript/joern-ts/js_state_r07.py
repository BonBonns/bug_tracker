#!/usr/bin/env python3
"""JS-STATE-R07: RETURN-CONTRACT + FAILURE-GUARD PRECONDITION.

Implements ONLY what JS-STATE-R06 demonstrated -- nothing broader. A
FailureStateErasureCandidateFact (JS-STATE-R02, already sink-reachability-
annotated by JS-STATE-R03/R04/R05) is promoted to an R07 CANDIDATE only if
ALL FIVE of the following hold:

  1. Existing ERASES fact (JS-STATE-R02 -- unchanged, not re-implemented here)
  2. Failure-style guard shape (SIGNAL A, this module)
  3. Positive union/return-contract evidence (SIGNAL B, this module)
  4. Guard subject = transformed value (already guaranteed by construction in
     JS-STATE-R02's own REF-based matching -- see note below, not
     re-implemented here)
  5. Sensitive sink reachability under current R04/R05 rules
     (JS-STATE-R03/R04/R05, unchanged -- security_sensitive_use == "SENSITIVE")

Item 4 needs no new code: JS-STATE-R02's `failure_state_facts.py` only ever
creates a fact when the guard condition's checked identifier's REF resolves
to the SAME local the erasing transformation produced (see
`failure_state_facts.py`'s `derive()` -- `producing_call_by_local[local_id]`
is looked up using the exact `local_id` the guard condition's identifier
referenced). Every fact this module receives as input already satisfies item
4 by construction; this module does not re-check it, only documents that the
precondition was already enforced upstream.

## SIGNAL A -- guard shape (closed set, deliberately narrow)

The guard condition's own top-level CALL name must be one of a small, closed
set of failure-style comparison operators. This set is DELIBERATELY narrow --
"closed to the exact structures verified," per the instruction that produced
this module -- and specifically does NOT include arbitrary truthiness
checks, `.has()`/`.includes()`/other named method calls, or custom predicate
functions, even though some of those could in principle be legitimate
failure checks in real code. Excluding them is a known, disclosed precision/
recall tradeoff (JS-STATE-R06's characterization report flags this
explicitly under "Missing facts"), not an oversight.

`<operator>.instanceOf` was the operator JS-STATE-R06's fixture itself
exercised directly (true positive vs. the real `.has()`-shaped false
positive). `<operator>.equals` / `<operator>.notEquals` are included because
JS-STATE-R01's case4b (`id === null`) -- the null/number case this milestone
was explicitly told to retain -- uses `<operator>.equals`, and JS-STATE-R01's
original characterization (Q3) already validated `<operator>.equals` as a
distinctly-identifiable CPG comparison node, using the same REF-based
mechanism as instanceOf. This is a disclosed, deliberate inclusion, not
silent scope creep: relational operators (`<operator>.lessThan` etc.) and any
named method call remain OUT of the closed set.

## SIGNAL B -- return contract (three-way, asymmetric)

Reads the erasing transformation's own argument's `dynamicTypeHintFullName`
(`type_hints.tsv`, an existing export originally built for a different
purpose -- union-receiver-type recovery for dispatch resolution in Gate
24-TS/JSTS-R01). Three possible outcomes, kept explicitly asymmetric per
instruction:

  - Hint present AND contains a union (` | `) with at least one branch
    matching a closed, small set of failure-capable markers (Error, Null,
    Undefined, Exception, Failure -- case-insensitive substring match, the
    same kind of small fixed table as `_ERASING_GLOBAL_BUILTINS` in
    `failure_state_facts.py`, not a heuristic guess) -> `ESTABLISHED`.
  - Hint present but contains no union, or a union with no failure-capable
    branch -> `NOT_UNION` (definitively not a candidate for this reason).
  - No hint recorded at all (JS-STATE-R06 found this happens for field-access
    arguments like `record.id` -- `type_hints.tsv` only covers IDENT/PARAM
    node kinds) -> `UNKNOWN`.

Only `ESTABLISHED` counts as "positive evidence" for item 3. `UNKNOWN` does
NOT suppress a real candidate by being silently treated as `NOT_UNION` or as
proof of safety -- but it also does not, by itself, satisfy the positive-
evidence requirement to emit. This is the same abstention discipline as every
other JS-STATE milestone: UNKNOWN is not SAFE, and here it is also not
sufficient grounds to CANDIDATE either. The distinction between `NOT_UNION`
and `UNKNOWN` is preserved in every fact's audit trail specifically so a
future review is never confused about which reason applied.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from security_sensitive_reachability import derive as derive_reachability  # noqa: E402
from failure_state_facts import _d, _rows  # noqa: E402

# SIGNAL A: closed set. See module docstring for exactly why each member is
# included and why nothing else is.
_FAILURE_STYLE_GUARD_OPERATORS = {
    "<operator>.instanceOf",
    "<operator>.equals",
    "<operator>.notEquals",
}

# SIGNAL B: closed set of failure-capable type markers. Small, fixed,
# documented -- the same pattern as failure_state_facts.py's builtin table.
_FAILURE_CAPABLE_MARKERS = ("error", "null", "undefined", "exception", "failure")


def _load_condition_call_names(raw):
    """control_structure_id -> its condition's own top-level CALL name."""
    raw = Path(raw)
    calls_by_id = {}
    for r in _rows(raw / "calls.tsv", 11):
        calls_by_id[int(r[0])] = _d(r[2])
    cs_condition_name = {}
    for r in _rows(raw / "control_structures.tsv", 6):
        cs_id = int(r[0])
        condition_id = int(r[3]) if r[3] else None
        if condition_id is not None and condition_id in calls_by_id:
            cs_condition_name[cs_id] = calls_by_id[condition_id]
    return cs_condition_name


def _load_type_hints(raw):
    """node_id -> raw dynamicTypeHintFullName string, IDENT/PARAM only."""
    raw = Path(raw)
    hints = {}
    for r in _rows(raw / "type_hints.tsv", 3):
        if r[0] == "IDENT" or r[0] == "PARAM":
            hints[int(r[1])] = _d(r[2])
    return hints


def _load_transformation_arg_node_ids(raw):
    """transformation_call_id -> [argument node ids] (all positional args)."""
    raw = Path(raw)
    args_by_call = {}
    for r in _rows(raw / "arguments.tsv", 8):
        args_by_call.setdefault(int(r[1]), []).append(int(r[0]))
    return args_by_call


def _classify_return_contract(hint_candidates):
    """hint_candidates: list of raw dynamicTypeHintFullName strings (one per
    argument node that had a hint at all; nodes with no hint contribute
    nothing here). Returns 'ESTABLISHED' | 'NOT_UNION' | 'UNKNOWN'.
    """
    if not hint_candidates:
        return "UNKNOWN"
    saw_any_union = False
    for raw_hint in hint_candidates:
        # "|||" separates independent candidate hints (JS TypeRecovery can
        # produce several); " | " within one candidate is an actual TS union.
        for candidate in raw_hint.split("|||"):
            if " | " not in candidate:
                continue
            saw_any_union = True
            branches = [b.strip() for b in candidate.split(" | ")]
            for b in branches:
                bl = b.lower()
                if any(marker in bl for marker in _FAILURE_CAPABLE_MARKERS):
                    return "ESTABLISHED"
    return "NOT_UNION" if saw_any_union else "UNKNOWN"


def derive(raw):
    reachability_result = derive_reachability(raw)
    cs_condition_name = _load_condition_call_names(raw)
    type_hints = _load_type_hints(raw)
    transformation_args = _load_transformation_arg_node_ids(raw)

    out_facts = []
    for fact in reachability_result["facts"]:
        cs_id = fact["control_structure_id"]
        guard_operator = cs_condition_name.get(cs_id)
        guard_shape_ok = guard_operator in _FAILURE_STYLE_GUARD_OPERATORS

        arg_node_ids = transformation_args.get(fact["transformation_call_id"], [])
        hint_candidates = [type_hints[nid] for nid in arg_node_ids if nid in type_hints]
        return_contract = _classify_return_contract(hint_candidates)

        sink_ok = fact["security_sensitive_use"] == "SENSITIVE"

        emit = guard_shape_ok and (return_contract == "ESTABLISHED") and sink_ok

        augmented = dict(fact)
        augmented["r07_guard_operator"] = guard_operator
        augmented["r07_guard_shape_established"] = guard_shape_ok
        augmented["r07_return_contract"] = return_contract
        augmented["r07_guard_subject_is_transformed_value"] = True  # by R02 construction, see docstring
        augmented["r07_sink_reachable"] = sink_ok
        augmented["r07_emit"] = emit
        out_facts.append(augmented)

    candidates = [f for f in out_facts if f["r07_emit"]]

    return {
        "schema": "portable-js-state-r07-candidates/0.1",
        "note": "r07_emit=true means ALL FIVE preconditions held: ERASES (R02), "
                "guard-shape (closed set, SIGNAL A), return-contract ESTABLISHED "
                "(positive evidence only, SIGNAL B), guard-subject=transformed-value "
                "(guaranteed by R02 construction), and sink reachability under R04/R05 "
                "rules resulting in SENSITIVE. r07_return_contract=UNKNOWN is NOT treated "
                "as safe and is NOT sufficient to emit -- it is recorded, not suppressed.",
        "all_facts": out_facts,
        "candidates": candidates,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
