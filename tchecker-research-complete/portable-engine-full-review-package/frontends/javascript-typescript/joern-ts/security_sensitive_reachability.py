#!/usr/bin/env python3
"""JS-STATE-R03/R04/R05: attach security-sensitive-sink reachability to each
FailureStateErasureCandidateFact from JS-STATE-R02, with branch-aware exclusion
of calls that only run inside the guard's own true-branch (JS-STATE-R04), and
reassignment-aware exclusion of calls that only see the local AFTER it was
reassigned to something else (JS-STATE-R05).

This module answers exactly one additional question beyond JS-STATE-R02: does
the guarded (post-transformation) value flow, unchanged, as an argument, into
a call that matches the EXTERNAL, human-curated profile in
security_sink_profile.py, on a path that is not simply "the guard's own
condition-true branch" and not after the local was reassigned to something
else?

Reachability is computed the same way JS-STATE-R02 computed guard-subject
identity: via the REF graph (identifier -> LOCAL/PARAMETER), never by matching
identifier names. An argument identifier "reaches" the guarded local if its REF
target is the same LOCAL id the erasure candidate's guard checked.

JS-STATE-R04 branch-awareness: a call whose id falls inside the SAME guard's
`guard_then_branch_members.tsv` entry only executes when that guard's condition
was true -- i.e. on the branch the guard's early-return (or equivalent) exists
to prevent from continuing. Such a call is excluded from `reaching_calls` /
`sink_matches` and instead reported separately in
`excluded_then_branch_calls`, so the exclusion is auditable rather than silent.

JS-STATE-R05 reassignment-awareness: a LOCAL node in the CPG represents a
variable's identity across its whole lifetime, so a REF match alone cannot
tell "the erased value is still in this variable" apart from "this variable
was reassigned to something else before this call." This module now checks,
per reaching call, whether ANY assignment to the same local has a line number
strictly between the erasure-producing assignment's line and the reaching
call's line -- and if so, excludes that call into
`excluded_reassigned_calls` instead of crediting it. This is a LINE-NUMBER
APPROXIMATION of ordering, not a real CFG/dominance check: it does not reason
about reassignments inside loops, reassignments on conditionally-executed
branches, or same-line reassign-and-use. It catches the straightforward,
common shape (`id = Number(r); if (...) return; id = 42; sink(id);`) and no
more than that -- documented explicitly, not silently assumed to be general.

This is still NOT full path-sensitivity. It does not reason about nested or
unrelated control structures, which of several sibling guards actually
dominates a given call, or true CFG reachability (nothing here uses Joern's
already-computed CFG; both R04 and R05 use AST/line-number approximations).
Those remain open gaps, called out in JS_STATE_R05_RESULT.md rather than
assumed solved.

The sink classification itself is never a claim of vulnerability. A
SINK_CATEGORY match means "this specific, externally-curated profile entry
matches on a path this module could not rule out"; UNKNOWN means "no profile
entry matched, or every reaching call was excluded as guard-branch-only or
reassigned-before-use," which is NOT the same as "proven not sensitive" (see
security_sink_profile.py docstring).
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from failure_state_facts import derive as derive_erasure_facts, _d, _rows, _ids  # noqa: E402
from security_sink_profile import classify_sink  # noqa: E402


def _load_calls_and_facts(raw):
    raw = Path(raw)
    calls = {}
    for r in _rows(raw / "calls.tsv", 11):
        calls[int(r[0])] = {
            "id": int(r[0]), "method_id": int(r[1]), "name": _d(r[2]), "code": _d(r[6]),
            "line": int(r[8]) if r[8] else None,
        }
    # JS-STATE-R04: node ids inside each control structure's "condition true"
    # branch (e.g. the body of `if (cond) { ... }`). A call whose id is in this
    # set for a given guard only runs when that guard's condition was true --
    # it is NOT on the continue/fall-through path the guard's early return (or
    # equivalent) was written to protect, so it must not be credited as
    # reaching the guarded value on the safe path.
    then_branch_members = {}
    for r in _rows(raw / "guard_then_branch_members.tsv", 2):
        then_branch_members.setdefault(int(r[0]), set()).add(int(r[1]))

    # JS-STATE-R04: every identifier inside the FULL AST subtree of each call's
    # arguments, resolved to its LOCAL/PARAMETER via REF -- not just bare
    # identifier arguments. This is what lets `authenticate(x as number)` or
    # `authenticate(x!)` be recognized as reaching `x`, the same way
    # condition_identifiers.tsv already does for guard conditions.
    call_arg_idents = []  # (call_id, argument_root_id, identifier_id, [ref_local_ids])
    for r in _rows(raw / "call_argument_identifiers.tsv", 4):
        call_arg_idents.append((int(r[0]), int(r[1]), int(r[2]), _ids(r[3])))

    # JS-STATE-R05: every assignment call in the program (not just the one
    # erasure-producing assignment JS-STATE-R02 tracks), keyed by which LOCAL
    # its LHS resolves to via REF, with its line number. Needed to tell "the
    # guarded local was reassigned before reaching this call" apart from "the
    # guarded (erased) value flows unchanged all the way to this call."
    identifiers = {}
    for r in _rows(raw / "identifiers.tsv", 7):
        identifiers[int(r[0])] = {"refs": _ids(r[6])}
    args_by_call = {}
    for r in _rows(raw / "arguments.tsv", 8):
        args_by_call.setdefault(int(r[1]), []).append({"node_id": int(r[0]), "index": int(r[2])})
    assignments_by_local = {}
    for c in calls.values():
        if c["name"] != "<operator>.assignment":
            continue
        a = sorted(args_by_call.get(c["id"], []), key=lambda x: x["index"])
        if not a or a[0]["index"] != 1:
            continue
        lhs_ident = identifiers.get(a[0]["node_id"])
        if not lhs_ident:
            continue
        for local_id in lhs_ident["refs"]:
            assignments_by_local.setdefault(local_id, []).append({"call_id": c["id"], "line": c["line"]})

    return calls, then_branch_members, call_arg_idents, assignments_by_local


def derive(raw):
    erasure_result = derive_erasure_facts(raw)
    calls, then_branch_members, call_arg_idents, assignments_by_local = _load_calls_and_facts(raw)

    # local_id -> [ (call_id, callee_name, line) for every call where SOME
    # identifier anywhere in an argument's full AST subtree has a REF
    # resolving to this local ]. Built once, REF-only, from
    # call_argument_identifiers.tsv (fixes the earlier shallow-argument-only
    # version, which missed calls like `authenticate(x as number)` where the
    # argument is a cast wrapping the identifier rather than the identifier
    # itself).
    calls_reached_by_local = {}
    for (call_id, _arg_root_id, _ident_id, ref_local_ids) in call_arg_idents:
        call = calls.get(call_id)
        if call is None:
            continue
        for local_id in ref_local_ids:
            calls_reached_by_local.setdefault(local_id, set()).add((call_id, call["name"], call["line"]))
    calls_reached_by_local = {k: sorted(v, key=lambda t: (t[2] is None, t[2], t[0])) for k, v in calls_reached_by_local.items()}

    def _is_operator_noise(callee_name):
        # `<operator>.assignment` (the guard local's own definition) and
        # `<operator>.instanceOf`/equals/etc. (the guard's own condition call)
        # trivially "reach" the guarded local via REF -- they are structural
        # noise for sink-reachability purposes, not calls a sink profile would
        # ever list. A real sink profile only ever names actual functions.
        return callee_name.startswith("<operator>.")

    out_facts = []
    for fact in erasure_result["facts"]:
        guard_local_id = fact["guard_local_id"]
        cs_id = fact["control_structure_id"]
        own_then_members = then_branch_members.get(cs_id, set())

        all_reaching = [
            (cid, name, line) for (cid, name, line) in calls_reached_by_local.get(guard_local_id, [])
            if not _is_operator_noise(name)
        ]
        # JS-STATE-R04: drop any reaching call that sits inside THIS guard's
        # own true-branch -- it only runs when the guard fired, not on the
        # continue path the guard was written to protect.
        then_excluded = [(cid, name, line) for (cid, name, line) in all_reaching if cid in own_then_members]
        after_then = [(cid, name, line) for (cid, name, line) in all_reaching if cid not in own_then_members]

        # JS-STATE-R05: drop any reaching call that comes AFTER an intervening
        # reassignment of the same local. This is a LINE-NUMBER approximation
        # of ordering, not a real CFG/dominance check (see module docstring for
        # the exact caveat) -- it catches the straightforward, common case
        # (`id = Number(r); if (...) return; id = 42; sink(id);`) but does not
        # attempt to reason about reassignments inside loops, conditionally
        # executed reassignments, or reassignments on the same source line as
        # the read.
        transformation_call = calls.get(fact["transformation_call_id"])
        origin_line = transformation_call["line"] if transformation_call else None
        reassignment_lines = sorted(
            a["line"] for a in assignments_by_local.get(guard_local_id, [])
            if a["line"] is not None and origin_line is not None and a["line"] > origin_line
        )

        def _reassigned_before(call_line):
            if call_line is None or origin_line is None:
                return False
            return any(origin_line < rl < call_line for rl in reassignment_lines)

        reassign_excluded = [(cid, name, line) for (cid, name, line) in after_then if _reassigned_before(line)]
        reaching_calls = [(cid, name, line) for (cid, name, line) in after_then if not _reassigned_before(line)]

        sink_hits = []
        for (call_id, callee_name, _line) in reaching_calls:
            category = classify_sink(callee_name)
            if category is not None:
                sink_hits.append({"call_id": call_id, "callee_name": callee_name, "category": category})

        augmented = dict(fact)
        augmented["reaching_calls"] = [
            {"call_id": cid, "callee_name": name} for (cid, name, _line) in reaching_calls
        ]
        augmented["excluded_then_branch_calls"] = [
            {"call_id": cid, "callee_name": name} for (cid, name, _line) in then_excluded
        ]
        augmented["excluded_reassigned_calls"] = [
            {"call_id": cid, "callee_name": name} for (cid, name, _line) in reassign_excluded
        ]
        augmented["sink_matches"] = sink_hits
        augmented["security_sensitive_use"] = "SENSITIVE" if sink_hits else "UNKNOWN"
        out_facts.append(augmented)

    return {
        "schema": "portable-failure-state-erasure-with-sink-reachability/0.3",
        "note": "security_sensitive_use=UNKNOWN means no profile entry matched on the continue path with no "
                "intervening reassignment -- NOT a proof of safety. excluded_then_branch_calls lists calls "
                "that reach the guarded local structurally but only run when the guard's condition was true. "
                "excluded_reassigned_calls lists calls that reach the same LOCAL id but only after a later "
                "assignment to it (by line-number approximation, not true CFG ordering), so the value "
                "actually reaching them is not provably the erased one. Neither exclusion list is credited "
                "toward SENSITIVE.",
        "facts": out_facts,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
