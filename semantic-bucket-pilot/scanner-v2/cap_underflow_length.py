#!/usr/bin/env python3
"""Capability: unsigned-underflow-fed length/offset (NO model calls).

Design note: dev_controls/UNDERFLOW_CAPABILITY_DESIGN.md. Implements the SCOPED
first cut of that design -- the two flow shapes it names as tractable without a
general dataflow engine, matching this whole capability family's existing
"recognize the shape textually, one-hop through a plain local, otherwise
abstain" discipline (see oob_runtime_capacity_verdict.py's own `scalar_defs`
one-hop resolver, which this mirrors):

  1. `A - B` feeds a CALLEE_CONTRACTS sink's width argument, directly inline
     OR through exactly one intervening `var = A - B;` assignment in the same
     function (this is `hmacct.c`'s real shape: `overhang = headerLen -
     mdBlockSize;` ... `memcpy(dst, src, overhang)`).
  2. `A - B` is used directly (or via the same one-hop) as an array index:
     `arr[A - B]` / `arr[var]`.

NOT attempted this round (same non-goals as the design doc, plus one honest
narrowing beyond it): pointer-arithmetic offsets (`ptr + (A - B)`), multi-hop
guards, accumulated loop underflow, and compound-adjustment guards
(`if (a - K >= b)`) -- the last three are the design doc's own explicit
non-goals; the pointer-offset shape IS in the design doc's scope but is left
out of this first cut to keep the build reviewable, flagged here rather than
silently claimed.

GUARD PROOF reuses `call_context_guard.py`'s CFG-dominance machinery verbatim,
retargeted from (guard, call-site) to (guard, subtraction's-use-site) -- see
`_guard_credits_no_underflow` below. That module is intentionally NOT modified;
this file only imports its pure functions and recomposes them for a same-
function query (no caller/callee argument mapping needed here, unlike its
original call-site-guard use).

Routing (mirrors cap1/cap_addr_indexed.py's lightweight route/reason
convention, not the strict AR.validate_record() schema used by base V1/V2 --
same posture as every other cap_*.py file in this family):
  guard PROVEN to entail A >= B on every path to the use
      -> disposition="deterministic_complete", reason="subtraction_underflow_guarded",
         property="subtraction_does_not_underflow" (explicitly NOT a claim about
         the write's destination-capacity -- that stays this producer's sibling
         capabilities' job, not this one's).
  no guard, or guard shape not provably matching
      -> disposition="open_candidate", route="range_arithmetic_review",
         reason="subtraction_may_underflow", llm_eligible=True.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS); sys.path.insert(0, HERE)
from callee_contracts import CALLEE_CONTRACTS
from allocation_extent import build_cfg_index, _dominates, _reachable_from
from call_context_guard import (
    CMP, NAME_CHAIN, NEG_OP,
    _collect_assert_codes, _collect_assert_arg_ids, _in_assert,
    _controls_call, _branch_polarity, _split_predicate, _entails_safe_bare,
    _resolve_expr_type, _signedness,
)

_SUB = re.compile(r'^\s*(' + NAME_CHAIN + r')\s*-\s*(' + NAME_CHAIN + r')\s*$')
_IDX = re.compile(r'^\s*([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]\s*$')


def _find_subtractions(calls):
    """{(fn, call_id): (a_expr, b_expr, code)} for every `<operator>.subtraction`
    whose code is an EXACT two-bare-operand form -- no nested arithmetic, no
    calls, on either side (same discipline as _entails_safe_bare's own bare-
    operand-only matching). Anything more complex is not recognized at all,
    never guessed at."""
    subs = {}
    for c in calls:
        if c.get('name') != '<operator>.subtraction':
            continue
        m = _SUB.match(c.get('code') or '')
        if not m:
            continue
        subs[(c.get('enclosing_function_id'), c.get('id'))] = (m.group(1), m.group(2), c.get('code').strip())
    return subs


def _one_hop_defs(calls):
    """{(fn, varname): (sub_call_id, a, b)} for `var = A - B;` -- a PLAIN
    assignment whose RHS is itself recognized as exactly one subtraction node
    (matched by CODE, mirroring oob_runtime_capacity_verdict.py's own
    scalar_defs resolver; not by node id, since the assignment's RHS operand
    and the subtraction node are two different representations of the same
    text in these facts, same as that resolver)."""
    subs_by_code = {}
    for c in calls:
        if c.get('name') != '<operator>.subtraction':
            continue
        m = _SUB.match(c.get('code') or '')
        if m:
            subs_by_code[(c.get('enclosing_function_id'), c.get('code').strip())] = \
                (c.get('id'), m.group(1), m.group(2))
    defs = {}
    for c in calls:
        if c.get('name') != '<operator>.assignment':
            continue
        code = c.get('code') or ''
        sm = re.match(r'^\s*([A-Za-z_]\w*)\s*=\s*(.+)$', code)
        if not sm:
            continue
        fn = c.get('enclosing_function_id')
        rhs = sm.group(2).strip()
        hit = subs_by_code.get((fn, rhs))
        if hit:
            defs[(fn, sm.group(1))] = hit
    return defs


def _guard_credits_no_underflow(d, cfg_index, fn, a_expr, b_expr, use_id,
                                 assert_codes, assert_ids):
    """Same proof `call_context_guard.guard_status_for_call` performs for a
    caller-side guard protecting a call site, retargeted: SAME function, no
    argument mapping (a_expr/b_expr are already in this function's own
    namespace), and the thing being "protected" is the USE of the subtraction
    (use_id: the sink call's id, or the index-access node's id) rather than a
    call site. Returns (credited: bool, evidence: list[str])."""
    g = cfg_index.get(fn)
    evidence = []
    w_type = _resolve_expr_type(d, fn, b_expr)   # subtrahend -- the "width" role
    c_type = _resolve_expr_type(d, fn, a_expr)   # minuend -- the "capacity" role
    if w_type:
        evidence.append(f"{b_expr}: type={w_type}")
    if c_type:
        evidence.append(f"{a_expr}: type={c_type}")
    w_sign, c_sign = _signedness(w_type), _signedness(c_type)
    signedness_mismatch = w_sign is not None and c_sign is not None and w_sign != c_sign
    if signedness_mismatch:
        evidence.append(
            f"SIGNEDNESS MISMATCH between {b_expr} ({w_sign}) and {a_expr} ({c_sign}) -- "
            "a C usual-arithmetic-conversion could change a guard's real meaning")

    if not g or use_id not in g.get('nodes', ()):
        evidence.append("no CFG data for this function/use site")
        return False, evidence

    candidates = []
    for c in d.get('calls', []):
        if c.get('enclosing_function_id') != fn or c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        toks = set(re.findall(NAME_CHAIN, code))
        if a_expr not in toks or b_expr not in toks:
            continue
        if c.get('id') not in g['nodes']:
            continue
        dominates = _dominates(g, c.get('id'), use_id)
        controls = _controls_call(g, c.get('id'), use_id) if dominates else None
        candidates.append((c, _in_assert(c, assert_codes, assert_ids), dominates, controls))

    if not candidates:
        evidence.append(f"no comparison in this function relates {a_expr} and {b_expr}")
        return False, evidence

    best = None
    for c, is_assert, dominates, controls in candidates:
        if dominates and controls:
            best = (c, is_assert, dominates, controls)
            break
    if best is None:
        evidence.append("a relating comparison exists but does not both dominate "
                         "and control the use -- not credited")
        return False, evidence

    c, is_assert, dominates, controls = best
    if is_assert:
        evidence.append(f"'{c.get('code')}' is assert-only (compiled out in release) -- not credited")
        return False, evidence

    polarity = _branch_polarity(g, c.get('id'), use_id)
    if polarity != 'NEGATED':
        evidence.append(f"'{c.get('code')}' controls the use but branch polarity is not "
                         "provable from CFG structure -- not credited")
        return False, evidence

    split = _split_predicate(c.get('code'), c.get('name'))
    # Reaching the use proves the NEGATION of c's predicate. We need that
    # negation to entail b_expr <= a_expr (i.e. a_expr >= b_expr, no underflow) --
    # the SAME two-bare-operand entailment _entails_safe_bare already proves for
    # "width <= capacity"; b_expr plays "width", a_expr plays "capacity" here.
    entails = (_entails_safe_bare(NEG_OP[c.get('name')], split[0], split[1], b_expr, a_expr)
               if split else None)
    if entails is not True:
        evidence.append(f"negation of '{c.get('code')}' does not provably entail "
                         f"{a_expr} >= {b_expr} (compound or wrong-direction adjustment)")
        return False, evidence
    if signedness_mismatch:
        evidence.append("guard shape proven but signedness mismatch leaves range unresolved")
        return False, evidence
    evidence.append(f"'{c.get('code')}' dominates, controls, and (negated) provably "
                     f"entails {a_expr} >= {b_expr}")
    return True, evidence


def analyze_underflow_length(cpp):
    d = json.load(open(cpp))
    calls = d.get('calls', [])
    fns = {f['id']: f for f in d.get('functions', [])}
    cfg_index = build_cfg_index(d)
    assert_codes = _collect_assert_codes(d)
    assert_ids = _collect_assert_arg_ids(d)
    subs = _find_subtractions(calls)          # (fn, sub_id) -> (a, b, code)
    one_hop = _one_hop_defs(calls)             # (fn, var) -> (sub_id, a, b)
    sub_code_index = {}                        # (fn, code) -> (a, b)
    for (fn, _sid), (a, b, code) in subs.items():
        sub_code_index[(fn, code)] = (a, b)

    def _resolve_operand(fn, text):
        """text is either the subtraction's own code (direct use) or a bare
        variable one-hop-defined as a subtraction. Returns (a, b, kind) or None."""
        text = (text or '').strip()
        hit = sub_code_index.get((fn, text))
        if hit:
            return hit[0], hit[1], 'direct'
        if re.fullmatch(r'[A-Za-z_]\w*', text) and (fn, text) in one_hop:
            _sid, a, b = one_hop[(fn, text)]
            return a, b, 'one_hop_local'
        return None

    uses = []   # (fn, use_id, a, b, kind, use_kind, evidence_code, line)
    for c in calls:
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is not None:
            args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
            wa = contract['width_arg']
            if wa < len(args):
                r = _resolve_operand(c.get('enclosing_function_id'), args[wa].get('code'))
                if r:
                    a, b, kind = r
                    uses.append((c.get('enclosing_function_id'), c.get('id'), a, b, kind,
                                 'sink_width', callee, c.get('line')))
        if c.get('name') in ('<operator>.indirectIndexAccess', '<operator>.indexAccess'):
            m = _IDX.match(c.get('code') or '')
            if m:
                r = _resolve_operand(c.get('enclosing_function_id'), m.group(2))
                if r:
                    a, b, kind = r
                    uses.append((c.get('enclosing_function_id'), c.get('id'), a, b, kind,
                                 'array_index', m.group(1), c.get('line')))

    ops = []
    seen = set()
    for fn, use_id, a, b, kind, use_kind, evidence_code, line in uses:
        key = (fn, use_id, a, b)
        if key in seen:
            continue
        seen.add(key)
        credited, guard_evidence = _guard_credits_no_underflow(
            d, cfg_index, fn, a, b, use_id, assert_codes, assert_ids)
        rec = {"function": fns.get(fn, {}).get("name"), "line": line,
               "capability": "underflow_length",
               "subtraction": f"{a} - {b}", "a_expr": a, "b_expr": b,
               "resolution": kind, "use_kind": use_kind, "use_evidence": evidence_code,
               "guard_evidence": guard_evidence}
        if credited:
            rec.update(disposition="deterministic_complete",
                       reason="subtraction_underflow_guarded",
                       property="subtraction_does_not_underflow",
                       route=None, llm_eligible=False)
        else:
            rec.update(disposition="open_candidate", reason="subtraction_may_underflow",
                       route="range_arithmetic_review", llm_eligible=True)
        ops.append(rec)
    return ops


if __name__ == "__main__":
    for r in analyze_underflow_length(sys.argv[1]):
        print(json.dumps(r, sort_keys=True))
