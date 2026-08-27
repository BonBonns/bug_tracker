#!/usr/bin/env python3
"""OOB_WRITE (INTERPROCEDURAL) candidate producer -- the first slice of expansion-
order step 6 (cross-function capacity propagation), unblocked per explicit
instruction once the local call-sink controls (oob-callsink-r01, moz-canon-r01)
passed. Single-hop only: a CALLER passes a known-capacity object (a fixed local byte
array, or a literal-sized heap allocation -- same two sources every producer in this
family already resolves) as a BARE argument to a STATICALLY-RESOLVED internal
function call; the CALLEE receives it as a pointer PARAMETER with no local capacity
of its own, and writes through that parameter via a contract-driven call sink
(reusing callee_contracts.py, same as oob_call_sink_verdict.py) with no visible
guard. The propagated capacity is then available to the SAME guard/safety logic
already used throughout this producer family.

WHAT THIS DELIBERATELY DOES NOT ATTEMPT (checked against the two real corroborating
CVEs BEFORE committing to this scope, not assumed):
  - Struct/union MEMBER capacity (NSS CVE-2021-43527's actual shape:
    `decodeECorDSASignature(encAlg, sig, cx->u.buffer, sigLen)` -- the argument is
    `cx->u.buffer`, a union field access, not a bare identifier; the union's byte
    capacity is the max size across its own alternative members, which would need
    walking `type_decls` to resolve an anonymous union's nested member list and
    compute sizes per alternative -- real type-system modeling, meaningfully bigger
    and riskier than anything built in this producer family so far, deliberately
    NOT attempted here). Confirmed by inspecting the real call fact: this pass
    correctly does NOT match `cx->u.buffer` (not a bare name) and abstains.
  - Multi-hop chains, or a callee-local variable DERIVED from a parameter (NSS bug
    1418780/h_page.c's `ugly_split`: the vulnerable `ino` is a local inside
    `ugly_split`, itself derived from a BUFHEAD parameter's own field, not a direct
    parameter -- two things this single-hop pass does not attempt: neither the
    struct-field capacity source, nor tracing a local's origin back through an
    assignment from a parameter's field). Confirmed by inspecting the real call
    site: `ugly_split`'s own parameters (`hashp, obucket, old_bufp, new_bufp,
    copyto, moved`) don't include `ino` at all.
  - Ambiguous propagation: if two different call sites propagate DIFFERENT
    capacities to the SAME (callee, parameter) pair, this pass drops the
    propagation entirely for that parameter rather than guessing which one is
    "the" capacity -- abstain over false certainty, same posture as everywhere
    else in this family.
  - Anything beyond ONE hop (a caller's caller is not consulted).

Uses Joern's own already-resolved call-graph edges (`candidate_target_ids` +
`resolution == 'EXACT'`) rather than doing any name-based call resolution itself --
only single, statically-resolved concrete targets are trusted; anything ambiguous or
virtual-dispatch abstains.

Reuses callee_contracts.py's contract table and its consuming logic (base+offset
destination parsing, guard crediting, literal-arithmetic safety) verbatim from
oob_call_sink_verdict.py -- this module's only new contribution is WHERE a
destination's capacity can come from (a propagated parameter, not just a local),
never a change to how a candidate is judged once a capacity is known. Never emits
VULNERABLE; only CANDIDATE. If in doubt, SUPPRESS or ABSTAIN.
"""
import json, re, sys
from callee_contracts import CALLEE_CONTRACTS

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
BYTE_ELEM_TYPES = {'char', 'unsigned char', 'signed char', 'uint8_t', 'PRUint8', 'int8_t',
                    'BYTE', 'u_char', 'uint8', 'JOCTET'}
ALLOC_FUNCS = ('malloc', 'PORT_Alloc', 'PORT_ZAlloc')
NAME_CHAIN = r'[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*'

ALLOC_RE = re.compile(
    r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(' + '|'.join(ALLOC_FUNCS) + r')\s*\(\s*([^()]+?)\s*\)\s*$')


def _eval_const_int_expr(expr):
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None


def _byte_array_elem_count(type_full_name):
    m = re.match(r'^\s*([A-Za-z_][\w ]*?)\s*\[\s*([\d\s+\-*/()]+)\s*\]\s*$', type_full_name or '')
    if not m:
        return None
    if m.group(1).strip() not in BYTE_ELEM_TYPES:
        return None
    return _eval_const_int_expr(m.group(2))


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])
    functions = d.get('functions', [])
    func_by_id = {f.get('id'): f for f in functions}

    # LOCAL capacity, per function -- identical to the rest of this producer family.
    arr_count = {}   # (function_id, name) -> N
    for l in locals_:
        n = _byte_array_elem_count(l.get('type_full_name'))
        if n is not None:
            arr_count[(l.get('method_id'), l.get('name'))] = n
    for c in (cc for cc in calls if cc.get('name') == '<operator>.assignment'):
        fn = c.get('enclosing_function_id')
        m = ALLOC_RE.match(c.get('code') or '')
        if not m:
            continue
        n = _eval_const_int_expr(m.group(3))
        if n is not None:
            arr_count[(fn, m.group(1))] = n

    # Parameter tables, for mapping a call's argument POSITION to the callee's
    # parameter NAME.
    params_by_fn = {}   # function_id -> {index: name}
    for f in functions:
        for p in f.get('parameters', []):
            params_by_fn.setdefault(f.get('id'), {})[p.get('index')] = p.get('name')

    # STEP 6, single hop: propagate a bare known-capacity argument across an
    # EXACT-resolved call into the callee's matching parameter. Ambiguous (two call
    # sites disagreeing on the same parameter's capacity) -> drop, don't guess.
    propagated = {}     # (callee_fn, param_name) -> N
    conflicted = set()
    for c in calls:
        if c.get('resolution') != 'EXACT':
            continue
        targets = c.get('candidate_target_ids') or []
        if len(targets) != 1:
            continue
        callee_fn = targets[0]
        caller_fn = c.get('enclosing_function_id')
        pmap = params_by_fn.get(callee_fn)
        if not pmap:
            continue
        for a in c.get('arguments', []):
            arg_code = (a.get('code') or '').strip()
            if not re.fullmatch(r'[A-Za-z_]\w*', arg_code):
                continue   # not a bare identifier -- e.g. `cx->u.buffer` -- abstain
            if (caller_fn, arg_code) not in arr_count:
                continue
            N = arr_count[(caller_fn, arg_code)]
            param_name = pmap.get(a.get('index'))
            if param_name is None:
                continue
            key = (callee_fn, param_name)
            if key in conflicted:
                continue
            if key in propagated and propagated[key] != N:
                conflicted.add(key)
                propagated.pop(key, None)
                continue
            propagated[key] = N

    # Effective capacity table for THIS module's own candidate generation: a
    # function's own locals/allocs take priority (more certain, no cross-function
    # inference needed); propagated entries only fill in names not already covered
    # -- which in practice means "this name is a parameter with no shadowing local
    # of the same name," the only case C even allows.
    effective = dict(arr_count)
    capacity_origin = {}   # (fn, name) -> (caller_fn, propagated_N), evidence only
    for (fn, name), N in propagated.items():
        if (fn, name) not in effective:
            effective[(fn, name)] = N
            capacity_origin[(fn, name)] = N

    if not effective:
        return []

    def _cap_guard_names(code, fn):
        hits = set()
        for (mid, name) in effective:
            if mid == fn and ('sizeof(%s)' % name) in (code or ''):
                hits.add(name)
        return hits

    assert_codes = [(c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES
                     or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]

    def _in_assert(cmp_code):
        cc = (cmp_code or '').strip()
        return bool(cc) and any(cc in ac for ac in assert_codes)

    guarded_by_fn = {}
    bounded_len_by_fn = {}
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(code):
            continue
        fn = c.get('enclosing_function_id')
        hits = _cap_guard_names(code, fn)
        if hits:
            guarded_by_fn.setdefault(fn, set()).update(hits)
        if c.get('name') in ('<operator>.lessThan', '<operator>.lessEqualsThan'):
            mlt = re.match(r'^\s*(' + NAME_CHAIN + r')\s*<=?', code)
            if mlt:
                bounded_len_by_fn.setdefault(fn, set()).add(mlt.group(1))

    # Contract-driven BufferOperationFact extraction -- identical to
    # oob_call_sink_verdict.py's `extract_buffer_operations`.
    ops = []
    for c in calls:
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        ops.append({'call_id': c.get('id'), 'function_id': c.get('enclosing_function_id'),
                     'file': c.get('file'), 'line': c.get('line'), 'callee': callee,
                     'dest_code': (args[da].get('code') or '').strip(),
                     'width_code': (args[wa].get('code') or '').strip(),
                     'contract_source': contract['source']})

    cand = []
    seen = set()
    for op in ops:
        fn = op['function_id']
        dest_code, len_code = op['dest_code'], op['width_code']
        if not re.fullmatch(r'[A-Za-z_]\w*', dest_code):
            continue   # only the bare-parameter destination shape, for this MVP
        if (fn, dest_code) not in capacity_origin:
            continue   # only candidates whose capacity came from PROPAGATION --
                        # a purely-local capacity is oob_call_sink_verdict.py's job
        N = effective[(fn, dest_code)]
        if re.fullmatch(r'\d+', len_code) and int(len_code) <= N:
            continue
        if dest_code in guarded_by_fn.get(fn, set()):
            continue
        if re.fullmatch(NAME_CHAIN, len_code) and len_code in bounded_len_by_fn.get(fn, set()):
            continue
        key = (fn, dest_code, len_code, op['call_id'])
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'INTERPROCEDURAL',
                     'callee': op['callee'], 'contract_source': op['contract_source'],
                     'dest': dest_code, 'elem_count': N, 'width_expr': len_code,
                     'file': op['file'], 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': op['line'],
                     'derivation': {'rule': 'CPP_INTERPROCEDURAL_PARAM_CAPACITY_UNBOUNDED',
                                    'capacity_source': 'PROPAGATED_SINGLE_HOP_BARE_ARGUMENT'}})
    return cand


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'INTERPROCEDURAL candidate(s)')
        for x in c:
            print('   ', x['callee'], '(', x['dest'], ',.., ', x['width_expr'], ') cap=',
                  x['elem_count'], '(propagated) @L', x.get('line'))
