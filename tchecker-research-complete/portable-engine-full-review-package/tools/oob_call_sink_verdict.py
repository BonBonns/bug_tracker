#!/usr/bin/env python3
"""OOB_WRITE (CALL_SINK) candidate producer -- generalizes the memcpy-family-only
COPY_LENGTH producer (oob_copy_length_verdict.py) from a hardcoded function-name
allowlist to ANY callee with an independently-verified CONTRACT in
callee_contracts.py, via a structured intermediate representation
(BufferOperationFact) rather than per-callee logic baked into this module.

WHY THIS EXISTS (round-5 finding, not a hypothetical): the cursor-write producer
(oob_cursor_write_verdict.py) generalized raw pointer-DEREFERENCE writes (`*p = x`,
`*p++ = x`, `*(p+n) = x`) but could not reach NSS CVE-2019-11759's actual write --
`HMAC_Finish(hmac, key_block + ((bi-1)*hashLen), &len, hashLen)` -- because that's a
function CALL with an offset-computed pointer ARGUMENT, not a dereference, and
COPY_LENGTH's `COPY_FUNCS` allowlist didn't include `HMAC_Finish`. The fix is NOT to
special-case `HMAC_Finish` inside a producer's verdict logic (that would be exactly
the per-CVE special-casing this module is built to avoid) -- it is to make "which
functions write through a destination argument, and which argument is the width" a
DATA question, answered once per callee in callee_contracts.py from that callee's
REAL signature, and never touched again by the code below. This module's own logic
knows nothing about `memcpy` or `HMAC_Finish` by name; it only knows how to read a
BufferOperationFact.

STRUCTURED INTERMEDIATE REPRESENTATION -- BufferOperationFact:
    {call_id, function_id, file, line, callee, dest_code, width_code, contract_source}
Built once, generically, from every call whose callee has a contract entry (see
`extract_buffer_operations`). A callee with NO contract entry produces NO
BufferOperationFact at all -- "unknown contracts must remain unresolved" is enforced
structurally (the lookup returns nothing to iterate over), not by an if-check anyone
downstream could get wrong or forget.

SCOPE -- same posture and same known limitations as oob_copy_length_verdict.py,
whose destination-matching and guard-crediting logic this module reuses verbatim
(bare fixed byte-array name, or that array plus an offset expression; a literal
+ literal offset/width pair is checked by pure arithmetic rather than flagged; a
`sizeof(base)`/literal-count guard anywhere in the function suppresses ALL matching
candidates in it, dominance-unaware, same documented limitation as the rest of this
producer family). What's NEW here is only WHICH calls get examined at all -- the
capacity/guard/offset reasoning itself is unchanged from COPY_LENGTH's round-4 logic,
intentionally, so this module can be read as "COPY_LENGTH's reasoning, over a
contract-driven call set" rather than a fresh design to re-review from scratch.

Deliberately NOT attempted here (per the explicit instruction that motivated this
module): cross-function or cross-translation-unit capacity propagation. A
BufferOperationFact's destination capacity is still resolved ONLY within its own
function (a fixed local byte array, or a literal-sized `malloc`/`PORT_Alloc`/
`PORT_ZAlloc` -- see `_byte_array_elem_count`/`ALLOC_RE`, copied from the cursor
producer). If the true capacity lives in a caller, a struct/union member, or a
symbolic allocation-size expression, this pass abstains, same as every other
producer in this family has abstained on those shapes so far.

Never emits VULNERABLE; only CANDIDATE. If in doubt, SUPPRESS or ABSTAIN.
"""
import json, re, sys
from callee_contracts import CALLEE_CONTRACTS

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
BYTE_ELEM_TYPES = {'char', 'unsigned char', 'signed char', 'uint8_t', 'PRUint8', 'int8_t',
                    'BYTE', 'u_char', 'uint8', 'JOCTET'}
ALLOC_FUNCS = ('malloc', 'PORT_Alloc', 'PORT_ZAlloc')
NAME_CHAIN = r'[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*'

ALLOC_RE = re.compile(
    r'^\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?(' + '|'.join(ALLOC_FUNCS) + r')\s*\(\s*([^()]+?)\s*\)\s*$')


def _eval_const_int_expr(expr):
    """Same charset-restricted constant-arithmetic folder used across this producer
    family (see oob_pointer_increment_verdict.py's module docstring for the original
    real-world finding that motivated it)."""
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


def extract_buffer_operations(calls):
    """The one place this module reads CALLEE_CONTRACTS. Generic over every entry in
    the table -- adding a new verified contract to callee_contracts.py extends this
    producer's reach with zero changes here."""
    ops = []
    for c in calls:
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue   # unresolved contract -- structurally abstained, not examined
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue   # call doesn't have enough arguments to match this contract
        ops.append({
            'call_id': c.get('id'), 'function_id': c.get('enclosing_function_id'),
            'file': c.get('file'), 'line': c.get('line'), 'callee': callee,
            'dest_code': (args[da].get('code') or '').strip(),
            'width_code': (args[wa].get('code') or '').strip(),
            'contract_source': contract['source'],
        })
    return ops


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])
    func_by_id = {f.get('id'): f for f in d.get('functions', [])}

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
    if not arr_count:
        return []

    def _cap_guard_arrays(code, fn):
        hits = set()
        for (mid, name) in arr_count:
            if mid == fn and ('sizeof(%s)' % name) in (code or ''):
                hits.add(name)
        return hits

    assert_codes = [(c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES
                     or (c.get('code', '').split('(')[0].strip() in ASSERT_NAMES)]

    def _in_assert(cmp_code):
        cc = (cmp_code or '').strip()
        return bool(cc) and any(cc in ac for ac in assert_codes)

    guarded_arrays_by_fn = {}
    bounded_len_by_fn = {}
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(code):
            continue
        fn = c.get('enclosing_function_id')
        arrs = _cap_guard_arrays(code, fn)
        if arrs:
            guarded_arrays_by_fn.setdefault(fn, set()).update(arrs)
        if c.get('name') in ('<operator>.lessThan', '<operator>.lessEqualsThan'):
            mlt = re.match(r'^\s*(' + NAME_CHAIN + r')\s*<=?', code)
            if mlt:
                bounded_len_by_fn.setdefault(fn, set()).add(mlt.group(1))

    ops = extract_buffer_operations(calls)
    cand = []
    seen = set()
    for op in ops:
        fn = op['function_id']
        dest_code, len_code = op['dest_code'], op['width_code']
        offset_shape = False
        base = dest_code
        offset_expr = None
        if not re.fullmatch(r'[A-Za-z_]\w*', dest_code):
            m_off = re.match(r'^([A-Za-z_]\w*)\s*\+\s*(.+)$', dest_code)
            if not m_off:
                continue   # not a bare name or base+offset shape -- abstain
            base, offset_expr = m_off.group(1), m_off.group(2).strip()
            if not offset_expr:
                continue
            offset_shape = True
        if (fn, base) not in arr_count:
            continue
        N = arr_count[(fn, base)]
        if offset_shape and re.fullmatch(r'\d+', offset_expr) and re.fullmatch(r'\d+', len_code):
            if int(offset_expr) + int(len_code) <= N:
                continue   # provably safe by pure arithmetic, no guess involved
        if not offset_shape and re.fullmatch(r'\d+', len_code) and int(len_code) <= N:
            continue
        if base in guarded_arrays_by_fn.get(fn, set()):
            continue
        if re.fullmatch(NAME_CHAIN, len_code) and len_code in bounded_len_by_fn.get(fn, set()):
            continue
        key = (fn, dest_code, len_code, op['call_id'])
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'CALL_SINK',
                     'callee': op['callee'], 'contract_source': op['contract_source'],
                     'dest': dest_code, 'array_base': base, 'offset_shape': offset_shape,
                     'elem_count': N, 'width_expr': len_code,
                     'file': op['file'], 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': op['line'],
                     'derivation': {'rule': 'CPP_CALL_SINK_CONTRACT_UNBOUNDED',
                                    'capacity_source': 'SYNTACTIC_BYTE_ELEM_COUNT_OR_LITERAL_ALLOC'}})
    return cand


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'CALL_SINK candidate(s)')
        for x in c:
            print('   ', x['callee'], '(', x['dest'], ',.., ', x['width_expr'], ') cap=',
                  x['elem_count'], 'bytes @L', x.get('line'), ' contract:', x['contract_source'])
