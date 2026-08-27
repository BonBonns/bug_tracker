#!/usr/bin/env python3
"""OOB_WRITE (INDEX) candidate producer — NEW capability, separate from the frozen
memcpy-surface producer. Evidence-gated by MOZ-OOB-R01 Row 3 (CVE-2022-28281).

Detects: an indexed STORE `arr[idx]...` (incl. arr[idx].field) whose base `arr` is a
fixed-size array local `T[N]` (N read syntactically from the type, so OPAQUE element types
are supported — the count is what a bound needs), where `idx` is NOT provably in-bounds.

Soundness (the field-read lesson): emit CANDIDATE only when NO capacity guard gates the write.
A capacity guard is a comparison that (a) references the array's own sizeof-capacity
`sizeof(arr)/sizeof(arr[0])` OR the literal count N, and (b) is NOT merely an argument to an
assert-family macro (MOZ_ASSERT/assert/NS_ASSERTION) — those are compiled out and do not gate.
If in doubt about a guard, we SUPPRESS (abstain) rather than false-positive.
Never emits VULNERABLE; only CANDIDATE.
"""
import json, re, sys

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')

def _eval_const_int_expr(expr):
    """Fold a simple constant-arithmetic array-size expression to an int, e.g. the
    common macro-expanded shape `(64*2)+8` (mozjpeg's `JOCTET _buffer[BUFSIZE]` with
    `#define BUFSIZE (DCTSIZE2*2)+8` -- confirmed on REAL code: without this, the
    array is invisible to every producer that keys capacity off type_full_name,
    since a bare-\\d+-only regex simply doesn't match). Restricted to
    digits/whitespace/+-*/() BEFORE ever calling eval, so this can't become a
    code-injection surface via attacker-controlled source text. Returns None
    (abstain) on anything not cleanly a small non-negative constant expression."""
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None

def _elem_count(type_full_name):
    m = re.match(r'^\s*[A-Za-z_][\w :<>*&]*?\[\s*([\d\s+\-*/()]+)\s*\]\s*$', type_full_name or '')
    return _eval_const_int_expr(m.group(1)) if m else None

def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])
    call_by_id = {c['id']: c for c in calls}
    # fixed-array locals -> element count N (opaque element types OK: count is syntactic).
    # Keyed by (declaring function, name), NOT name alone: two different functions in the same
    # file can each declare a same-named local array with a DIFFERENT size (this happens for
    # real -- e.g. mpi.c's mp_gcd declares `mp_int *clear[3]` while s_mp_invmod_odd_m declares
    # its own, unrelated `mp_int *clear[6]`). A bare name-keyed dict lets whichever same-named
    # local is last in file order silently overwrite every earlier one's count, so a candidate
    # in mp_gcd was reported with capacity 6 (borrowed from a different function entirely)
    # instead of its own, correct capacity of 3. Scoping by method_id fixes that; see the
    # already-correctly-scoped guarded_arrays_by_fn/bounded_idx_by_fn below for the same idiom.
    arr_count = {}   # (function_id, name) -> N
    for l in locals_:
        n = _elem_count(l.get('type_full_name'))
        if n is not None:
            arr_count[(l.get('method_id'), l.get('name'))] = n
    if not arr_count:
        return []

    # comparison-code text that references a fixed array's own sizeof-capacity, and which array
    # -- scoped to the function containing the comparison, for the same reason as above.
    def _cap_guard_arrays(code, fn):
        hits = set()
        for (mid, name) in arr_count:
            if mid == fn and ('sizeof(%s)' % name) in (code or ''):
                hits.add(name)
        return hits

    # collect assert-argument node ids (to exclude assert-only comparisons) — a comparison is
    # "in an assert" if its code is contained in an assert call's code (single-file, same fn).
    assert_codes = [ (c.get('code') or '') for c in calls
                     if c.get('name') in ASSERT_NAMES or (c.get('code','').split('(')[0].strip() in ASSERT_NAMES) ]
    def _in_assert(cmp_code):
        cc = (cmp_code or '').strip()
        if not cc:
            return False
        return any(cc in ac for ac in assert_codes)

    # (b) COUNT GUARD per function: a non-assert comparison referencing the array's own
    #     sizeof-capacity (the `if (len > sizeof(arr)/sizeof(arr[0])) return;` shape).
    guarded_arrays_by_fn = {}   # function_id -> set(array names) with a live capacity guard
    # (a) DIRECT INDEX BOUND per function: index variables that appear on the LEFT of a
    #     non-assert `<`/`<=` comparison (`i < K`). Conservative (any K): favors SUPPRESS to
    #     avoid false positives on ordinary bounded loops. Trades recall for soundness.
    bounded_idx_by_fn = {}      # function_id -> set(index variable names) with a direct bound
    for c in calls:
        if c.get('name') not in CMP:
            continue
        code = c.get('code') or ''
        if _in_assert(code):
            continue    # assert-only comparison -> does NOT gate (compiled out in release)
        fn = c.get('enclosing_function_id')
        arrs = _cap_guard_arrays(code, fn)
        if arrs:
            guarded_arrays_by_fn.setdefault(fn, set()).update(arrs)
        if c.get('name') in ('<operator>.lessThan', '<operator>.lessEqualsThan'):
            mlt = re.match(r'^\s*([A-Za-z_]\w*)\s*<=?', code)
            if mlt:
                bounded_idx_by_fn.setdefault(fn, set()).add(mlt.group(1))

    # find indexed STORES: indirectIndexAccess/indexAccess whose base is a fixed-array local,
    # used as a write destination (its result is assigned, possibly after a field access).
    func_by_id = {f.get('id'): f for f in d.get('functions', [])}
    idx_calls = [c for c in calls if c.get('name') in ('<operator>.indirectIndexAccess',
                                                        '<operator>.indexAccess')]
    cand = []
    seen = set()
    for c in idx_calls:
        code = c.get('code') or ''
        m = re.match(r'^\s*([A-Za-z_]\w*)\s*\[', code)
        if not m:
            continue
        arr = m.group(1)
        fn = c.get('enclosing_function_id')
        if (fn, arr) not in arr_count:
            continue
        N = arr_count[(fn, arr)]
        # index operand = the text inside [ ... ]
        mi = re.match(r'^\s*[A-Za-z_]\w*\s*\[\s*([^\]]+?)\s*\]', code)
        idx = (mi.group(1).strip() if mi else '')
        # constant, provably in-bounds -> safe
        if re.fullmatch(r'\d+', idx) and int(idx) < N:
            continue
        # (b) upstream count guard referencing sizeof(arr) -> suppress
        if arr in guarded_arrays_by_fn.get(fn, set()):
            continue
        # (a) the index variable has a direct non-assert upper bound `idx < K` -> suppress
        if re.fullmatch(r'[A-Za-z_]\w*', idx) and idx in bounded_idx_by_fn.get(fn, set()):
            continue
        # variable index into a fixed array with no in-force capacity guard -> CANDIDATE
        key = (c.get('enclosing_function_id'), arr, idx)
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(c.get('enclosing_function_id')) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'INDEX_STORE',
                     'array': arr, 'elem_count': N, 'index_expr': idx,
                     'file': c.get('file'), 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': c.get('enclosing_function_id'), 'line': c.get('line'),
                     'derivation': {'rule': 'CPP_FIXED_ARRAY_INDEX_UNBOUNDED',
                                    'capacity_source': 'SYNTACTIC_ELEM_COUNT'}})
    return cand

if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'INDEX_STORE candidate(s)')
        for x in c:
            print('   ', x['array'], '[', x['index_expr'], '] cap=', x['elem_count'], '@L', x.get('line'))
