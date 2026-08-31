#!/usr/bin/env python3
"""OOB_WRITE (INDEX) candidate producer — NEW capability, separate from the frozen
memcpy-surface producer. Evidence-gated by MOZ-OOB-R01 Row 3 (CVE-2022-28281).

Detects: an indexed STORE `arr[idx]...` (incl. arr[idx].field) whose base `arr` is EITHER
a fixed-size array local `T[N]` (N read syntactically from the type, so OPAQUE element types
are supported — the count is what a bound needs) OR (PARAM-CAP-R01, task #44) a pointer
PARAMETER whose real capacity is evidence-backed derivable from a separate integer parameter
in the same function — see param_length_capacity.py for the full evidence model (real
data-flow chase through this function's own assignments, never a loose "pointer followed by
integer" heuristic). Motivated by, and directly re-verified against, the real Mozilla Tremor
CVE-2018-5147 fixture, whose vulnerable write (`a[o+j]+=...`) is exactly this shape: `a` is a
pointer parameter, its real capacity is carried by a sibling parameter `n`, and neither this
producer's prior fixed-local-array-only logic nor the memcpy-surface `oob_write_verdict.py`
(no `memcpy`-family call exists at this site at all) could ever represent it.

Soundness (the field-read lesson): emit CANDIDATE only when NO capacity guard gates the write.
A capacity guard is a comparison that (a) references the array's own sizeof-capacity
`sizeof(arr)/sizeof(arr[0])`, the literal count N, OR (PARAM-CAP-R01) the real, identity-matched
length parameter for a param-based array, and (b) is NOT merely an argument to an
assert-family macro (MOZ_ASSERT/assert/NS_ASSERTION) — those are compiled out and do not gate.
If in doubt about a guard, we SUPPRESS (abstain) rather than false-positive.
Never emits VULNERABLE; only CANDIDATE.
"""
import json, re, sys
import param_length_capacity as plc
from cfg_loop_guard import build_cfg_index, loop_iteration_safe_dominates

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert', 'PR_ASSERT')
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
    # PARAM-CAP-R01 phase 2 (task #44): real dominator-tree data, built once per file, used
    # ONLY to CFG-verify PARAM-CAP-R01 guard suppression below -- the pre-existing fixed-array
    # guard logic (guarded_arrays_by_fn/bounded_idx_by_fn) is untouched, its own established
    # heuristic tradeoff unchanged.
    cfg_index = build_cfg_index(d)
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
    # NOTE (task #44): no early `if not arr_count: return []` here anymore -- PARAM-CAP-R01
    # candidates (a pointer parameter's capacity via a separate length parameter) can exist in a
    # file with ZERO fixed-array locals at all. The real Tremor CVE-2018-5147 fixture is exactly
    # this case (arr_count is empty for the whole file; its only real candidate is param-based).

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
    # PARAM-CAP-R01 (task #44): a non-assert `<`/`<=` comparison whose RHS argument is
    # IDENTITY-matched (value_ref.kind=='PARAMETER', value_ref.id==param id -- not text alone)
    # to a real integer parameter, keyed by (function, exact LHS index-expression text). Handles
    # COMPOUND index expressions (`o+j < n`), which the bare-identifier `bounded_idx_by_fn` above
    # cannot (the real Tremor PATCHED guard is exactly `o+j<n` -- not a bare identifier).
    #
    # TEXTUAL EXISTENCE ALONE IS NOT SOUND (found and fixed in a second #44 phase, per direct
    # review): a name being referenced in SOME `<`/`<=` comparison ANYWHERE in the function is
    # necessary but not sufficient evidence that a given write is actually gated by it -- the
    # comparison may not control-flow-DOMINATE the write on every execution. Confirmed concretely
    # on the real Tremor `vorbis_book_decodev_add`: `for(i=0;i<n;)` exists, UNCHANGED, in BOTH the
    # vulnerable and patched source -- it genuinely DOMINATES the write (nothing bypasses it
    # structurally), yet the vulnerability is real: the write sits inside a NESTED inner loop that
    # can re-execute many times per outer iteration without ever re-passing through the outer
    # check. Plain dominance cannot see this; see cfg_loop_guard.py's
    # `loop_iteration_safe_dominates()` (real dominator-tree machinery, reused from
    # `allocation_extent.py`/`call_context_guard.py`, not a new algorithm) for the fix: a guard
    # must dominate the write AND be at-or-inside the write's own innermost enclosing loop (so it
    # is genuinely re-evaluated on every iteration, not checked once from outside and bypassed by
    # the loop's own back-edge). Verified directly: the real fix's own new guard
    # (`for (j=0;i<n && j<book->dim;)`, evaluated as part of the INNER loop's own header) passes
    # this check; the pre-existing OUTER `i<n` does not, in EITHER file. This entry now stores the
    # comparison's OWN node id (not just the matched parameter id) so the suppression check below
    # can run this CFG proof, not just an existence check.
    param_guarded_idx_by_fn = {}   # function_id -> {(idx_expr_text) -> set((param_id, cmp_call_id))}
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
            args = {a.get('index'): a for a in c.get('arguments', [])}
            lhs, rhs = args.get(0), args.get(1)
            if lhs and rhs:
                rvr = rhs.get('value_ref') or {}
                if rvr.get('kind') == 'PARAMETER':
                    lhs_text = re.sub(r'\s+', '', (lhs.get('value_ref') or {}).get('code') or '')
                    if lhs_text:
                        param_guarded_idx_by_fn.setdefault(fn, {}).setdefault(lhs_text, set()).add(
                            (rvr.get('id'), c.get('id')))

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
        # index operand = the text inside [ ... ]
        mi = re.match(r'^\s*[A-Za-z_]\w*\s*\[\s*([^\]]+?)\s*\]', code)
        idx = (mi.group(1).strip() if mi else '')

        if (fn, arr) in arr_count:
            N = arr_count[(fn, arr)]
            # constant, provably in-bounds -> safe
            if re.fullmatch(r'\d+', idx) and int(idx) < N:
                continue
            # (b) upstream count guard referencing sizeof(arr) -> suppress
            if arr in guarded_arrays_by_fn.get(fn, set()):
                continue
            # (a) the index variable has a direct non-assert upper bound `idx < K` -> suppress
            if re.fullmatch(r'[A-Za-z_]\w*', idx) and idx in bounded_idx_by_fn.get(fn, set()):
                continue
            key = (fn, arr, idx)
            if key in seen:
                continue
            seen.add(key)
            _fn = func_by_id.get(fn) or {}
            cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'INDEX_STORE',
                         'array': arr, 'elem_count': N, 'index_expr': idx,
                         'file': c.get('file'), 'function': _fn.get('full_name'),
                         'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                         'function_id': fn, 'line': c.get('line'),
                         'derivation': {'rule': 'CPP_FIXED_ARRAY_INDEX_UNBOUNDED',
                                        'capacity_source': 'SYNTACTIC_ELEM_COUNT'}})
            continue

        # Not a fixed local array. PARAM-CAP-R01 (task #44): is `arr` a pointer parameter (or a
        # local pointer-arithmetic offset from one) with a real, evidence-backed length
        # parameter?
        param, offset, base_status = plc.resolve_pointer_base(d, fn, arr)
        if base_status == 'NOT_PARAM_BASED' or param is None:
            continue                                        # not representable -> abstain
        if base_status == 'OFFSET_UNRESOLVED':
            continue                                        # can't bound the offset -> abstain
        result = plc.derive_length_param(d, fn, idx)
        if result['status'] != 'RESOLVED':
            continue                                        # no/ambiguous/unit-mismatched -> abstain
        L = result['length_param']
        # constant index, offset known, no guard needed to check boundedness only when we can
        # ALSO bound L -- L is runtime, so a constant idx does not make this statically safe here
        # (unlike the fixed-N case): only an explicit guard or STATIC_EXTENT_SAFE-style match can
        # clear it. (b) capacity guard: a real, non-assert, identity-matched `idx < L` / `idx<=L`.
        # normalize the write's own index text for guard lookup: `i++`/`++i`/`i--`/`--i` compares
        # against a guard on the bare loop variable `i` (the guard text itself, e.g. `i<n`, never
        # contains an increment operator -- only the WRITE side's own subscript does, e.g.
        # `a[i++]`); a compound expression (`o+j`) is matched verbatim, unchanged.
        _idx_incdec = re.fullmatch(r'(?:\+\+|--)?([A-Za-z_]\w*)(?:\+\+|--)?', idx.strip())
        idx_guard_key = _idx_incdec.group(1) if _idx_incdec else re.sub(r'\s+', '', idx)
        # PARAM-CAP-R01 phase 2 (task #44): TEXTUAL match against L is necessary but NOT
        # sufficient -- require a real CFG proof that the matched guard protects THIS write on
        # every execution (dominance + loop-iteration-safety), not merely that a same-named
        # comparison exists somewhere in the function. Fails CLOSED toward NOT suppressing (stays
        # a candidate) whenever CFG data for this function/these nodes is missing -- the opposite
        # fail-direction from the pre-existing fixed-array heuristic, deliberately: this is new,
        # narrower machinery whose whole purpose is to stop crediting unproven guards, so an
        # inability to prove protection must never silently become a suppression.
        fg = cfg_index.get(fn)
        write_node_id = c.get('id')
        credited = False
        for pid, cmp_id in param_guarded_idx_by_fn.get(fn, {}).get(idx_guard_key, set()):
            if pid != L['id']:
                continue
            if fg and cmp_id in fg['nodes'] and write_node_id in fg['nodes']:
                if loop_iteration_safe_dominates(fg, cmp_id, write_node_id):
                    credited = True
                    break
        if credited:
            continue                                        # validly guarded against the real L -> suppress
        key = (fn, arr, idx, 'PARAM_LENGTH_PAIR')
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        entry = {'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'INDEX_STORE',
                 'array': arr, 'index_expr': idx,
                 'file': c.get('file'), 'function': _fn.get('full_name'),
                 'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                 'function_id': fn, 'line': c.get('line'),
                 'length_param_name': L['name'], 'length_param_id': L['id'],
                 'pointer_offset': offset,
                 'derivation': {'rule': 'CPP_PARAM_LENGTH_PAIR_INDEX_UNBOUNDED',
                                'capacity_source': 'PARAM_LENGTH_PAIR',
                                'reaching_names': sorted(result['reaching_names'])}}
        corrob = plc.corroborate_from_call_sites(d, fn, L)
        if corrob:
            entry['call_site_corroboration'] = corrob
        cand.append(entry)
    return cand

if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'INDEX_STORE candidate(s)')
        for x in c:
            cap = x['elem_count'] if 'elem_count' in x else ('param:' + x.get('length_param_name', '?'))
            print('   ', x['array'], '[', x['index_expr'], '] cap=', cap, '@L', x.get('line'))
