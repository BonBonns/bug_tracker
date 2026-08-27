#!/usr/bin/env python3
"""OOB_WRITE (COPY_LENGTH) candidate producer -- a REPRESENTATION VARIANT of the
INDEX_STORE rule in oob_index_write_verdict.py. Same property (an out-of-bounds
write into a fixed-size local array), different C syntax shape: a copy-family call
(`memcpy`/`memmove`/`PORT_Memcpy`/`wmemcpy`) writing `len` bytes into `dest`, where
`len` is not provably <= dest's capacity in bytes.

Motivation: the index-store rule catches `arr[idx] = x` where idx is unbounded, but
real browser/library memory-safety bugs are at least as often shaped like
    memcpy(dest, src, len)
with `len` (not an index) as the attacker/parser-influenced quantity. This is the
same OOB_WRITE property, reached through a different syntactic path -- exactly the
kind of "representation variant" that should be added before inventing a new
property class.

SCOPE (MVP) -- what this pass does NOT yet do, by design (abstain rather than guess):
  - `dest` must be a BARE fixed-size local array name (`T dest[N]`) OR, as of the
    pointer-offset extension below, `arr + offset_expr` where `arr` is itself a bare
    fixed-size local array name -- matched the same syntactic way as
    oob_index_write_verdict.py's `_elem_count`, and scoped per-function via
    (method_id, name) from the start (that producer originally got this wrong via
    bare-name keying -- fixed after being caught scanning real mozilla/nss code; see
    its module history). Heap-allocated destinations (the result of
    `malloc(...)`/`PORT_Alloc(...)`) and offsets into a STRUCT/UNION FIELD
    (`obj->field + off`) remain OUT OF SCOPE and abstained on -- this extension only
    covers a fixed local array plus an offset, not a pointer of unknown capacity plus
    an offset.

  POINTER-OFFSET-DESTINATION EXTENSION -- motivated by two REAL, disclosed bugs found
  during round-3 paired CVE validation, not hypotheticals: NSS CVE-2016-1950
  (`PORT_Memcpy(item->data + item->len, buf, len)`, a heap pointer plus an
  ACCUMULATED offset) and NSS bug 1577953/CVE-2019-11759
  (`HMAC_Finish(hmac, key_block + ((bi - 1) * hashLen), &len, hashLen)`, a local array
  plus a COMPUTED offset, through a non-memcpy sink). Neither is fully covered by this
  extension: the first needs a heap pointer's capacity (unknown here, out of scope)
  and loop-accumulated-offset tracking (temporal, not attempted); the second needs a
  non-memcpy sink recognized (COPY_FUNCS is a fixed allowlist) and its array's
  capacity resolved (blocked separately by unresolved macro names in its size
  expression, not this extension's own limitation). What THIS extension buys: the
  narrower, honestly-scoped slice of the same underlying property -- a fixed local
  array's capacity is known, and a `memcpy`-family call writes `len` bytes starting
  `offset` bytes into it, where neither `offset` nor `len` is provably bounded. It
  does NOT attempt to compute `N - offset` as a tighter remaining-capacity bound (that
  would require evaluating `offset_expr`, which may be an arbitrary runtime
  expression); it treats ANY visible `arr+offset` write into a byte-array with no
  guard mentioning that array's capacity as a CANDIDATE, same suppression rules as the
  bare-destination case. This can NOT currently discriminate "offset is small, len is
  small, definitely still in bounds" from "offset+len exceeds capacity" -- it is
  strictly a widening of WHERE this pass looks (offset-adjusted destinations, not just
  bare ones), not a new soundness capability for THIS shape. Still abstain-by-default
  everywhere else (heap pointers, struct fields, macro-unresolved capacities).
  - The full allocation-size-vs-copy-size chain --
        size_t bytes = count * elementSize;
        T *p = malloc(bytes);
        memcpy(p, src, suppliedLength);
    -- requires tracking a capacity VALUE through an arithmetic assignment and a
    separate allocation call, then relating it to a POINTER (not an array local).
    This pass does not do that yet; it is the natural next representation variant
    once this simpler, array-local shape is validated. Do not read "0 candidates"
    on pointer/heap-target code as "no bug" -- it means "out of scope", not "safe".
  - Element-size arithmetic: a memcpy length is in BYTES, but a fixed array's
    syntactic element count is in ELEMENTS. `T dest[N]` only lets N be compared
    directly against a byte length when T is itself one byte wide. This pass
    therefore ONLY considers destinations whose element type is a known byte-sized
    type (char/unsigned char/uint8_t/...); anything else (e.g. `int dest[8]`, a
    32-byte buffer) is abstained on rather than silently comparing element-count
    to byte-count, which would be a *unit* bug, not a soundness feature.

Soundness (same posture as oob_index_write_verdict.py): emit CANDIDATE only when NO
capacity guard gates the copy. A capacity guard is a comparison that (a) references
the destination array's own sizeof-capacity `sizeof(dest)` OR its literal element
count N, and (b) is NOT merely an argument to an assert-family macro (compiled out
in release builds, does not gate). If in doubt, SUPPRESS. Never emits VULNERABLE;
only CANDIDATE.

KNOWN LIMITATION (inherited from oob_index_write_verdict.py's guard mechanism, not
new here): a guard is credited PER FUNCTION, not per branch/dominance. If a guard
comparing `len` (or a same-named/same-expression length) appears ANYWHERE in the
function, every copy in that function using that same length expression is
suppressed -- even one reached by a completely different code path the guard does
not actually dominate. Found scanning real mozilla/nss lib/ssl/sslsock.c
(ssl_WriteV): a second, unguarded-looking memcpy at a later call site was
suppressed as a side effect of crediting an earlier `if (myIov.iov_len < first_len)`
guard that does not control-flow-dominate it. Manually verified that call site IS
in fact safe too, but for an unrelated reason (a preceding while-loop's exit
condition establishes the same bound) -- so the suppression was numerically
correct here by coincidence, not because this pass proved it. Treat "0
candidates" as "nothing this pass's guard-recognition could distinguish from
guarded", not as a soundness guarantee across an entire function once any guard
appears in it. Real dominance-aware guard scoping would need CFG reachability
between the guard and the copy, which this text-pattern pass does not do.
"""
import json, re, sys

ASSERT_NAMES = ('MOZ_ASSERT', 'MOZ_RELEASE_ASSERT', 'assert', 'NS_ASSERTION', 'NS_ABORT_IF_FALSE',
                'MOZ_DIAGNOSTIC_ASSERT', 'PORT_Assert')
CMP = ('<operator>.lessThan', '<operator>.lessEqualsThan', '<operator>.greaterThan',
       '<operator>.greaterEqualsThan')
# (dest, src, len) argument order, all byte-count length semantics.
COPY_FUNCS = {'memcpy', 'memmove', 'PORT_Memcpy', 'wmemcpy'}
BYTE_ELEM_TYPES = {'char', 'unsigned char', 'signed char', 'uint8_t', 'PRUint8', 'int8_t',
                    'BYTE', 'u_char', 'uint8'}


def _eval_const_int_expr(expr):
    """Fold a simple constant-arithmetic array-size expression to an int, e.g. the
    common macro-expanded shape `(64*2)+8` (mozjpeg's `JOCTET _buffer[BUFSIZE]` with
    `#define BUFSIZE (DCTSIZE2*2)+8` -- confirmed on REAL code: without this, the
    array is invisible to this producer, since a bare-\\d+-only regex simply doesn't
    match). Restricted to digits/whitespace/+-*/() BEFORE ever calling eval, so this
    can't become a code-injection surface via attacker-controlled source text.
    Returns None (abstain) on anything not cleanly a small non-negative constant
    expression."""
    e = (expr or '').strip()
    if not e or not re.fullmatch(r'[\d\s+\-*/()]+', e):
        return None
    try:
        v = eval(e, {'__builtins__': {}}, {})
    except Exception:
        return None
    return v if isinstance(v, int) and v >= 0 else None


def _byte_array_elem_count(type_full_name):
    """Element count N for a fixed-size array local, but ONLY when the element type
    is one byte wide (so N elements == N bytes, the unit a copy length is in).
    Anything else returns None -- abstain, don't guess at a unit conversion."""
    m = re.match(r'^\s*([A-Za-z_][\w ]*?)\s*\[\s*([\d\s+\-*/()]+)\s*\]\s*$', type_full_name or '')
    if not m:
        return None
    elem_type = m.group(1).strip()
    if elem_type not in BYTE_ELEM_TYPES:
        return None
    return _eval_const_int_expr(m.group(2))


def emit_candidates(prefix):
    d = json.load(open(prefix))
    calls = d.get('calls', [])
    locals_ = d.get('locals', [])

    # byte-sized fixed-array locals -> element count N, scoped by (function, name).
    # See oob_index_write_verdict.py: a bare name-keyed dict here would let two
    # functions' same-named, differently-sized arrays clobber each other's capacity.
    arr_count = {}   # (function_id, name) -> N
    for l in locals_:
        n = _byte_array_elem_count(l.get('type_full_name'))
        if n is not None:
            arr_count[(l.get('method_id'), l.get('name'))] = n
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
        if not cc:
            return False
        return any(cc in ac for ac in assert_codes)

    # (b) COUNT GUARD per function: a non-assert comparison referencing the
    #     destination's own sizeof-capacity or literal count.
    guarded_arrays_by_fn = {}   # function_id -> set(array names) with a live capacity guard
    # (a) DIRECT LENGTH BOUND per function: length expressions appearing on the LEFT
    #     of a non-assert `<`/`<=` comparison. Conservative: favors SUPPRESS over FP.
    #     A copy length is often a struct field (`myIov.iov_len < first_len`), not a
    #     bare variable -- the token pattern allows a dotted/arrow chain so that
    #     shape is recognized too (found scanning real NSS code: sslsock.c's
    #     ssl_WriteV guards exactly this way and was otherwise reported as a false
    #     positive because only bare identifiers were being matched).
    NAME_CHAIN = r'[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*'
    bounded_len_by_fn = {}      # function_id -> set(length expressions) with a direct bound
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

    func_by_id = {f.get('id'): f for f in d.get('functions', [])}
    copy_calls = [c for c in calls if (c.get('method_full_name') or c.get('name')) in COPY_FUNCS]
    cand = []
    seen = set()
    for c in copy_calls:
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        if len(args) != 3:
            continue   # not the (dest, src, len) shape this pass models -- abstain
        dest_code = (args[0].get('code') or '').strip()
        len_code = (args[2].get('code') or '').strip()
        fn = c.get('enclosing_function_id')
        # dest must be a BARE fixed-array local name, OR `arr + offset_expr` where
        # arr is one -- a pointer, a struct/union field (`obj->field[+off]`), and a
        # field-plus-offset (`obj->field + off`) all remain out of scope; abstain
        # rather than guess (see module docstring's pointer-offset extension note).
        offset_shape = False
        base = dest_code
        offset_expr = None
        if not re.fullmatch(r'[A-Za-z_]\w*', dest_code):
            m_off = re.match(r'^([A-Za-z_]\w*)\s*\+\s*(.+)$', dest_code)
            if not m_off:
                continue
            base, offset_expr = m_off.group(1), m_off.group(2).strip()
            if not offset_expr:
                continue
            offset_shape = True
        if (fn, base) not in arr_count:
            continue
        N = arr_count[(fn, base)]
        # BOTH offset and length are literal integers -> pure arithmetic, provably
        # safe or unsafe, no guess involved (e.g. real NSS pkcs11c.c's DES2->DES3 key
        # extension: `memcpy(newdeskey, src, 16); memcpy(newdeskey + 16, newdeskey,
        # 8);` on a 24-byte newdeskey -- 16+8 == 24, exactly fits, a legitimate idiom
        # this pass initially false-positived on before this check was added, caught
        # by manually verifying a real candidate this pass produced, not hypothetical).
        if offset_shape and re.fullmatch(r'\d+', offset_expr) and re.fullmatch(r'\d+', len_code):
            if int(offset_expr) + int(len_code) <= N:
                continue
        # constant length, provably in bounds -> safe. Only valid for the BARE
        # destination case: with an offset, the true remaining capacity is N minus
        # whatever `offset_expr` evaluates to at runtime, which this pass does not
        # attempt to compute -- so this fast path is skipped entirely when
        # offset_shape, per the module docstring (widen WHERE we look, not what we
        # can prove safe for this new shape).
        if not offset_shape and re.fullmatch(r'\d+', len_code) and int(len_code) <= N:
            continue
        # capacity guard on this exact base array -> suppress
        if base in guarded_arrays_by_fn.get(fn, set()):
            continue
        # length expression has a direct non-assert upper bound `len < K` -> suppress
        if re.fullmatch(NAME_CHAIN, len_code) and len_code in bounded_len_by_fn.get(fn, set()):
            continue
        key = (fn, dest_code, len_code, c.get('id'))
        if key in seen:
            continue
        seen.add(key)
        _fn = func_by_id.get(fn) or {}
        cand.append({'verdict': 'CANDIDATE', 'class': 'OOB_WRITE', 'subclass': 'COPY_LENGTH',
                     'callee': (c.get('method_full_name') or c.get('name')),
                     'dest': dest_code, 'array_base': base, 'offset_shape': offset_shape,
                     'elem_count': N, 'len_expr': len_code,
                     'file': c.get('file'), 'function': _fn.get('full_name'),
                     'function_line': _fn.get('line'), 'function_line_end': _fn.get('line_end'),
                     'function_id': fn, 'line': c.get('line'),
                     'derivation': {'rule': ('CPP_FIXED_ARRAY_OFFSET_COPY_LENGTH_UNBOUNDED'
                                              if offset_shape else
                                              'CPP_FIXED_ARRAY_COPY_LENGTH_UNBOUNDED'),
                                    'capacity_source': 'SYNTACTIC_BYTE_ELEM_COUNT'}})
    return cand


if __name__ == '__main__':
    for p in sys.argv[1:]:
        c = emit_candidates(p)
        print(p, '->', len(c), 'COPY_LENGTH candidate(s)')
        for x in c:
            print('   ', x['callee'], '(', x['dest'], ',.., ', x['len_expr'], ') cap=',
                  x['elem_count'], 'bytes @L', x.get('line'))
