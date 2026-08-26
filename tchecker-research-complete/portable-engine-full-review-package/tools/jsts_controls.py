#!/usr/bin/env python3
"""JSTS-MEASURE-R01: executable POSITIVE and NEGATIVE controls for every JS/TS
classifier bucket. A bucket is only trustworthy if it fires on a case that should
fire AND stays silent on a near-miss that should not.

Three real measurement defects motivated this (lambda filtering, vacuous zero-arg
INSUFFICIENT_TYPE_INFO, require-as-callee), all found only after they had already
distorted a roadmap decision.
"""
import io, json, os, subprocess, sys, tempfile, contextlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hof_r02

FID, LID, CID, PID = 100, 200, 300, 400

def doc(functions, calls, locals_=(), assigns=(), captures=()):
    return ({'schema': 'portable-program-facts/0.3', 'frontend': 'test',
             'functions': functions, 'calls': calls, 'locals': list(locals_),
             'assignments': list(assigns), 'returns': [], 'identifiers': [],
             'type_decls': [], 'members': [], 'method_returns': []},
            {'schema': 'portable-capture-facts/0.2', 'captures': list(captures)})

def fn(i, name, full, params=()):
    return {'id': i, 'name': name, 'full_name': full, 'is_external': False, 'file': 'a.js',
            'line': 1, 'line_end': 9, 'parameters': [
                {'id': PID + j, 'method_id': i, 'index': j, 'name': p, 'code': p,
                 'type_full_name': 'ANY', 'line': 1} for j, p in enumerate(params)]}

def call(i, encl, name, targets=(), res='UNRESOLVED', args=()):
    return {'id': i, 'enclosing_function_id': encl, 'name': name, 'method_full_name': name,
            'dispatch_type': '', 'type_full_name': '', 'code': f'{name}()', 'file': 'a.js',
            'line': 2, 'candidate_target_ids': list(targets), 'candidate_target_full_names': [],
            'resolution': res, 'arguments': list(args)}

def classify(d, caps):
    w = tempfile.mkdtemp()
    json.dump(d, open(f'{w}/js.json', 'w')); json.dump(caps, open(f'{w}/js_capture.json', 'w'))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): hof_r02.main(w, 'ctl')
    return buf.getvalue()

ok = tot = 0
def ck(name, cond, detail=''):
    global ok, tot; tot += 1; ok += bool(cond)
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else f'  [{detail}]'))

# ---- EXACT_CALLABLE: local bound to a FUNCTION ref, then invoked -------------
lam = fn(FID + 1, '<lambda>0', 'a.js::program:<lambda>0')
outer = fn(FID, 'outer', 'a.js::program:outer')
d, c = doc([outer, lam], [call(CID, FID, 'cb')],
           [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
           [{'id': 1, 'function_id': FID, 'target_local_id': LID, 'line': 1,
             'value_ref': {'kind': 'FUNCTION', 'id': FID + 1, 'code': '<lambda>0'},
             'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}])
out = classify(d, c)
ck('EXACT_CALLABLE positive: FUNCTION-ref binding fires', 'EXACT_CALLABLE' in out, out)
# NEGATIVE: same shape but the value is an UNKNOWN, not a callable reference
d2, c2 = doc([outer, lam], [call(CID, FID, 'cb')],
             [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
             [{'id': 1, 'function_id': FID, 'target_local_id': LID, 'line': 1,
               'value_ref': {'kind': 'UNKNOWN', 'id': -1, 'code': 'someValue'},
               'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}])
out2 = classify(d2, c2)
ck('EXACT_CALLABLE negative: non-callable value does NOT fire',
   'EXACT_CALLABLE' not in out2 and 'UNKNOWN_CALLABLE' in out2, out2)

# ---- BOUNDED_CALLABLE_SET: two distinct FUNCTION defs -----------------------
lam2 = fn(FID + 2, '<lambda>1', 'a.js::program:<lambda>1')
mk = lambda tgt, i: {'id': i, 'function_id': FID, 'target_local_id': LID, 'line': i,
                     'value_ref': {'kind': 'FUNCTION', 'id': tgt, 'code': f'<lambda>{i}'},
                     'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [i]}}
d3, c3 = doc([outer, lam, lam2], [call(CID, FID, 'cb')],
             [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
             [mk(FID + 1, 1), mk(FID + 2, 2)])
out3 = classify(d3, c3)
ck('BOUNDED_CALLABLE_SET positive: two callable defs fire', 'BOUNDED_CALLABLE_SET' in out3, out3)
ck('BOUNDED negative: two defs of the SAME target do not report bounded',
   'BOUNDED_CALLABLE_SET' not in classify(*doc([outer, lam], [call(CID, FID, 'cb')],
        [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
        [mk(FID + 1, 1), mk(FID + 1, 2)])))

# ---- EXTERNAL_CALLABLE: require(...) bound value ----------------------------
d4, c4 = doc([outer], [call(CID, FID, 'cb')],
             [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
             [{'id': 1, 'function_id': FID, 'target_local_id': LID, 'line': 1,
               'value_ref': {'kind': 'CALL', 'id': 9, 'code': 'require("pkg")'},
               'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}])
ck('EXTERNAL_CALLABLE positive: require-bound value fires', 'EXTERNAL_CALLABLE' in classify(d4, c4))
d5, c5 = doc([outer], [call(CID, FID, 'cb')],
             [{'id': LID, 'method_id': FID, 'name': 'cb', 'code': 'cb', 'type_full_name': 'ANY', 'line': 1}],
             [{'id': 1, 'function_id': FID, 'target_local_id': LID, 'line': 1,
               'value_ref': {'kind': 'CALL', 'id': 9, 'code': 'helper()'},
               'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}])
ck('EXTERNAL negative: an ordinary call result is NOT external',
   'EXTERNAL_CALLABLE' not in classify(d5, c5))

# ---- MODULE_LOADER_BUILTIN: require itself must not be a higher-order site ---
d6, c6 = doc([outer], [call(CID, FID, 'require')],
             [{'id': LID, 'method_id': FID, 'name': 'require', 'code': 'require',
               'type_full_name': 'ANY', 'line': 1}])
out6 = classify(d6, c6)
ck('MODULE_LOADER_BUILTIN: require(...) is NOT counted as a higher-order site',
   'no higher-order call sites' in out6 or '0 higher-order' in out6, out6)

# ---- UNKNOWN_CALLABLE: capture chain terminating at an API-boundary param ----
inner = fn(FID + 3, 'inner', 'a.js::program:outer:inner')
d7, c7 = doc([fn(FID, 'outer', 'a.js::program:outer', ('fn',)), inner],
             [call(CID, FID + 3, 'fn')],
             [{'id': LID + 1, 'method_id': FID + 3, 'name': 'fn', 'code': 'fn',
               'type_full_name': 'ANY', 'line': 2}], (),
             [{'inner_function': FID + 3, 'inner_binding': 'fn', 'inner_local_id': LID + 1,
               'outer_function': FID, 'outer_binding': 'fn', 'outer_kind': 'PARAMETER',
               'outer_node_id': PID, 'resolution': 'EXACT',
               'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}])
out7 = classify(d7, c7)
ck('UNKNOWN_CALLABLE positive: API-boundary parameter with no in-repo callers',
   'UNKNOWN_CALLABLE' in out7, out7)
ck('UNKNOWN negative: that same chain does not fabricate an EXACT',
   'EXACT_CALLABLE' not in out7, out7)

print(f'JSTS_CONTROLS={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
