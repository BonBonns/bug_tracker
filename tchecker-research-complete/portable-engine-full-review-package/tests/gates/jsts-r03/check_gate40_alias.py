#!/usr/bin/env python3
"""Gate 40: may-alias keyed-state provenance from REAL Joern facts reproduces the
prototype Gate-13 ground truth, composing three neutral layers:

  1. identity_facts   — binding -> identity set (must/may) from assignment structure
  2. state_facts      — callee FIELD write/read summaries (this.value = v)
  3. promoted dispatch — callsite -> concrete target (resolution from program_facts)

Store semantics (call-id order == source order, same convention Gate 39 validated):
  - method call whose concrete target has a field WRITE summary: instantiate at the
    callsite receiver's identity set. must receiver -> strong update (kills prior);
    may receiver -> weak update on every identity (adds possibility, keeps prior).
  - the function result is the final method call whose target has a field READ
    summary: union the store over the receiver's identities for that key.
  Resolution: EXACT iff receiver is must AND the slot holds exactly one origin and
  was never weakly written; empty slot -> UNKNOWN; anything else -> AMBIGUOUS.
"""
import base64, json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
FR = HERE.parents[2] / 'frontends' / 'javascript-typescript' / 'joern-ts'
sys.path.insert(0, str(FR))
from state_facts import derive as derive_state, load
from identity_facts import derive_identities

RAW = Path(sys.argv[1])
PF = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else json.load(open(Path(sys.argv[1]).parent / 'program_facts.json'))

methods, calls, args, idents = load(RAW)
state = derive_state(RAW)
ident = derive_identities(RAW)

_d = lambda s: base64.b64decode(s).decode() if s else ''
name_of = {mid: m['name'] for mid, m in methods.items()}
fid_by_name = {v: k for k, v in name_of.items()}
full_by_name = {m['full_name']: mid for mid, m in methods.items()}

# param user-index per function (this-normalized)
param_index = {}
for l in (RAW / 'parameters.tsv').read_text().splitlines():
    r = l.split('\t')
    if len(r) >= 4:
        mid = int(r[1]); nm = _d(r[3]); idx = int(r[2])
        param_index.setdefault(mid, []).append((idx, nm))
user_param = {}
for mid, ps in param_index.items():
    ps = sorted(ps)
    shift = 1 if ps and ps[0][1] == 'this' else 0
    for idx, nm in ps:
        if nm != 'this':
            user_param[(mid, nm)] = idx - shift

# identity lookup
ids_of = {}
for b in ident['bindings']:
    ids_of[(b['function_id'], b['binding'])] = (set(b['identities']), b['must'])

# callee field summaries from state_facts (writes/reads on receiver `this`)
writes_in = {}
for w in state['state_writes']:
    if w['receiver']['name'] == 'this' and w['key']['kind'] == 'LITERAL':
        writes_in.setdefault(w['function_id'], []).append(w)
reads_in = {}
for r in state['state_reads']:
    if r['receiver']['name'] == 'this' and r['key']['kind'] == 'LITERAL':
        reads_in.setdefault(r['function_id'], []).append(r)

# promoted dispatch calls per function (user dispatch only), in call-id order
disp = {}
for c in PF['calls']:
    if c.get('resolution_reason') == 'NOT_DISPATCH_CALL':
        continue
    if c['resolution'] in ('EXACT', 'HEURISTIC') and c.get('corrected_targets'):
        disp.setdefault(c['enclosing_function_id'], []).append(c)
for v in disp.values():
    v.sort(key=lambda c: c['id'])

def origin_of(mid, arg):
    """origin descriptor for a callsite argument: PARAM index, CONST literal, or OPAQUE."""
    nm = arg.get('name') or ''
    if (mid, nm) in user_param:
        return ('PARAM', user_param[(mid, nm)])
    code = arg.get('code') or ''
    if code.startswith('"') or code.startswith("'"):
        return ('CONST', code)
    return ('OPAQUE', code)

def resolve(fname):
    mid = fid_by_name[fname]
    store = {}          # (identity, key) -> set(origin)
    weak_touched = set()  # (identity, key) weakly written at least once
    read_result = None
    for c in disp.get(mid, []):
        tgt = full_by_name.get(c['corrected_targets'][0])
        if tgt is None:
            continue
        cargs = sorted(c.get('arguments', []), key=lambda a: a['index'])
        recv = c.get('receiver_name') or (cargs[0]['name'] if cargs else None)
        rid = ids_of.get((mid, recv))
        if rid is None:
            continue
        rids, must = rid
        # apply callee writes
        for w in writes_in.get(tgt, []):
            vparam = w['value']['name']
            vi = user_param.get((tgt, vparam))
            if vi is None:
                val = ('OPAQUE', vparam)
            else:
                # arguments are receiver-dropped, 0-based positional
                val = origin_of(mid, cargs[vi]) if vi < len(cargs) else ('OPAQUE', vparam)
            for one in rids:
                slot = (one, w['key']['value'])
                if must and len(rids) == 1:
                    store[slot] = {val}                      # strong update
                else:
                    store.setdefault(slot, set()).add(val)   # weak update
                    weak_touched.add(slot)
        # apply callee reads (function result convention: last read wins)
        for r in reads_in.get(tgt, []):
            vals, weak = set(), False
            for one in rids:
                slot = (one, r['key']['value'])
                vals |= store.get(slot, set())
                if slot in weak_touched:
                    weak = True
            read_result = (vals, must and len(rids) == 1 and not weak)
    if read_result is None:
        return ('UNKNOWN', [])
    vals, strong = read_result
    if not vals:
        return ('UNKNOWN', [])
    positions = sorted(v[1] for v in vals if v[0] == 'PARAM')
    if strong and len(vals) == 1:
        return ('EXACT', positions)
    return ('AMBIGUOUS', positions)

truth = {
    'mayAliasWrite':          ('AMBIGUOUS', [1]),
    'sameAliasBothBranches':  ('EXACT',     [1]),
    'mayAliasDifferentField': ('UNKNOWN',   []),
    'mayAliasOverwrite':      ('AMBIGUOUS', [1]),
    'mayAliasRead':           ('AMBIGUOUS', [1]),
}

checks = []
def ck(n, ok, d=''):
    checks.append(bool(ok)); print(('PASS' if ok else 'FAIL'), n, ('- ' + str(d) if d else ''))

for fname, exp in truth.items():
    got = resolve(fname)
    ck(f'{fname}: {exp}', got == exp, f'got {got}')

# non-hardening invariant: only the collapsed must-alias is EXACT
exacts = [f for f in truth if resolve(f)[0] == 'EXACT']
ck('non_hardening: only sameAliasBothBranches is EXACT', exacts == ['sameAliasBothBranches'], exacts)

ok = sum(checks)
print(f'GATE40_ALIAS={ok}/{len(checks)}')
sys.exit(0 if ok == len(checks) else 1)
