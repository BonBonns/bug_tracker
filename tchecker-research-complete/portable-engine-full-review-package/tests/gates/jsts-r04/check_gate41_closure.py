#!/usr/bin/env python3
"""Gate 41: closure-capture provenance from REAL Joern CLOSURE_BINDING facts.

Layers composed:
  1. closure_bindings.tsv + local_closure.tsv (NEW export): inner materialized LOCAL
     --closureBindingId--> CLOSURE_BINDING --REF--> outer LOCAL / PARAMETER.
     Chains are transitive (nested lambdas capture through intermediate lambdas).
  2. identity/def structure for outer locals (single def -> follow; multi-def -> MAY).
  3. enclosing-scope call narrowing: Joern's NaiveCallLinker links `f()` to EVERY
     same-named lambda file-wide (measured: AMBIGUOUS/10). When exactly one candidate
     is scoped inside the calling function AND the called binding has one def, narrow
     to it. (Candidate classifier improvement; used here gate-locally.)

Lambda return convention (explicit): fixtures are single-expression lambdas, so the
lambda's returned origins are the identifiers in its body: own parameters map through
callsite arguments; captured locals map through the capture chain to the outer
binding, then through that binding's defs. Multi-def outer bindings yield MAY
(both possibilities preserved; never hardened to the exact source).
"""
import base64, json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
FR = HERE.parents[2] / 'frontends' / 'javascript-typescript' / 'joern-ts'
sys.path.insert(0, str(FR))
from state_facts import load

RAW = Path(sys.argv[1])
_d = lambda s: base64.b64decode(s).decode() if s else ''

methods, calls, args, idents = load(RAW)
name_of = {mid: m['name'] for mid, m in methods.items()}
full_of = {mid: m['full_name'] for mid, m in methods.items()}
fid_by_name = {v: k for k, v in name_of.items()}

locals_ = {}
for l in (RAW / 'locals.tsv').read_text().splitlines():
    r = l.split('\t')
    locals_[int(r[0])] = {'method_id': int(r[1]), 'name': _d(r[2])}
params = {}
for l in (RAW / 'parameters.tsv').read_text().splitlines():
    r = l.split('\t')
    params[int(r[0])] = {'method_id': int(r[1]), 'index': int(r[2]), 'name': _d(r[3])}
user_param = {}
by_m = {}
for pid, p in params.items():
    by_m.setdefault(p['method_id'], []).append(p)
for mid, ps in by_m.items():
    ps = sorted(ps, key=lambda x: x['index'])
    shift = 1 if ps and ps[0]['name'] == 'this' else 0
    for p in ps:
        if p['name'] != 'this':
            user_param[(mid, p['name'])] = p['index'] - shift

# capture chains
cb = {}
for l in (RAW / 'closure_bindings.tsv').read_text().splitlines():
    r = l.rstrip('\n').split('\t')
    cb[_d(r[1])] = [int(x) for x in r[3].split(',') if x.strip()]
capture = {}   # (inner_method, name) -> outer node id (local or param)
for l in (RAW / 'local_closure.tsv').read_text().splitlines():
    r = l.rstrip('\n').split('\t')
    lid = int(r[0]); targets = cb.get(_d(r[1]), [])
    if targets:
        inner = locals_[lid]
        capture[(inner['method_id'], inner['name'])] = targets[0]

# defs of locals: (method, name) -> list of RHS descriptors (identifier name or opaque)
defs = {}
for cid, c in calls.items():
    if c['name'] != '<operator>.assignment':
        continue
    aa = args.get(cid, [])
    if len(aa) < 2 or not aa[0]['name']:
        continue
    rhs = aa[1]
    key = (c['method_id'], aa[0]['name'])
    if rhs['name']:
        defs.setdefault(key, []).append(('IDENT', rhs['name']))
    elif (rhs.get('code') or '').startswith(('"', "'")):
        defs.setdefault(key, []).append(('CONST', rhs['code']))
    else:
        defs.setdefault(key, []).append(('OPAQUE', rhs.get('code', '')))

def binding_origins(mid, name, depth=0):
    """(origins:set, exact:bool) for a binding in mid; origins are ('PARAM',i)/('CONST',c)."""
    if depth > 8:
        return set(), False
    if (mid, name) in user_param:
        return {('PARAM', user_param[(mid, name)])}, True
    node = capture.get((mid, name))
    if node is not None:  # captured: follow to outer binding
        if node in params:
            p = params[node]
            return {('PARAM', user_param[(p['method_id'], p['name'])])}, True
        if node in locals_:
            o = locals_[node]
            return binding_origins(o['method_id'], o['name'], depth + 1)
    ds = defs.get((mid, name), [])
    if not ds:
        return set(), False
    origins, exact = set(), len(ds) == 1
    for kind, v in ds:
        if kind == 'IDENT':
            o, e = binding_origins(mid, v, depth + 1)
            origins |= o; exact = exact and e
        elif kind == 'CONST':
            origins.add(('CONST', v))
        else:
            origins.add(('OPAQUE', v))
    return origins, exact

def lambda_return_origins(caller_mid, lam_mid, callsite_args):
    """Origins of a single-expression lambda's return, at a given callsite."""
    origins, exact = set(), True
    for pm, nm in sorted(ident_pairs):
        if pm != lam_mid:
            continue
        if (lam_mid, nm) in user_param:      # lambda's own param -> callsite arg
            ui = user_param[(lam_mid, nm)]
            pos_args = [a for a in callsite_args if a['index'] >= 1]
            if ui < len(pos_args):
                a = pos_args[ui]
                if a['name'] and (caller_mid, a['name']) in user_param:
                    origins.add(('PARAM', user_param[(caller_mid, a['name'])]))
                elif (a.get('code') or '').startswith(('"', "'")):
                    origins.add(('CONST', a['code']))
                else:
                    origins.add(('OPAQUE', a.get('code', '')))
        else:
            o, e = binding_origins(lam_mid, nm)
            origins |= o; exact = exact and e
    return origins, exact

# identifiers per method (raw). NOTE: the exporter walks owner.ast, so a nested
# lambda's identifiers appear under BOTH the lambda and its enclosing function with
# the same node id — collect (method_id, name) pairs, do not key by node id.
ident_pairs = set()
for l in (RAW / 'identifiers.tsv').read_text().splitlines():
    r = l.split('\t')
    ident_pairs.add((int(r[1]), _d(r[2])))

def resolve(fname):
    mid = fid_by_name[fname]
    # calls to local lambdas in this function, in id order; take the LAST one (= return f()/g())
    lam_calls = []
    for cid, c in sorted(calls.items()):
        if c['method_id'] != mid or c['name'].startswith('<'):
            continue
        # enclosing-scope narrowing: is there a lambda method named c.name scoped in mid?
        scoped = [m for m, f in full_of.items() if f == full_of[mid] + ':' + c['name']]
        if len(scoped) == 1 and len(defs.get((mid, c['name']), [])) <= 1:
            lam_calls.append((cid, scoped[0]))
    if not lam_calls:
        return ('UNKNOWN', [])
    cid, lam = lam_calls[-1]
    # nested: if the lambda returns another lambda (its body defines a scoped lambda and
    # has no own identifiers), follow one level: g = f() then g() -> inner lambda of f.
    origins, exact = lambda_return_origins(mid, lam, sorted(args.get(cid, []), key=lambda a: a['index']))
    if not origins:
        inner = [m for m, f in full_of.items() if f.startswith(full_of[lam] + ':')]
        if len(inner) == 1:
            origins, exact = lambda_return_origins(mid, inner[0], [])
    origins = {o for o in origins if o[0] != 'CONST' or not exact} if False else origins
    positions = sorted(o[1] for o in origins if o[0] == 'PARAM')
    non_param = [o for o in origins if o[0] != 'PARAM']
    if not origins:
        return ('EXACT', [])          # returns constant-only lambda: no external provenance
    if exact and not non_param and len(positions) == len(origins):
        return ('EXACT', positions)
    if exact and positions == [] :
        return ('EXACT', [])
    return ('MAY', positions)

truth = {
    'closureDirect':           ('EXACT', [0]),
    'closureParam':            ('EXACT', [0]),
    'closureShadow':           ('EXACT', []),
    'closureUnrelated':        ('EXACT', []),
    'closureAlias':            ('EXACT', [0]),
    'closureTwoCaptures':      ('EXACT', [0, 1]),
    'nestedClosure':           ('EXACT', [0]),
    'closureLocalShadowsOuter':('EXACT', []),
    # mutation cases: multi-def captured binding -> MAY, source position preserved,
    # NEVER hardened to exact-source (matches the canonical engine's hard-channel []).
    'closureMutation':         ('MAY',   [0]),
    'closureMutationToSource': ('MAY',   [0]),
}

checks = []
def ck(n, ok, d=''):
    checks.append(bool(ok)); print(('PASS' if ok else 'FAIL'), n, ('- ' + str(d) if d else ''))

for fname, exp in truth.items():
    got = resolve(fname)
    ck(f'{fname}: {exp}', got == exp, f'got {got}')

exact_src = [f for f, e in truth.items() if e[0] == 'MAY' and resolve(f)[0] == 'EXACT']
ck('non_hardening: mutation cases never EXACT', exact_src == [], exact_src)

ok = sum(checks)
print(f'GATE41_CLOSURE={ok}/{len(checks)}')
sys.exit(0 if ok == len(checks) else 1)
