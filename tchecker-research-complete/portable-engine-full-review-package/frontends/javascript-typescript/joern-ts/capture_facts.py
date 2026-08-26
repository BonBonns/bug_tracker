#!/usr/bin/env python3
"""Closure-capture facts (portable-capture-facts/0.1) from CLOSURE_BINDING exports.

Neutral fact: CaptureFact { inner_function, inner_binding, outer_function,
outer_binding, outer_kind (LOCAL|PARAMETER), resolution } with FactDerivation.
The core never sees CLOSURE_BINDING; this layer does.
"""
import base64, json, sys
from pathlib import Path
_d = lambda s: base64.b64decode(s).decode() if s else ''

def derive_captures(raw):
    raw = Path(raw)
    loc, par, cb = {}, {}, {}
    for l in (raw/'locals.tsv').read_text().splitlines():
        r = l.split('\t'); loc[int(r[0])] = (int(r[1]), _d(r[2]))
    for l in (raw/'parameters.tsv').read_text().splitlines():
        r = l.split('\t'); par[int(r[0])] = (int(r[1]), _d(r[3]))
    if not (raw/'closure_bindings.tsv').exists():
        return {'schema': 'portable-capture-facts/0.2', 'captures': []}
    for l in (raw/'closure_bindings.tsv').read_text().splitlines():
        r = l.rstrip('\n').split('\t')
        cb[_d(r[1])] = {'node_id': int(r[0]), 'refs': [int(x) for x in r[3].split(',') if x.strip()]}
    out = []
    for l in (raw/'local_closure.tsv').read_text().splitlines():
        r = l.rstrip('\n').split('\t')
        lid = int(r[0]); binding = cb.get(_d(r[1]))
        if not binding or not binding['refs']:
            continue
        inner_fn, inner_name = loc[lid]
        t = binding['refs'][0]
        if t in par:
            ofn, oname, okind = par[t][0], par[t][1], 'PARAMETER'
        elif t in loc:
            ofn, oname, okind = loc[t][0], loc[t][1], 'LOCAL'
        else:
            continue
        out.append({'inner_function': inner_fn, 'inner_binding': inner_name,
                    'inner_local_id': lid,
                    'outer_function': ofn, 'outer_binding': oname, 'outer_kind': okind,
                    'outer_node_id': t,
                    'resolution': 'EXACT',
                    'derivation': {'origin': 'FRONTEND_DIRECT',
                                   'rule': 'CLOSURE_BINDING_REF',
                                   'source_node_ids': [lid, binding['node_id'], t]}})
    return {'schema': 'portable-capture-facts/0.2', 'captures': out}

if __name__ == '__main__':
    print(json.dumps(derive_captures(sys.argv[1]), indent=2))
