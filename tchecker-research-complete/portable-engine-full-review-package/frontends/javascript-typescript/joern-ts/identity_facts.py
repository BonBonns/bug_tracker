#!/usr/bin/env python3
"""Binding-identity facts from real Joern assignment structure: the aliasing layer.

Neutral model:
  IdentityFact(function, binding, identities: set, must: bool)

Rules (no CFG required; deliberately weaker than reaching-defs, never stronger):
  - An assignment `bind = <non-identifier RHS>` creates a FRESH opaque identity,
    anchored at the defining assignment call id (covers `new A()` blocks, calls,
    literals — anything we can't see through).
  - An assignment `bind = <identifier RHS>` copies the RHS binding's identity set.
  - A binding with multiple assignments takes the UNION of all its defs' identities.
    must == (|identities| == 1). Two branches assigning the same source binding
    collapse to must; different sources make a may-alias. Nothing is hardened.
  - Parameters get a fresh identity anchored at the parameter id (distinct receivers
    stay distinct).

This is exactly the neutral core's multi-definition discipline lifted to object
identity: union, and only a singleton union is exact.
"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from state_facts import load

def derive_identities(raw):
    methods, calls, args, idents = load(raw)
    # collect per-function: defs[binding] = list of RHS descriptors
    defs = {}
    for cid, c in calls.items():
        if c['name'] != '<operator>.assignment':
            continue
        aa = args.get(cid, [])
        if len(aa) < 2:
            continue
        lhs, rhs = aa[0], aa[1]
        if not lhs['name']:
            continue  # keyed writes handled by state_facts, not identity
        key = (c['method_id'], lhs['name'])
        rhs_desc = ('COPY', rhs['name']) if rhs['name'] else ('FRESH', cid)
        defs.setdefault(key, []).append(rhs_desc)

    # parameters: fresh identity per param id
    param_rows = []
    p = Path(raw) / 'parameters.tsv'
    if p.exists():
        import base64
        d = lambda s: base64.b64decode(s).decode() if s else ''
        for l in p.read_text().splitlines():
            r = l.split('\t')
            if len(r) >= 4:
                param_rows.append((int(r[1]), d(r[3]), int(r[0])))

    identities = {}
    for mid, name, pid in param_rows:
        if name != 'this':
            identities[(mid, name)] = {f'PARAM@{pid}'}

    # fixpoint over copy equations (cycles safe: monotone union)
    changed = True
    while changed:
        changed = False
        for key, rhss in defs.items():
            cur = set(identities.get(key, set()))
            new = set(cur)
            for kind, v in rhss:
                if kind == 'FRESH':
                    new.add(f'ALLOC@{v}')
                else:
                    new |= identities.get((key[0], v), set())
            if new != cur:
                identities[key] = new
                changed = True

    out = []
    for (mid, name), ids in sorted(identities.items()):
        srcs = []
        for kind, v in defs.get((mid, name), []):
            if kind == 'FRESH': srcs.append(v)
        out.append({'function_id': mid, 'binding': name,
                    'identities': sorted(ids), 'must': len(ids) == 1,
                    'resolution': 'EXACT' if len(ids) == 1 else 'AMBIGUOUS',
                    'derivation': {
                        'origin': 'DATAFLOW_DERIVED',
                        'rule': 'DEF_UNION_IDENTITY' + ('_PARAM' if (mid, name) not in defs else ''),
                        'source_node_ids': sorted(srcs),
                    }})
    return {'schema': 'portable-identity-facts/0.2', 'bindings': out}

if __name__ == '__main__':
    print(json.dumps(derive_identities(sys.argv[1]), indent=2))
