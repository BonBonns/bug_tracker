#!/usr/bin/env python3
"""MERGE-R01: source-definition identity on top of per-TU extraction identity.

Three distinct concepts, previously conflated:
  extraction identity      TU_A:function123        (what Joern emitted)
  source-definition identity  leveldb::Slice::Slice(char*,size_t)
  runtime dispatch target  (what the engine resolves)
Per-TU instances are NEVER deleted — invariant I4 still holds. They are GROUPED
under a canonical definition, and matching then operates over canonical
definitions instead of raw instances.

KEY CHOICE, forced by measurement: the key is full_name, which in c2cpg already
encodes qualified scope AND signature (leveldb.Slice.Slice:void(char*,size_t)).
Line span is deliberately NOT part of the key: preprocessing shifts line numbers,
so the same header definition shows 36 instances across 36 TUs with 21 DISTINCT
spans — a span-based key would under-merge by ~20x.

CONSERVATISM: only QUALIFIED names (namespace/class-scoped) are canonicalized.
An unqualified name may be a file-local `static` function, where two TUs can hold
genuinely DIFFERENT functions sharing a name; those are left un-canonicalized.
"""
import json, sys
from collections import defaultdict

def canonical_key(f):
    full = f.get('full_name') or ''
    head = full.split(':')[0]
    if '.' not in head:
        return None                      # unqualified -> possible file-local static
    return full                          # qualified name + signature

def build(functions):
    groups = defaultdict(list)
    for f in functions:
        k = canonical_key(f)
        if k: groups[k].append(f)
    canon = []
    inst2canon = {}
    for i, (k, fs) in enumerate(sorted(groups.items())):
        cid = f'CANON{i:06d}'
        tus = sorted({f.get('translation_unit') for f in fs if f.get('translation_unit')})
        canon.append({'canonical_id': cid, 'full_name': k, 'name': fs[0]['name'],
                      'signature': k.split(':', 1)[1] if ':' in k else '',
                      'arity': len(fs[0].get('parameters', [])),
                      'instance_ids': sorted(f['id'] for f in fs),
                      'member_tus': tus, 'instances': len(fs),
                      'line_spans': sorted({(f.get('line'), f.get('line_end')) for f in fs})[:1]})
        for f in fs: inst2canon[f['id']] = cid
    return canon, inst2canon

def main():
    merged = json.load(open(sys.argv[1]))
    canon, inst2canon = build(merged['functions'])
    collapsed = sum(c['instances'] - 1 for c in canon)
    doc = {'schema': 'portable-canonical-defs/0.1', 'canonical_definitions': canon,
           'derivation': {'origin': 'FRONTEND_COMPOSED', 'rule': 'CPP_CANONICAL_DEFINITION',
                          'key': 'qualified full_name (scope+signature); line span excluded '
                                 '(preprocessing shifts lines); unqualified names not canonicalized'}}
    json.dump(doc, open(sys.argv[2], 'w'), indent=1, sort_keys=True)
    multi = [c for c in canon if c['instances'] > 1]
    print(f"canonical definitions: {len(canon)}  (from {len(merged['functions'])} instances)")
    print(f"  definitions seen in >1 TU: {len(multi)}; redundant instances grouped: {collapsed}")
    print(f"  largest: " + ", ".join(f"{c['name']}x{c['instances']}" for c in sorted(multi, key=lambda x:-x['instances'])[:3]))

if __name__ == '__main__':
    main()
