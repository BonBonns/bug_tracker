#!/usr/bin/env python3
"""EXT-R01: characterize external/out-param blockers and count what each BLOCKS.

For every abstaining row we record the external call behind it and its provenance
class, then compute the transitive set of OTHER abstaining rows that depend on it
(via EXACT internal calls, which is also how expression operands of kind CALL
reach a callee). The question answered is not "should we support externals" but
"which class blocks enough rows, mechanically safely, to justify a neutral fact".
"""
import json, sys
from collections import defaultdict, Counter, deque

CLASS = {
 'malloc':'FRESH_ALLOCATION','realloc':'FRESH_ALLOCATION','calloc':'FRESH_ALLOCATION','free':'OPAQUE',
 'strdup':'VALUE_PRESERVING','memcpy':'VALUE_PRESERVING','memmove':'VALUE_PRESERVING','strcpy':'VALUE_PRESERVING',
 'atoi':'VALUE_DERIVED','atol':'VALUE_DERIVED','strtol':'VALUE_DERIVED','strlen':'VALUE_DERIVED',
 'memcmp':'PREDICATE','strcmp':'PREDICATE','strncmp':'PREDICATE','isspace':'PREDICATE',
 'sscanf':'OUT_PARAM_WRITE','snprintf':'OUT_PARAM_WRITE','vsnprintf':'OUT_PARAM_WRITE',
 'read':'OUT_PARAM_WRITE','write':'VALUE_DERIVED','ioctl':'OUT_PARAM_WRITE',
}
ARTIFACT = ('__bswap','__builtin','__')

rows_out = []
class_blocks = defaultdict(set)
class_direct = defaultdict(list)

for repo in ('sds','linenoise','jsmn','logc'):
    doc = json.load(open(f'/tmp/pp2_{repo}/cpp.json'))
    rep = json.load(open(f'/tmp/pp2_{repo}.json'))['sides'][0]
    fn_by_id = {f['id']: f['name'] for f in doc['functions']}
    id_by_name = {f['name']: f['id'] for f in doc['functions']}
    abst = {r['function']: r for r in rep['rows'] if 'abstention' in r
            and not r['function'].startswith(ARTIFACT)}
    # caller -> callees (EXACT internal dispatch)
    callees = defaultdict(set)
    for c in doc['calls']:
        if c['resolution'] == 'EXACT' and len(c['candidate_target_ids']) == 1:
            caller = fn_by_id.get(c['enclosing_function_id'])
            callee = fn_by_id.get(c['candidate_target_ids'][0])
            if caller and callee and caller != callee:
                callees[caller].add(callee)
    callers = defaultdict(set)
    for a, bs in callees.items():
        for b in bs: callers[b].add(a)

    for name, r in abst.items():
        parts = r['abstention'].split('+')
        ext = [p.split(':',1)[1] for p in parts if p.startswith('EXTERNAL_OR_UNRESOLVED_CALL')]
        outp = [p for p in parts if p.startswith('LOCAL_ONLY_OUTPARAM')]
        if not ext and not outp: continue
        for callee in (ext or ['<out-param>']):
            cls = CLASS.get(callee, 'OUT_PARAM_WRITE' if outp and not ext else 'OPAQUE')
            # transitive abstaining ancestors
            seen, dq = set(), deque([name])
            while dq:
                cur = dq.popleft()
                for up in callers.get(cur, ()):
                    if up in abst and up not in seen:
                        seen.add(up); dq.append(up)
            rows_out.append((repo, name, callee, cls, len(seen)))
            class_direct[cls].append(f'{repo}:{name}')
            class_blocks[cls] |= {f'{repo}:{x}' for x in seen}

print(f"{'repo':10s} {'blocked function':24s} {'external call':16s} {'class':17s} downstream")
for repo, name, callee, cls, n in sorted(rows_out, key=lambda x: (-x[4], x[3])):
    print(f"  {repo:8s} {name:24s} {callee:16s} {cls:17s} {n}")
print()
print(f"{'class':18s} {'direct rows':>11s} {'distinct downstream rows':>25s}")
for cls in sorted(set(list(class_direct) + list(class_blocks))):
    print(f"  {cls:16s} {len(class_direct[cls]):11d} {len(class_blocks[cls]):25d}"
          + (f"   {sorted(class_blocks[cls])[:3]}" if class_blocks[cls] else ""))
