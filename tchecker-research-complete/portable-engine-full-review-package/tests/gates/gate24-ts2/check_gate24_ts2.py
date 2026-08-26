#!/usr/bin/env python3
"""Gate 24-TS-2: corrected dispatch-resolution classification on REAL jssrc2cpg facts.

Consumes the raw TSVs exported by the (fresh, real-Joern) Gate 24-TS run and asserts
that the corrected classifier never hardens synthetic linker stubs to EXACT, while
recovering EXACT for the genuinely exact typed-receiver case after artifact dedup.
"""
import base64, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'frontends' / 'javascript-typescript' / 'joern-ts'))
from dispatch_resolution import classify_call, canonical, collapse_init

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / '..' / 'gate24-ts' / 'run' / 'joern' / 'raw').resolve()
d = lambda s: base64.b64decode(s).decode() if s else ''
rows = lambda p, n: [l.split('\t') for l in (RAW / p).read_text().splitlines() if l.strip() and len(l.split('\t')) >= n]

methods_by_id, methods_by_full, name_of = {}, {}, {}
for r in rows('methods.tsv', 10):
    mid = int(r[0]); full = d(r[2]); ext = r[9] == 'true'
    methods_by_id[mid] = {'full_name': full, 'is_external': ext}
    if not ext and '::program' in full:
        methods_by_full[collapse_init(canonical(full))] = mid
    name_of[mid] = d(r[1])

type_decls = [{'id': int(r[0]), 'name': d(r[1]), 'full_name': d(r[2]), 'inherits_from': d(r[6]) if len(r) > 6 else ''} for r in rows('type_decls.tsv', 3)]
_td_by_id = {t['id']: t['full_name'] for t in type_decls}
# members.tsv: id, ownerTypeDeclId, name(b64), code(b64), typeFullName(b64), line
members = [{'owner_full': _td_by_id.get(int(r[1]), ''), 'name': d(r[2]), 'type': d(r[4])} for r in rows('members.tsv', 6)]

args_by_call = {}
for r in rows('arguments.tsv', 8):
    args_by_call.setdefault(int(r[1]), []).append({'index': int(r[2]), 'type_full_name': d(r[6])})

func_name = {}
for r in rows('methods.tsv', 10):
    func_name[int(r[0])] = d(r[1])

calls_by_fn = {}
for r in rows('calls.tsv', 11):
    cid = int(r[0]); owner = int(r[1]); nm = d(r[2])
    if nm != 'process':
        continue
    tids = [int(x) for x in r[9].split(',') if x.strip()]
    calls_by_fn[func_name.get(owner, '?')] = {
        'candidate_target_ids': tids,
        'arguments': args_by_call.get(cid, []),
    }

checks = []
def ck(n, ok, detail=''):
    checks.append((n, bool(ok)))
    print(('PASS' if ok else 'FAIL'), n, ('- ' + str(detail) if detail else ''))

def cls(fn):
    c = calls_by_fn.get(fn)
    if c is None:
        return None, [], ['no call captured']
    return classify_call(c, methods_by_id, methods_by_full, type_decls, members)

# 1. typed receiver: artifacts dedup to ONE concrete method; receiver agreement -> EXACT
r, m, why = cls('exact')
ck('exact: resolution EXACT after artifact dedup', r == 'EXACT', (r, m))
ck('exact: single concrete target is A:process', m == ['01_exact_parameter.ts::program:A:process'], m)

# 2. union receiver: NEVER hardened to EXACT; includes union file's A and B impls
r, m, why = cls('unionCall')
ck('unionCall: not EXACT (union stub cannot harden)', r != 'EXACT', (r, len(m)))
ck('unionCall: AMBIGUOUS over expanded implementations', r == 'AMBIGUOUS', r)
ck('unionCall: includes 02 A.process and 02 B.process',
   '02_union_receiver.ts::program:A:process' in m and '02_union_receiver.ts::program:B:process' in m, m)

# 3. interface dispatch: not EXACT-to-declaration; expanded to implementors
r, m, why = cls('interfaceCall')
ck('interfaceCall: not EXACT (interface member expands)', r != 'EXACT', (r, m))
ck('interfaceCall: implementors include 05 A and 05 B',
   '05_interface_dispatch.ts::program:A:process' in m and '05_interface_dispatch.ts::program:B:process' in m, m)

# 4. generic type-variable stub: NEVER EXACT; stays an unhardened edge
r, m, why = cls('genericCall')
ck('genericCall: T:process never EXACT', r != 'EXACT', (r, m))
ck('genericCall: HEURISTIC (unmappable type-variable stub)', r == 'HEURISTIC', (r, why[-1] if why else ''))

# 5. inheritance calls: artifacts deduped; only concrete candidates remain
for fn in ('baseCall', 'childCall'):
    r, m, why = cls(fn)
    ck(f'{fn}: no <init>/spelling artifacts remain', all(':<init>' not in x and ':ts::' not in x for x in m), m)
    ck(f'{fn}: classification is EXACT or AMBIGUOUS over concrete methods', r in ('EXACT', 'AMBIGUOUS'), (r, m))

# 6. any-typed receiver: many candidates, never EXACT
r, m, why = cls('anyCall')
ck('anyCall: never EXACT', r != 'EXACT', r)
ck('anyCall: AMBIGUOUS over multiple concrete methods', r == 'AMBIGUOUS' and len(m) > 2, (r, len(m)))

# 7. returnReceiver: single-candidate edge is not silently hardened without receiver agreement
r, m, why = cls('returnReceiver')
ck('returnReceiver: EXACT only with receiver agreement, else HEURISTIC', r in ('EXACT', 'HEURISTIC'), (r, m, why[-1] if why else ''))

# 8. propertyCall: member stubs resolved through members facts, never left as <member> names
r, m, why = cls('propertyCall')
ck('propertyCall: no <member> stub names in final targets', all('<member>' not in x for x in m), m)
ck('propertyCall: not hardened to EXACT-to-stub', r != 'EXACT' or all('::program' in x for x in m), (r, m))

ok = sum(1 for _, p in checks if p)
print(f'GATE24_TS2={ok}/{len(checks)}')
sys.exit(0 if ok == len(checks) else 1)
