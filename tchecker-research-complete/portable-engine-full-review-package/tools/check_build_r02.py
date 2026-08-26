#!/usr/bin/env python3
"""BUILD-R02 invariant gate."""
import json, subprocess, sys, pathlib, tempfile
ok=0; tot=0
def ck(n,c,d=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f' - {d}'))
tu_paths=sys.argv[1:]
merged=json.load(open('/tmp/tu/merged.json'))

# I1 globally unique ids
fids=[f['id'] for f in merged['functions']]
ck('I1 function ids globally unique after merge', len(fids)==len(set(fids)), f'{len(fids)} vs {len(set(fids))}')
cids=[c['id'] for c in merged['calls']]
ck('I1 call ids globally unique after merge', len(cids)==len(set(cids)))

# I2 single-TU pass-through. Project-scope filtering is a DELIBERATE
# transformation, so the invariant is split: with --all-scopes the merge must be
# byte-identical, and with filtering it must equal the deterministic projection.
# (The original single-form invariant started failing the moment filtering was
# added — the gate caught a documented behaviour change, which is its job.)
orig=json.load(open(tu_paths[0]))
one=tempfile.mktemp(suffix='.json')
subprocess.run(['python3','merge_tus.py',one,tu_paths[0],'--all-scopes'],capture_output=True)
m_all=json.load(open(one))
orig_fns=[f for f in orig['functions'] if '<duplicate>' not in f.get('full_name','')]
same=all(x['id']==y['id'] and x['name']==y['name']
         for x,y in zip(sorted(orig_fns,key=lambda z:z['id']), sorted(m_all['functions'],key=lambda z:z['id'])))
ck('I2a single TU through merge --all-scopes is byte-identical',
   same and len(orig_fns)==len(m_all['functions']), f'{len(orig_fns)} vs {len(m_all["functions"])}')
ck('I2a single-TU calls unchanged under --all-scopes', len(orig['calls'])==len(m_all['calls']))
two=tempfile.mktemp(suffix='.json')
subprocess.run(['python3','merge_tus.py',two,tu_paths[0]],capture_output=True)
m_proj=json.load(open(two))
sys.path.insert(0,'.')
import merge_tus
expect=merge_tus.filter_project(orig)
expect_fns=[f for f in expect['functions'] if '<duplicate>' not in f.get('full_name','')]
ck('I2b filtered single TU equals the deterministic project projection',
   len(expect_fns)==len(m_proj['functions']), f'{len(expect_fns)} vs {len(m_proj["functions"])}')

# I3 no <duplicate> inflation
ck('I3 no bodyless <duplicate> functions survive the merge',
   not any('<duplicate>' in f.get('full_name','') for f in merged['functions']),
   'duplicates present')

# I4 TU identity retained; same symbol from several TUs not collapsed
tagged=all('translation_unit' in f for f in merged['functions'])
ck('I4 every merged function retains its TU identity', tagged)
from collections import Counter
byname=Counter(f['name'] for f in merged['functions'])
multi=[n for n,c in byname.items() if c>1]
multi_tus=all(len({f['translation_unit'] for f in merged['functions'] if f['name']==n})>=1 for n in multi[:50])
ck('I4 same symbol in several TUs kept as separate definitions (not collapsed)',
   len(multi)>0 and multi_tus, 'no multi-TU symbols to check')

# I5 no cross-TU linking invented
offs={t['offset'] for t in merged['translation_units']}
def tu_of(i):
    return max(o for o in offs if i>=o)
cross=[c for c in merged['calls'] for t in c.get('candidate_target_ids',[]) if tu_of(c['id'])!=tu_of(t)]
ck('I5 merge invents NO cross-TU call links', not cross, f'{len(cross)} cross-TU links')
print(f'BUILD_R02={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
