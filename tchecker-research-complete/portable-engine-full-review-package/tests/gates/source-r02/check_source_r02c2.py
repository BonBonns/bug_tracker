#!/usr/bin/env python3
"""SOURCE-R02c2: source-TARGET recognition. Proves the four target cases and, in
particular, that the MAY-alias negative control can now FAIL — it was vacuous
twice (no fact at all, then a fact on the wrong object)."""
import json, sys
work = sys.argv[1]
d = json.load(open(f'{work}/program.json'))
src = json.load(open(f'{work}/program.json.source.json'))['source_origins']
mem = {m['id']: m for m in json.load(open(f'{work}/program.json.memory.json'))['memory_locations']}
fns = {f['id']: f['name'] for f in d['functions']}
loc = {l['id']: l for l in d['locals']}
by = {}
for s in src: by.setdefault(fns.get(s['function_id'], '?'), []).append(s)
ok = tot = 0
def ck(n, c, dd=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{dd}]'))
def tgt(case):
    s = by.get(case)
    if not s: return None
    x = s[0]; k = x.get('target_kind', 'LOCAL')
    nm = mem[x['target_local_id']]['name'] if k == 'MEMORY_LOCATION' and x['target_local_id'] in mem \
         else loc.get(x['target_local_id'], {}).get('name', '?')
    return k, nm

ck('C1 &local -> LOCAL target', tgt('h1_whole_to_field') == ('LOCAL', 'img'), tgt('h1_whole_to_field'))
ck('C2 &obj.field -> MEMORY_LOCATION(field)', tgt('h3_field_same') == ('MEMORY_LOCATION', 'img.w'), tgt('h3_field_same'))
ck('C3 storage-valued local (char buf[]) passed bare -> LOCAL target',
   tgt('h9_array') == ('LOCAL', 'buf'), tgt('h9_array'))
ck('C4 MAY/absent points-to -> NO source fact at all', tgt('h7_may_alias') is None, tgt('h7_may_alias'))
# the assertion that pins the specific regression
ptr_targets = [s for s in src
               if s.get('target_kind', 'LOCAL') == 'LOCAL'
               and (loc.get(s['target_local_id'], {}).get('type_full_name') or '').endswith('*')]
ck('C5 NO SourceOriginFact may target a POINTER VARIABLE', not ptr_targets,
   [(fns.get(s['function_id']), loc[s['target_local_id']]['name']) for s in ptr_targets])
ck('C6 unresolvable pointer parameter -> no fact', tgt('h8_ptr_aggregate') is None, tgt('h8_ptr_aggregate'))
ck('C7 sibling control EXISTS (a source on img.w while img.h is read)',
   tgt('h4_field_sibling') == ('MEMORY_LOCATION', 'img.w'), tgt('h4_field_sibling'))
# SOURCE-R02d/f + REACH-R02 behavioural controls, asserted only when the shadow
# flags are on (in default mode the propagation is not active and these do not apply).
import os, re, subprocess
if not os.environ.get('SOURCE_R02E_OFF'):
    eng = os.environ.get('SINK_OUT')
    out = open(eng).read() if eng and os.path.exists(eng) else ''
    def sink(fn):
        m = re.search(rf'SINK {fn} \S+ resolution=(\S+).*?origins=\[([^\]]*)\] mayOrigins=\[([^\]]*)\]', out)
        return (m.group(1), 'FILE_INPUT' in m.group(2), 'FILE_INPUT' in m.group(3)) if m else None
    ck('K1 conditional overwrite keeps FILE_INPUT POSSIBLE (never killed)',
       sink('k1_cond_overwrite') and sink('k1_cond_overwrite')[2], sink('k1_cond_overwrite'))
    ck('K3 nested-field overwrite kills that subtree',
       sink('k3_nested_overwrite') and not sink('k3_nested_overwrite')[1]
       and not sink('k3_nested_overwrite')[2], sink('k3_nested_overwrite'))
    ck('K4 nested overwrite leaves the SIBLING external',
       sink('k4_nested_sibling') and sink('k4_nested_sibling')[1], sink('k4_nested_sibling'))
    ck('K5 MAY-targeted overwrite: FILE_INPUT POSSIBLE, never definite, never clean',
       sink('k5_may_overwrite') and (not sink('k5_may_overwrite')[1]) and sink('k5_may_overwrite')[2],
       sink('k5_may_overwrite'))
    ck('H5 definite overwrite after external write KILLS the origin',
       sink('h5_ext_then_overwrite') and not sink('h5_ext_then_overwrite')[1]
       and not sink('h5_ext_then_overwrite')[2], sink('h5_ext_then_overwrite'))
    ck('H6 external write after overwrite RETAINS the origin',
       sink('h6_overwrite_then_ext') and sink('h6_overwrite_then_ext')[1], sink('h6_overwrite_then_ext'))

print(f'SOURCE_R02C2={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
