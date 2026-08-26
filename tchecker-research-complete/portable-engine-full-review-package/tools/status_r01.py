#!/usr/bin/env python3
"""STATUS-R01 (CHARACTERIZE ONLY): can existing facts already separate the three
claims currently collapsed into UNRESOLVED?

  POSSIBLE_UNBOUNDED   a contribution IS known, but the target/origin relation
                       cannot be bounded  (buf[i] = input; return buf[0])
  PROVEN_ABSENCE       absence is ESTABLISHED, not merely unfound
  GENUINELY_UNRESOLVED evidence is missing

STRICTNESS: PROVEN_ABSENCE requires positive evidence that no write path can
connect. "The engine found no path" is NOT proven absence and is classified
GENUINELY_UNRESOLVED. No inference is changed; this only asks what the facts
already support.
"""
import json, re, sys
from collections import Counter, defaultdict

def main(tag, work, engine_out):
    d = json.load(open(f'{work}/B.json')) if __import__('os').path.exists(f'{work}/B.json') \
        else json.load(open(f'{work}/cpp.json'))
    out = open(engine_out).read()
    fns = {f['id']: f for f in d['functions']}
    by_name = {f['name']: f for f in d['functions']}
    assigns = defaultdict(list)
    for a in d.get('assignments', []): assigns[a['function_id']].append(a)
    rets = defaultdict(list)
    for r in d.get('returns', []): rets[r['function_id']].append(r)
    mem = {}
    try:
        mem = {m['id']: m for m in json.load(open(f'{work}/B.json.memory.json'))['memory_locations']}
    except Exception: pass
    stats = d.get('cpp_memory', {})

    cat = Counter(); ex = defaultdict(list); tot = 0
    for m in re.finditer(r'SUMMARY (\S+) resolution=UNRESOLVED proven=\[\] may=\[([^\]]*)\] unknown=(\S+)', out):
        name, may, unk = m.group(1), [x for x in m.group(2).split(',') if x.strip()], m.group(3)
        f = by_name.get(name)
        if not f: continue
        tot += 1
        fa = assigns.get(f['id'], [])
        frets = rets.get(f['id'], [])
        param_valued = [a for a in fa if a['value_ref']['kind'] == 'PARAMETER']
        # POSSIBLE_UNBOUNDED: a known parameter contribution exists (already surfaced
        # as a MAY position, or a parameter-valued write is present) while the
        # return itself could not be bound.
        if may:
            cat['POSSIBLE_UNBOUNDED (contribution known, relation unbounded)'] += 1
            ex['pu'].append(f'{name} may={may}')
        elif param_valued and frets:
            cat['POSSIBLE_UNBOUNDED (parameter-valued write present, target unbound)'] += 1
            ex['pu2'].append(f'{name} {len(param_valued)} param writes')
        elif not frets:
            # NOT proven absence. A function with no value-returning path (void,
            # constructor) has NOTHING TO TRACE — that is the NO_VALUE_RESULT class
            # already removed from the abstention taxonomy in the JS/TS work.
            # Counting it as PROVEN_ABSENCE inflated that status to 53% at scale
            # and contradicted the earlier decision. Excluded from the population.
            cat['NO_VALUE_RESULT (excluded: nothing to trace)'] += 1
        else:
            kinds = {r['value_ref']['kind'] for r in frets}
            vr = frets[0]['value_ref']
            # STRICT: absence is established only if EVERY return path is a
            # constant. Inspecting only the first return (as this tool originally
            # did) misclassified multi-return functions — 8 of 9 jsmn functions
            # have several returns, so that shortcut was an artifact, not a result.
            if kinds == {'CONSTANT'}:
                cat['PROVEN_ABSENCE (ALL return paths constant)'] += 1
            elif 'UNKNOWN' in kinds and len(kinds) > 1:
                cat['CANNOT CLASSIFY (mixed return paths, some unmodelled)'] += 1
            elif False:
                pass
            elif vr['kind'] == 'UNKNOWN':
                cat['GENUINELY_UNRESOLVED (return value not modelled)'] += 1
                ex['gu'].append(f"{name} <- {(vr.get('code') or '')[:26]}")
            else:
                cat['CANNOT CLASSIFY from current facts'] += 1
                ex['cc'].append(f"{name} <- {vr['kind']}")
    print(f'=== {tag}: {tot} UNRESOLVED rows ===')
    for k, v in cat.most_common():
        print(f'  {v:4d}  {100*v//tot if tot else 0:3d}%  {k}')
    for k in ('pu', 'pu2', 'gu', 'cc'):
        if ex[k]: print(f'        e.g. {ex[k][0]}')
    return tot, cat

if __name__ == '__main__':
    agg = Counter(); T = 0
    for spec in sys.argv[1:]:
        tag, work, out = spec.split(':')
        t, c = main(tag, work, out); T += t; agg += c
    print(f'\n=== TOTAL over {T} UNRESOLVED rows ===')
    for k, v in agg.most_common(): print(f'  {v:4d}  {100*v//T if T else 0:3d}%  {k}')
