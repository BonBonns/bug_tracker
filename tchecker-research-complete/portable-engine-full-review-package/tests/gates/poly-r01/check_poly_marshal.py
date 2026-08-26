#!/usr/bin/env python3
import json, re, sys
merged = json.load(open(sys.argv[1]))
out = open(sys.argv[2]).read()
sidecar = json.load(open(sys.argv[1] + '.crosslang.json'))
ok = 0; total = 0
def ck(n, c):
    global ok, total; total += 1; ok += bool(c); print(('PASS' if c else 'FAIL'), n)
def summ(name):
    m = re.search(r'SUMMARY ' + name + r' resolution=(\S+) proven=\[([^\]]*)\]', out)
    return (m.group(1), m.group(2)) if m else None
ck('callFirst: JS arg 0 -> info[0] slot -> back, EXACT proven=[0]', summ('callFirst') == ('EXACT', '0'))
ck('callSecond: marshalling discriminator — C++ reads info[1], engine projects JS arg 1',
   summ('callSecond') == ('EXACT', '1'))
ck('callVia: slot flows through a C++ LOCAL before returning, still EXACT proven=[1]',
   summ('callVia') == ('EXACT', '1'))
ck('callVar: variable slot index -> honest abstention', summ('callVar') == ('UNRESOLVED', ''))
marsh = [l for l in sidecar['links'] if 'marshalled_positions' in l]
ck('exactly 3 callees marshalled (varIdx excluded: no constant slot)', len(marsh) == 3)
ck('every marshalling carries its own derivation (NAPI_MARSHALLING + source ids)',
   all(l['marshalling_derivation']['rule'] == 'NAPI_MARSHALLING'
       and len(l['marshalling_derivation']['source_node_ids']) >= 2 for l in marsh))
ck('slot positions recorded per link',
   sorted(l['marshalled_positions'] for l in marsh) == [[0], [1], [1]])
print(f'POLY_MARSHAL={ok}/{total}')
sys.exit(0 if ok == total else 1)
