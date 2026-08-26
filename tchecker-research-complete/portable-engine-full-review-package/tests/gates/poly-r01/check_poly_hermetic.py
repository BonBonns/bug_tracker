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
ck('wrap: JS param 0 -> C++ dbl -> back, EXACT proven=[0]', summ('wrap') == ('EXACT', '0'))
ck('wrapShuffle: position discriminator — C++ returns param 1, engine projects JS arg 1',
   summ('wrapShuffle') == ('EXACT', '1'))
ck('wrapOpaque: C++ computed return -> honest abstention', summ('wrapOpaque') == ('UNRESOLVED', ''))
ck('wrapMissing: unregistered name stays UNLINKED and non-EXACT', summ('wrapMissing')[0] != 'EXACT')
rewritten = [c for c in merged['calls'] if c.get('resolution_reason') == 'NAPI_BINDING_TABLE']
ck('merged doc is UNREWRITTEN: linkage lives only in the fact family', len(rewritten) == 0)
ck('exactly 3 edges linked in the sidecar (missing excluded)', len(sidecar['links']) == 3)
ck('engine loaded the links as a first-class family', 'CROSSLANG_LINKS edges=3' in out)
ck('crosslang sidecar: 3 links, every one carries FactDerivation',
   len(sidecar['links']) == 3 and
   all(l['derivation']['origin'] == 'FRONTEND_COMPOSED'
       and l['derivation']['rule'] == 'NAPI_BINDING_TABLE'
       and len(l['derivation']['source_node_ids']) == 4 for l in sidecar['links']))
ck('sidecar schema is versioned', sidecar['schema'] == 'portable-crosslang-facts/0.1')
print(f'POLY_R01_HERMETIC={ok}/{total}')
sys.exit(0 if ok == total else 1)
