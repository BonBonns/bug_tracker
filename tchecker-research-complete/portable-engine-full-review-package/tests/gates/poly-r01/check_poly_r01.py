#!/usr/bin/env python3
import json, re, sys
merged = json.load(open(sys.argv[1]))
merged_out = open(sys.argv[2]).read()
js_only_out = open(sys.argv[3]).read()
ok = 0; total = 0
def ck(n, c):
    global ok, total; total += 1; ok += bool(c); print(('PASS' if c else 'FAIL'), n)
def summ(text, name):
    m = re.search(r'SUMMARY ' + name + r' resolution=(\S+) proven=\[([^\]]*)\].*unknown=(\S+) completeness=(\S+)', text)
    return (m.group(1), m.group(2), m.group(3), m.group(4)) if m else None

sidecar = json.load(open(sys.argv[1] + '.crosslang.json'))
ck('all 8 native-binding calls linked (in the fact family)', len(sidecar['links']) == 8)
ck('merged doc is UNREWRITTEN',
   not any(c.get('resolution_reason') == 'NAPI_BINDING_TABLE' for c in merged['calls']))
ck('every linked target is a C++ N-API function',
   all(l['callee_full_name'].endswith('(Napi.CallbackInfo&)') for l in sidecar['links']))
ck('engine ingested the family', 'CROSSLANG_LINKS edges=8' in merged_out)
ck('loader accepted the merged polyglot doc', 'frontend=polyglot' in merged_out and 'ANALYSIS_STATUS' in merged_out)
# cross-language composition: JS wrapper now reflects the PROVEN C++ callee's honest
# abstention (N-API-constructed return), not a shallow heuristic-dispatch guess
ck('genSaltSync composes through the proven C++ callee (UNRESOLVED/unknown)',
   summ(merged_out, 'genSaltSync') == ('UNRESOLVED', '', 'true', 'UNKNOWN'))
ck('genSaltSync was HEURISTIC before linking (JS-only baseline)',
   summ(js_only_out, 'genSaltSync') == ('HEURISTIC', '', 'false', 'COMPLETE'))
# no cross-contamination in either direction
ck('C++ init result identical in merged graph (EXACT proven=[1])',
   summ(merged_out, 'init') == ('EXACT', '1', 'false', 'COMPLETE'))
ck('unlinked JS rows identical in merged graph',
   summ(merged_out, 'use') == summ(js_only_out, 'use'))
ck('function id spaces disjoint after offset',
   len({f['id'] for f in merged['functions']}) == len(merged['functions']))
print(f'POLY_R01={ok}/{total}')
sys.exit(0 if ok == total else 1)
