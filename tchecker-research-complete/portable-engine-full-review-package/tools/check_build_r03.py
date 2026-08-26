#!/usr/bin/env python3
"""BUILD-R03 promotion gate: the narrow contract, asserted."""
import json, sys, subprocess
merged=json.load(open(sys.argv[1])); links=json.load(open(sys.argv[2]))
ok=0; tot=0
def ck(n,c,d=''):
    global ok,tot; tot+=1; ok+=bool(c); print(('PASS ' if c else 'FAIL ')+n+('' if c else f' - {d}'))
fns={f['id']:f for f in merged['functions']}
calls={c['id']:c for c in merged['calls']}
tu={f['id']:f.get('translation_unit') for f in merged['functions']}
L=links['links']
ck('schema is the versioned neutral family', links['schema']=='portable-crosslang-facts/0.1')
ck('every link carries a CPP_CROSS_TU_SIGNATURE_MATCH derivation with source ids',
   all(l['derivation']['rule']=='CPP_CROSS_TU_SIGNATURE_MATCH' and len(l['derivation']['source_node_ids'])==2 for l in L))
ck('every link is EXACT', all(l['resolution']=='EXACT' for l in L))
ck('every link target exists in the merged graph', all(l['callee_function_id'] in fns for l in L))
ck('every link is genuinely CROSS-TU (never same-TU)',
   all(tu.get(l['callee_function_id']) != tu.get(calls[l['js_call_id']]['enclosing_function_id']) for l in L if l['js_call_id'] in calls))
# one call site -> at most one link (no "closest candidate" duplicates)
ids=[l['js_call_id'] for l in L]
ck('at most one link per call site (no closest-candidate fallback)', len(ids)==len(set(ids)))
# no link may target a call the frontend already resolved internally
already=[l for l in L if l['js_call_id'] in calls and
         [t for t in calls[l['js_call_id']].get('candidate_target_ids',[]) if t in fns and not fns[t].get('is_external')]]
ck('links never override a frontend-proven internal target', not already, f'{len(already)}')
# abstention classes must NOT appear: rerun classifier and compare counts
# The classifier must be re-run in the SAME mode the links were emitted in;
# comparing canonicalized links against a non-canonical baseline is meaningless.
import os
out=subprocess.run(['python3','shadow_link.py',sys.argv[1]],capture_output=True,text=True,
                   env={**os.environ}).stdout
import re
uniq_cross=int(re.search(r'(\d+)\s+\d+%\s+UNIQUE_SIGNATURE_MATCH\(cross-TU\)',out).group(1))
ck('emitted link count equals exactly the unique cross-TU class (nothing else promoted)',
   len(L)==uniq_cross, f'{len(L)} vs {uniq_cross}')
print(f'BUILD_R03={ok}/{tot}')
sys.exit(0 if ok==tot else 1)
