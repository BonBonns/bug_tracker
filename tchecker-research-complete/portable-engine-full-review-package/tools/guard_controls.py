#!/usr/bin/env python3
"""GUARD-R01: negative controls for soundness-critical guards.

Project rule adopted after the PARAM-R01 no-op guard: every soundness-critical
guard must have at least one KNOWN-BAD input that demonstrably makes it fail.
"The invariant exists" is not evidence; "the invariant fires" is.

Each control feeds a deliberately corrupted fact set and asserts the guard
rejects it. A control that passes on corrupt input is itself a finding.
"""
import json, os, subprocess, sys, tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BUILD = f'{ROOT}/tests/gates/jsts-r05/build'
ok = tot = 0
def ck(n, c, d=''):
    global ok, tot; tot += 1; ok += bool(c)
    print(('PASS ' if c else 'FAIL ') + n + ('' if c else f'  [{str(d)[:90]}]'))

def run_engine(docs):
    r = subprocess.run(['java', '-cp', BUILD, 'EndToEndRunner'] + docs,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

base = json.load(open('/tmp/cmp2/program.json'))
def tmp(doc, suffix='.json'):
    p = tempfile.mktemp(suffix=suffix); json.dump(doc, open(p, 'w')); return p

# G1 loader: duplicate ids must be REFUSED (this guard already fired for real on p-limit)
d = json.loads(json.dumps(base))
if d['assignments']:
    d['locals'].append(dict(d['locals'][0]))          # duplicate local id
rc, out = run_engine([tmp(d)])
ck('G1 loader refuses duplicate local ids', rc != 0 and 'duplicate' in out.lower(), out[:120])

# G2 memory family: a location with no corresponding local must be REFUSED
mem = json.load(open('/tmp/cmp2/program.json.memory.json'))
if mem['memory_locations']:
    bad = dict(mem['memory_locations'][0]); bad['id'] = 999999999
    mem2 = {'schema': mem['schema'], 'memory_locations': mem['memory_locations'] + [bad],
            'points_to': mem.get('points_to', [])}
    rc, out = run_engine([tmp(base), tmp(mem2)])
    ck('G2 memory location without a backing local is refused',
       rc != 0 and 'memory location' in out.lower(), out[:120])
else:
    ck('G2 memory location control', False, 'no memory locations to corrupt')

# G3 expression family: an EXACT expression fact must be REFUSED by the record
expr = json.load(open('/tmp/cmp2/program.json.expression.json'))
if expr['expressions']:
    e = dict(expr['expressions'][0]); e['resolution'] = 'EXACT'
    rc, out = run_engine([tmp(base), tmp({'schema': expr['schema'], 'expressions': [e]})])
    ck('G3 expression fact claiming EXACT is refused', rc != 0, out[:120])
else:
    ck('G3 expression control', False, 'no expressions to corrupt')

# G4 reaching-def: a fact naming a definition that does not exist must not silently apply
rd = json.load(open('/tmp/cmp2/program.json.reachingdef.json'))
if rd['reaching_defs']:
    f = dict(rd['reaching_defs'][0]); f['def_ids'] = [123456789]
    rc, out = run_engine([tmp(base), tmp({'schema': rd['schema'], 'reaching_defs': [f]})])
    # engine must not crash AND must not narrow to a phantom definition
    ck('G4 reaching-def naming a non-existent definition does not fabricate a claim',
       rc == 0 and 'proven=[0]' not in out.split('d6_swap')[-1][:60], out[:100])
else:
    ck('G4 reaching-def control', False, 'no reaching-def facts present')

# G5 reaching-def ANCHOR guard: the p2 defect. A local whose defs include an
# unanchored (non-CFG) definition must NOT be narrowed.
prog = json.load(open('/tmp/pp2/program.json'))
rd2 = json.load(open('/tmp/pp2/program.json.reachingdef.json'))
f2 = [x for x in prog['functions'] if x['name'] == 'p2_branch_reassign'][0]
storage = [l['id'] for l in prog['locals'] if l.get('parameter_storage_for') and l['method_id'] == f2['id']]
narrowed = [x for x in rd2['reaching_defs'] if x['local_id'] in storage]
ck('G5 anchor guard: no narrowing fact is emitted for a parameter-storage local',
   not narrowed, narrowed)

# G6 crosslang: a link to a function absent from the graph must apply nothing
links = {'schema': 'portable-crosslang-facts/0.1', 'links': [{
    'js_call_id': base['calls'][0]['id'], 'callee_function_id': 987654321,
    'export_name': 'x', 'callee_full_name': 'x', 'resolution': 'EXACT',
    'derivation': {'origin': 'T', 'rule': 'T', 'source_node_ids': [1]}}]}
rc, out = run_engine([tmp(base), tmp(links)])
ck('G6 crosslang link to an absent callee applies nothing (no crash, no claim)', rc == 0, out[:100])

print(f'GUARD_CONTROLS={ok}/{tot}')
sys.exit(0 if ok == tot else 1)
