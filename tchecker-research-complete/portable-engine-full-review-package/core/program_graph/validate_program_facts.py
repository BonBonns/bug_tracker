#!/usr/bin/env python3
import json, pathlib, sys
ALLOWED={'EXACT','HEURISTIC','AMBIGUOUS','UNRESOLVED'}

def fail(msg):
    raise SystemExit('INVALID_PROGRAM_FACTS: '+msg)

def main():
    if len(sys.argv)!=2: fail('usage: validate_program_facts.py FILE.json')
    p=pathlib.Path(sys.argv[1]); d=json.loads(p.read_text())
    if d.get('schema')!='portable-program-facts/0.2': fail('schema')
    for k in ('functions','type_decls','members','method_returns','locals','calls','identifiers','returns'):
        if k not in d or not isinstance(d[k],list): fail('missing/list '+k)
    ids={f['id'] for f in d['functions']}
    for c in d['calls']:
        r=c.get('resolution'); ts=c.get('candidate_target_ids',[])
        if r not in ALLOWED: fail(f"call {c.get('id')} resolution {r}")
        if r=='EXACT' and len(ts)!=1: fail(f"call {c.get('id')} EXACT target count")
        if r=='AMBIGUOUS' and len(ts)<2: fail(f"call {c.get('id')} AMBIGUOUS target count")
        if r=='UNRESOLVED' and len(ts)!=0: fail(f"call {c.get('id')} UNRESOLVED target count")
        if r=='HEURISTIC' and len(ts)<1: fail(f"call {c.get('id')} HEURISTIC target count")
        missing=[x for x in ts if x not in ids]
        if missing: fail(f"call {c.get('id')} target ids not in functions: {missing}")
    print(f"PROGRAM_FACTS_VALID functions={len(d['functions'])} calls={len(d['calls'])} types={len(d['type_decls'])}")
if __name__=='__main__': main()
