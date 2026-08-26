#!/usr/bin/env python3
"""TS-UNRESOLVED-R01: for every UNRESOLVED sink instance, find the FIRST
unresolved boundary on the path and classify it. Multi-cause labels allowed.
Also asks: would resolving THIS boundary alone change the sink result, or is it
downstream of another unresolved dependency? Characterization only."""
import json, os, re, sys
from collections import Counter, defaultdict

def analyse(work, tag, summaries):
    d=json.load(open(f'{work}/js.json'))
    try: caps={c['inner_local_id']:c for c in json.load(open(f'{work}/js_capture.json'))['captures']}
    except Exception: caps={}
    fns={f['id']:f for f in d['functions']}
    calls={c['id']:c for c in d['calls']}
    locals_by_fn=defaultdict(dict)
    for l in d.get('locals',[]): locals_by_fn[l['method_id']][l['name']]=l
    assigns=defaultdict(list)
    for a in d.get('assignments',[]): assigns[a['target_local_id']].append(a)
    bodied={c['enclosing_function_id'] for c in d['calls']}
    try: reach={r['use_id']:r for r in json.load(open(f'{work}/js.json.reachingdef.json'))['reaching_defs']}
    except Exception: reach={}
    cursor={}
    out=[]
    for line in open(f'/tmp/{tag}'):
        m=re.match(r'SINK (\S+) (\S+)#(\d+) resolution=UNRESOLVED', line)
        if not m: continue
        fname, sink, idx = m.group(1), m.group(2), int(m.group(3))
        # FIX 1 (R02): find the CALL first and take its enclosing_function_id.
        # Locating the function by NAME collided on repeated symbols such as
        # `<lambda>0`, producing 16 spurious NO_CALL_FACT rows in R01.
        cands=[x for x in d['calls'] if x['name']==sink
               and fns.get(x['enclosing_function_id'],{}).get('name')==fname]
        if not cands: out.append((fname,sink,{'NO_CALL_FACT'},False)); continue
        c=cands[cursor.setdefault((fname,sink),0) % len(cands)]
        cursor[(fname,sink)] += 1
        f=fns.get(c['enclosing_function_id'])
        if not f: out.append((fname,sink,{'NO_FUNCTION_FACT'},False)); continue
        arg=next((a for a in c.get('arguments',[]) if a['index']==idx), None)
        if not arg: out.append((fname,sink,{'NO_ARG_FACT'},False)); continue
        vr=arg.get('value_ref') or {}
        causes=set()
        # R03: recoverable is now a TEST, not a default. It starts UNSET and is
        # decided per cause by asking whether the blocker is the ONLY unresolved
        # edge, or whether something upstream is also unresolved.
        recoverable=None; upstream_unresolved=False
        seen=0; cur=vr; curfn=f
        while seen<6:
            seen+=1
            k=cur.get('kind'); code=(cur.get('code') or '')
            if k=='PARAMETER': causes.add('RESOLVED_TO_PARAM'); break
            if k=='CONSTANT': causes.add('RESOLVED_TO_CONST'); break
            if k=='CALL':
                cc=calls.get(cur.get('id'))
                nm=cc['name'] if cc else '?'
                tgt=[t for t in (cc or {}).get('candidate_target_ids',[]) if t in fns and not fns[t].get('is_external')]
                if tgt:
                    causes.add('TRANSITIVE_IN_REPO_CALLEE')
                    sm=summaries.get(fns[tgt[0]]['name'])
                    recoverable = bool(sm and sm!='UNRESOLVED')
                else:
                    # R04: split EXTERNAL_CALL into IMPLEMENTATION-SHAPED causes.
                    # The aggregate conflated dynamic module imports, template
                    # literals and genuine unknown callees — three unrelated
                    # engineering problems.
                    cd=(cc.get('code') or '') if cc else ''
                    if nm in ('import','require') or re.match(r'(await\s+)?import\s*\(', cd):
                        causes.add('MODULE_IMPORT')
                    elif '`' in cd or nm in ('<operator>.formatString','__ecma.String.template'):
                        causes.add('TEMPLATE_LITERAL')
                    elif re.search(r'\w+\.\w+\s*\(', cd):
                        causes.add('MODULE_MEMBER_CALL')
                    else:
                        causes.add('OTHER_EXTERNAL')
                    # EXTERNAL_CALL is recoverable ALONE only if the call's own
                    # arguments are already resolved — i.e. the unresolved edge is
                    # genuinely the callee's semantics, not an unknown input.
                    if cc is None: recoverable=False
                    else:
                        unres=0
                        for aa in cc.get('arguments',[]):
                            av=aa.get('value_ref') or {}
                            if av.get('kind') in ('UNKNOWN',): unres+=1
                            elif av.get('kind')=='CALL': unres+=1
                            elif av.get('kind')=='LOCAL':
                                lid2=av.get('id')
                                if not assigns.get(lid2): unres+=1
                        recoverable = (unres==0)
                        if unres: upstream_unresolved=True
                break
            if k=='STATE_READ' or re.search(r'\w+\.\w+', code):
                causes.add('OBJECT_PROPERTY_READ')
                # Recoverable ALONE only if the BASE object is itself resolved:
                # adding property semantics cannot help if the object's own
                # provenance is unknown.
                base=code.split('.')[0].strip()
                bl=locals_by_fn.get(curfn['id'],{}).get(base)
                bp=any(p['name']==base for p in curfn.get('parameters',[]))
                if bp: recoverable=True
                elif bl is not None and assigns.get(bl['id']):
                    bv=assigns[bl['id']][0]['value_ref']
                    recoverable = bv.get('kind') in ('PARAMETER','CONSTANT')
                    if not recoverable: upstream_unresolved=True
                else:
                    recoverable=False; upstream_unresolved=True
                break
            if k=='LOCAL':
                lid=cur.get('id')
                if lid in caps:
                    causes.add('VIA_CLOSURE_CAPTURE')   # traversed, not a blocker
                    cap=caps[lid]; curfn=fns.get(cap['outer_function'], curfn)
                    outer=locals_by_fn.get(curfn['id'],{}).get(cap['outer_binding'])
                    if not outer: causes.add('CAPTURE_OUTER_MISSING'); break
                    ds=assigns.get(outer['id'],[])
                    if not ds: causes.add('NO_DEFINITION'); break
                    cur=ds[0]['value_ref']; continue
                ds=assigns.get(lid,[])
                if not ds: causes.add('LOCAL_NO_DEFINITION'); break
                # FIX 2 (R02): use the REACHING definition at this use, not ds[0].
                # R01 followed the first assignment and produced impossible labels
                # (RESOLVED_TO_CONST as the sole cause of an UNRESOLVED sink).
                rd=reach.get(c['id'])
                if rd and rd.get('local_id')==lid:
                    live=[a2 for a2 in ds if a2['id'] in rd['def_ids']]
                    if live: ds=live
                if len(ds)>1:
                    causes.add('MULTI_DEF')
                    kinds={ (a2['value_ref'].get('kind')) for a2 in ds }
                    if kinds=={'CONSTANT'}: causes.add('ALL_DEFS_CONSTANT'); break
                cur=ds[0]['value_ref']; continue
            causes.add(f'OTHER:{k}'); break
        if recoverable is None: recoverable=False   # never silently optimistic
        out.append((fname,sink,causes,recoverable))
    return out

summaries={}
rows=[]
SRC=[('zx','/tmp/ew_zx','es_zx.out'),
     ('prettier','/tmp/ew_prettier','es_prettier.out'),
     ('eslint','/tmp/ew_eslint','es_eslint.out'),
     ('rollup','/tmp/ew_rollup','es_rollup.out')]
for name,w,tag in SRC:
    if not os.path.exists(f'/tmp/{tag}') or not os.path.exists(f'{w}/js.json'): continue
    sm={}
    for l in open(f'{w}/js_ts.engine.out') if os.path.exists(f'{w}/js_ts.engine.out') else []:
        mm=re.match(r'SUMMARY (\S+) resolution=(\S+)',l)
        if mm: sm[mm.group(1)]=mm.group(2)
    for r in analyse(w,tag,sm): rows.append((name,)+r)
cnt=Counter(); sole=Counter(); rec=Counter()
for name,fn,sink,causes,recoverable in rows:
    for c in causes: cnt[c]+=1
    blockers={c for c in causes if c not in ('VIA_CLOSURE_CAPTURE','MULTI_DEF')}
    if len(blockers)==1: sole[list(blockers)[0]]+=1
    rec['recoverable alone' if recoverable else 'downstream of another unresolved dep']+=1
print(f"TS-UNRESOLVED-R01: {len(rows)} UNRESOLVED sink instances\n")
print(f"{'cause':42s}{'mentions':>9s}{'sole':>6s}")
for k,v in cnt.most_common(): print(f"  {k:40s}{v:9d}{sole.get(k,0):6d}")
print("\nwould resolving THIS boundary alone change the sink result?")
for k,v in rec.most_common(): print(f"  {v:4d}  {k}")
# EFFECTIVE RECOVERABLE YIELD PER CAUSE — the number that should choose the
# milestone. Raw frequency overstates a cause that is usually blocked behind
# another unresolved dependency.
yield_=Counter(); occur=Counter()
for name,fn,sink,causes,recoverable in rows:
    for c in causes:
        if c in ('VIA_CLOSURE_CAPTURE','MULTI_DEF'): continue
        occur[c]+=1
        if recoverable: yield_[c]+=1
print("\nEFFECTIVE RECOVERABLE YIELD PER CAUSE")
print(f"  {'cause':32s}{'occurs':>7s}{'recoverable alone':>19s}{'yield':>8s}")
for c,n in occur.most_common():
    y=yield_.get(c,0)
    print(f"  {c:32s}{n:7d}{y:19d}{(100*y//n if n else 0):7d}%")
# ALL rows, so downstream controls sample the full population rather than the
# deduplicated example list (which hid recoverable OBJECT_PROPERTY_READ rows and
# made a positive control fail spuriously).
print("\nALL ROWS:")
for name,fn,sink,causes,recoverable in rows:
    print(f"  ROW {name}:{fn} {sink} -> {sorted(causes)} recoverable={recoverable}")
print("\nrepresentative examples:")
seen=set()
for name,fn,sink,causes,recoverable in rows:
    key=tuple(sorted(causes))
    if key in seen: continue
    seen.add(key); print(f"  {name}:{fn} {sink} -> {sorted(causes)} recoverable={recoverable}")
