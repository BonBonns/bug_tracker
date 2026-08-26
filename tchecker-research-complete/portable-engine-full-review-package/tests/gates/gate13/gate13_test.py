import json,re,sys
from pathlib import Path
P=Path(__file__).parent
D=json.loads((P/'state_results.json').read_text())
checks=[]
def add(name,ok,detail): checks.append((name,bool(ok),detail))
add('mayAliasWrite_preserves_may_flow', D['mayAliasWrite']['resolution']=='AMBIGUOUS' and any(x.startswith('PARAM:mayAliasWrite.source') for x in D['mayAliasWrite']['origins']) and any(x.startswith('STATE_UNKNOWN:') for x in D['mayAliasWrite']['origins']), D['mayAliasWrite'])
add('sameAliasBothBranches_collapses_exact', D['sameAliasBothBranches']['resolution']=='EXACT' and D['sameAliasBothBranches']['origins']==['PARAM:sameAliasBothBranches.source'], D['sameAliasBothBranches'])
add('differentField_no_crossflow', D['mayAliasDifferentField']['resolution']=='UNKNOWN' and not any('source' in x for x in D['mayAliasDifferentField']['origins']), D['mayAliasDifferentField'])
add('conditional_overwrite_preserves_both', D['mayAliasOverwrite']['resolution']=='AMBIGUOUS' and set(D['mayAliasOverwrite']['origins'])=={'CONST:"CONST"','PARAM:mayAliasOverwrite.source'}, D['mayAliasOverwrite'])
add('mayAliasRead_union', D['mayAliasRead']['resolution']=='AMBIGUOUS' and set(D['mayAliasRead']['origins'])=={'CONST:"CONST"','PARAM:mayAliasRead.source'}, D['mayAliasRead'])
rows=[x for x in (P/'frontend_state_return.tsv').read_text().splitlines() if x.strip()]
add('bridge_only_exact', len(rows)==1 and '\tCOMPLETE\t1' in rows[0], rows)
def pos(text,name):
    m=re.search(r'^RET \d+ '+re.escape(name)+r'.*positions=\[([^]]*)\]',text,re.M)
    return None if not m else [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
on=(P/'gate13_on.out').read_text(); off=(P/'gate13_off.out').read_text()
add('real_engine_exact_summary_consumed', pos(off,'sameAliasBothBranches')==[] and pos(on,'sameAliasBothBranches')==[1], (pos(off,'sameAliasBothBranches'),pos(on,'sameAliasBothBranches')))
nonexact=['mayAliasWrite','mayAliasDifferentField','mayAliasOverwrite','mayAliasRead']
add('nonexact_not_hardened', all(pos(on,n)==pos(off,n) for n in nonexact), {n:(pos(off,n),pos(on,n)) for n in nonexact})
add('engine_loaded_one_complete', 'FRONTEND_STATE_RETURN loaded=1 rejected=0 complete=1' in (P/'gate13_on.err').read_text(), (P/'gate13_on.err').read_text())
for n,ok,d in checks: print(('PASS' if ok else 'FAIL'),n,'-',d)
print(f'GATE13={sum(x[1] for x in checks)}/{len(checks)}')
sys.exit(0 if all(x[1] for x in checks) else 1)
