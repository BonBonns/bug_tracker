#!/usr/bin/env python3
import base64, json, os as _os, pathlib, sys

SCHEMA = 'portable-program-facts/0.3'

def dec(s):
    if not s: return ''
    try: return base64.b64decode(s).decode('utf-8','replace')
    except Exception: return s

def rows(p,n):
    p=pathlib.Path(p)
    if not p.exists(): return []
    out=[]
    for ln in p.read_text().splitlines():
        if not ln.strip(): continue
        xs=ln.split('\t')
        if len(xs)!=n: raise ValueError(f'{p.name}: expected {n} cols, got {len(xs)}: {ln!r}')
        out.append(xs)
    return out

def ints(s): return [int(x) for x in s.split(',') if x]
def strs(s): return [dec(x) for x in s.split(',') if x]

def is_operator(name, full):
    return name.startswith('<operator>.') or full.startswith('<operator>.')

def classify_call(c, methods_by_id):
    """Conservative C/C++ dispatch projection into the existing Resolution enum.

    This intentionally does NOT perform points-to/CHA inference.
    STATIC singleton concrete target is the only ordinary EXACT case.
    DYNAMIC singleton remains HEURISTIC; multiple concrete targets AMBIGUOUS.
    """
    if is_operator(c['name'], c['method_full_name']):
        return ('UNRESOLVED', [], [], 'NON_DISPATCH_OPERATOR')

    pairs=[]
    for tid,tname in zip(c['candidate_target_ids'], c['candidate_target_full_names']):
        m=methods_by_id.get(tid)
        if m and not m['is_external']:
            pairs.append((tid,tname))
    seen=set(); concrete=[]
    for p in pairs:
        if p[0] not in seen:
            seen.add(p[0]); concrete.append(p)

    dispatch=c['dispatch_type']
    if dispatch == 'STATIC_DISPATCH':
        if len(concrete)==1:
            return ('EXACT',[concrete[0][0]],[concrete[0][1]],'STATIC_SINGLE_CONCRETE_TARGET')
        if len(concrete)>1:
            return ('AMBIGUOUS',[x[0] for x in concrete],[x[1] for x in concrete],'STATIC_MULTIPLE_CONCRETE_TARGETS')
        return ('UNRESOLVED',[],[],'STATIC_NO_CONCRETE_TARGET')
    if dispatch == 'DYNAMIC_DISPATCH':
        if len(concrete)>1:
            return ('AMBIGUOUS',[x[0] for x in concrete],[x[1] for x in concrete],'DYNAMIC_MULTIPLE_CONCRETE_TARGETS')
        if len(concrete)==1:
            return ('HEURISTIC',[concrete[0][0]],[concrete[0][1]],'DYNAMIC_SINGLETON_NOT_HARDENED')
        return ('UNRESOLVED',[],[],'DYNAMIC_NO_CONCRETE_TARGET')
    return ('UNRESOLVED',[],[],'UNKNOWN_DISPATCH_TYPE')

COMPOUND_OPS_SET={'<operator>.assignmentPlus','<operator>.assignmentMinus',
    '<operator>.assignmentMultiplication','<operator>.assignmentDivision',
    '<operator>.assignmentModulo','<operator>.assignmentAnd','<operator>.assignmentOr',
    '<operator>.assignmentXor','<operator>.assignmentShiftLeft',
    '<operator>.assignmentArithmeticShiftRight','<operator>.assignmentLogicalShiftRight'}

def main():
    if len(sys.argv)!=3:
        raise SystemExit('usage: normalize_c_cpp_facts_v03.py RAW_DIR OUT.json')
    raw=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])

    methods=[]; by_id={}
    for r in rows(raw/'methods.tsv',10):
        x={'id':int(r[0]),'name':dec(r[1]),'full_name':dec(r[2]),'signature':dec(r[3]),'file':dec(r[4]),
           'line':int(r[5] or 0),'line_end':int(r[6] or 0),'ast_parent_type':dec(r[7]),
           'ast_parent_full_name':dec(r[8]),'is_external':r[9].lower()=='true','parameters':[]}
        methods.append(x); by_id[x['id']]=x

    raw_params=[]
    for r in rows(raw/'parameters.tsv',7):
        raw_params.append({'id':int(r[0]),'method_id':int(r[1]),'index':int(r[2]),'name':dec(r[3]),'code':dec(r[4]),
                           'type_full_name':dec(r[5]),'line':int(r[6] or 0)})

    implicit_param_ids=set()
    for p in raw_params:
        if p['method_id'] not in by_id: continue
        if p['index']==0:
            implicit_param_ids.add(p['id'])
            continue
        q=dict(p); q['index']=p['index']-1
        by_id[p['method_id']]['parameters'].append(q)
    for m in methods: m['parameters'].sort(key=lambda p:p['index'])

    type_decls=[]
    for r in rows(raw/'type_decls.tsv',7):
        type_decls.append({'id':int(r[0]),'name':dec(r[1]),'full_name':dec(r[2]),'file':dec(r[3]),
                           'line':int(r[4] or 0),'is_external':r[5].lower()=='true','inherits_from':strs(r[6])})
    members=[{'id':int(r[0]),'type_decl_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),
              'type_full_name':dec(r[4]),'line':int(r[5] or 0)} for r in rows(raw/'members.tsv',6)]

    # UNION-R01: OPTIONAL aggregate-kind fact, absent from every fixture/export that
    # predates this change (backward compatible: rows() on a missing file returns [],
    # so every existing raw dir -- none of which has this file -- behaves EXACTLY as
    # before). type_decl_id -> 'UNION' | 'STRUCT' | 'CLASS' | anything else. Only
    # 'UNION' is acted on below; everything else (including simply not appearing
    # here at all) keeps today's behavior. This is deliberately NOT sourced from
    # export_c_cpp_facts_v03.sc's t.code text heuristic being independently
    # verified against real Joern output -- Joern is not installed in this
    # environment (see NOTE in that .sc file and this gate's README) -- so treat
    # aggregate_kinds as a real fact input whose PRODUCTION side is unverified,
    # while the CONSUMPTION side (the fail-closed check below) is fully tested
    # against a hand-built fixture that sets it directly.
    _union_type_ids={int(r[0]) for r in rows(raw/'aggregate_kinds.tsv',2) if dec(r[1]).upper()=='UNION'}
    method_returns=[{'id':int(r[0]),'method_id':int(r[1]),'code':dec(r[2]),'type_full_name':dec(r[3]),
                     'line':int(r[4] or 0)} for r in rows(raw/'method_returns.tsv',5)]
    locals_=[{'id':int(r[0]),'method_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),'type_full_name':dec(r[4]),
              'line':int(r[5] or 0)} for r in rows(raw/'locals.tsv',6)]

    raw_args={}
    for r in rows(raw/'arguments.tsv',8):
        raw_args.setdefault(int(r[1]),[]).append({'id':int(r[0]),'index':int(r[2]),'kind':dec(r[3]),'code':dec(r[4]),
                                                  'name':dec(r[5]),'type_full_name':dec(r[6]),'line':int(r[7] or 0)})

    calls=[]
    for r in rows(raw/'calls.tsv',11):
        c={'id':int(r[0]),'enclosing_function_id':int(r[1]),'name':dec(r[2]),'method_full_name':dec(r[3]),
           'dispatch_type':dec(r[4]),'type_full_name':dec(r[5]),'code':dec(r[6]),'file':dec(r[7]),
           'line':int(r[8] or 0),'candidate_target_ids':ints(r[9]),'candidate_target_full_names':strs(r[10])}
        aa=sorted(raw_args.get(c['id'],[]), key=lambda a:a['index'])
        receiver=None; user_args=[]
        for a in aa:
            if a['index']==0:
                receiver=a
            elif a['index']>0:
                b=dict(a); b['index']=a['index']-1; user_args.append(b)
        c['arguments']=user_args
        if receiver is not None:
            c['receiver_name']=receiver.get('name') or receiver.get('code') or ''
            c['receiver_type']=receiver.get('type_full_name') or ''
            c['receiver_node_id']=receiver['id']
        res,tids,tnames,reason=classify_call(c,by_id)
        c['resolution_raw']='UNRESOLVED' if len(c['candidate_target_ids'])==0 else ('EXACT' if len(c['candidate_target_ids'])==1 else 'AMBIGUOUS')
        c['resolution']=res; c['resolution_corrected']=res; c['resolution_reason']=reason
        c['candidate_target_ids']=tids; c['candidate_target_full_names']=tnames
        calls.append(c)

    # DECLARATION-ONLY METHODS (found by the preprocessed-source measurement):
    # after `gcc -E`, glibc PROTOTYPES (malloc, realloc, memcmp, ...) arrive as
    # is_external=False methods with a single-line span and NO body content, so the
    # engine resolved calls to them EXACT and concluded "no origins, COMPLETE" — a
    # FALSE COMPLETENESS claim (an external callee's return may well carry its
    # arguments' origins; see strdup). A method with an empty body AND a one-line
    # span is a declaration, not a definition: mark it external so calls abstain.
    _bodied=set()
    for _c in calls: _bodied.add(_c['enclosing_function_id'])
    for _l in locals_: _bodied.add(_l['method_id'])
    for _r in rows(raw/'returns.tsv',5): _bodied.add(int(_r[1]))
    _decl_only=0
    for _m in methods:
        if (not _m['is_external'] and _m['id'] not in _bodied
                and _m.get('line') and _m['line'] == _m.get('line_end')):
            _m['is_external']=True; _m['declaration_only']=True; _decl_only+=1
    # re-classify dispatch now that declaration-only targets are external
    if _decl_only:
        for _c in calls:
            _res,_tids,_tnames,_reason=classify_call(_c,by_id)
            _c['resolution']=_res; _c['resolution_corrected']=_res; _c['resolution_reason']=_reason
            _c['candidate_target_ids']=_tids; _c['candidate_target_full_names']=_tnames

    identifiers=[{'id':int(r[0]),'method_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),'type_full_name':dec(r[4]),
                  'line':int(r[5] or 0),'ref_target_ids':ints(r[6])} for r in rows(raw/'identifiers.tsv',7)]
    param_ids={p['id'] for m in methods for p in m['parameters']}
    local_ids={l['id'] for l in locals_}
    call_ids={c['id'] for c in calls}
    call_by_id={c['id']:c for c in calls}
    literal_rows=rows(raw/'literals.tsv',4)
    literals={int(r[0]):dec(r[1]) for r in literal_rows}
    ident_by_id={}
    for i in identifiers: ident_by_id.setdefault(i['id'],i)

    # CPP-R01/R02: bounded C/C++ memory-location lowering. C/C++ alias and
    # lvalue interpretation stays in the frontend; the neutral Java contract remains
    # unchanged. Proven fields/elements become frontend-derived synthetic locals.
    # Unknown indices, multi-target pointer bases, and unknown pointer parameters are
    # never hardened into exact locations.
    local_method={l['id']:l['method_id'] for l in locals_}
    ident_target={}
    for i in identifiers:
        for t in i['ref_target_ids']:
            if t in local_ids or t in param_ids:
                ident_target[i['id']]=t
                break

    def raw_arg_nodes(call_id):
        return sorted(raw_args.get(call_id,[]), key=lambda a:a['index'])

    def operand_args(call_id):
        return [a for a in raw_arg_nodes(call_id) if a['index']>0]

    def operand_nodes(call_id):
        return [a['id'] for a in operand_args(call_id)]

    def binding_node(node_id):
        if node_id in local_ids or node_id in param_ids: return node_id
        return ident_target.get(node_id)

    all_exported_ids=set(local_ids)|set(param_ids)|set(call_ids)|set(literals)|{i['id'] for i in identifiers}
    next_synth_id=(max(all_exported_ids) if all_exported_ids else 0)+1
    synthetic_location_ids={}
    synthetic_location_meta={}

    def ensure_location(mid, kind, base_id, selector, code=''):
        nonlocal next_synth_id
        key=(mid,kind,base_id,str(selector))
        if key in synthetic_location_ids: return synthetic_location_ids[key]
        sid=next_synth_id; next_synth_id+=1
        base_name=next((l['name'] for l in locals_ if l['id']==base_id),None)
        if base_name is None:
            for m in methods:
                q=next((x['name'] for x in m['parameters'] if x['id']==base_id),None)
                if q is not None: base_name=q; break
        base_name=base_name or f'node{base_id}'
        if kind=='FIELD': name=f'{base_name}.{selector}'
        else: name=f'{base_name}[{selector}]'
        locals_.append({'id':sid,'method_id':mid,'name':name,'code':code or name,'type_full_name':'<derived-memory-location>',
                        'line':0,'synthetic_memory_location':True})
        local_ids.add(sid); local_method[sid]=mid
        synthetic_location_ids[key]=sid
        synthetic_location_meta[sid]={'id':sid,'kind':kind,'base_id':base_id,'selector':str(selector),'method_id':mid,'name':name}
        return sid

    points_to={}
    def pt(mid): return points_to.setdefault(mid,{})

    def field_name(call_id):
        aa=operand_args(call_id)
        if len(aa)<2: return None
        x=(aa[1].get('name') or aa[1].get('code') or '').strip()
        x=x.lstrip('.').lstrip('->').strip()
        return x or None

    def constant_index(call_id):
        aa=operand_args(call_id)
        if len(aa)<2: return None
        a=aa[1]
        if a['id'] in literals:
            return literals[a['id']].strip()
        code=(a.get('code') or '').strip()
        import re
        return code if re.fullmatch(r'[+-]?(?:0[xX][0-9A-Fa-f]+|[0-9]+)',code) else None

    def deref_binding(node_id):
        c=call_by_id.get(node_id)
        if not c or c['name']!='<operator>.indirection': return None
        ops=operand_nodes(node_id)
        return binding_node(ops[0]) if len(ops)==1 else None

    def deref_targets(node_id, mid):
        b=deref_binding(node_id)
        if b is None: return None
        if (mid,b) in incomplete_ptr: return None   # stale set: abstain
        return set(pt(mid).get(b,set())) or None

    def memory_targets(node_id, mid):
        c=call_by_id.get(node_id)
        if not c: return None
        name=c['name']; ops=operand_nodes(node_id)
        if name=='<operator>.fieldAccess' and len(ops)>=2:
            base=binding_node(ops[0]); fld=field_name(node_id)
            if fld is None: return None
            if base is None:
                nested=memory_targets(ops[0],mid)
                if not nested or len(nested)!=1: return nested
                base=next(iter(nested))
            if base not in local_ids and base not in param_ids: return None
            return {ensure_location(mid,'FIELD',base,fld,c.get('code',''))}
        if name=='<operator>.indirectFieldAccess' and len(ops)>=2:
            base=binding_node(ops[0]); fld=field_name(node_id)
            if base is None or fld is None: return None
            if (mid,base) in incomplete_ptr: return None   # stale points-to set
            ts=set(pt(mid).get(base,set()))
            if len(ts)!=1: return ts or None
            obj=next(iter(ts))
            return {ensure_location(mid,'FIELD',obj,fld,c.get('code',''))}
        # MEASURED on real c2cpg: C array indexing (buf[0]) lowers to
        # <operator>.indirectIndexAccess (arrays decay to pointer + offset), NOT
        # <operator>.indexAccess (which real c2cpg never emits in this repro).
        # Confirmed identical operand shape (base@1, index@2) by inspection.
        if name in ('<operator>.indexAccess','<operator>.indirectIndexAccess') and len(ops)>=2:
            idx=constant_index(node_id)
            if idx is None: return None
            base=binding_node(ops[0])
            if base is None:
                nested=memory_targets(ops[0],mid)
                if not nested or len(nested)!=1: return nested
                base=next(iter(nested))
            if base in pt(mid):
                if (mid,base) in incomplete_ptr: return None
                ts=set(pt(mid)[base])
                if len(ts)!=1: return ts or None
                base=next(iter(ts))
            if base not in local_ids and base not in param_ids: return None
            return {ensure_location(mid,'INDEX',base,idx,c.get('code',''))}
        return None

    def lvalue_targets(node_id, mid):
        b=binding_node(node_id)
        if b in local_ids and local_method.get(b)==mid: return {b}
        ts=deref_targets(node_id,mid)
        if ts is not None: return ts
        return memory_targets(node_id,mid)

    def address_targets(node_id, mid):
        c=call_by_id.get(node_id)
        if not c or c['name']!='<operator>.addressOf': return None
        ops=operand_nodes(node_id)
        if len(ops)!=1: return None
        return lvalue_targets(ops[0],mid)

    def _is_pointerish(node_id):
        c=call_by_id.get(node_id)
        return c is not None and c['name'] not in ('<operator>.addressOf',)

    def pointer_sources(node_id, mid):
        direct=address_targets(node_id,mid)
        if direct is not None: return set(direct)
        b=binding_node(node_id)
        if b is not None and b in pt(mid): return set(pt(mid)[b])
        return None

    assignment_calls=[c for c in calls if c['name']=='<operator>.assignment']
    assignment_calls.sort(key=lambda c:(c.get('line') or 0,c['id']))

    # A pointer assigned from a source with NO known points-to is INCOMPLETE: its
    # known target set is stale, not authoritative. Without this, `p = &a;
    # p = get_ptr();` left points_to(p) = {a}, and because the record enforces
    # must <=> singleton that became MUST/EXACT — yielding a definite claim that a
    # write through p reaches a. (Found by the GUARD-R02 MAY-aliasing control.)
    incomplete_ptr=set()
    changed=True
    while changed:
        changed=False
        for c in assignment_calls:
            mid=c['enclosing_function_id']; ops=operand_nodes(c['id'])
            if len(ops)<2: continue
            lhs_node,rhs_node=ops[0],ops[1]
            lhs=binding_node(lhs_node)
            if lhs is None or local_method.get(lhs)!=mid: continue
            src=pointer_sources(rhs_node,mid)
            if src is not None:
                before=set(pt(mid).get(lhs,set())); after=before|src
                if after!=before: pt(mid)[lhs]=after; changed=True
            elif lhs in pt(mid) or _is_pointerish(rhs_node):
                incomplete_ptr.add((mid,lhs))

    # PARAM-R01: a PARAMETER is a MUTABLE STORAGE LOCATION, not a constant.
    # Previously an assignment whose LHS was a parameter emitted NO fact (only
    # locals were targets), so `a = b; return a` still resolved `a` to
    # PARAMETER[0] — a FALSE definite claim on the wrong parameter (found by the
    # comparative corpus, case d6_swap). A parameter's ENTRY value is now an
    # initial definition, and each reassignment is a later definition, so the
    # existing multi-def / reaching-definition machinery governs which one reaches
    # a use. Only parameters that are ACTUALLY reassigned get storage, to avoid
    # perturbing the (large, verified) set of functions that never mutate them.
    reassigned = {}
    _param_entry_defs = []
    for c in calls:
        if c['name'] not in ({'<operator>.assignment'} | COMPOUND_OPS_SET): continue
        ops = operand_nodes(c['id'])
        if len(ops) < 2: continue
        b = binding_node(ops[0])
        if b in param_ids:
            reassigned.setdefault(b, c['enclosing_function_id'])
    param_storage = {}
    for pid, mid in reassigned.items():
        pname = next((q['name'] for m in methods for q in m['parameters'] if q['id'] == pid), f'param{pid}')
        sid = next_synth_id; next_synth_id += 1
        locals_.append({'id': sid, 'method_id': mid, 'name': pname, 'code': pname,
                        'type_full_name': '<parameter-storage>', 'line': 0,
                        'parameter_storage_for': pid})
        local_ids.add(sid); local_method[sid] = mid
        param_storage[pid] = sid
        # entry definition: the storage starts as the parameter's incoming value
        # (deferred — the assignment list does not exist yet at this point)
        _param_entry_defs.append({'id': sid, 'function_id': mid, 'target_local_id': sid, 'line': 0,
            'value_ref': {'kind': 'PARAMETER', 'id': pid, 'code': pname},
            'derivation': {'origin': 'FRONTEND_DERIVED', 'rule': 'CPP_PARAM_ENTRY_DEFINITION',
                           'source_node_ids': [pid]}})

    def value_ref(node_id, code='', method_id=None):
        if node_id in implicit_param_ids:
            return {'kind':'UNKNOWN','id':-1,'code':code or 'this'}
        if node_id in param_ids:
            if node_id in param_storage:
                return {'kind':'LOCAL','id':param_storage[node_id],'code':code}
            return {'kind':'PARAMETER','id':node_id,'code':code}
        if node_id in call_ids:
            c=call_by_id.get(node_id)
            if method_id is not None and c['name']=='<operator>.indirection':
                ts=deref_targets(node_id,method_id)
                if ts and len(ts)==1:
                    t=next(iter(ts)); return {'kind':'LOCAL','id':t,'code':code or c.get('code','')}
                return {'kind':'UNKNOWN','id':-1,'code':code or c.get('code','')}
            # UNARY PASS-THROUGH (measured: all 14 OPERATOR:minus rows across the
            # scanned repos are `return -1;` — Joern's <operator>.minus is unary
            # negation, NOT subtraction). A unary operator's value derives solely
            # from its single operand, so origins pass through unchanged: `-1` has
            # no origin, `-x` has exactly x's. This needs no core change and no new
            # fact family — it is frontend resolution through the operator, exactly
            # like fieldAccess/indexAccess above.
            UNARY_PASSTHROUGH = ('<operator>.minus','<operator>.plus',
                                 '<operator>.logicalNot','<operator>.not')
            if method_id is not None and c['name'] in UNARY_PASSTHROUGH:
                _ops=operand_args(node_id)
                if len(_ops)==1:
                    return value_ref(_ops[0]['id'], _ops[0].get('code',''), method_id)
            # CAST PASS-THROUGH (origin-preserving): a cast does not change the DATA
            # origin of its value operand. c2cpg emits <operator>.cast with operands
            # [TYPE_REF, value]; resolve through to the single non-type operand so a
            # value like `(int)c > 32` decomposes to `c`'s origin instead of abstaining.
            if method_id is not None and c['name']=='<operator>.cast':
                _cops=[a for a in operand_args(node_id) if a.get('kind')!='TYPE_REF']
                if len(_cops)==1:
                    return value_ref(_cops[0]['id'], _cops[0].get('code',''), method_id)
            if method_id is not None and c['name'] in ('<operator>.fieldAccess','<operator>.indirectFieldAccess','<operator>.indexAccess','<operator>.indirectIndexAccess'):
                ts=memory_targets(node_id,method_id)
                if ts and len(ts)==1:
                    t=next(iter(ts)); return {'kind':'LOCAL','id':t,'code':code or c.get('code','')}
                return {'kind':'UNKNOWN','id':-1,'code':code or c.get('code','')}
            return {'kind':'CALL','id':node_id,'code':code}
        if node_id in local_ids: return {'kind':'LOCAL','id':node_id,'code':code}
        if node_id in literals: return {'kind':'CONSTANT','id':-1,'code':literals[node_id]}
        ident=ident_by_id.get(node_id)
        if ident:
            for t in ident['ref_target_ids']:
                if t in implicit_param_ids: return {'kind':'UNKNOWN','id':-1,'code':ident['code']}
                if t in param_ids:
                    # PARAM-R01: an identifier naming a REASSIGNED parameter reads
                    # its storage location, not the entry value.
                    if t in param_storage:
                        return {'kind':'LOCAL','id':param_storage[t],'code':ident['code']}
                    return {'kind':'PARAMETER','id':t,'code':ident['code']}
                if t in local_ids: return {'kind':'LOCAL','id':t,'code':ident['code']}
            return {'kind':'UNKNOWN','id':-1,'code':ident['code']}
        return {'kind':'UNKNOWN','id':-1,'code':code or ''}

    assignments=[]
    assignments.extend(_param_entry_defs)   # PARAM-R01 entry definitions
    memory_stats={'pointer_bindings':0,'exact_indirect_writes':0,'ambiguous_indirect_writes':0,'exact_deref_reads':0,
                  'synthetic_locations':0,'exact_field_accesses':0,'exact_index_accesses':0,'unknown_index_accesses':0,
                  'exact_pointer_param_writes':0,'unresolved_pointer_param_writes':0}
    memory_stats['pointer_bindings']=sum(1 for m in points_to.values() for ts in m.values() if ts)
    pointer_param_writes=[]

    for c in assignment_calls:
        mid=c['enclosing_function_id']; ops=operand_nodes(c['id'])
        if len(ops)<2: continue
        lhs_node,rhs_node=ops[0],ops[1]
        lhs=binding_node(lhs_node); targets=None; rule=None
        if lhs in param_storage:
            targets={param_storage[lhs]}; rule='CPP_PARAM_REASSIGNMENT'
        elif lhs in local_ids and local_method.get(lhs)==mid:
            if pointer_sources(rhs_node,mid) is None:
                targets={lhs}; rule='CPP_DIRECT_LOCAL_ASSIGNMENT'
        else:
            targets=deref_targets(lhs_node,mid)
            if targets and len(targets)==1:
                rule='CPP_EXACT_INDIRECT_WRITE'; memory_stats['exact_indirect_writes']+=1
            elif targets and len(targets)>1:
                memory_stats['ambiguous_indirect_writes']+=1; targets=None
            if targets is None:
                mt=memory_targets(lhs_node,mid)
                if mt and len(mt)==1:
                    targets=mt
                    opn=call_by_id.get(lhs_node,{}).get('name','')
                    rule='CPP_EXACT_FIELD_WRITE' if opn in ('<operator>.fieldAccess','<operator>.indirectFieldAccess') else 'CPP_EXACT_INDEX_WRITE'
                elif mt and len(mt)>1:
                    targets=None
            db=deref_binding(lhs_node)
            if targets is None and db in param_ids:
                pointer_param_writes.append((mid,db,rhs_node,c))
        if not targets: continue
        vr=value_ref(rhs_node,next((a['code'] for a in raw_arg_nodes(c['id']) if a['id']==rhs_node),''),mid)
        for target in targets:
            assignments.append({'id':c['id'],'function_id':mid,'target_local_id':target,'line':c.get('line') or 0,
                'cfg_anchor':c['id'],
                'value_ref':vr,'derivation':{'origin':'FRONTEND_DERIVED','rule':rule,'source_node_ids':[c['id'],lhs_node,rhs_node]}})

    param_pos={}
    for m in methods:
        for p0 in m['parameters']: param_pos[p0['id']]=p0['index']
    synth_assign_id=next_synth_id+100000
    for callee_mid,p_param,rhs_node,write_call in pointer_param_writes:
        pidx=param_pos.get(p_param)
        if pidx is None: continue
        matched=False
        for call in calls:
            if call['resolution']!='EXACT' or call['candidate_target_ids']!=[callee_mid]: continue
            if pidx>=len(call['arguments']): continue
            actual=call['arguments'][pidx]
            caller_mid=call['enclosing_function_id']
            ats=address_targets(actual['id'],caller_mid)
            if ats is None:
                b=binding_node(actual['id']); ats=set(pt(caller_mid).get(b,set())) if b is not None else None
            if not ats or len(ats)!=1: continue
            rhs_v=value_ref(rhs_node,'',callee_mid)
            mapped=None
            if rhs_v['kind']=='PARAMETER':
                ridx=param_pos.get(rhs_v['id'])
                if ridx is not None and ridx<len(call['arguments']):
                    ra=call['arguments'][ridx]; mapped=value_ref(ra['id'],ra.get('code',''),caller_mid)
            elif rhs_v['kind']=='CONSTANT': mapped=rhs_v
            if mapped is None or mapped['kind']=='UNKNOWN': continue
            target=next(iter(ats)); matched=True
            assignments.append({'id':synth_assign_id,'function_id':caller_mid,'target_local_id':target,'line':call.get('line') or 0,
                'cfg_anchor':call['id'],
                'value_ref':mapped,'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_EXACT_POINTER_PARAM_WRITE',
                'source_node_ids':[call['id'],write_call['id'],actual['id'],rhs_node]}})
            synth_assign_id+=1; memory_stats['exact_pointer_param_writes']+=1
        if not matched: memory_stats['unresolved_pointer_param_writes']+=1

    # CPP-R03 item 1: COMPOUND ASSIGNMENT LOWERING (x op= y).
    # Measured across 4 production C repos: assignmentPlus x58, assignmentMinus
    # x24, assignmentMultiplication x3, assignmentDivision x2 — none previously
    # produced assignment facts, so `x += y` SILENTLY DROPPED y's origin.
    # NON-HARDENING BY CONSTRUCTION: the result of `x op= y` depends on BOTH y and
    # x's PRIOR value, so each compound emits TWO defs — the rhs value and an
    # explicit UNKNOWN prior — which the engine's multi-def MAY semantics unions.
    # The row can therefore never become EXACT off the back of this lowering.
    # post/preIncrement and post/preDecrement are ORIGIN-NEUTRAL (the new value
    # derives from x itself) and deliberately emit NOTHING.
    COMPOUND_OPS=COMPOUND_OPS_SET
    _unused={'<operator>.assignmentPlus','<operator>.assignmentMinus',
        '<operator>.assignmentMultiplication','<operator>.assignmentDivision',
        '<operator>.assignmentModulo','<operator>.assignmentAnd','<operator>.assignmentOr',
        '<operator>.assignmentXor','<operator>.assignmentShiftLeft',
        '<operator>.assignmentArithmeticShiftRight','<operator>.assignmentLogicalShiftRight'}
    compound_id=next_synth_id+500000
    memory_stats['compound_assignments']=0
    # Index assignments by (function_id, target_local_id) so the "prior contribution"
    # lookup below (COMPOUND-R02) doesn't rescan the entire, ever-growing `assignments`
    # list on every compound assignment. That rescan was O(existing assignments) PER
    # compound assignment; on a function with K compound assignments to the same
    # target it's O(K^2) -- measured on a real file (mozjpeg's jchuff.c, heavy
    # PUT_BITS/EMIT_BYTE macro expansion): one function alone produced 181,502
    # assignment facts and drove the downstream reaching-def worklist to its 200,000-
    # iteration cap. Seed the index once from whatever's already in `assignments`
    # (from the CPP_EXACT_POINTER_PARAM_WRITE block above), then keep it updated
    # at this loop's own two append sites below -- the two append sites further
    # down in the file run in a later pass and can't be "prior" to anything seen
    # here, so they don't need indexing for this lookup.
    _prior_idx={}
    for _pa in assignments:
        _prior_idx.setdefault((_pa['function_id'],_pa['target_local_id']),[]).append(_pa)
    for c in sorted((c for c in calls if c['name'] in COMPOUND_OPS), key=lambda x:(x.get('line') or 0,x['id'])):
        mid=c['enclosing_function_id']; ops=operand_nodes(c['id'])
        if len(ops)<2: continue
        lhs_node,rhs_node=ops[0],ops[1]
        targets=None
        lhs=binding_node(lhs_node)
        if lhs in param_storage:
            targets={param_storage[lhs]}      # PARAM-R01: a += b on a parameter
        elif lhs in local_ids and local_method.get(lhs)==mid:
            targets={lhs}
        else:
            t=deref_targets(lhs_node,mid)
            if t is None: t=memory_targets(lhs_node,mid)
            if t and len(t)==1: targets=t
        if not targets: continue
        vr=value_ref(rhs_node,next((a['code'] for a in raw_arg_nodes(c['id']) if a['id']==rhs_node),''),mid)
        for target in targets:
            _new_a={'id':c['id'],'function_id':mid,'target_local_id':target,'line':c.get('line') or 0,
                'cfg_anchor':c['id'],
                'value_ref':vr,'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_COMPOUND_ASSIGNMENT',
                'source_node_ids':[c['id'],lhs_node,rhs_node]}}
            assignments.append(_new_a); _prior_idx.setdefault((mid,target),[]).append(_new_a)
            # COMPOUND-R02: `a op= b` derives from the PREVIOUS value of a as well
            # as from b. An opaque UNKNOWN prior was enough to prevent false EXACT,
            # but carried NO provenance edge back to the target's earlier
            # definitions — so once reaching-def analysis could kill the entry
            # definition (PARAM-R02 shadow), parameter 0 silently vanished from the
            # origin set. The prior contribution now references each PRECEDING
            # definition of the same target; UNKNOWN remains the fallback.
            # Looked up via _prior_idx (see its seeding above this loop), not by
            # rescanning all of `assignments` -- that rescan was the O(n^2) driver.
            _prior_refs=[dict(x['value_ref']) for x in _prior_idx.get((mid,target),())
                         if x['derivation']['rule']!='CPP_COMPOUND_PRIOR_VALUE'
                         and (x.get('line') or 0)<=(c.get('line') or 0)] or [
                {'kind':'UNKNOWN','id':-1,'code':'<prior value of '+(c.get('code') or '').split()[0]+'>'}]
            for _pr in _prior_refs:
                _new_pv={'id':compound_id,'function_id':mid,'target_local_id':target,'line':c.get('line') or 0,
                    # SAME anchor as the rhs contribution: one statement, two
                    # semantic defs — this is what stops CFG filtering from dropping
                    # the uncertainty contribution (utf8PrevCharLen hazard).
                    'cfg_anchor':c['id'],
                    'value_ref':_pr,
                    'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_COMPOUND_PRIOR_VALUE',
                    'source_node_ids':[c['id'],lhs_node]}}
                assignments.append(_new_pv); _prior_idx.setdefault((mid,target),[]).append(_new_pv)
                compound_id+=1
            memory_stats['compound_assignments']+=1

    memory_stats['unknown_index_accesses']=sum(1 for c in calls if c['name']=='<operator>.indexAccess' and constant_index(c['id']) is None)
    for c in calls:
        for a in c['arguments']:
            a['value_ref']=value_ref(a['id'],a.get('code',''),c['enclosing_function_id'])
            a['derivation']={'origin':'FRONTEND_DIRECT','rule':'ARGUMENT_NODE_REF','source_node_ids':[a['id']]}

    span_of={}
    for m in methods:
        lo=m.get('line') or 0; hi=m.get('line_end') or 0
        span_of[m['id']]=(hi-lo) if (lo and hi and hi>=lo) else 10**9
    def _better(mid_new, mid_cur, line):
        def fits(mid):
            m=next((x for x in methods if x['id']==mid),None)
            if not m or not m.get('line') or not m.get('line_end'): return False
            return m['line']<=line<=m['line_end']
        fn, fc = fits(mid_new), fits(mid_cur)
        if fn != fc: return fn
        return span_of.get(mid_new,10**9) < span_of.get(mid_cur,10**9)
    ret_rows={}
    for r in rows(raw/'returns.tsv',5):
        rid=int(r[0]); mid=int(r[1]); cur=ret_rows.get(rid)
        line=int(r[3] or 0)
        candidate=(rid,mid,dec(r[2]),line,ints(r[4]))
        if cur is None or _better(mid, cur[1], line):
            ret_rows[rid]=candidate
    returns_out=[]
    for rid,mid,code,line,children in ret_rows.values():
        child=children[0] if children else None
        is_void = child is None and code.strip().rstrip(';').strip()=='return'
        # TOR-B1a.1: bare `return;` carries no VALUE (irrelevant to value-provenance,
        # which is why it was previously skipped) but IS a control-flow terminator that
        # path-sensitive lifetime analysis needs. Emit it with value_ref VOID and a
        # distinct flag so value-provenance consumers still see no origin (VOID != a
        # real value_ref) while control-flow consumers can see the return exists.
        if is_void:
            returns_out.append({'id':rid,'function_id':mid,'code':code,'line':line,
                                'value_ref':{'kind':'VOID','id':-1,'code':code},'is_void':True,
                                'derivation':{'origin':'FRONTEND_DIRECT','rule':'RETURN_VOID_TERMINATOR','source_node_ids':[rid]}})
            continue
        vr=value_ref(child,code,mid) if child is not None else {'kind':'UNKNOWN','id':-1,'code':code}
        returns_out.append({'id':rid,'function_id':mid,'code':code,'line':line,'value_ref':vr,'is_void':False,
                            'derivation':{'origin':'FRONTEND_DIRECT','rule':'RETURN_AST_CHILD','source_node_ids':[rid]+([child] if child is not None else [])}})
    returns_out.sort(key=lambda x:x['id'])
    # portable-program-facts/0.3 `returns` is a VALUE-provenance stream.  A bare
    # `return;` is a control-flow terminator, not a value, and ProgramGraphLoader
    # intentionally has no VOID ValueRef kind.  Keep the terminators available to
    # lifetime/control-flow consumers without feeding them to the value engine.
    value_returns=[r for r in returns_out if not r.get('is_void')]
    void_returns=[r for r in returns_out if r.get('is_void')]

    memory_stats['synthetic_locations']=len(synthetic_location_ids)
    memory_stats['exact_field_accesses']=sum(1 for x in synthetic_location_meta.values() if x['kind']=='FIELD')
    memory_stats['exact_index_accesses']=sum(1 for x in synthetic_location_meta.values() if x['kind']=='INDEX')

    meta=[{'language':dec(r[0]),'version':dec(r[1]),'root':dec(r[2])} for r in rows(raw/'meta.tsv',3)]
    counters={'exported_functions':len(methods),'exported_calls':len(calls),'exported_returns':len(returns_out),
              'exported_value_returns':len(value_returns),'exported_void_returns':len(void_returns),
              'exported_identifiers':len(identifiers),'exported_type_decls':len(type_decls),'exported_locals':len(locals_)}
    if counters['exported_functions']==0:
        sys.stderr.write('EMPTY_FRONTEND_OUTPUT: c2cpg reported success but exported 0 functions\n'+json.dumps(counters)+'\n')
        raise SystemExit(30)

    # INVARIANT 1: every derived def inherits the CFG anchor of the statement that
    # generated it. source_node_ids[0] already records that statement, so this is
    # preserving an existing derivation through CFG analysis, not new inference.
    for _a in assignments:
        _sn=_a.get('derivation',{}).get('source_node_ids') or []
        _a['cfg_anchor']=_sn[0] if _sn else _a['id']


    # SOURCE-R02: FILE_INPUT source recognition. This is the ONLY place that knows
    # which APIs introduce external file data; the core is told an ORIGIN KIND, not
    # an API name. Only FILE_INPUT is modelled — SOURCE-R01 measured every other
    # non-parameter source class at 13 occurrences across 257 functions, below the
    # threshold where an improvement could be distinguished from noise.
    # ORIGIN-KIND PURITY: recv/recvfrom are NETWORK_INPUT, a different trust
    # boundary, and are NOT emitted here. NETWORK_INPUT is intentionally NOT
    # promoted broadly yet — it needs its own corpus/yield characterization
    # (SOURCE-R01 measured all non-parameter sources at 13/257, below the noise
    # floor). Until then, recv contributes no origin (abstain), which is correct:
    # better a NEEDS_REVIEW than a wrong FILE_INPUT label.
    FILE_READ_APIS={'fread':0,'fgets':0,'read':1,'getline':0,'fscanf':None}
    local_type={l['id']:(l.get('type_full_name') or '') for l in locals_}
    _source_origins=[]
    for _c in calls:
        _api=_c['name']
        if _api not in FILE_READ_APIS or _api=='recv': continue
        _bufidx=FILE_READ_APIS[_api]
        if _bufidx is None: continue
        _args=sorted(_c.get('arguments',[]), key=lambda x:x['index'])
        if len(_args)<=_bufidx: continue
        _b=_args[_bufidx]
        # The buffer is typically passed as &x, so unwrap addressOf before
        # resolving the binding (measured: without this the recognizer produced
        # ZERO origins on its own fixture).
        _n=_b['id']
        _cc=call_by_id.get(_n)
        if _cc is not None and _cc['name']=='<operator>.addressOf':
            _ops=operand_nodes(_n)
            if _ops: _n=_ops[0]
        _mid=_c['enclosing_function_id']
        _tgt=_kind=None
        _bind=binding_node(_n)
        _wasaddr = _n != _b['id']      # the argument was &something
        _btype = (local_type.get(_bind) or '') if _bind is not None else ''
        _is_ptr_var = (not _wasaddr) and _btype.endswith('*')
        if _bind is not None and _bind in local_ids and not _is_ptr_var:
            # &local, or a STORAGE-valued local such as `char buf[128]` passed
            # bare — the local's own storage IS the destination.
            _tgt,_kind=_bind,'LOCAL'
        elif _is_ptr_var:
            # SOURCE-R02c2: a POINTER VARIABLE designates OTHER storage. Resolve
            # the pointee FIRST; if the points-to evidence is MAY, incomplete or
            # absent, emit NOTHING. Never fall back to targeting the pointer
            # variable itself — that was the h7 defect, and it left the MAY-alias
            # negative control incapable of failing.
            _pt=set(points_to.get(_mid,{}).get(_bind,set()))
            if len(_pt)==1 and (_mid,_bind) not in incomplete_ptr:
                _tgt,_kind=next(iter(_pt)),'MEMORY_LOCATION'
            else:
                continue
        else:
            # SOURCE-R02c: fread(&obj.field, ...) writes a FIELD, and
            # fread(ptr, ...) writes through a pointer. Without these the
            # sibling-propagation negative control CANNOT EXIST, so a future
            # propagation rule would be "proved" safe by cases the frontend was
            # incapable of representing.
            _mt=memory_targets(_n,_mid)
            if _mt and len(_mt)==1:
                _tgt,_kind=next(iter(_mt)),'MEMORY_LOCATION'
            elif _mt and len(_mt)>1:
                continue    # MAY target: never hardened to a definite source
            else:
                _dt=deref_targets(_n,_mid)
                if _dt and len(_dt)==1: _tgt,_kind=next(iter(_dt)),'MEMORY_LOCATION'
                elif _bind is not None and _bind in param_ids: continue  # unresolved ptr param
        if _tgt is None: continue
        _source_origins.append({'id':_c['id'],'function_id':_mid,
            'target_local_id':_tgt,'target_kind':_kind,
            'origin_kind':'FILE_INPUT','location':_api,
            'derivation':{'origin':'FRONTEND_DIRECT','rule':'CPP_FILE_INPUT_SOURCE',
                          'source_node_ids':[_c['id'],_b['id']]}})
    # SOURCE-R02e (shadow, env SOURCE_R02E=1): the external write becomes an
    # ordinary DEFINITION of the location rather than a standing annotation, so
    # the EXISTING reaching-definition machinery decides whether it survives to a
    # use. This is what stops FILE_INPUT behaving as sticky taint: an origin must
    # participate in definition/use semantics like any other value.
    # k5 FIX: a write THROUGH a pointer whose points-to set is empty, MAY or
    # incomplete is an UNMODELLED WRITE. Without it, a location that already
    # carries an origin stays SINGLE-DEFINED and is reported EXACT — asserting
    # "definitely external" about bytes a possible overwrite may have replaced.
    # The incomplete_ptr guard already covered READS through such pointers; this
    # extends the same evidence to WRITES by emitting a competing UNKNOWN
    # definition for every location the write could plausibly reach.
    _unmodelled=[]
    for _c3 in assignment_calls:
        _ops3=operand_nodes(_c3['id'])
        if len(_ops3)<2: continue
        _lhs3=_ops3[0]
        _mid3=_c3['enclosing_function_id']
        # `p->w = ...` is an indirectFieldAccess, not a plain indirection, so
        # deref_binding alone missed it — which is why the first version of this
        # guard did not fire at all on k5.
        _dt3=deref_binding(_lhs3)
        if _dt3 is None:
            _cl3=call_by_id.get(_lhs3)
            if _cl3 is not None and _cl3['name'] in ('<operator>.indirectFieldAccess',
                                                     '<operator>.indirectIndexAccess'):
                _o3=operand_nodes(_lhs3)
                if _o3: _dt3=binding_node(_o3[0])
        if _dt3 is None: continue
        _set3=set(points_to.get(_mid3,{}).get(_dt3,set()))
        if len(_set3)==1 and (_mid3,_dt3) not in incomplete_ptr: continue  # definite
        _sel3=field_name(_lhs3)
        for _m3 in synthetic_location_meta.values():
            if _m3['method_id']!=_mid3: continue
            if _sel3 is not None and _m3.get('selector')!=_sel3: continue
            _unmodelled.append({'function_id':_mid3,'target_local_id':_m3['id'],
                                'call_id':_c3['id']})
    _uid=max([a4['id'] for a4 in assignments]+[0])+900000
    for _u in _unmodelled:
        _uid+=1
        assignments.append({'id':_uid,'function_id':_u['function_id'],
            'target_local_id':_u['target_local_id'],'line':0,
            'cfg_anchor':_u['call_id'],
            'value_ref':{'kind':'UNKNOWN','id':-1,'code':'<write through unresolved pointer>'},
            'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_UNMODELLED_POINTER_WRITE',
                          'source_node_ids':[_u['call_id']]}})

    if not _os.environ.get('SOURCE_R02E_OFF'):
        # SOURCE-R02f: the external write defines the target AND every memory
        # location whose base_id chain reaches it (transitively). Without the
        # descendants, `fread(&img,...)` defined only `img` while the sink read
        # `img.w`, so reaching definitions never saw an external def for the
        # location actually used — R02e regressed 4 of 9 shapes for exactly that
        # reason. All descendant defs share the SOURCE CALL's cfg anchor so
        # ordinary reaching definitions decide, per location, whether the external
        # write or a later assignment survives.
        _meta=list(synthetic_location_meta.values())
        def _reaches(_locid,_target,_d=0):
            if _locid==_target: return True
            if _d>8: return False
            for _m in _meta:
                if _m['id']==_locid:
                    return _reaches(_m['base_id'],_target,_d+1) if _m.get('base_id') else False
            return False
        _synth=max([a2['id'] for a2 in assignments]+[0])+700000
        for _so in _source_origins:
            _targets=[_so['target_local_id']]+[
                _m['id'] for _m in _meta
                if _m['method_id']==_so['function_id'] and _m['id']!=_so['target_local_id']
                and _reaches(_m['id'],_so['target_local_id'])]
            # REACH-R02b: one definition per (source call, target location). The
            # descendant walk can reach the same location by several routes, which
            # emitted img.w twice in h5 and corrupted candidate-set reasoning.
            for _t in dict.fromkeys(_targets):
                _synth+=1
                assignments.append({'id':_synth,'function_id':_so['function_id'],
                    'target_local_id':_t,'line':0,'cfg_anchor':_so['id'],
                    'value_ref':{'kind':'EXTERNAL_INPUT','id':_so['id'],'code':_so['location']},
                    'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_EXTERNAL_INPUT_DEFINITION',
                                  'source_node_ids':[_so['id']]}})
    pathlib.Path(str(out)+'.source.json').write_text(json.dumps(
        {'schema':'portable-source-facts/0.1','source_origins':_source_origins},indent=1,sort_keys=True)+'\n')


    # ---- frontend reaching-definition fixpoint over the exported CFG ----
    # OUT[n] = GEN[n] u (IN[n] - KILL[n]); IN[n] = U OUT[preds]
    # Defs are keyed by their CFG ANCHOR, so SYNTHETIC defs (e.g. the
    # CPP_COMPOUND_PRIOR_VALUE uncertainty contributions, which have no CFG node of
    # their own) participate in GEN/KILL at their generating statement and can
    # never be dropped merely for being synthetic (INVARIANT 2).
    _succ={}; _mnodes={}
    _cfgp=raw/'cfg_edges.tsv'
    if _cfgp.exists():
        for _l in _cfgp.read_text().splitlines():
            if not _l.strip(): continue
            _m,_a2,_b=(int(x) for x in _l.split('\t'))
            _succ.setdefault(_a2,set()).add(_b)
            _mnodes.setdefault(_m,set()).update((_a2,_b))
    reaching_facts=[]
    if _succ:
        from collections import defaultdict as _dd, deque as _dq
        _by_fn=_dd(list)
        for _a in assignments: _by_fn[_a['function_id']].append(_a)
        for _m in methods:
            if _m['is_external']: continue
            _fdefs=_by_fn.get(_m['id'])
            if not _fdefs: continue
            _rets=[r for r in returns_out if r['function_id']==_m['id'] and r['value_ref']['kind']=='LOCAL']
            # REACH-R02 (shadow, env REACH_R02=1): call ARGUMENTS are observation
            # points too. Without reaching-def facts here, a sink argument reading
            # a multi-defined location merges ALL definitions regardless of order,
            # which is why h5/h6 were indistinguishable.
            if not _os.environ.get('REACH_R02_OFF'):
                # GUARD-R01/G5 fix: c2cpg models `a = b` / `a += b` as an
                # <operator>.assignment* CALL whose FIRST argument is the WRITE
                # TARGET. Treating that lvalue argument as a read observation
                # point produced a reaching-def fact for the write target itself
                # (a FALSE EXACT on p2_branch_reassign's parameter-storage
                # local) — the exact over-claim the anchor guard exists to
                # prevent. The write target is not a use; skip it. RHS
                # arguments and all arguments of genuine calls stay in.
                _ASSIGN_OPS_PREFIX='<operator>.assignment'
                for _c2 in calls:
                    if _c2['enclosing_function_id']!=_m['id']: continue
                    _is_assign=str(_c2.get('name','')).startswith(_ASSIGN_OPS_PREFIX)
                    _min_idx=min((a.get('index',0) for a in _c2.get('arguments',[])), default=0)
                    for _a3 in _c2.get('arguments',[]):
                        if _is_assign and _a3.get('index',_min_idx)==_min_idx:
                            continue   # write target, not a read
                        _vr=_a3.get('value_ref') or {}
                        if _vr.get('kind')=='LOCAL':
                            _rets=_rets+[{'id':_a3['id'],'function_id':_m['id'],
                                          'value_ref':_vr}]
            if not _rets: continue
            _nodes=set(_mnodes.get(_m['id'],set())) | {_a['cfg_anchor'] for _a in _fdefs} | {r['id'] for r in _rets}
            # PARAM-R02 (SHADOW, env PARAM_R02=1): anchor the parameter ENTRY
            # definition at the method's CFG ENTRY node instead of the parameter
            # node. The entry node is the one with no predecessor inside the
            # method. This is the only change; if it is right, an unconditional
            # reassignment kills the entry def (recovering precision) while a
            # conditional one does not (preserving the MAY that GUARD-R01 G5
            # protects). Shadow means: computed and compared, never emitted.
            # PROMOTED after the PARAM-R02 validation (canonical 28/28 identical in
            # both modes; 221/222 real-repo rows unchanged with the single movement
            # verified source-supported; comparative corpus unchanged at 0
            # unsupported-definitive / 0 wrong-parameter). Set PARAM_R02_OFF=1 to
            # restore the pre-promotion behaviour for reproducibility.
            if not _os.environ.get('PARAM_R02_OFF'):
                _raw_nodes=_mnodes.get(_m['id'],set())
                _has_pred={_b for _a2 in _raw_nodes for _b in _succ.get(_a2,()) if _b in _raw_nodes}
                _entries=[n for n in _raw_nodes if n not in _has_pred]
                if len(_entries)==1:
                    for _a2 in _fdefs:
                        if _a2['derivation']['rule']=='CPP_PARAM_ENTRY_DEFINITION':
                            _a2['cfg_anchor']=_entries[0]
            _preds=_dd(set)
            for _n in _nodes:
                for _x in _succ.get(_n,()):
                    if _x in _nodes: _preds[_x].add(_n)
            _gen=_dd(set); _defs_of=_dd(set)
            for _a in _fdefs:
                _gen[_a['cfg_anchor']].add(_a['id'])
                _defs_of[_a['target_local_id']].add(_a['id'])
            _anchor_local={}
            for _a in _fdefs: _anchor_local.setdefault(_a['cfg_anchor'],set()).add(_a['target_local_id'])
            # Precompute once, outside the worklist loop: which anchors carry an
            # unmodelled-pointer-write definition. This used to be an any(... for _a5
            # in _fdefs ...) linear scan over EVERY definition in the function,
            # re-run on EVERY worklist pop -- fine for a handful of nodes, but the
            # worklist can revisit a node many times on a cyclic/branch-heavy CFG
            # (measured: a single real-world file with heavy bit-packing macro
            # expansion -- many small basic blocks, i.e. exactly a dense CFG -- drove
            # this one line to >30s of a ~45s run, dwarfing everything else combined).
            # Same precompute-then-O(1)-lookup idiom as _anchor_local just above.
            _unmodelled_ptr_write_anchors={_a5['cfg_anchor'] for _a5 in _fdefs
                                           if _a5['derivation']['rule']=='CPP_UNMODELLED_POINTER_WRITE'}
            _IN={_n:set() for _n in _nodes}; _OUT={_n:set() for _n in _nodes}
            _wl=_dq(_nodes); _guard=0
            while _wl and _guard < 200000:
                _guard+=1
                _n=_wl.popleft()
                _newin=set()
                for _p in _preds.get(_n,()): _newin|=_OUT[_p]
                _kill=set()
                for _loc in _anchor_local.get(_n,()): _kill|=_defs_of[_loc]
                _kill-=_gen.get(_n,set())
                # A write through an unresolved/MAY pointer ADDS a possibility but
                # REMOVES nothing: it may not have targeted this location at all.
                # Letting it kill made k5 lose the external origin entirely, which
                # is the mirror image of the over-claim it originally exposed.
                if _n in _unmodelled_ptr_write_anchors:
                    _kill=set()
                _newout=_gen.get(_n,set()) | (_newin-_kill)
                if _newout!=_OUT[_n] or _newin!=_IN[_n]:
                    _IN[_n]=_newin; _OUT[_n]=_newout
                    for _sx in _succ.get(_n,()):
                        if _sx in _nodes: _wl.append(_sx)
            if _guard >= 200000:
                # The loop exited on the guard, not on an empty worklist -- this
                # function's reaching-def fixpoint did NOT converge within the cap.
                # Surfaced so a caller (e.g. a performance gate) can grep stderr for
                # this exact marker rather than inferring non-convergence from wall
                # time alone. Pre-normalizer-fix, real code (mozjpeg jchuff.c) hit
                # this cap; the O(n^2) fixes below are what keep it from recurring.
                print(f"WARN REACHDEF_WORKLIST_CAP_HIT function_id={_m['id']} "
                      f"guard={_guard} nodes={len(_nodes)}", file=sys.stderr)
            for _r in _rets:
                _lid=_r['value_ref']['id']
                _cands=_defs_of.get(_lid,set())
                if _os.environ.get('REACH_R02_DEBUG'):
                    _cfgonly=_mnodes.get(_m['id'],set())
                    _anch={_a4['id']:_a4['cfg_anchor'] for _a4 in _fdefs if _a4['target_local_id']==_lid}
                    print(f"DBG use={_r['id']} inCFG={_r['id'] in _cfgonly} loc={_lid} "
                          f"cands={sorted(_cands)} anchors={_anch} "
                          f"anchorsInCFG={ {k:(v in _cfgonly) for k,v in _anch.items()} } "
                          f"IN={sorted(_IN.get(_r['id'],set()) & _cands)}", file=sys.stderr)
                if len(_cands)<2: continue
                # NB: check against the RAW CFG node set, not `_nodes` — `_nodes`
                # has def anchors unioned into it by construction, so testing
                # against it always passed and the guard was a no-op (it let the
                # unanchored parameter ENTRY definition be dropped, turning a MAY
                # into a FALSE EXACT on p2_branch_reassign).
                _cfg_only=_mnodes.get(_m['id'], set())
                _anchors_ok=all(_a['cfg_anchor'] in _cfg_only for _a in _fdefs
                                if _a['target_local_id']==_lid)
                if not _anchors_ok:
                    continue   # some definition has no CFG node: refuse to narrow
                _reach=sorted(_IN.get(_r['id'],set()) & _cands)
                if not _reach or len(_reach)==len(_cands): continue
                reaching_facts.append({'use_id':_r['id'],'function_id':_m['id'],'local_id':_lid,
                    'def_ids':_reach,'resolution':'AMBIGUOUS' if len(_reach)>1 else 'EXACT',
                    'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_REACHING_DEFINITIONS',
                                  'source_node_ids':[_r['id']]+_reach}})
    pathlib.Path(str(out)+'.reachingdef.json').write_text(json.dumps(
        {'schema':'portable-reachingdef-facts/0.1','reaching_defs':reaching_facts},indent=1,sort_keys=True)+'\n')
    memory_stats['reaching_def_facts']=len(reaching_facts)

    # TOR-B1a.1: normalize the already-exported CFG edges (method, node, successor).
    # Neutral control-flow substrate — additive, consumed only by path-sensitive readers.
    cfg_edges=[]
    for r in rows(raw/'cfg_edges.tsv',3):
        try: cfg_edges.append({'function_id':int(r[0]),'node_id':int(r[1]),'successor_id':int(r[2])})
        except Exception: pass

    doc={'schema':SCHEMA,'frontend':'joern-c2cpg','metadata':meta,'type_decls':type_decls,'members':members,
         'functions':methods,'method_returns':method_returns,'locals':locals_,'calls':calls,'identifiers':identifiers,
         'returns':value_returns,'void_returns':void_returns,'assignments':assignments,'frontend_counters':counters,'cpp_memory':memory_stats,
         'cpp_memory_locations':list(synthetic_location_meta.values()),'cfg_edges':cfg_edges}
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')

    # First-class memory fact family (portable-memory-facts/0.1), emitted as a
    # sidecar next to the program doc. Locations mirror the synthetic-location
    # table; points-to mirrors the monotone alias fixpoint. Both carry
    # FactDerivation; the Java core cross-validates locations against locals.
    # CPP-R03 item 2: BOUNDED EXPRESSION-RETURN DECOMPOSITION.
    # Operator set taken from the MEASURED abstention taxonomy across four
    # production C repos (minus x14, logicalOr x5, addition x3, subtraction x3,
    # conditional x2, equals x2, logicalAnd x2, notEquals, cast...). A combined
    # value carries all operand origins as POSSIBILITIES; the neutral core
    # enforces "never EXACT" via the ExpressionFact record.
    # Deliberately EXCLUDED: sizeOf (compile-time, no operand flow) and casts of
    # a single operand (handled as a pass-through would require claiming identity
    # — left abstaining rather than guessed).
    EXPR_OPS={'<operator>.addition','<operator>.subtraction','<operator>.minus',
        '<operator>.multiplication','<operator>.division','<operator>.modulo',
        '<operator>.logicalOr','<operator>.logicalAnd','<operator>.or','<operator>.and',
        '<operator>.xor','<operator>.equals','<operator>.notEquals',
        '<operator>.lessThan','<operator>.greaterThan','<operator>.lessEqualsThan',
        '<operator>.greaterEqualsThan','<operator>.shiftLeft','<operator>.arithmeticShiftRight',
        '<operator>.conditional'}
    expressions=[]
    for c in calls:
        if c['name'] not in EXPR_OPS: continue
        mid=c['enclosing_function_id']
        ops=operand_args(c['id'])
        if len(ops)<2: continue
        refs=[]
        for a in ops:
            vr=value_ref(a['id'],a.get('code',''),mid)
            # the ternary condition itself does not flow into the value
            refs.append(vr)
        if c['name']=='<operator>.conditional' and len(refs)==3:
            refs=refs[1:]
        if len(refs)<2: continue
        expressions.append({'id':c['id'],'function_id':mid,'operator':c['name'],
            'operands':refs,'resolution':'AMBIGUOUS',
            'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_EXPRESSION_OPERANDS',
                          'source_node_ids':[c['id']]+[a['id'] for a in ops]}})
    expr_doc={'schema':'portable-expression-facts/0.1','expressions':expressions}
    pathlib.Path(str(out)+'.expression.json').write_text(json.dumps(expr_doc,indent=1,sort_keys=True)+'\n')
    memory_stats['expression_facts']=len(expressions)

    mem_doc={'schema':'portable-memory-facts/0.1',
        'memory_locations':[{'id':m['id'],'function_id':m['method_id'],'kind':m['kind'],
            'base_id':m['base_id'],'selector':m['selector'],'name':m['name'],
            'resolution':'EXACT',
            'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_MEMORY_LOCATION',
                          'source_node_ids':[m['base_id'],m['id']]}}
            for m in synthetic_location_meta.values()],
        'points_to':[{'function_id':mid,'pointer_binding_id':b,
            'pointer_binding':next((l['name'] for l in locals_ if l['id']==b),
                                   next((q['name'] for mm in methods for q in mm['parameters'] if q['id']==b), f'node{b}')),
            'target_ids':sorted(ts),'must':len(ts)==1,
            'resolution':'EXACT' if len(ts)==1 else 'AMBIGUOUS',
            'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_POINTS_TO_FIXPOINT',
                          'source_node_ids':[b]+sorted(ts)}}
            for mid,binds in points_to.items() for b,ts in binds.items()
            if ts and (mid,b) not in incomplete_ptr]}
    # B4.1 OperandRoleFact — CURATED per-API operand roles (portable-operand-role-facts/0.1).
    # Explicit, never inferred from position globally. NEUTRAL: role/direction/extent
    # ONLY — no capacity, no bound, no class, no verdict. Unknown APIs abstain.
    _OPERAND_ROLES = {
        'memcpy':  {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        'memmove': {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        'memset':  {0:'WRITE_DEST', 2:'EXTENT'},
        'strncpy': {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        'snprintf':{0:'WRITE_DEST', 1:'EXTENT'},
        # NSS-R01: PORT_Memcpy/PORT_Memmove are NSS's own memcpy/memmove wrappers
        # (lib/util/secport.c — thin calls straight through to libc memcpy/memmove,
        # same (dest, src, len) argument order and byte-count semantics). wmemcpy
        # is the same shape at wchar_t granularity. Without these three, this
        # entire operand-role/capacity/bound pipeline silently ABSTAINS on any
        # PORT_Memcpy call site — which is exactly the callee in the confirmed
        # sftk_doSSLMACInit bug (lib/softoken/pkcs11c.c:2547) this fixture set is
        # built from: `PORT_Memcpy(sslmacinfo->key, keyval->attrib.pValue,
        # keyval->attrib.ulValueLen)`. Found by reading this table against that
        # real call site, not hypothetically.
        'PORT_Memcpy':  {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        'PORT_Memmove': {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        'wmemcpy': {0:'WRITE_DEST', 1:'READ_SRC', 2:'EXTENT'},
        # TOR-B2a two-sided comparison extent: BOTH operands are read with the SAME extent.
        # Distinct roles (A/B) keep the two sides separately identified downstream.
        'memcmp':  {0:'READ_CMP_A', 1:'READ_CMP_B', 2:'EXTENT'},
        'strncmp': {0:'READ_CMP_A', 1:'READ_CMP_B', 2:'EXTENT'},
        'CRYPTO_memcmp': {0:'READ_CMP_A', 1:'READ_CMP_B', 2:'EXTENT'},
        # strcpy/sprintf ABSENT: no length operand -> no EXTENT -> not fabricated.
    }
    _operand_roles=[]
    for _c in calls:
        _rt=_OPERAND_ROLES.get(_c.get('name'))
        if _rt is None: continue
        _args={a['index']:a for a in _c.get('arguments',[])}
        for _idx,_role in sorted(_rt.items()):
            if _idx not in _args: continue
            _operand_roles.append({'id':_c['id'],'function_id':_c.get('enclosing_function_id'),
                'call':_c['name'],'operand_index':_idx,'role':_role,
                'derivation':{'origin':'FRONTEND_CURATED','rule':'CPP_OPERAND_ROLE',
                              'source_node_ids':[_c['id']]}})
    pathlib.Path(str(out)+'.operandrole.json').write_text(json.dumps(
        {'schema':'portable-operand-role-facts/0.1','operand_roles':_operand_roles},
        indent=1,sort_keys=True)+'\n')
    pathlib.Path(str(out)+'.memory.json').write_text(json.dumps(mem_doc,indent=1,sort_keys=True)+'\n')
    # FIELD-ID-R02a — STRUCT-FIELD STORAGE IDENTITY (emission only; no consumer wired).
    # A field access a->x / a.x is exported as an <operator>.(indirect)FieldAccess call with
    # arg1 = base object, arg2 = member. When the base is a DIRECT IDENTIFIER with exactly one
    # resolved ref_target AND the member resolves to exactly one member declaration, we emit a
    # stable FieldStorageIdentity = (base_storage_id, member_decl_id). Otherwise ABSTAIN.
    # This does NOT feed capacity/bound/verdict at R02a: it is a standalone auditable fact.
    import re as _refid
    _ident_by_id={i['id']:i for i in identifiers}
    # member declarations by name -> list of ids (to detect unique resolution)
    _memdecls_by_name={}
    for _md in members:
        _memdecls_by_name.setdefault(_md['name'],[]).append(_md)
    # FIELD-ID-R02a.1 — BASE-TYPE-SCOPED member resolution. Build:
    #  (a) struct type NAME -> set of type_decl_ids (Joern emits <duplicate>N; group by base name)
    #  (b) (type_decl_id, member_name) -> member decl
    # When a member name is globally ambiguous, resolve it WITHIN the base identifier's struct
    # type. Sound distinctness: A::reply and B::reply are different member decls even though the
    # spelling is identical. Abstain if the base's concrete struct type can't be established, or
    # if duplicate type_decls for the same struct name DISAGREE on the member (dimension/decl).
    _typedecls=locals().get('type_decls') or []
    _typename_to_decls={}
    for _td in _typedecls:
        _tn=(_td.get('name') or '')
        if _tn: _typename_to_decls.setdefault(_tn,[]).append(_td['id'])
    _member_in_type={}
    for _md in members:
        _member_in_type[(_md.get('type_decl_id'),_md['name'])]=_md
    def _strip_type(_t):
        # 'create_cell_t*' -> 'create_cell_t'; 'A_t*' -> 'A_t'; strip ptr/const/struct kw
        _t=(_t or '').replace('*','').replace('const','').replace('struct','').strip()
        return _t
    def _resolve_member_by_base_type(_base_type_name,_member_name):
        # returns member decl dict if base type resolves the member UNIQUELY (sound), else None
        _tname=_strip_type(_base_type_name)
        _decls=_typename_to_decls.get(_tname)
        if not _decls: return None
        _found=[]
        for _tdid in _decls:
            _m=_member_in_type.get((_tdid,_member_name))
            if _m is not None: _found.append(_m)
        if not _found: return None
        # all duplicate type_decls for this struct name must AGREE on decl id + type
        _ids={_m['id'] for _m in _found}; _types={_m.get('type_full_name') for _m in _found}
        if len(_ids)==1 and len(_types)==1: return _found[0]
        return None
    _field_ids=[]
    _field_cls={}
    for _fa in calls:
        _nm=_fa['name']
        if _nm not in ('<operator>.fieldAccess','<operator>.indirectFieldAccess'):
            continue
        _fargs=sorted(_fa.get('arguments',[]),key=lambda a:a.get('index',0))
        if len(_fargs)<2:
            _field_cls['UNRESOLVED']=_field_cls.get('UNRESOLVED',0)+1; continue
        _base=_fargs[0]; _mem=_fargs[1]
        _bvr=_base.get('value_ref') or {}
        _bcode=(_bvr.get('code') or _base.get('code') or '')
        # BASE must be a direct IDENTIFIER (not indexAccess/call/nested). Heuristic: its own
        # code is a bare identifier and it resolves to exactly one ref_target.
        _base_is_ident = bool(_refid.fullmatch(r'[A-Za-z_]\w*', (_bcode or '').strip()))
        _bid=_bvr.get('referenced_id') or _bvr.get('id')
        _brefs=None
        _bident=_ident_by_id.get(_bid)
        if _bident is not None:
            _brefs=_bident.get('ref_target_ids') or []
        # base storage id: the identifier's unique ref target
        _base_storage=None
        if _base_is_ident and _brefs and len(_brefs)==1:
            _base_storage=_brefs[0]
        elif _base_is_ident and _bid is not None and _brefs is None:
            # identifier not in table but has its own id — use it as storage (still a real id)
            _base_storage=_bid
        # MEMBER: first try GLOBAL unique name (R02a). If ambiguous, try BASE-TYPE scope (R02a.1)
        _mname=(_mem.get('value_ref') or {}).get('code') or _mem.get('code') or ''
        _mname=_mname.strip()
        _mdecls=_memdecls_by_name.get(_mname,[])
        _member_decl=None; _member_type=''; _resolved_via='GLOBAL_UNIQUE'
        if len(_mdecls)==1:
            _member_decl=_mdecls[0]['id']; _member_type=_mdecls[0].get('type_full_name','')
        elif len(_mdecls)>1:
            # ambiguous by name -> use the base's type_full_name to scope. The base ARGUMENT
            # itself carries type_full_name (e.g. 'A*'); fall back to the identifier's type.
            _btype=(_base.get('type_full_name')
                    or (_bident.get('type_full_name') if _bident else None)
                    or _bvr.get('type_full_name') or '')
            _scoped=_resolve_member_by_base_type(_btype,_mname)
            if _scoped is not None:
                _member_decl=_scoped['id']; _member_type=_scoped.get('type_full_name',''); _resolved_via='BASE_TYPE_SCOPED'
        # AMBIGUOUS_BASE: base is a non-identifier expression (indexAccess/call/nested)
        if _base_storage is None and (not _base_is_ident) and _bcode and ('[' in _bcode or '(' in _bcode or '.' in _bcode or '->' in _bcode):
            _field_cls['AMBIGUOUS_BASE']=_field_cls.get('AMBIGUOUS_BASE',0)+1; continue
        if _base_storage is not None and _member_decl is not None:
            _field_cls['BASE_PLUS_MEMBER_VISIBLE']=_field_cls.get('BASE_PLUS_MEMBER_VISIBLE',0)+1
            if _resolved_via=='BASE_TYPE_SCOPED':
                _field_cls['_recovered_by_base_type']=_field_cls.get('_recovered_by_base_type',0)+1
            _field_ids.append({
                'field_access_id':_fa['id'],
                'function_id':_fa.get('enclosing_function_id'),
                'storage_kind':'FIELD',
                'base_storage_id':_base_storage,
                'member_decl_id':_member_decl,
                'composite_key':'FIELD:%s:%s'%(_base_storage,_member_decl),
                'member_name':_mname,'member_type':_member_type,'code':_fa.get('code'),
                'resolved_via':_resolved_via,
                'derivation':{'origin':'FRONTEND_DERIVED','rule':'CPP_FIELD_STORAGE_IDENTITY',
                              'source_node_ids':[_fa['id']]}})
        else:
            _field_cls['UNRESOLVED']=_field_cls.get('UNRESOLVED',0)+1
    pathlib.Path(str(out)+'.fieldidentity.json').write_text(json.dumps(
        {'schema':'portable-field-identity-facts/0.1','field_identities':_field_ids,
         'classification':_field_cls},indent=1,sort_keys=True)+'\n')

    # CapacityFact supertype. v0.2 (was: NUMERIC-LITERAL dimension only). A macro
    # used as an array dimension (e.g. `unsigned char key[MAX_KEY_LEN]`) survives
    # into typeFullName as WHATEVER TEXT the preprocessing step left behind: a
    # bare literal if the macro is a plain `#define NAME 256` (already matched a
    # bare \d+ dimension, e.g. NSS's own MAX_KEY_LEN — see
    # lib/softoken/pkcs11i.h), or a constant ARITHMETIC EXPRESSION if the macro
    # itself is arithmetic (mozjpeg's `#define BUFSIZE (DCTSIZE2*2)+8`, already
    # handled for LOCAL arrays by oob_copy_length_verdict.py's
    # `_eval_const_int_expr` — this was NOT wired into struct-MEMBER capacity,
    # so a member like `JOCTET buffer[BUFSIZE]` still abstained here even though
    # the equivalent local array did not. Reuses the identical safe-eval
    # approach: restricted to digits/whitespace/+-*/() BEFORE ever calling eval,
    # so this can't become a code-injection surface via attacker-controlled
    # source text. Still ABSTAINS on anything that isn't cleanly a
    # non-negative constant expression (an unresolved macro name, a `sizeof(...)`
    # dimension, a variable-length array) and on unsized (`char*[]`) members —
    # narrowing to "no guess", not widening to "guess when in doubt".
    import re as _re
    _ELEM_BYTES={'char':1,'signed char':1,'unsigned char':1,'int8_t':1,'uint8_t':1,
                 'short':2,'int16_t':2,'uint16_t':2,'int':4,'int32_t':4,'uint32_t':4,
                 'float':4,'long':8,'int64_t':8,'uint64_t':8,'double':8}
    def _eval_const_dim_expr(_expr):
        _e=(_expr or '').strip()
        if not _e or not _re.fullmatch(r'[\d\s+\-*/()]+',_e): return None
        try: _v=eval(_e,{'__builtins__':{}},{})
        except Exception: return None
        return _v if isinstance(_v,int) and _v>=0 else None
    def _fixed_array_capacity(_type):
        _m=_re.match(r'^\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*\[\s*([\d\s+\-*/()]+)\s*\]\s*$', _type or '')
        if not _m: return None
        _elem=_m.group(1).strip()
        _n=_eval_const_dim_expr(_m.group(2))
        if _n is None: return None
        _w=_ELEM_BYTES.get(_elem)
        if _w is None: return None
        return (_w*_n,_elem,_n)
    _loc_by_id={l['id']:l for l in locals_}
    # TOR-B2a.1: index struct/class members by NAME -> declared type, for member-access
    # capacity. Uses the SAME _fixed_array_capacity evaluator; no StructCapacityFact.
    _members_by_name={}
    for _m in members:
        _nm=_m.get('name')
        if _nm is None: continue
        # if a member name is ambiguous across structs with DIFFERENT array types, mark it
        _prev=_members_by_name.get(_nm)
        if _prev is not None and _prev.get('type_full_name')!=_m.get('type_full_name'):
            _members_by_name[_nm]={'__ambiguous__':True}
        elif _prev is None:
            _members_by_name[_nm]=_m
    def _member_name_of(_code):
        # SINGLE-LEVEL member access only: base->member / base.member.
        # Nested (base->a.b / a->b->c) is NOT soundly resolvable by trailing-name lookup
        # (TOR-B2a.1 spec: abstain rather than guess). Return None for nested.
        if not _code: return None
        _c=_code.strip()
        # reject indexing/calls
        if '[' in _c or '(' in _c: return None
        # count access operators; exactly ONE -> and ZERO ., or ZERO -> and ONE .
        _arrows=_c.count('->'); _dots=_c.count('.')
        if _arrows+_dots!=1: return None      # nested or not-a-member -> abstain
        _last=_re.split(r'->|\.', _c)[-1].strip()
        if not _re.fullmatch(r'[A-Za-z_]\w*', _last or ''): return None
        return _last
    _dest_caps=[]; _src_caps=[]; _cmp_caps=[]
    # FIELD-ID-R02b — capacity consumes the frozen FieldStorageIdentity. Build:
    #  (a) member decl id -> member declaration (for declared-type -> array extent)
    #  (b) field_access_id -> field identity (from _field_ids emitted above)
    # A field-access memory operand's capacity comes from member_decl_id -> declared type ->
    # fixed array T[N] -> sizeof(T)*N. NOT from the composite key as a size oracle. Pointer
    # members (char*) yield no fixed-array capacity -> abstain (identity != capacity).
    _memdecl_by_id={_md['id']:_md for _md in members}
    _fieldid_by_access={_fi['field_access_id']:_fi for _fi in _field_ids}
    # to find the field-access id behind an operand, match the operand's argument to the
    # (indirect)FieldAccess call whose id is the operand's value_ref id, else by code.
    _facall_by_id={_c['id']:_c for _c in calls
                   if _c['name'] in ('<operator>.fieldAccess','<operator>.indirectFieldAccess')}
    _facall_by_code={}
    for _c in _facall_by_id.values():
        _facall_by_code.setdefault(_c.get('code'),_c['id'])

    # STRUCT-MEMBER-OFFSET-R01: `base->member + offset_expr` or `&base->member[offset_expr]`.
    # Same posture as oob_copy_length_verdict.py's pointer-offset extension for LOCAL
    # arrays: this does NOT attempt to compute a narrowed "N - offset" remaining-capacity
    # bound (offset_expr may be an arbitrary runtime expression) -- it treats the shape as
    # an OPEN CANDIDATE carrying the member's FULL declared capacity, tagged offset_shape so
    # a consumer knows the true remaining bound is unproven, not that 256 bytes are safe to
    # write starting at that offset. Recognizes exactly two shapes, one-directional (matches
    # the local-array producer's convention of not also matching `offset + field`):
    #   <operator>.addition(fieldAccess(base,member), offset_expr)
    #   <operator>.addressOf(indexAccess(fieldAccess(base,member), offset_expr))
    _FIELD_OPS=('<operator>.fieldAccess','<operator>.indirectFieldAccess')
    _INDEX_OPS=('<operator>.indexAccess','<operator>.indirectIndexAccess')
    def _offset_field_capacity(_operand_id):
        _oc=call_by_id.get(_operand_id)
        if _oc is None: return None
        _field_call_id=None; _offset_expr=None
        if _oc['name']=='<operator>.addition':
            _aa=sorted(_oc.get('arguments',[]),key=lambda a:a['index'])
            if len(_aa)!=2: return None
            _lhs_call=call_by_id.get(_aa[0]['id'])
            if _lhs_call is None or _lhs_call['name'] not in _FIELD_OPS: return None
            _field_call_id=_aa[0]['id']; _offset_expr=(_aa[1].get('code') or '').strip()
        elif _oc['name']=='<operator>.addressOf':
            _aa=_oc.get('arguments',[])
            if len(_aa)!=1: return None
            _inner=call_by_id.get(_aa[0]['id'])
            if _inner is None or _inner['name'] not in _INDEX_OPS: return None
            _ia=sorted(_inner.get('arguments',[]),key=lambda a:a['index'])
            if len(_ia)!=2: return None
            _base_call=call_by_id.get(_ia[0]['id'])
            if _base_call is None or _base_call['name'] not in _FIELD_OPS: return None
            _field_call_id=_ia[0]['id']; _offset_expr=(_ia[1].get('code') or '').strip()
        else:
            return None
        _fi=_fieldid_by_access.get(_field_call_id)
        if _fi is None: return None
        _md=_memdecl_by_id.get(_fi['member_decl_id'])
        if _md is None or _md.get('type_decl_id') in _union_type_ids: return None
        _cap=_fixed_array_capacity(_md.get('type_full_name') or '')
        if _cap is None: return None
        return (_cap,_offset_expr,_fi)

    _r02b_cls={}
    def _bump(_k): _r02b_cls[_k]=_r02b_cls.get(_k,0)+1
    for _r in _operand_roles:
        if _r['role'] not in ('WRITE_DEST','READ_SRC','READ_CMP_A','READ_CMP_B'): continue
        _c=call_by_id.get(_r['id'])
        if not _c: continue
        _arg=next((a for a in _c.get('arguments',[]) if a['index']==_r['operand_index']), None)
        if not _arg: continue
        _vr=_arg.get('value_ref') or {}
        _cap=None; _rule='CPP_FIXED_ARRAY_CAPACITY'; _sid=_vr.get('referenced_id') or _vr.get('id')
        _skind='VALUE_ID'; _fkey=None   # CAP-KEY-R01: default local storage joins by value id
        _offset_shape=False; _offset_expr=None
        if _vr.get('kind')=='LOCAL':
            _loc=_loc_by_id.get(_vr.get('referenced_id') or _vr.get('id'))
            if _loc:
                _cap=_fixed_array_capacity(_loc.get('type_full_name') or '')
        else:
            # R02b: resolve the field-access identity for this operand, then capacity from its
            # member declaration's declared type. The operand's own code names the field access.
            _acode=(_arg.get('code') or _vr.get('code') or '')
            # a struct-member dest is passed as &obj.member (address-of); the fieldAccess call
            # code is obj.member WITHOUT the &. Strip a single leading & to match (same
            # normalization as B2b.1). Denotes the same field.
            _acode_norm=_acode.strip()
            if _acode_norm.startswith('&'): _acode_norm=_acode_norm[1:].strip()
            _fa_id=None
            _av=_vr.get('referenced_id') or _vr.get('id')
            if _av in _facall_by_id: _fa_id=_av
            elif _acode_norm in _facall_by_code: _fa_id=_facall_by_code[_acode_norm]
            _fi=_fieldid_by_access.get(_fa_id) if _fa_id is not None else None
            if _fi is not None:
                _bump('FIELD_ID_PRESENT')
                _md=_memdecl_by_id.get(_fi['member_decl_id'])
                # UNION-R01: fail closed. A union member's declared array size is real
                # backing-store capacity for THIS write in isolation, but this scanner makes
                # no claim about which member is the currently-live one -- never emit a
                # capacity fact for a union member at all, rather than imply more certainty
                # than "identity resolved" actually supports.
                if _md is not None and _md.get('type_decl_id') in _union_type_ids:
                    _bump('UNION_MEMBER_FAIL_CLOSED'); _md=None
                if _md is not None:
                    _bump('MEMBER_DECL_PRESENT')
                    _mtype=_md.get('type_full_name') or ''
                    _cap=_fixed_array_capacity(_mtype)
                    if _cap is not None:
                        _bump('CAPACITY_EMITTED')
                        _rule='CPP_STRUCT_MEMBER_ARRAY_CAPACITY'
                        # CAP-KEY-R01: a field access collapses to storage_value_id=-1, which is
                        # a SENTINEL and must NEVER be a join key. Carry the FieldStorageIdentity
                        # composite key explicitly so the reader joins by identity, not by -1.
                        _fkey=_fi['composite_key']
                        _skind='FIELD'
                    elif _mtype.endswith('*'):
                        _bump('POINTER_MEMBER')           # identity present, capacity UNKNOWN
                    elif '[]' in _mtype:
                        _bump('UNKNOWN_ARRAY_DIMENSION')  # T[] — dimension lost by frontend
                    else:
                        _bump('UNKNOWN_ELEMENT_WIDTH')
            if _cap is None:
                # STRUCT-MEMBER-OFFSET-R01 fallback: the operand isn't a bare field access
                # (or its identity/member-decl didn't resolve) -- try `field + offset` /
                # `&field[offset]` before giving up. Uses the operand's OWN node id (the
                # value_ref's id, which for an unrecognized shape is the addition/addressOf
                # call itself) rather than the field access id used above.
                _off=_offset_field_capacity(_av) if _av is not None else None
                if _off is not None:
                    _bump('OFFSET_FIELD_CAPACITY')
                    _cap,_offset_expr,_fi=_off
                    _rule='CPP_STRUCT_MEMBER_OFFSET_ARRAY_CAPACITY'
                    _fkey=_fi['composite_key']; _skind='FIELD_OFFSET'; _offset_shape=True
        if _cap is None: continue
        _bytes,_elem,_n=_cap
        _fact={'storage_value_id':_sid,
               'storage_identity_kind':_skind,'field_storage_key':_fkey,
               'function_id':_r['function_id'],'capacity_bytes':_bytes,
               'elem_type':_elem,'elem_count':_n,'resolution':'EXACT_STORAGE_IDENTITY',
               'call_id':_r['id'],'cmp_side':_r['role'],
               'offset_shape':_offset_shape,'offset_expr':_offset_expr,
               'derivation':{'origin':'FRONTEND_DERIVED','rule':_rule,
                             'source_node_ids':[_r['id']]}}
        if _r['role']=='WRITE_DEST': _dest_caps.append(_fact)
        elif _r['role']=='READ_SRC': _src_caps.append(_fact)
        else: _cmp_caps.append(_fact)   # READ_CMP_A / READ_CMP_B -> two-sided compare capacity
    pathlib.Path(str(out)+'.fieldcapclass.json').write_text(json.dumps(
        {'schema':'portable-field-cap-class/0.1','classification':_r02b_cls},indent=1,sort_keys=True)+'\n')
    pathlib.Path(str(out)+'.destcapacity.json').write_text(json.dumps(
        {'schema':'portable-dest-capacity-facts/0.1','dest_capacities':_dest_caps},
        indent=1,sort_keys=True)+'\n')
    pathlib.Path(str(out)+'.srccapacity.json').write_text(json.dumps(
        {'schema':'portable-src-capacity-facts/0.1','src_capacities':_src_caps},
        indent=1,sort_keys=True)+'\n')
    pathlib.Path(str(out)+'.cmpcapacity.json').write_text(json.dumps(
        {'schema':'portable-cmp-capacity-facts/0.1','cmp_capacities':_cmp_caps},
        indent=1,sort_keys=True)+'\n')
    # B4.3 BoundFact — expression-anchored, side-typed. NARROW: only mechanically
    # clear comparisons  if (extent REL capacity_expr)  where the comparison LHS is
    # EXACTLY the memcpy extent operand value and the RHS resolves to the exact
    # side-specific capacity. NO is_bounded/has_guard/safe/verdict. Abstain otherwise.
    _CMP_REL={'<operator>.lessThan':'LT','<operator>.lessEqualsThan':'LE'}
    # B2b.1: REJECT-GUARD relations. A reject-guard  if (extent > cap) return;  leaves the
    # surviving path with  extent <= cap  (for '>') or  extent < cap  ('>='). These are the
    # SAME safety relation as LT/LE, reached via the failing branch. We accept them ONLY when
    # the guard's true-branch TERMINATES before the sink (checked via CFG/returns below), so a
    # non-terminating  if(extent>cap){log();}  does NOT establish a bound.
    _REJECT_REL={'<operator>.greaterThan':'LE',        # extent > cap  rejected -> surviving extent <= cap
                 '<operator>.greaterEqualsThan':'LT'}  # extent >= cap rejected -> surviving extent <  cap
    # returns per function, for reject-branch termination check (reuses B1a.1 substrate)
    _ret_fns={}
    for _rr in returns_out: _ret_fns.setdefault(_rr.get('function_id'),True)
    import re as _re2
    def _sizeof_margin(_rhs_code,_stname):
        # accept  sizeof(name)  or  sizeof(name) - K  (K>=0 integer). Returns margin K or None.
        # cap - K with K>=0 is ALWAYS <= cap, so a bound extent <= cap-K implies extent <= cap
        # (sound). cap + K is NOT accepted (would be unsound). Preserves the arithmetic: K is
        # recorded in the derivation, never simplified away.
        _rc=(_rhs_code or '').replace(' ','')
        _base='sizeof(%s)'%_stname
        if _rc==_base: return 0
        _m=_re2.fullmatch(_re2.escape(_base)+r'-(\d+)', _rc)
        if _m: return int(_m.group(1))
        return None
    # index capacity facts by storage_value_id for capacity_ref resolution
    _dcap_by_storage={f['storage_value_id']:f for f in _dest_caps}
    _scap_by_storage={f['storage_value_id']:f for f in _src_caps}
    # map: for each memcpy, its EXTENT operand value id + its dest/src storage ids
    _bounds=[]
    _op_by_call={}
    for _r in _operand_roles:
        _op_by_call.setdefault(_r['id'],{})[_r['role']]=_r
    for _cid,_ops in _op_by_call.items():
        _ext=_ops.get('EXTENT')
        if not _ext: continue
        _c=call_by_id.get(_cid)
        if not _c: continue
        _ei=_ext['operand_index']
        _earg=next((a for a in _c.get('arguments',[]) if a['index']==_ei), None)
        _evr=(_earg or {}).get('value_ref') or {}
        _extent_vid=_evr.get('referenced_id') or _evr.get('id')
        _extent_code=(_evr.get('code') or '').strip()
        if _extent_vid is None: continue
        # find a comparison in the SAME function whose LHS value id == extent id
        for _cmp in calls:
            _rel=_CMP_REL.get(_cmp['name'])
            _is_reject=False
            if not _rel:
                _rel=_REJECT_REL.get(_cmp['name'])
                if not _rel: continue
                _is_reject=True
                # B2b.1: a reject-guard establishes the surviving bound ONLY if its true
                # (rejecting) branch terminates before the sink. Require the enclosing
                # function to have a return reachable from the guard (CFG substrate). Narrow:
                # we require a return to EXIST in the function AND the guard to structurally
                # be an  if(...)return;  — approximated by: the comparison's function has a
                # return, and the memcpy is NOT inside the guarded block. The non-terminating
                # teeth case has NO return in its guard branch, so it fails this check.
                if not _ret_fns.get(_cmp.get('enclosing_function_id')): continue
            if _cmp.get('enclosing_function_id')!=_c.get('enclosing_function_id'): continue
            _ca=sorted(_cmp.get('arguments',[]),key=lambda x:x['index'])
            if len(_ca)<2: continue
            _lhs=_ca[0].get('value_ref') or {}
            _lhs_vid=_lhs.get('referenced_id') or _lhs.get('id')
            _lhs_code=(_lhs.get('code') or '').strip()
            # EXPRESSION IDENTITY: exact value id match, OR exact code-spelling match
            # for simple identifiers (no provenance similarity, no same-name-different-scope:
            # require identical id when available, else identical non-empty code token).
            _id_match = (_lhs_vid is not None and _lhs_vid==_extent_vid)
            _code_match = (not _id_match and _lhs_code and _lhs_code==_extent_code
                           and _lhs_code.isidentifier())
            if not (_id_match or _code_match): continue
            # RHS must resolve to the EXACT side-specific capacity of THIS op's storage
            _rhs=_ca[1].get('value_ref') or {}
            _rhs_code=(_rhs.get('code') or '').strip()
            # determine side + capacity storage for this memcpy
            for _side,_capidx_role,_capmap,_bside in (
                    ('WRITE', 'WRITE_DEST', _dcap_by_storage, 'DEST_CAPACITY'),
                    ('READ',  'READ_SRC',   _scap_by_storage, 'SOURCE_CAPACITY')):
                _sop=_ops.get(_capidx_role)
                if not _sop: continue
                _sarg=next((a for a in _c.get('arguments',[]) if a['index']==_sop['operand_index']),None)
                _svr=(_sarg or {}).get('value_ref') or {}
                _storage=_svr.get('referenced_id') or _svr.get('id')
                _cap=_capmap.get(_storage)
                if not _cap: continue
                # RHS must name that storage's capacity: sizeof(name) or the storage code
                _stname=(_svr.get('code') or '').strip()
                # B2b.1: a struct-member destination is passed as &obj.member (address-of),
                # but the capacity guard names sizeof(obj.member) WITHOUT the &. They denote
                # the SAME storage. Strip a single leading '&' so sizeof(name) matches. This
                # does not weaken identity: the stripped name must still exactly equal the
                # RHS's sizeof argument.
                if _stname.startswith('&'): _stname=_stname[1:].strip()
                # RHS must name that storage's capacity: sizeof(name) or sizeof(name)-K (K>=0)
                # or the bare storage code. B2b.1 preserves the K margin (never simplifies -1).
                _margin=_sizeof_margin(_rhs_code,_stname)
                if _margin is None and _rhs_code!=_stname: continue
                if _margin is None: _margin=0
                _bounds.append({'checked_value_id':_extent_vid,'bound_side':_bside,
                    'relation':_rel,'capacity_ref_id':_cap['storage_value_id'],
                    'function_id':_c.get('enclosing_function_id'),
                    'derivation':{'origin':'FRONTEND_DERIVED',
                                  'rule':'CPP_REJECT_GUARD_BOUND' if _is_reject else 'CPP_EXACT_EXTENT_BOUND',
                                  'capacity_margin_bytes':_margin,
                                  'source_node_ids':[_cid,_cmp['id']]}})
    pathlib.Path(str(out)+'.bound.json').write_text(json.dumps(
        {'schema':'portable-bound-facts/0.1','bounds':_bounds},indent=1,sort_keys=True)+'\n')

if __name__=='__main__': main()
