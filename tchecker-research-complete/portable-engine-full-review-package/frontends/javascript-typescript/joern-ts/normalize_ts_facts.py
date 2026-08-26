#!/usr/bin/env python3
import base64, json, pathlib, re, sys

def dec(s):
    if not s: return ""
    try: return base64.b64decode(s).decode("utf-8", "replace")
    except Exception: return s

def rows(p, n):
    p=pathlib.Path(p)
    if not p.exists(): return []
    out=[]
    for ln in p.read_text().splitlines():
        if not ln.strip(): continue
        xs=ln.split("\t")
        if len(xs)!=n: raise ValueError(f"{p.name}: expected {n} cols, got {len(xs)}: {ln!r}")
        out.append(xs)
    return out

def ints(s): return [int(x) for x in s.split(',') if x]
def strs(s): return [dec(x) for x in s.split(',') if x]

_WEBEXT_EXTERNAL_LISTENER = re.compile(
    r'^\s*(?:browser|chrome)\s*\.\s*runtime\s*\.\s*onMessageExternal\s*\.\s*addListener\s*\(',
    re.DOTALL)

_WEBEXT_TAB_LISTENER = re.compile(
    r'^\s*(?:browser|chrome)\s*\.\s*tabs\s*\.\s*(onCreated|onUpdated)\s*\.\s*addListener\s*\(',
    re.DOTALL)

def _listener_callback_id(call, assignments):
    """Resolve only an inline function or an exactly-once local function binding."""
    args = sorted(call.get('arguments', []), key=lambda a: a['index'])
    if not args: return None
    ref = args[0].get('value_ref') or {}
    if ref.get('kind') == 'FUNCTION':
        return ref.get('id')
    if ref.get('kind') != 'LOCAL':
        return None
    candidates = [a for a in assignments
                  if a['function_id'] == call['enclosing_function_id']
                  and a['target_local_id'] == ref.get('id')]
    targets = {a['value_ref'].get('id') for a in candidates
               if (a.get('value_ref') or {}).get('kind') == 'FUNCTION'}
    return next(iter(targets)) if len(candidates) == 1 and len(targets) == 1 else None

def derive_webext_external_message_sources(methods, calls, assignments):
    """Derive high-confidence WebExtension external-message parameter origins.

    Scope is deliberately narrow: direct browser/chrome.runtime.onMessageExternal
    registrations whose callback resolves to exactly one function. Generic
    `.onMessage`, ports, browser.test, tabs events, aliases and ambiguous handler
    locals remain outside this source class.
    """
    functions = {m['id']: m for m in methods if not m.get('is_external')}
    out = []
    for call in calls:
        if call.get('name') != 'addListener' or not _WEBEXT_EXTERNAL_LISTENER.match(call.get('code', '')):
            continue
        target = functions.get(_listener_callback_id(call, assignments))
        if target is None or not target.get('parameters'):
            continue
        payload = sorted(target['parameters'], key=lambda p: p['index'])[0]
        arg = sorted(call.get('arguments', []), key=lambda a: a['index'])[0]
        out.append({'id': call['id'], 'function_id': target['id'],
            'target_local_id': payload['id'], 'target_kind': 'PARAMETER',
            'origin_kind': 'WEBEXT_EXTERNAL_MESSAGE_INPUT',
            'location': 'runtime.onMessageExternal',
            'derivation': {'origin': 'FRONTEND_COMPOSED',
                'rule': 'JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE',
                'source_node_ids': [call['id'], arg['id'], payload['id']]}})
    return out

def derive_webext_tab_url_sources(methods, calls, assignments, state_reads):
    """Identify only URL-bearing reads from direct tabs event registrations.

    onCreated: callback parameter 0, field `url`.
    onUpdated: callback parameter 1 (`changeInfo.url`) and parameter 2 (`tab.url`).
    Facts target the individual STATE_READ, so sibling fields never inherit the
    browser URL origin. Aliased event objects and ambiguous callbacks abstain.
    """
    functions = {m['id']: m for m in methods if not m.get('is_external')}
    out = []
    for call in calls:
        if call.get('name') != 'addListener':
            continue
        match = _WEBEXT_TAB_LISTENER.match(call.get('code', ''))
        if not match:
            continue
        event = match.group(1)
        target = functions.get(_listener_callback_id(call, assignments))
        if target is None:
            continue
        params = {p['index']: p for p in target.get('parameters', [])}
        allowed = ({0} if event == 'onCreated' else {1, 2})
        allowed_param_ids = {params[i]['id']: i for i in allowed if i in params}
        for read in state_reads:
            root = (read.get('receiver_location') or {}).get('root_ref') or {}
            key = read.get('key') or {}
            if (read.get('function_id') != target['id']
                    or root.get('kind') != 'PARAMETER'
                    or root.get('id') not in allowed_param_ids
                    or (read.get('receiver_location') or {}).get('path') != []
                    or key.get('kind') != 'LITERAL' or key.get('value') != 'url'):
                continue
            read_id = read['index_call_id']
            param_index = allowed_param_ids[root['id']]
            location = ('tabs.onCreated.tab.url' if event == 'onCreated'
                        else ('tabs.onUpdated.changeInfo.url' if param_index == 1
                              else 'tabs.onUpdated.tab.url'))
            out.append({'id': read_id, 'function_id': target['id'],
                'target_local_id': read_id, 'target_kind': 'STATE_READ',
                'origin_kind': 'WEBEXT_TAB_URL_INPUT', 'location': location,
                'derivation': {'origin': 'FRONTEND_COMPOSED',
                    'rule': 'JS_WEBEXT_TAB_URL_SOURCE',
                    'source_node_ids': [call['id'], root['id'], read_id]}})
    return out

def main():
    raw=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])
    methods=[]; by_id={}
    for r in rows(raw/'methods.tsv',10):
        x={'id':int(r[0]),'name':dec(r[1]),'full_name':dec(r[2]),'signature':dec(r[3]),'file':dec(r[4]),'line':int(r[5] or 0),'line_end':int(r[6] or 0),'ast_parent_type':dec(r[7]),'ast_parent_full_name':dec(r[8]),'is_external':r[9].lower()=='true','parameters':[]}
        methods.append(x); by_id[x['id']]=x
    for r in rows(raw/'parameters.tsv',7):
        x={'id':int(r[0]),'method_id':int(r[1]),'index':int(r[2]),'name':dec(r[3]),'code':dec(r[4]),'type_full_name':dec(r[5]),'line':int(r[6] or 0)}
        if x['method_id'] in by_id: by_id[x['method_id']]['parameters'].append(x)
    for m in methods: m['parameters'].sort(key=lambda x:x['index'])

    type_decls=[]
    for r in rows(raw/'type_decls.tsv',7):
        type_decls.append({'id':int(r[0]),'name':dec(r[1]),'full_name':dec(r[2]),'file':dec(r[3]),'line':int(r[4] or 0),'is_external':r[5].lower()=='true','inherits_from':strs(r[6])})
    members=[{'id':int(r[0]),'type_decl_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),'type_full_name':dec(r[4]),'line':int(r[5] or 0)} for r in rows(raw/'members.tsv',6)]
    # --- shadow dispatch-resolution audit (Gate 24-TS-2 classifier); NON-PROMOTED ---
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__)))
    from dispatch_resolution import classify_call_audit as _audit
    _methods_by_id={m['id']:{'full_name':m['full_name'],'is_external':m['is_external']} for m in methods}
    from dispatch_resolution import canonical as _canon, collapse_init as _ci
    _methods_by_full={_ci(_canon(m['full_name'])):m['id'] for m in methods if not m['is_external'] and '::program' in m['full_name']}
    _td_by_id={t['id']:t['full_name'] for t in type_decls}
    _td_shadow=[{'name':t['name'],'full_name':t['full_name'],'inherits_from':(t['inherits_from'][0] if t['inherits_from'] else '')} for t in type_decls]
    _mem_shadow=[{'owner_full':_td_by_id.get(m['type_decl_id'],''),'name':m['name'],'type':m['type_full_name']} for m in members]
    method_returns=[{'id':int(r[0]),'method_id':int(r[1]),'code':dec(r[2]),'type_full_name':dec(r[3]),'line':int(r[4] or 0)} for r in rows(raw/'method_returns.tsv',5)]
    locals_=[{'id':int(r[0]),'method_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),'type_full_name':dec(r[4]),'line':int(r[5] or 0)} for r in rows(raw/'locals.tsv',6)]
    arguments={}
    for r in rows(raw/'arguments.tsv',8):
        arguments.setdefault(int(r[1]),[]).append({'id':int(r[0]),'index':int(r[2]),'kind':dec(r[3]),'code':dec(r[4]),'name':dec(r[5]),'type_full_name':dec(r[6]),'line':int(r[7] or 0)})
    # tsc union sidecar (optional): recovers declared union receivers that
    # jssrc2cpg destroys (measured on gate4). Keyed (function name, param name).
    _union_sidecar={}
    if (raw/'union_hints.tsv').exists():
        _name_scope={m['name']:m['full_name'] for m in methods}
        for _l in (raw/'union_hints.tsv').read_text().splitlines():
            _r=_l.rstrip('\n').split('\t')
            if len(_r)==3:
                _fn,_pn,_members=_r
                _scope=_name_scope.get(_fn,'')
                _prefix=_scope.rsplit(':',1)[0] if ':' in _scope else ''
                _scoped=[(_prefix+':'+m) if _prefix else m for m in _members.split('|')]
                _union_sidecar[(_fn,_pn)]=' | '.join(_scoped)
    # JSTS-R08: method references -> first-class callable value refs
    _method_refs={}
    if (raw/'method_refs.tsv').exists():
        _full_to_id={_ci(_canon(m['full_name'])):m['id'] for m in methods}
        for _l in (raw/'method_refs.tsv').read_text().splitlines():
            _r=_l.rstrip('\n').split('\t')
            if len(_r)==3:
                _mfn=dec(_r[1])
                _tid=_full_to_id.get(_ci(_canon(_mfn)))
                if _tid is not None: _method_refs[int(_r[0])]=(_tid,_mfn,dec(_r[2]))
    _assign_count={}
    for r in rows(raw/'calls.tsv',11):
        if dec(r[2])=='<operator>.assignment':
            _cid=int(r[0])
            _aa=sorted(arguments.get(_cid,[]),key=lambda x:x['index'])
            if _aa and (_aa[0].get('name') or ''):
                _k=(int(r[1]),_aa[0]['name'])
                _assign_count[_k]=_assign_count.get(_k,0)+1
    calls=[]
    for r in rows(raw/'calls.tsv',11):
        tids=ints(r[9]); tnames=strs(r[10])
        # This is an observation-level projection, not a claim of semantic soundness.
        resolution='UNRESOLVED' if len(tids)==0 else ('EXACT' if len(tids)==1 else 'AMBIGUOUS')
        _c={'id':int(r[0]),'enclosing_function_id':int(r[1]),'name':dec(r[2]),'method_full_name':dec(r[3]),'dispatch_type':dec(r[4]),'type_full_name':dec(r[5]),'code':dec(r[6]),'file':dec(r[7]),'line':int(r[8] or 0),'candidate_target_ids':tids,'candidate_target_full_names':tnames,'resolution':resolution,'arguments':sorted(arguments.get(int(r[0]),[]),key=lambda x:x['index'])}
        # PRE-AUDIT receiver handling: Joern argument_index 0 is the receiver slot.
        # Drop it (positional args shift -1) and record the receiver reference; the
        # DECLARED parameter type is authoritative for the classifier (measured:
        # jssrc2cpg collapses union receiver-arg types to the first member's ctor).
        _aa=_c['arguments']
        if _aa and _aa[0]['index']==0:
            _recv=_aa[0]
            _c['arguments']=[{**x,'index':x['index']-1} for x in _aa[1:]]
            _declmap={pp['name']:pp['type_full_name'] for mm in methods if mm['id']==_c['enclosing_function_id'] for pp in mm['parameters']}
            _encl_name=next((m['name'] for m in methods if m['id']==_c['enclosing_function_id']),'')
            _side=_union_sidecar.get((_encl_name,_recv.get('name') or ''))
            _c['receiver_declared_type']=_side or _declmap.get(_recv.get('name') or '') or _recv.get('type_full_name') or ''
            _c['receiver_name']=_recv.get('name') or _recv.get('code') or ''
        _sh=_audit(_c,_methods_by_id,_methods_by_full,_td_shadow,_mem_shadow)
        # SHADOW-ONLY scope narrowing (JSTS-R07 measurement): recorded, never authoritative here.
        from dispatch_resolution import scope_narrow as _scope_narrow
        _encl=next((m for m in methods if m['id']==_c['enclosing_function_id']),None)
        if _encl is not None and _sh['resolution_corrected']=='AMBIGUOUS':
            _defs_count=_assign_count.get((_c['enclosing_function_id'],_c['name']),0)
            _sn=_scope_narrow(_c,_methods_by_id,_methods_by_full,_encl['full_name'],_sh['canonical_targets'],_defs_count)
            if _sn is not None:
                _c['resolution_scope_corrected'],_c['scope_corrected_targets'],_c['scope_reason']=_sn
        # PROMOTED: corrected resolution is authoritative; raw retained as diagnostic provenance.
        _corr=_sh['resolution_corrected']
        if _corr=='NOT_DISPATCH':
            _c['resolution']='UNRESOLVED'          # enum-valid projection for non-dispatch CALL nodes
            _c['candidate_target_ids']=[]           # keep UNRESOLVED arity invariant for a future loader
            _c['candidate_target_full_names']=[]
        else:
            _c['resolution']=_corr
            # align candidate ids with the corrected targets so a future CallFact loader's
            # per-resolution arity validation (EXACT=1, AMBIGUOUS>=2, UNRESOLVED=0) holds.
            if _corr in ('EXACT','AMBIGUOUS'):
                _c['candidate_target_ids']=_sh['corrected_target_ids']
                _c['candidate_target_full_names']=_sh['corrected_targets']
            elif _corr=='UNRESOLVED':
                _c['candidate_target_ids']=[]; _c['candidate_target_full_names']=[]
        _c.update({'resolution_raw':_sh['resolution_raw'],'resolution_corrected':_sh['resolution_corrected'],'resolution_reason':_sh['resolution_reason'],'canonical_targets':_sh['canonical_targets'],'concrete_targets':_sh['concrete_targets'],'stub_targets':_sh['stub_targets'],'corrected_targets':_sh['corrected_targets'],'receiver_type':_sh['receiver_type'],'receiver_owner_match':_sh['receiver_owner_match']})
        # PROMOTED scope narrowing (JSTS-R07: 3/3 correct narrowings, 4/4 correct
        # refusals on adversarial fixtures; applied LAST so the corrected-resolution
        # stage cannot clobber it; shadow fields retained as diagnostics).
        if 'resolution_scope_corrected' in _c:
            _c['resolution']='EXACT'
            _c['corrected_targets']=list(_c['scope_corrected_targets'])
            _c['candidate_target_full_names']=list(_c['scope_corrected_targets'])
            _c['candidate_target_ids']=[_methods_by_full[t] for t in _c['scope_corrected_targets'] if t in _methods_by_full]
            _c['resolution_reason']='SCOPE_NARROWED_LOCAL_LAMBDA'
        calls.append(_c)
    identifiers=[{'id':int(r[0]),'method_id':int(r[1]),'name':dec(r[2]),'code':dec(r[3]),'type_full_name':dec(r[4]),'line':int(r[5] or 0),'ref_target_ids':ints(r[6])} for r in rows(raw/'identifiers.tsv',7)]
    # --- frontend-side value_ref resolution (the loader must never infer this) ---
    _param_ids={p['id'] for m in methods for p in m['parameters']}
    _local_ids={l['id'] for l in locals_}
    _call_ids={c['id'] for c in calls}
    _literals={}
    if (raw/'literals.tsv').exists():
        for r in rows(raw/'literals.tsv',4):
            _literals[int(r[0])]=dec(r[1])
    # keyed-state READ accessor calls resolve as STATE_READ refs (CORE-S01):
    # composition happens here in the frontend; the loader/core never see operators.
    try:
        from state_facts import derive as _derive_state
        _derived_state = _derive_state(raw)
        _state_reads = _derived_state['state_reads']
        _state_read_ids={r['index_call_id'] for r in _state_reads}
    except Exception:
        _state_reads=[]
        _state_read_ids=set()
    _ident_by_id={}
    for i in identifiers:
        # ast-walk lists nested nodes under ancestors too; refs are identical per node id
        _ident_by_id.setdefault(i['id'], i)
    def _value_ref(node_id, code=''):
        # JSTS-R08: a lambda used as a VALUE is a first-class callable reference,
        # not an untyped node. Joern already knows its methodFullName; the target
        # is looked up by EXACT full-name identity, never by code text.
        if node_id in _method_refs:
            _tid,_mfn,_c=_method_refs[node_id]
            return {'kind':'FUNCTION','id':_tid,'code':code or _c}
        if node_id in _param_ids: return {'kind':'PARAMETER','id':node_id,'code':code}
        if node_id in _state_read_ids: return {'kind':'STATE_READ','id':node_id,'code':code}
        if node_id in _call_ids:  return {'kind':'CALL','id':node_id,'code':code}
        if node_id in _local_ids: return {'kind':'LOCAL','id':node_id,'code':code}
        if node_id in _literals:
            return {'kind':'CONSTANT','id':-1,'code':_literals[node_id]}
        ident=_ident_by_id.get(node_id)
        if ident:
            for t in ident['ref_target_ids']:
                if t in _param_ids: return {'kind':'PARAMETER','id':t,'code':ident['code']}
                if t in _local_ids: return {'kind':'LOCAL','id':t,'code':ident['code']}
            return {'kind':'UNKNOWN','id':-1,'code':ident['code']}
        c=(code or '').strip()
        if c.startswith(('"',"'")) or c.replace('.','',1).isdigit():
            return {'kind':'CONSTANT','id':-1,'code':c}
        return {'kind':'UNKNOWN','id':-1,'code':c}
    # attach value_ref to every argument (by its node id)
    for c in calls:
        for a in c['arguments']:
            a['value_ref']=_value_ref(a['id'], a.get('code',''))
            a['derivation']={'origin':'FRONTEND_DIRECT','rule':'ARGUMENT_NODE_REF','source_node_ids':[a['id']]}
    # returns: dedupe ast-walk duplicates by keeping the most-nested owner (longest fullName)
    _full_of={m['id']:m['full_name'] for m in methods}
    _ret_rows={}
    for r in rows(raw/'returns.tsv',5):
        rid=int(r[0]); mid=int(r[1])
        cur=_ret_rows.get(rid)
        if cur is None or len(_full_of.get(mid,''))>len(_full_of.get(cur[1],'')):
            _ret_rows[rid]=(rid,mid,dec(r[2]),int(r[3] or 0),ints(r[4]))
    returns_out=[]
    for rid,mid,code,line,children in _ret_rows.values():
        child=children[0] if children else None
        if child is None and code.strip().rstrip(';').strip()=='return':
            # bare `return;` carries no value (same consistency fix as the C side)
            continue
        vr=_value_ref(child, code) if child is not None else {'kind':'UNKNOWN','id':-1,'code':code}
        returns_out.append({'id':rid,'function_id':mid,'code':code,'line':line,'value_ref':vr,
            'derivation':{'origin':'FRONTEND_DIRECT','rule':'RETURN_AST_CHILD','source_node_ids':[rid]+([child] if child is not None else [])}})
    returns_out.sort(key=lambda x:x['id'])
    # assignments to locals (single- and multi-def; the CORE decides semantics)
    assignments_out=[]
    for r in rows(raw/'calls.tsv',11):
        if dec(r[2])!='<operator>.assignment': continue
        _cid=int(r[0]); _mid=int(r[1])
        _aa=sorted(arguments.get(_cid,[]),key=lambda x:x['index'])
        if len(_aa)<2: continue
        lhs,rhs=_aa[0],_aa[1]
        _tid=None
        if lhs['id'] in _local_ids: _tid=lhs['id']
        else:
            _ii=_ident_by_id.get(lhs['id'])
            if _ii:
                for t in _ii['ref_target_ids']:
                    if t in _local_ids: _tid=t; break
        if _tid is None: continue
        assignments_out.append({'id':_cid,'function_id':_mid,'target_local_id':_tid,
            'value_ref':_value_ref(rhs['id'], rhs.get('code','')),'line':int(r[8] or 0),
            'derivation':{'origin':'FRONTEND_DIRECT','rule':'ASSIGNMENT_TO_LOCAL','source_node_ids':[_cid,_tid,rhs['id']]}})

    # --- this-normalization (frontend artifact; core sees user-signature indices) ---
    _this_param_ids=set()
    for m in methods:
        ps=sorted(m['parameters'],key=lambda p:p['index'])
        if ps and ps[0]['name']=='this':
            _this_param_ids.add(ps[0]['id'])
            m['parameters']=[{**p,'index':p['index']-1} for p in ps[1:]]
    _params_by_fn={}
    for m in methods:
        _params_by_fn[m['id']]={p['name']:p['type_full_name'] for p in m['parameters']}
    for c in calls:
        aa=sorted(c['arguments'],key=lambda a:a['index'])
        # receiver slot already dropped PRE-AUDIT in the calls loop; nothing to drop here.
        if False:
            recv=aa[0]
            aa=[{**a,'index':a['index']-1} for a in aa[1:]]
            # authoritative receiver type: the DECLARED parameter type when the receiver
            # names an enclosing-function parameter (jssrc2cpg may collapse union arg
            # types to the first member's constructor — measured on gate4).
            declared=_params_by_fn.get(c['enclosing_function_id'],{}).get(recv.get('name') or '')
            c['receiver_declared_type']=declared or recv.get('type_full_name') or ''
        c['arguments']=aa
    def _fix_vr(vr):
        if vr.get('kind')=='PARAMETER' and vr.get('id') in _this_param_ids:
            return {'kind':'UNKNOWN','id':-1,'code':vr.get('code','this')}
        return vr
    for c in calls:
        for a in c['arguments']: a['value_ref']=_fix_vr(a['value_ref'])
    for r in returns_out: r['value_ref']=_fix_vr(r['value_ref'])
    meta=[]
    for r in rows(raw/'meta.tsv',3): meta.append({'language':dec(r[0]),'version':dec(r[1]),'root':dec(r[2])})
    # Generic frontend-output invariant: structured counters + loud EMPTY_FRONTEND_OUTPUT.
    # A frontend that silently skipped all sources must never look like clean empty results.
    frontend_counters={'exported_functions':len(methods),'exported_calls':len(calls),
        'exported_returns':len(returns_out),'exported_identifiers':len(identifiers),
        'exported_type_decls':len(type_decls),'exported_locals':len(locals_)}
    if frontend_counters['exported_functions']==0:
        import sys as _s
        _s.stderr.write('EMPTY_FRONTEND_OUTPUT: frontend reported success but exported 0 functions\n'
                        +json.dumps(frontend_counters)+'\n')
        _s.exit(30)
    # JSTS expression decomposition (same neutral family as the C/C++ side):
    # a combined value carries all operand origins as POSSIBILITIES. This lifts
    # the long-recorded closureTwoCaptures limit (lambda returning `a + b`).
    _EXPR_OPS={'<operator>.addition','<operator>.subtraction','<operator>.multiplication',
        '<operator>.division','<operator>.modulo','<operator>.exponentiation',
        '<operator>.logicalOr','<operator>.logicalAnd','<operator>.nullishCoalescing',
        '<operator>.equals','<operator>.notEquals','<operator>.strictEquals',
        '<operator>.notStrictEquals','<operator>.lessThan','<operator>.greaterThan',
        '<operator>.lessEqualsThan','<operator>.greaterEqualsThan','<operator>.conditional',
        # TEMPLATE-R01: a template literal `a${x}b${y}` lowers to formatString and
        # is an ordinary combined value — its provenance is the UNION of the
        # interpolated operands. No new family, no new invariant: it reuses the
        # gated ExpressionFact lattice (EXACT forbidden, MAY over operands,
        # unknown preserved if any operand is unresolved).
        '<operator>.formatString'}
    _expressions=[]
    for _c in calls:
        if _c['name'] not in _EXPR_OPS: continue
        _aa=sorted(arguments.get(_c['id'],[]),key=lambda x:x['index'])
        _ops=[a for a in _aa if a['index']>=1]
        if len(_ops)<2: continue
        _refs=[_value_ref(a['id'], a.get('code','')) for a in _ops]
        if _c['name']=='<operator>.conditional' and len(_refs)==3:
            _refs=_refs[1:]   # the condition does not flow into the value
        if _c['name']=='<operator>.formatString':
            # The literal chunks of the template carry no provenance; keeping them
            # would pad the operand list without adding origins. Interpolated
            # expressions only.
            _refs=[r for r in _refs if r.get('kind')!='CONSTANT']
        if len(_refs)<2: continue
        _expressions.append({'id':_c['id'],'function_id':_c['enclosing_function_id'],
            'operator':_c['name'],'operands':_refs,'resolution':'AMBIGUOUS',
            'derivation':{'origin':'FRONTEND_DERIVED','rule':'JSTS_EXPRESSION_OPERANDS',
                          'source_node_ids':[_c['id']]+[a['id'] for a in _ops]}})
    import pathlib as _pl

    # JS-SOURCE-R01: FILE_INPUT source recognition for JavaScript.
    # Mirrors the C SOURCE-R02 contract (emit an ORIGIN KIND, not an API name),
    # but the JS model is SIMPLER and needs none of the pointer-target machinery:
    # JS file readers RETURN the buffer (const x = await fs.readFile(...)), so the
    # destination is an ordinary assignment target, never a &out-parameter.
    # Recognized readers (return value carries external file content):
    #   fs.readFile / fs.readFileSync / fs.promises.readFile / createReadStream
    # A reader whose result is NOT bound to a local emits nothing (no target).
    # NEVER emit EXACT; the core treats FILE_INPUT as an origin that must still
    # survive reaching-definition to a use, exactly as on the C side.
    # ORIGIN-KIND PURITY: only ATOMIC readers that RETURN bytes belong here.
    # readFileSync / readFile(await) -> the buffer IS the return value, so binding
    # FILE_INPUT to the assignment target is correct.
    # createReadStream is DELIBERATELY EXCLUDED: it returns a STREAM HANDLE, not
    # bytes. Tagging the handle as FILE_INPUT would fabricate a false EXACT on the
    # wrong object. Its event-driven source contract (the 'data' chunk carries the
    # bytes) is a separate, not-yet-implemented recognizer (JS-SOURCE-R02).
    _JS_FILE_READERS={'readFile','readFileSync'}
    _src_origins=[]
    # map: which local is assigned directly from a reader call?
    _asg_by_rhs={}
    for _a in assignments_out:
        _vr=_a.get('value_ref') or {}
        _asg_by_rhs.setdefault(_vr.get('id'), []).append(_a['target_local_id'])
    for _c in calls:
        if _c['name'] not in _JS_FILE_READERS: continue
        _cid=_c['id']; _mid=_c['enclosing_function_id']
        # the reader's return may be wrapped in await; unwrap one await layer
        _feed_ids=[_cid]
        for _w in calls:
            if _w['name']=='<operator>.await':
                _wa=sorted(arguments.get(_w['id'],[]),key=lambda x:x['index'])
                if _wa and _wa[0]['id']==_cid: _feed_ids.append(_w['id'])
        _tgts=[]
        for _fid in _feed_ids:
            _tgts.extend(_asg_by_rhs.get(_fid, []))
        # dedupe, keep only real locals
        _tgts=[t for t in dict.fromkeys(_tgts) if t in _local_ids]
        if len(_tgts)!=1:
            # 0 targets (result not bound) or >1 (ambiguous): abstain, emit nothing
            continue
        _src_origins.append({'id':_cid,'function_id':_mid,
            'target_local_id':_tgts[0],'target_kind':'LOCAL',
            'origin_kind':'FILE_INPUT','location':_c['name'],
            'derivation':{'origin':'FRONTEND_DIRECT','rule':'JS_FILE_INPUT_SOURCE',
                          'source_node_ids':[_cid]}})
    _src_origins.extend(derive_webext_external_message_sources(methods, calls, assignments_out))
    _src_origins.extend(derive_webext_tab_url_sources(
        methods, calls, assignments_out, _state_reads))
    # Emit even when empty: a silently-skipped frontend must not look like clean
    # empty results (same discipline as the C source sidecar).
    _pl.Path(str(out)+'.source.json').write_text(
        json.dumps({'schema':'portable-source-facts/0.1','source_origins':_src_origins},indent=1,sort_keys=True)+'\n')

    _pl.Path(str(out)+'.expression.json').write_text(
        json.dumps({'schema':'portable-expression-facts/0.1','expressions':_expressions},indent=1,sort_keys=True)+'\n')

    doc={'schema':'portable-program-facts/0.3','frontend':'joern-jssrc2cpg','metadata':meta,'type_decls':type_decls,'members':members,'functions':methods,'method_returns':method_returns,'locals':locals_,'calls':calls,'identifiers':identifiers,'returns':returns_out,'assignments':assignments_out,'frontend_counters':frontend_counters}
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+'\n')
if __name__=='__main__': main()
