#!/usr/bin/env python3
import argparse, base64, json, pathlib, os

def d(s):
    if not s: return ""
    return base64.b64decode(s).decode("utf-8", errors="replace")

def rows(path, n):
    p=pathlib.Path(path)
    if not p.exists(): return []
    out=[]
    for raw in p.read_text(encoding="utf-8").splitlines():
        if not raw.strip(): continue
        xs=raw.split("\t")
        if len(xs) != n:
            raise ValueError(f"{p.name}: expected {n} columns, got {len(xs)}: {raw[:120]}")
        out.append(xs)
    return out

def ints_csv(s):
    return [int(x) for x in s.split(',') if x]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("raw_dir")
    ap.add_argument("out_json")
    a=ap.parse_args()
    r=pathlib.Path(a.raw_dir)

    meta_rows=rows(r/'meta.tsv',3)
    meta={"language": d(meta_rows[0][0]), "cpg_version": d(meta_rows[0][1]), "root": d(meta_rows[0][2])} if meta_rows else {}

    funcs={}
    for x in rows(r/'methods.tsv',10):
        fid=int(x[0])
        funcs[fid]={"id":fid,"name":d(x[1]),"full_name":d(x[2]),"signature":d(x[3]),"file":d(x[4]),
                    "line":int(x[5]) if x[5] else None,"line_end":int(x[6]) if x[6] else None,
                    "ast_parent_type":d(x[7]),"ast_parent_full_name":d(x[8]),"is_external":x[9].lower()=="true",
                    "parameters":[]}
    for x in rows(r/'parameters.tsv',7):
        p={"id":int(x[0]),"method_id":int(x[1]),"index":int(x[2]),"name":d(x[3]),"code":d(x[4]),
           "type_full_name":d(x[5]),"line":int(x[6]) if x[6] else None}
        if p["method_id"] in funcs: funcs[p["method_id"]]["parameters"].append(p)
    for f in funcs.values(): f["parameters"].sort(key=lambda p:p["index"])

    args_by_call={}
    for x in rows(r/'arguments.tsv',8):
        q={"id":int(x[0]),"call_id":int(x[1]),"index":int(x[2]),"kind":d(x[3]),"code":d(x[4]),
           "name":d(x[5]),"type_full_name":d(x[6]),"line":int(x[7]) if x[7] else None}
        args_by_call.setdefault(q["call_id"],[]).append(q)
    for v in args_by_call.values(): v.sort(key=lambda q:q["index"])

    import sys as _sys, os as _os
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'joern-ts'))
    from dispatch_resolution import classify_call_audit as _audit
    from dispatch_resolution import canonical as _canon, collapse_init as _ci
    # JS neutral export has methods only (no type_decls/members): classifier still does
    # spelling/<init> dedup + receiver-agreement, but cannot expand union/interface stubs here.
    _methods_by_id={mid:{'full_name':f['full_name'],'is_external':f.get('is_external',False)} for mid,f in funcs.items()}
    _methods_by_full={_ci(_canon(f['full_name'])):mid for mid,f in funcs.items() if not f.get('is_external',False) and '::program' in f['full_name']}
    calls=[]
    for x in rows(r/'calls.tsv',10):
        target_ids=ints_csv(x[9])
        method_full_name=d(x[3])
        target_full_names=[funcs[i]["full_name"] for i in target_ids if i in funcs]
        if len(target_ids) > 1:
            resolution="AMBIGUOUS"
        elif len(target_ids)==1 and target_full_names and method_full_name and method_full_name==target_full_names[0]:
            resolution="EXACT"
        elif len(target_ids)==1:
            # A demonstrated edge exists, but the names disagree. Preserve it without hardening it.
            resolution="HEURISTIC"
        else:
            resolution="UNRESOLVED"
        cid=int(x[0])
        _c0={"id":cid,"enclosing_function_id":int(x[1]),"name":d(x[2]),"method_full_name":method_full_name,"candidate_target_ids":target_ids,"arguments":args_by_call.get(cid,[])}
        _sh=_audit(_c0,_methods_by_id,_methods_by_full,[],[])
        # PROMOTED: corrected authoritative; NOT_DISPATCH projects to UNRESOLVED (enum-valid, arity 0).
        _corr=_sh["resolution_corrected"]
        _promoted="UNRESOLVED" if _corr=="NOT_DISPATCH" else _corr
        if _corr in ("EXACT","AMBIGUOUS"):
            _pt_ids=_sh["corrected_target_ids"]; _pt_names=_sh["corrected_targets"]
        elif _corr in ("NOT_DISPATCH","UNRESOLVED"):
            _pt_ids=[]; _pt_names=[]
        else:
            _pt_ids=target_ids; _pt_names=target_full_names
        calls.append({"id":cid,"enclosing_function_id":int(x[1]),"name":d(x[2]),"method_full_name":method_full_name,
                      "resolution_raw":_sh["resolution_raw"],"resolution_corrected":_sh["resolution_corrected"],"resolution_reason":_sh["resolution_reason"],"canonical_targets":_sh["canonical_targets"],"concrete_targets":_sh["concrete_targets"],"stub_targets":_sh["stub_targets"],"corrected_targets":_sh["corrected_targets"],"receiver_type":_sh["receiver_type"],"receiver_owner_match":_sh["receiver_owner_match"],
                      "dispatch_type":d(x[4]),"type_full_name":d(x[5]),"code":d(x[6]),"file":d(x[7]),
                      "line":int(x[8]) if x[8] else None,"candidate_target_ids":_pt_ids,
                      "candidate_target_full_names":_pt_names,"resolution":_promoted,
                      "arguments":args_by_call.get(cid,[])})

    returns=[]
    for x in rows(r/'returns.tsv',5):
        returns.append({"id":int(x[0]),"method_id":int(x[1]),"code":d(x[2]),
                        "line":int(x[3]) if x[3] else None,"returned_value_ids":ints_csv(x[4])})
    identifiers=[]
    for x in rows(r/'identifiers.tsv',7):
        identifiers.append({"id":int(x[0]),"method_id":int(x[1]),"name":d(x[2]),"code":d(x[3]),
                            "type_full_name":d(x[4]),"line":int(x[5]) if x[5] else None,"ref_target_ids":ints_csv(x[6])})

    # CROSSLANG-LINK-FIX01G: real CFG edges + per-method entry/exit ids, for downstream
    # reaching-definition/dominance proof in link_napi_facts.py -- absent (empty lists)
    # for any raw export produced before this fix, since `rows()` returns [] for a
    # missing file rather than erroring; older raw exports stay fully readable.
    cfg_edges=[]
    for x in rows(r/'cfg_edges.tsv',3):
        cfg_edges.append({"owner":int(x[0]),"from":int(x[1]),"to":int(x[2])})
    method_cfg_endpoints=[]
    for x in rows(r/'method_cfg_endpoints.tsv',3):
        method_cfg_endpoints.append({"method_id":int(x[0]),"entry_id":int(x[1]),"exit_id":int(x[2])})

    # CROSSLANG-LINK-FIX01G addendum: real call ids nested inside a `try` block --
    # `rows()` yields one column per real line here (a plain id list, not a 3-column
    # TSV), so it is read directly rather than through `rows()`'s own fixed-width check.
    try_nested_calls=[]
    _tnc_path=r/'try_nested_calls.tsv'
    if _tnc_path.exists():
        for _line in _tnc_path.read_text(encoding="utf-8").splitlines():
            if _line.strip(): try_nested_calls.append(int(_line.strip()))

    doc={"schema":"portable-program-facts/0.2","frontend":"joern-jssrc2cpg","metadata":meta,
         "type_decls":[],"members":[],"method_returns":[],"locals":[],
         "functions":sorted(funcs.values(),key=lambda z:z["id"]),"calls":calls,"returns":returns,"identifiers":identifiers,
         "cfg_edges":cfg_edges,"method_cfg_endpoints":method_cfg_endpoints,
         "try_nested_calls":try_nested_calls}
    pathlib.Path(a.out_json).write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",encoding="utf-8")

if __name__=="__main__": main()
