#!/usr/bin/env python3
"""NAPI-EXPORT-ROOT-R01: recognize the native export-registration chain structurally and
mark ONLY the registered callback as an externally reachable native root. Separate
revision -- does NOT modify the frozen virtual_dispatch_reachability.py and does NOT
weaken promote_gated_by_root; it PRODUCES the `root_is_reachable` predicate those consume.

Recognized chain (by N-API call + argument IDENTITIES, never by macro spelling, source
text, or any function name):

    napi_create_function(env, name, len, CALLBACK_METHOD_REF, data, &FUNCTION_VALUE)
            |  same FUNCTION_VALUE identity (identifier referent)
            v
    napi_set_named_property(env, EXPORTS, export_name, FUNCTION_VALUE)
            |  same EXPORTS identity (identifier referent)
            v
    a proven MODULE INITIALIZER returns EXPORTS
            (a function with the N-API init signature (napi_env, napi_value P) that
             RETURNS its own napi_value parameter P, and to whose P the property was
             attached -- directly, or one hop away through an init(env, P) call it makes)

Only CALLBACK_METHOD_REF's resolved native function id is marked a root. Everything is
abstain-first: any broken/ambiguous identity link establishes nothing.

Public API:
  established_roots(raw) -> {function_id: evidence}   # proven export roots
  root_reachable_predicate(raw) -> (full_name -> bool)  # for promote_gated_by_root

Usage (diagnostic): napi_export_root.py RAW_DIR [OUT.json]
"""
import base64
import json
import sys
from collections import defaultdict

CREATE_FUNCTION = "napi_create_function"
SET_NAMED_PROPERTY = "napi_set_named_property"
DEFINE_PROPERTIES = "napi_define_properties"   # alternative idiom -> explicit abstention
ADDRESS_OF = "<operator>.addressOf"


def _dec(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def _rows(path):
    out = []
    for ln in open(path):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        out.append(ln.split("\t"))
    return out


class Facts:
    def __init__(self, raw):
        self.methods = {}          # id -> {name, full_name, sig}
        for r in _rows(f"{raw}/methods.tsv"):
            self.methods[int(r[0])] = {"id": int(r[0]), "name": _dec(r[1]),
                                       "full_name": _dec(r[2]), "sig": _dec(r[3]),
                                       "external": r[9] == "true"}
        self.calls = {}
        self.calls_by_owner = defaultdict(list)
        for r in _rows(f"{raw}/calls.tsv"):
            cid, owner = int(r[0]), int(r[1])
            self.calls[cid] = {"id": cid, "owner": owner, "name": _dec(r[2]),
                               "mfn": _dec(r[3]), "code": _dec(r[6])}
            self.calls_by_owner[owner].append(cid)
        self.args = defaultdict(dict)     # call_id -> {index: {nid, kind, code, name}}
        for r in _rows(f"{raw}/arguments.tsv"):
            self.args[int(r[1])][int(r[2])] = {"nid": int(r[0]), "kind": _dec(r[3]),
                                               "code": _dec(r[4]), "name": _dec(r[5])}
        self.ident = {}                   # identifier node id -> {owner, name, refs}
        for r in _rows(f"{raw}/identifiers.tsv"):
            self.ident[int(r[0])] = {"owner": int(r[1]), "name": _dec(r[2]),
                                     "refs": [int(x) for x in r[6].split(",") if x]}
        self.params = {}                  # (owner, index) -> {pid, name, type}
        self.params_by_method = defaultdict(list)
        for r in _rows(f"{raw}/parameters.tsv"):
            owner, idx = int(r[1]), int(r[2])
            p = {"pid": int(r[0]), "name": _dec(r[3]), "type": _dec(r[5])}
            self.params[(owner, idx)] = p
            self.params_by_method[owner].append((idx, p))
        # returns: owner -> list of child node ids returned
        self.returns_by_method = defaultdict(list)
        for r in _rows(f"{raw}/returns.tsv"):
            self.returns_by_method[int(r[1])].extend(int(x) for x in r[4].split(",") if x)
        # method_returns: declared return type per method (for the init signature check)
        self.ret_type = {}
        for r in _rows(f"{raw}/method_returns.tsv"):
            self.ret_type[int(r[1])] = _dec(r[3])

    def referent_of_ident_node(self, nid):
        """The single referent (local/param id) an identifier node refers to, or None if
        zero/ambiguous."""
        info = self.ident.get(nid)
        if not info or len(info["refs"]) != 1:
            return None
        return info["refs"][0]

    def addressof_inner_referent(self, addr_nid):
        """For an `&x` addressOf call node, the referent of its inner identifier x."""
        c = self.calls.get(addr_nid)
        if not c or c["name"] != ADDRESS_OF:
            return None
        inner = self.args.get(addr_nid, {}).get(1)
        if not inner or inner["kind"] != "IDENTIFIER":
            return None
        return self.referent_of_ident_node(inner["nid"])

    def method_ref_target(self, arg):
        """Resolve a METHOD_REF argument to a single native function id, or None if
        zero/ambiguous (control 5)."""
        if arg["kind"] != "METHOD_REF":
            return None
        code = arg["code"].strip()
        cands = [m["id"] for m in self.methods.values()
                 if m["name"] == code and not m["external"]]
        return cands[0] if len(cands) == 1 else None


def _create_function_facts(F):
    """Every napi_create_function call -> {call_id: {callback_fn_id, callback_kind,
    value_referent, owner}} with abstain markers for the malformed ones (controls 5/6)."""
    out = {}
    for cid, c in F.calls.items():
        if c["name"] != CREATE_FUNCTION:
            continue
        a = F.args.get(cid, {})
        method_refs = [v for v in a.values() if v["kind"] == "METHOD_REF"]
        addr_args = [v for v in a.values()
                     if v["kind"] == "CALL" and (F.calls.get(v["nid"], {}) or {}).get("name") == ADDRESS_OF]
        rec = {"owner": c["owner"], "callback_fn_id": None, "value_referent": None,
               "abstain": None}
        if len(method_refs) != 1:
            rec["abstain"] = "CALLBACK_NOT_A_METHOD_REF" if not method_refs \
                else "AMBIGUOUS_CALLBACK_METHOD_REF"
        else:
            fnid = F.method_ref_target(method_refs[0])
            if fnid is None:
                rec["abstain"] = "AMBIGUOUS_CALLBACK_IDENTITY"
            else:
                rec["callback_fn_id"] = fnid
        if len(addr_args) == 1:
            rec["value_referent"] = F.addressof_inner_referent(addr_args[0]["nid"])
        out[cid] = rec
    return out


def _is_module_init_returning(F, fn_id, exports_referent):
    """Proof that `fn_id` is a module initializer that RETURNS the object identified by
    `exports_referent`: fn_id has the N-API init shape (a napi_value parameter whose id
    == exports_referent) AND returns that same parameter (a returned identifier whose
    referent == exports_referent). Control 8: returning a DIFFERENT napi_value fails
    here."""
    # the exports_referent must be one of fn_id's own napi_value parameters
    own_params = {p["pid"] for _idx, p in F.params_by_method.get(fn_id, [])}
    if exports_referent not in own_params:
        return False
    for child in F.returns_by_method.get(fn_id, []):
        if F.referent_of_ident_node(child) == exports_referent:
            return True
    return False


def _exports_is_module_return(F, attach_owner, exports_referent):
    """Establish that the object attached-to (exports_referent, a parameter of
    attach_owner) is returned by a proven module initializer.

    Case A (single function): attach_owner itself is the module init returning exports.
    Case B (one-hop wrapper): some caller W calls attach_owner passing W's own napi_value
    parameter Q as the argument bound to attach_owner's exports parameter, and W is a
    module init returning Q. Returns evidence dict or None."""
    # Case A
    if _is_module_init_returning(F, attach_owner, exports_referent):
        return {"module_init_fn": attach_owner, "kind": "attach_function_is_init"}
    # Case B: find the parameter index of exports_referent within attach_owner
    exp_idx = None
    for idx, p in F.params_by_method.get(attach_owner, []):
        if p["pid"] == exports_referent:
            exp_idx = idx
            break
    if exp_idx is None:
        return None
    # find callers W of attach_owner passing their own param Q at that arg index
    for wid, cids in F.calls_by_owner.items():
        for cid in cids:
            c = F.calls[cid]
            # a call to attach_owner (by name/mfn) -- resolve callee
            callee_name = F.methods.get(attach_owner, {}).get("name")
            if c["name"] != callee_name:
                continue
            arg = F.args.get(cid, {}).get(exp_idx)
            if not arg or arg["kind"] != "IDENTIFIER":
                continue
            q_ref = F.referent_of_ident_node(arg["nid"])
            if q_ref is None:
                continue
            if _is_module_init_returning(F, wid, q_ref):
                return {"module_init_fn": wid, "kind": "one_hop_wrapper",
                        "wrapper_call_id": cid, "exports_param_index": exp_idx}
    return None


def established_roots(raw):
    """{function_id: evidence} of native functions proven to be externally reachable
    export roots via the create_function -> same-value set_named_property(exports) ->
    module-init-returns-exports chain. Abstain-first: only fully-proven chains count."""
    F = Facts(raw)
    cf = _create_function_facts(F)
    # index create_function by value_referent (to detect control 9: multiple defs)
    by_value = defaultdict(list)
    for cid, rec in cf.items():
        if rec["value_referent"] is not None:
            by_value[rec["value_referent"]].append(cid)

    roots = {}
    abstained = []
    for cid, c in F.calls.items():
        if c["name"] != SET_NAMED_PROPERTY:
            continue
        a = F.args.get(cid, {})
        obj = a.get(2)
        val = a.get(4)
        if not obj or not val or obj["kind"] != "IDENTIFIER" or val["kind"] != "IDENTIFIER":
            continue
        val_ref = F.referent_of_ident_node(val["nid"])
        obj_ref = F.referent_of_ident_node(obj["nid"])
        if val_ref is None or obj_ref is None:
            abstained.append({"reason": "AMBIGUOUS_ATTACH_IDENTITY", "set_call": cid})
            continue
        # which create_function produced val_ref?
        producers = by_value.get(val_ref, [])
        if not producers:
            abstained.append({"reason": "ATTACHED_VALUE_NOT_FROM_CREATE_FUNCTION",
                              "set_call": cid})
            continue
        if len(producers) > 1:
            abstained.append({"reason": "MULTIPLE_CREATE_FUNCTION_DEFS_REACH_PROPERTY",
                              "set_call": cid, "producers": producers})
            continue
        prod = cf[producers[0]]
        if prod["abstain"]:
            abstained.append({"reason": prod["abstain"], "create_call": producers[0]})
            continue
        # obj must be the exports returned by a proven module initializer
        mod = _exports_is_module_return(F, c["owner"], obj_ref)
        if mod is None:
            abstained.append({"reason": "EXPORTS_NOT_RETURNED_BY_MODULE_INIT",
                              "set_call": cid, "attach_owner": c["owner"]})
            continue
        fnid = prod["callback_fn_id"]
        roots[fnid] = {
            "function": F.methods[fnid]["full_name"],
            "create_function_call": producers[0],
            "set_named_property_call": cid,
            "value_referent": val_ref, "exports_referent": obj_ref,
            "module_init": F.methods[mod["module_init_fn"]]["full_name"],
            "module_init_evidence": mod,
        }
    # explicit abstention for the unresolved alternative idiom (control 10)
    for cid, c in F.calls.items():
        if c["name"] == DEFINE_PROPERTIES:
            abstained.append({"reason": "UNRESOLVED_DEFINE_PROPERTIES_IDIOM",
                              "call": cid})
    return roots, abstained, F


def root_reachable_predicate(raw):
    """Returns a predicate `full_name -> bool` marking proven export-root native
    functions -- suitable as the `root_is_reachable` argument to the frozen
    virtual_dispatch_reachability.promote_gated_by_root, WITHOUT modifying it."""
    roots, _ab, F = established_roots(raw)
    root_full_names = {ev["function"] for ev in roots.values()}
    # match on the callee name portion too (virtual-dispatch root_entry uses full_name
    # like 'iterator_next:napi_value(...)'; compare on the pre-':' head robustly).
    heads = {fn.split(":", 1)[0] for fn in root_full_names}

    def pred(root_full_name):
        if root_full_name in root_full_names:
            return True
        return root_full_name.split(":", 1)[0] in heads
    return pred


def main():
    raw = sys.argv[1]
    roots, abstained, F = established_roots(raw)
    result = {
        "schema": "napi-export-root/0.1",
        "established_roots": {str(k): v for k, v in roots.items()},
        "n_established": len(roots),
        "abstained_reasons": sorted({a["reason"] for a in abstained}),
    }
    if len(sys.argv) > 2:
        json.dump(result, open(sys.argv[2], "w"), indent=1, sort_keys=True, default=str)
    print(f"established export roots: {sorted(v['function'] for v in roots.values())[:6]}"
          f"{'...' if len(roots) > 6 else ''} (n={len(roots)})")
    print(f"abstained reasons: {result['abstained_reasons']}")


if __name__ == "__main__":
    main()
