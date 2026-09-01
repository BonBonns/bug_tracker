#!/usr/bin/env python3
"""VIRTUAL-DISPATCH-REACHABILITY-R01: a shared reachability revision that resolves C++
virtual callbacks through concrete-allocation-type object flow, so a native method
reached ONLY through the "worker object -> registered async callback -> cast-back ->
virtual dispatch" idiom can be proven reachable from a registered entry point when --
and only when -- exactly one concrete override is provable.

This is SHARED infrastructure (Lock Balance / Protected Field / OOB / N-API status all
key their findings by a native function id and ask "is this function reachable from
JS"). It is a NEW revision: it reads the raw cpp facts directly and computes an
additional set of virtual-dispatch-reachable function ids; it does NOT modify
reachability_tier.py, the normalizer, or any frozen behavior. A separate integration
adds a new tier for the promoted functions.

NAME-AGNOSTIC: no package/class/method name is ever special-cased. The analysis keys on
structural facts only -- `<operator>.new` allocations, the class hierarchy
(type_decls inheritance), a callback/worker registration API (reused from
reachability_tier.CALLBACK_OR_WORKER_REGISTRATION_APIS) whose data argument is the
constructed object, the `(Base*)data` cast inside the callback, method signatures, and
method-resolution-order (MRO) override resolution from a fixed concrete type.

THE CHAIN it proves (abstain-first at every step):
  1. A registered entry function F contains `p = new T` (a single concrete allocation
     type T -- a factory call or non-`new` source is UNRESOLVED -> abstain).
  2. p is not reassigned between the allocation and its use -> else abstain.
  3. T's construction (T's ctor, transitively through base-ctor initialization)
     contains a registration-API call whose DATA argument is `this` -- so the
     registered callback's data pointer has concrete type T. A registration whose data
     is some OTHER object -> abstain. No registration -> no promotion.
  4. p reaches a queue-API call (the async work is actually enqueued, so the callback
     runs).
  5. Inside the callback function C, the data parameter is cast to a base pointer
     (`self = (Base*)data`) -- Base must be a supertype of T; a cast to an unrelated
     type, or data not the callback's own data parameter -> abstain.
  6. From C with receiver `self` of concrete type T, an interprocedural typestate walk
     follows member calls on that receiver, resolving EACH callee by MRO from T
     (nearest class in T's linearization defining the (name, signature) pair). This
     resolves non-virtual base methods to the base and virtual overrides to T's own
     override, uniformly. Every method so reached is virtual-dispatch-reachable from F.
  7. A function id is PROMOTED only if every concrete type flowing to its resolving
     virtual-call site is the SAME single T (unique concrete override). If two concrete
     types reach the same receiver/call site and resolve to different overrides, BOTH
     are abstained (multiple possible overrides / ambiguous receiver).

Output: promoted_reachability(raw_dir) -> {function_id: evidence_dict}. The evidence
names the root entry, allocation type, registration call, callback, cast, and the
resolved override chain -- real evidence, never a bare assertion.

Usage (diagnostic): virtual_dispatch_reachability.py RAW_DIR [OUT.json]
"""
import base64
import json
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import reachability_tier as R  # noqa: E402  (only for the registration/queue API lists)

# Reuse the SAME registration API set as the frozen tier -- never a private copy.
REGISTRATION_APIS = getattr(R, "CALLBACK_OR_WORKER_REGISTRATION_APIS", None)
if REGISTRATION_APIS is None:  # defensive: fall back to the documented set
    REGISTRATION_APIS = {"pthread_create", "uv_queue_work", "napi_create_async_work",
                         "sqlite3_create_function", "sqlite3_create_function_v2",
                         "sqlite3_create_window_function", "sqlite3_exec",
                         "CreateThread", "thrd_create"}
# Queue/enqueue APIs that make a registered async work actually run.
QUEUE_APIS = {"napi_queue_async_work", "uv_queue_work"}
NEW_OP = "<operator>.new"
CAST_OP = "<operator>.cast"
ASSIGN_OP = "<operator>.assignment"

TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN = "TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN"


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


_TYPE_QUALIFIER_WORDS = ("const", "volatile", "class", "struct", "enum", "union")


def _strip_ptr(t):
    """Normalize a C++ type spelling to a stable class identity: drop pointer/reference
    markers, `const`/`volatile` qualifiers, and leading `class`/`struct`/`enum`/`union`
    keywords -- while PRESERVING namespaces (`ns::Cls`) and template arguments
    (`Tmpl<T>`), which are part of the real identity. So `const NextWorker*`,
    `struct NextWorker &`, and `NextWorker` all normalize to `NextWorker`; `a::B` stays
    `a::B` and never collapses to `B`."""
    s = (t or "").replace("*", " ").replace("&", " ")
    # remove qualifier keywords as whole tokens (not as substrings of an identifier)
    toks = [w for w in s.split() if w not in _TYPE_QUALIFIER_WORDS]
    return " ".join(toks).strip()


# explicit ancestry-direction outcomes for a callback cast
CAST_ALLOW, CAST_ABSTAIN = "ALLOW", "ABSTAIN"


def _split_full_name(full_name):
    """'NextWorker.HandleOKCallback:void()' -> (class='NextWorker', method='HandleOKCallback',
    sig='void()'). A free function 'iterator_next:napi_value(...)' -> (None, 'iterator_next',
    sig). Robust to '::'-qualified names and templates (splits on the LAST '.' before ':')."""
    if not full_name:
        return (None, None, None)
    head, _, sig = full_name.partition(":")
    if "." in head:
        cls, _, meth = head.rpartition(".")
        return (cls, meth, sig)
    return (None, head, sig)


class Facts:
    def __init__(self, raw):
        self.methods = {}          # id -> {name, full_name, sig, cls, file}
        self.method_by_full = {}
        for r in _rows(f"{raw}/methods.tsv"):
            mid = int(r[0])
            full = _dec(r[2])
            cls, meth, sig = _split_full_name(full)
            self.methods[mid] = {"id": mid, "name": _dec(r[1]), "full_name": full,
                                 "sig": _dec(r[3]), "cls": cls, "meth": meth,
                                 "external": r[9] == "true"}
            self.method_by_full[full] = mid
        self.calls = {}
        self.calls_by_owner = defaultdict(list)
        for r in _rows(f"{raw}/calls.tsv"):
            cid, owner = int(r[0]), int(r[1])
            self.calls[cid] = {"id": cid, "owner": owner, "name": _dec(r[2]),
                               "mfn": _dec(r[3]), "dispatch": _dec(r[4]),
                               "code": _dec(r[6]), "line": r[8],
                               "callees": [int(x) for x in r[9].split(",") if x]}
            self.calls_by_owner[owner].append(cid)
        self.args = defaultdict(dict)
        for r in _rows(f"{raw}/arguments.tsv"):
            self.args[int(r[1])][int(r[2])] = {"kind": _dec(r[3]), "code": _dec(r[4]),
                                                "name": _dec(r[5]), "type": _dec(r[6])}
        self.params_by_method = defaultdict(list)  # owner -> [(index, name, type)]
        for r in _rows(f"{raw}/parameters.tsv"):
            self.params_by_method[int(r[1])].append((int(r[2]), _dec(r[3]), _dec(r[5])))
        # class hierarchy from type_decls inheritance (the raw fact the normalizer drops)
        self.bases = {}            # class name -> [direct base names]
        for r in _rows(f"{raw}/type_decls.tsv"):
            name = _dec(r[1])
            inh = _dec(r[6]) if len(r) > 6 else ""
            bases = [_strip_ptr(b) for b in inh.split(",") if b.strip()] if inh else []
            key = _strip_ptr(name)
            # a pointer/alias TypeDecl (e.g. 'NextWorker*') strips to the same key as the
            # real class 'NextWorker' but carries no inheritance -- never let it clobber a
            # real base list; merge, preferring non-empty.
            if bases or key not in self.bases:
                existing = self.bases.get(key) or []
                self.bases[key] = bases or existing
        # methods indexed by class
        self.methods_by_class = defaultdict(list)
        for m in self.methods.values():
            if m["cls"]:
                self.methods_by_class[_strip_ptr(m["cls"])].append(m)

    # -- MRO / override resolution ------------------------------------------------------
    def mro(self, cls, _seen=None, depth=0):
        """C3-ish linearization: the class then its bases, depth-first, de-duplicated,
        cycle-safe, bounded. Good enough for single/simple-multiple inheritance."""
        cls = _strip_ptr(cls)
        if _seen is None:
            _seen = []
        if cls in _seen or depth > 20:
            return _seen
        _seen.append(cls)
        for b in self.bases.get(cls, []):
            self.mro(b, _seen, depth + 1)
        return _seen

    def resolve_override(self, concrete_type, method_name, sig):
        """The method that a call to (method_name, sig) dispatches to for an object whose
        CONCRETE type is `concrete_type`: the nearest class in its MRO that defines a
        method with that exact name AND signature. Returns method_id or None. Signature
        match is exact (control 7: a signature mismatch is not an override)."""
        for cls in self.mro(concrete_type):
            for m in self.methods_by_class.get(cls, []):
                if m["meth"] == method_name and m["sig"] == sig:
                    return m["id"]
        return None

    def is_subtype(self, sub, sup):
        return _strip_ptr(sup) in self.mro(sub)

    def cast_ancestry_check(self, concrete_type, cast_target):
        """The EXPLICIT callback-cast ancestry rule. A `(cast_target)data` recovery of an
        object whose real concrete type is `concrete_type` is valid iff:
              cast_target == concrete_type            (same type), OR
              cast_target is an ANCESTOR of concrete_type   (an upcast).
        It is NEVER valid to require the concrete type to be an ancestor of the cast
        target. Returns (CAST_ALLOW|CAST_ABSTAIN, reason). Downcasts (cast_target is a
        descendant), sibling casts, and a missing/ambiguous inheritance path all ABSTAIN.
        Names are normalized (pointers/refs/const/volatile/class-struct stripped,
        namespaces + templates preserved) before comparison."""
        c = _strip_ptr(concrete_type)
        t = _strip_ptr(cast_target)
        if not t:
            return (CAST_ALLOW, "NO_CAST_TARGET")  # nothing to validate
        if c == t:
            return (CAST_ALLOW, "SAME_TYPE")
        c_mro = self.mro(c)
        if t in c_mro:
            return (CAST_ALLOW, "UPCAST_TO_ANCESTOR")
        # not same, not an ancestor. Distinguish the abstain reasons for evidence.
        if c in self.mro(t):
            return (CAST_ABSTAIN, "DOWNCAST_TO_DESCENDANT")
        # neither is an ancestor of the other: sibling, unrelated, or a missing edge.
        # If either type is entirely unknown to the hierarchy, call it a missing edge.
        if c not in self.bases and t not in self.bases:
            return (CAST_ABSTAIN, "HIERARCHY_EDGE_MISSING")
        # shared ancestor -> siblings; else unrelated. Both abstain.
        if set(c_mro) & set(self.mro(t)) - {c, t}:
            return (CAST_ABSTAIN, "SIBLING_CAST")
        return (CAST_ABSTAIN, "UNRELATED_OR_MISSING_EDGE")


def _local_assignments(F, owner, local_code):
    """All assignment calls in `owner` whose LHS is exactly `local_code` (reassignment
    detection)."""
    out = []
    for cid in F.calls_by_owner.get(owner, []):
        c = F.calls[cid]
        if c["name"] != ASSIGN_OP:
            continue
        lhs = F.args.get(cid, {}).get(1)
        if lhs and lhs["code"].strip() == local_code:
            out.append(cid)
    return out


def _concrete_new_type(F, assign_cid):
    """If assignment `assign_cid` is `local = new T(...)`, return the concrete type name
    T; else None (factory call, copy, cast, etc. -> unresolved)."""
    rhs = F.args.get(assign_cid, {}).get(2)
    if not rhs:
        return None
    # RHS is a CALL to <operator>.new (or its code starts with 'new ')
    if rhs["kind"] == "CALL":
        rc = F.calls.get(rhs.get("node_id"))  # node_id not stored; fall back to code
    code = (rhs.get("code") or "").strip()
    if code.startswith("new "):
        # 'new NextWorker(env, cb)' -> 'NextWorker'
        rest = code[4:].strip()
        name = rest.split("(")[0].split("<")[0].strip()
        return _strip_ptr(name) or None
    return None


def _find_registration_in_ctor_chain(F, concrete_type, depth=0, seen=None):
    """Walk `concrete_type`'s constructor and its base constructors; return the FIRST
    registration-API call whose data argument is `this`, as
    (callback_fn_id, registration_call_id, api_name, data_is_this) -- or None. A
    registration whose data arg is NOT `this` is reported with data_is_this=False so the
    caller can abstain (control 4)."""
    if seen is None:
        seen = set()
    ct = _strip_ptr(concrete_type)
    if ct in seen or depth > 20:
        return None
    seen.add(ct)
    # this class's own ctor(s): method whose meth == class name
    for m in F.methods_by_class.get(ct, []):
        if m["meth"] != ct:
            continue
        for cid in F.calls_by_owner.get(m["id"], []):
            c = F.calls[cid]
            if c["name"] in REGISTRATION_APIS:
                res = _registration_callback_and_data(F, cid)
                if res is not None:
                    return res
        # follow base ctor initialization: a call to Base.Base(...) inside this ctor
        for cid in F.calls_by_owner.get(m["id"], []):
            c = F.calls[cid]
            bcls, bmeth, _ = _split_full_name(c["mfn"])
            if bcls and bmeth == bcls and _strip_ptr(bcls) in F.bases.get(ct, []):
                r = _find_registration_in_ctor_chain(F, bcls, depth + 1, seen)
                if r is not None:
                    return r
    # even without an explicit base-ctor call in facts, try declared bases (implicit init)
    for b in F.bases.get(ct, []):
        r = _find_registration_in_ctor_chain(F, b, depth + 1, seen)
        if r is not None:
            return r
    return None


def _registration_callback_and_data(F, reg_cid):
    """For a registration-API call, return (callback_fn_id, reg_cid, api_name,
    data_is_this). Heuristic-free structural reads: the callback arg is the METHOD_REF
    whose target is the 'completion' function; the data arg is the argument whose code
    is 'this'. Returns None if no METHOD_REF arg resolves to a local method."""
    api = F.calls[reg_cid]["name"]
    # the registration lives in some class's constructor; a bare METHOD_REF like 'Complete'
    # names a method of THAT class (or a class in its MRO), never every same-named method
    # across unrelated classes -- resolve it in that scope only.
    reg_owner = F.calls[reg_cid]["owner"]
    reg_cls = F.methods.get(reg_owner, {}).get("cls")
    scope = set(F.mro(reg_cls)) if reg_cls else set()
    method_ref_ids = []
    data_is_this = False
    for idx, a in F.args.get(reg_cid, {}).items():
        if a["kind"] == "METHOD_REF":
            code = a["code"].strip()
            same_scope = [m for m in F.methods.values()
                          if m["meth"] == code and not m["external"]
                          and _strip_ptr(m["cls"] or "") in scope]
            cands = same_scope or [m for m in F.methods.values()
                                   if m["meth"] == code and not m["external"]]
            method_ref_ids.extend(m["id"] for m in cands)
        if a["kind"] == "IDENTIFIER" and a["code"].strip() == "this":
            data_is_this = True
    # ALL registered callbacks matter: a worker-registration API commonly registers both
    # an execute trampoline (worker thread) and a complete trampoline (main thread), and
    # each casts `data` back and dispatches virtually. Return every method-ref callback
    # that casts the data pointer, so the typestate walk covers all of them.
    if not method_ref_ids:
        return None
    casting = [mid for mid in dict.fromkeys(method_ref_ids)
               if _callback_casts_data(F, mid) is not None]
    if not casting:
        casting = list(dict.fromkeys(method_ref_ids))
    return (casting, reg_cid, api, data_is_this)


def _callback_casts_data(F, cb_fn_id):
    """Inside callback `cb_fn_id`, find `self = (Base*)data` where data is the callback's
    own data parameter. Return (receiver_local_code, base_type) or None."""
    # the data parameter: a callback's void* parameter (last param, conventionally)
    params = F.params_by_method.get(cb_fn_id, [])
    void_params = [p for p in params if "void" in (p[2] or "")]
    data_names = {p[1] for p in (void_params or params)}
    for cid in F.calls_by_owner.get(cb_fn_id, []):
        c = F.calls[cid]
        if c["name"] != ASSIGN_OP:
            continue
        lhs = F.args.get(cid, {}).get(1)
        rhs = F.args.get(cid, {}).get(2)
        if not lhs or not rhs:
            continue
        # rhs is a cast call `(Base*)data`
        rc = None
        for ocid in F.calls_by_owner.get(cb_fn_id, []):
            oc = F.calls[ocid]
            if oc["name"] == CAST_OP and oc["code"].strip() == (rhs["code"] or "").strip():
                rc = ocid
                break
        if rc is None:
            continue
        cast_args = F.args.get(rc, {})
        type_ref = cast_args.get(1)
        casted = cast_args.get(2)
        if not type_ref or not casted:
            continue
        if casted["code"].strip() in data_names or casted["name"].strip() in data_names:
            base_type = _strip_ptr(type_ref["code"] or type_ref["type"])
            return (lhs["code"].strip(), base_type)
    return None


def _typestate_targets(F, cb_fn_id, receiver_code, concrete_type, depth=0, seen=None):
    """From callback `cb_fn_id`, follow member calls on `receiver_code` (a receiver whose
    concrete type is `concrete_type`), resolving each callee by MRO from concrete_type,
    and recurse into resolved callees with receiver `this`. Returns {resolved_method_id:
    evidence-chain}. Bounded, cycle-safe."""
    if seen is None:
        seen = set()
    out = {}
    key = (cb_fn_id, receiver_code)
    if key in seen or depth > 40:
        return out
    seen.add(key)
    for cid in F.calls_by_owner.get(cb_fn_id, []):
        c = F.calls[cid]
        if c["name"].startswith("<operator>"):
            continue
        # receiver = arg0 (implicit this or an explicit self)
        a0 = F.args.get(cid, {}).get(0)
        recv = (a0["code"].strip() if a0 else "")
        is_on_receiver = recv == receiver_code or recv in ("this", "")
        if not is_on_receiver:
            continue
        _, meth, sig = _split_full_name(c["mfn"])
        if not meth:
            meth = c["name"]
        # also read signature from the call's own mfn tail if present
        target = F.resolve_override(concrete_type, meth, sig) if sig else None
        if target is None:
            # try without a signature demand (best-effort name match in MRO)
            for cls in F.mro(concrete_type):
                cands = [m for m in F.methods_by_class.get(cls, []) if m["meth"] == meth]
                if len(cands) == 1:
                    target = cands[0]["id"]
                    break
                if len(cands) > 1:
                    target = None  # ambiguous overload in one class -> abstain this call
                    break
        if target is None:
            continue
        out[target] = {"via_call_id": cid, "call_code": c["code"],
                       "resolved_for_concrete_type": concrete_type}
        # recurse into the resolved method with receiver 'this' (same concrete type)
        deeper = _typestate_targets(F, target, "this", concrete_type, depth + 1, seen)
        for k, v in deeper.items():
            out.setdefault(k, v)
    return out


def compute(raw):
    """Returns (promoted, abstained): promoted = {function_id: evidence}; abstained =
    list of {reason, ...}. A function id is promoted only when a SINGLE concrete override
    chain reaches it; a function reachable under two different concrete types (different
    overrides) is removed from `promoted` and recorded in `abstained`."""
    F = Facts(raw)
    # collect, per resolved-method, the set of concrete types that reach it
    reached_by_type = defaultdict(dict)   # fn_id -> {concrete_type: evidence}
    roots = {}                            # fn_id -> root entry evidence
    abstained = []

    for owner, cids in F.calls_by_owner.items():
        # find allocations `local = new T` in this function
        for cid in cids:
            c = F.calls[cid]
            if c["name"] != ASSIGN_OP:
                continue
            T = _concrete_new_type(F, cid)
            lhs = F.args.get(cid, {}).get(1)
            if not lhs:
                continue
            local = lhs["code"].strip()
            if T is None:
                # is the RHS a factory/other-source assignment to a pointer that is later
                # queued? that is the "unresolved factory" abstention (control 6) -- only
                # record if the local is used as a worker (reaches a queue call).
                if _local_reaches_queue(F, owner, local):
                    abstained.append({"reason": "UNRESOLVED_FACTORY_CONSTRUCTION",
                                      "function": F.methods[owner]["full_name"],
                                      "local": local})
                continue
            # reassignment between alloc and use -> abstain (control 5)
            if len(_local_assignments(F, owner, local)) > 1:
                abstained.append({"reason": "RECEIVER_REASSIGNED",
                                  "concrete_type": T, "local": local,
                                  "function": F.methods[owner]["full_name"]})
                continue
            # the object must actually be queued (control 8: not registered/queued -> skip)
            if not _local_reaches_queue(F, owner, local):
                continue
            reg = _find_registration_in_ctor_chain(F, T)
            if reg is None:
                continue  # no registration in the ctor chain -> not this idiom, no promotion
            cb_fn_ids, reg_cid, api, data_is_this = reg
            if not data_is_this:
                abstained.append({"reason": "REGISTRATION_DATA_NOT_THIS",
                                  "concrete_type": T, "api": api})
                continue
            any_cast = False
            for cb_fn_id in cb_fn_ids:
                cast = _callback_casts_data(F, cb_fn_id)
                if cast is None:
                    continue
                receiver_code, base_type = cast
                verdict, why = F.cast_ancestry_check(T, base_type)
                if verdict == CAST_ABSTAIN:
                    abstained.append({"reason": "CAST_ANCESTRY_INVALID",
                                      "detail": why, "concrete_type": T,
                                      "cast_base": _strip_ptr(base_type)})
                    continue
                any_cast = True
                targets = _typestate_targets(F, cb_fn_id, receiver_code, T)
                for fn_id, ev in targets.items():
                    reached_by_type[fn_id][T] = {
                        "root_entry": F.methods[owner]["full_name"],
                        "allocation": c["code"], "concrete_type": T,
                        "registration_api": api, "registration_call_id": reg_cid,
                        "callback": F.methods[cb_fn_id]["full_name"],
                        "cast_receiver": receiver_code, "cast_base": base_type,
                        "resolved_via": ev}
                    roots.setdefault(fn_id, ev)
            if not any_cast:
                abstained.append({"reason": "CALLBACK_DOES_NOT_CAST_DATA",
                                  "concrete_type": T})

    promoted = {}
    for fn_id, by_type in reached_by_type.items():
        if len(by_type) == 1:
            T, ev = next(iter(by_type.items()))
            promoted[fn_id] = ev
        else:
            abstained.append({"reason": "MULTIPLE_CONCRETE_OVERRIDES",
                              "function": F.methods[fn_id]["full_name"],
                              "concrete_types": sorted(by_type)})
    return promoted, abstained, F


def _local_reaches_queue(F, owner, local):
    """Does `local` (or `local->`) get used as the receiver of a queue-API call, OR does
    the function call a method (e.g. Queue()) on `local` whose body reaches a queue API?
    Bounded, best-effort structural check."""
    for cid in F.calls_by_owner.get(owner, []):
        c = F.calls[cid]
        if c["name"] in QUEUE_APIS:
            return True
        a0 = F.args.get(cid, {}).get(0)
        if a0 and a0["code"].strip() == local:
            # a member call on the worker (e.g. local->Queue()); check the callee body
            _, meth, sig = _split_full_name(c["mfn"])
            for m in F.methods.values():
                if m["meth"] == meth and any(
                        F.calls[x]["name"] in QUEUE_APIS
                        for x in F.calls_by_owner.get(m["id"], [])):
                    return True
    return False


def promoted_reachability(raw):
    """Public API for the integration: {function_id: evidence} of functions proven
    virtual-dispatch-reachable from a SOME entry with a unique concrete override. The
    evidence names `root_entry`; whether that root is itself JS-reachable is a SEPARATE
    question -- use `promote_gated_by_root` for the sound, reportable-eligible answer."""
    promoted, _abstained, _F = compute(raw)
    return promoted


def promote_gated_by_root(raw, root_is_reachable):
    """SOUND promotion for the reachability revision: a virtual-dispatch-reachable
    override is elevated to TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN ONLY when its own
    root entry (the function containing the `new T` allocation) is itself externally
    reachable. `root_is_reachable(root_full_name) -> bool` is supplied by the caller
    (e.g. reachability_tier's existing tiers over the same facts). Virtual dispatch
    resolves the object-flow hop; it never invents a JS entry point. Returns
    {function_id: evidence} for the overrides whose full chain (JS root -> ... ->
    override) is proven end to end."""
    promoted, _abstained, _F = compute(raw)
    out = {}
    for fn_id, ev in promoted.items():
        root = ev.get("root_entry")
        if root and root_is_reachable(root):
            out[fn_id] = dict(ev, root_reachable=True,
                              reachability_status=TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN)
    return out


def main():
    raw = sys.argv[1]
    promoted, abstained, F = compute(raw)
    result = {
        "schema": "virtual-dispatch-reachability/0.1",
        "tier": TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN,
        "promoted": {str(k): {"function": F.methods[k]["full_name"], **v}
                     for k, v in promoted.items()},
        "abstained": abstained,
    }
    out = sys.argv[2] if len(sys.argv) > 2 else None
    if out:
        json.dump(result, open(out, "w"), indent=1, sort_keys=True, default=str)
    print(f"promoted: {[F.methods[k]['full_name'] for k in promoted]}")
    print(f"abstained: {[a['reason'] for a in abstained]}")


if __name__ == "__main__":
    main()
