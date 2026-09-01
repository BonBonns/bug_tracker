#!/usr/bin/env python3
"""NAPI-STATUS-R01: raw N-API return-code / output-initialization handling.

A SOFTWARE-RELIABILITY classification, not a vulnerability detector: for each supported
fallible N-API creation call, this capability determines -- from real Joern-derived graph
facts only (the same cpp_raw/*.tsv every other capability consumes; no source-text
substring matching anywhere) -- whether execution can reach a use of the call's OUTPUT
parameters without first establishing that the call's `napi_status` result was
`napi_ok`. Every verdict is an API-HANDLING classification with evidence node ids; none
of them is an impact, exploitability, severity, or vulnerability claim, and the analyzer
never characterizes what an uninitialized output would do at runtime.

Supported calls (this revision -- registration table is load-bearing, verified by the
c09 negative control):
  napi_create_buffer(env, length, void** data, napi_value* result)   -- outs at args 3,4
  napi_create_buffer_copy(env, length, data, void** result_data,
                          napi_value* result)                        -- outs at args 4,5
`napi_create_external_buffer` is DELIBERATELY unregistered: its memory-ownership and
lifetime semantics differ (caller-owned external data, finalizer contract), so its
handling shapes are not this property's shapes. Excluded by registration, not by luck.

STRUCTURAL IDENTITIES (never text):
  - call identity: calls.tsv name + STATIC_DISPATCH + exact registered arity. A call
    carrying a supported name with any other shape ABSTAINS
    (ABSTAIN_CALL_IDENTITY_UNRESOLVED) -- see the p07 wrong-arity control.
  - status identity: the creation call NODE ID's one structural consumer --
      * RHS of `<operator>.assignment`  -> status variable = LHS identifier's refsTo
        referent (identifiers.tsv col 7; never matched by name text),
      * direct operand of a comparison  -> condition-direct mode,
      * direct child of a return        -> STATUS_PROPAGATED_BEFORE_USE,
      * argument of another call        -> wrapper logic (below),
      * appears nowhere                 -> STATUS_DISCARDED (provably unchecked -- the
        node id is absent from every consumer fact family, checkable because
        arguments.tsv/returns.tsv are complete over the CPG).
  - output identity: registered out-argument ROLE positions; each must be
    `<operator>.addressOf`(identifier-with-referent) or a plain identifier-with-referent
    (a forwarded pointer). Anything else (e.g. `&slots[i]`) ABSTAINS
    (ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED) -- see the c08 control.
  - output use: any identifiers.tsv node whose refsTo referent is an output referent,
    outside the creation call's own argument subtree, reached by the CFG walk below.

SUCCESS-GUARD PROOF (edge-keyed, value-sensitive):
  A related check is `<operator>.equals`/`<operator>.notEquals` between the status
  identity and the `napi_ok` enum constant (an identifier bound by c2cpg to a synthetic
  same-named local; also accepted: literal `0`, napi_ok's registered N-API value), or a
  2-successor truthiness branch directly on the status identifier. Polarity comes from
  the OPERATOR's own semantics (notEquals: true=failure; equals: true=success; truthy:
  true=failure), flipped per `<operator>.logicalNot` wrapper, and lifted through
  compound conditions only where implication is sound: through `logicalAnd` only for
  success-on-true (AND true implies every operand true), through `logicalOr` only for
  success-on-false (OR false implies every operand false). Any other compound shape
  ABSTAINS (ABSTAIN_BRANCH_POLARITY_UNRESOLVED) -- see the p05 control. The branch
  node's FIRST cfg successor is its TRUE target: a pinned-exporter convention this
  repository's resource_guard_verdict_r04.resolve_branch_targets already relies on,
  re-verified against real frozen v4.0.608 facts by check_napi_status.py's p01 polarity
  probes on every gate run.

  The walk is a state BFS from the creation call over (node, status_value_intact,
  success_proven): crossing a redefinition of the status variable clears
  status_value_intact (a later check of the recycled variable proves nothing for THIS
  call -- and equally, a check consumed before redefinition stays proven); crossing a
  resolved check's success edge while intact sets success_proven; paths stop at
  returns and at registered terminating calls. An output use reached with
  success_proven=False is the finding shape; a use reached only with
  success_proven=True is proven-guarded.

WRAPPERS (the only interprocedural step, both directions proven from the wrapper's own
body in the SAME fact base, else abstain):
  - identity-propagating filter (c10): single parameter, never reassigned, every
    return returns that parameter's identifier -> a check of `filter(status)` is a
    check of `status`.
  - terminating-on-failure guard (p03): single parameter, never reassigned, a single
    related check on it whose failure branch reaches a registered terminating call
    (abort/exit/_exit/quick_exit/napi_fatal_error) on every path before the method
    exit, whose success branch does not terminate, and which every entry path crosses
    -> a call `guard(status)` is a success barrier.
  - anything else consuming the status (external body, unproven local body, an
    unexpanded function-like macro) -> ABSTAIN_WRAPPER_UNRESOLVED rather than either
    flagging or clearing -- see the c11 control.

INPUT-SIZE ORIGIN (diagnostic ONLY): the length argument's structural origin (literal /
parameter / assignment-traced) is recorded on every finding for review convenience. It
carries NO claim about intent, influence, or impact, and plays NO part in any verdict.

Verdicts/abstentions per creation site:
  STATUS_GUARD_ESTABLISHED, STATUS_PROPAGATED_BEFORE_USE, NO_OUTPUT_USE,
  STATUS_GUARD_MISSING (the finding shape; sub_reason diagnoses NO_RELATED_CHECK /
  STATUS_DISCARDED / RELATED_CHECK_AFTER_USE / NON_TERMINATING_OR_BYPASSED_FAILURE_PATH
  / UNRELATED_CHECK_ONLY), ABSTAIN_CALL_IDENTITY_UNRESOLVED,
  ABSTAIN_STATUS_IDENTITY_UNRESOLVED, ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED,
  ABSTAIN_WRAPPER_UNRESOLVED, ABSTAIN_BRANCH_POLARITY_UNRESOLVED.

Standalone output (schema napi-status-verdict/0.1): {schema, classification, findings}
-- the same conventions as the other property scanners. Deliberately NOT wired into
six_property_aggregator.py (its six-property contract stays frozen); provenance/
reachability/adjudication modules are untouched and their interfaces preserved by
addition only.

Usage: napi_status_verdict.py RAW_DIR OUT.json
"""
import base64
import json
import sys
from collections import defaultdict

SUPPORTED_CREATION_CALLS = {
    # arity / size_arg / out_args are the REAL node_api.h argument roles (1-based, as
    # c2cpg emits C call arguments).
    "napi_create_buffer":      {"arity": 4, "size_arg": 2, "out_args": (3, 4),
                                "out_roles": ("data", "result")},
    "napi_create_buffer_copy": {"arity": 5, "size_arg": 2, "out_args": (4, 5),
                                "out_roles": ("result_data", "result")},
}
# napi_create_external_buffer: DELIBERATELY absent (different ownership/lifetime
# semantics) -- see module docstring and the c09 negative control.

TERMINATING_CALLS = {"abort", "exit", "_exit", "quick_exit", "napi_fatal_error"}
CMP_OPS = {"<operator>.equals", "<operator>.notEquals"}
ASSIGN_PREFIX = "<operator>.assignment"
NAPI_OK_LITERAL = "0"  # napi_ok's registered N-API ABI value (node_api_types.h)

SUCCESS_ON_TRUE, SUCCESS_ON_FALSE = "success_on_true", "success_on_false"


def dec(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def rows(path, n):
    out = []
    for ln in open(path):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) != n:
            raise ValueError(f"{path}: expected {n} cols, got {len(xs)}: {ln!r}")
        out.append(xs)
    return out


class Facts:
    """Loaded graph facts, indexed the way this capability queries them."""

    def __init__(self, raw):
        self.methods = {}          # id -> {name, file, external}
        for r in rows(f"{raw}/methods.tsv", 10):
            self.methods[int(r[0])] = {"name": dec(r[1]), "file": dec(r[4]),
                                        "external": r[9] == "true"}
        self.calls = {}
        self.calls_by_method = defaultdict(list)
        for r in rows(f"{raw}/calls.tsv", 11):
            cid, owner = int(r[0]), int(r[1])
            self.calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2]),
                               "dispatch": dec(r[4]), "code": dec(r[6]),
                               "file": dec(r[7]), "line": r[8],
                               "callees": [int(x) for x in r[9].split(",") if x]}
            self.calls_by_method[owner].append(cid)
        self.args = defaultdict(dict)      # call_id -> {index: arg}
        self.arg_parent = {}               # arg node id -> (call_id, index)
        for r in rows(f"{raw}/arguments.tsv", 8):
            call_id, idx = int(r[1]), int(r[2])
            a = {"nid": int(r[0]), "kind": dec(r[3]), "code": dec(r[4]),
                 "name": dec(r[5]), "type": dec(r[6])}
            self.args[call_id][idx] = a
            self.arg_parent[a["nid"]] = (call_id, idx)
        self.ident = {}                    # identifier node id -> {owner, name, refs, line}
        self.idents_by_ref = defaultdict(set)   # (owner, referent) -> {identifier ids}
        for r in rows(f"{raw}/identifiers.tsv", 7):
            nid, owner = int(r[0]), int(r[1])
            refs = [int(x) for x in r[6].split(",") if x]
            self.ident[nid] = {"owner": owner, "name": dec(r[2]), "line": r[5],
                               "refs": refs}
            for ref in refs:
                self.idents_by_ref[(owner, ref)].add(nid)
        self.returns_by_method = defaultdict(dict)   # owner -> {ret id: [child ids]}
        for r in rows(f"{raw}/returns.tsv", 5):
            self.returns_by_method[int(r[1])][int(r[0])] = \
                [int(x) for x in r[4].split(",") if x]
        self.method_exit = {}              # method id -> METHOD_RETURN node id
        for r in rows(f"{raw}/method_returns.tsv", 5):
            self.method_exit[int(r[1])] = int(r[0])
        self.params_by_method = defaultdict(list)    # owner -> [(param id, index, name)]
        for r in rows(f"{raw}/parameters.tsv", 7):
            self.params_by_method[int(r[1])].append((int(r[0]), int(r[2]), dec(r[3])))
        self.locals_by_id = {}             # local id -> name (for evidence text only)
        for r in rows(f"{raw}/locals.tsv", 6):
            self.locals_by_id[int(r[0])] = dec(r[2])
        self.cfg_next = defaultdict(list)
        for r in rows(f"{raw}/cfg_edges.tsv", 3):
            self.cfg_next[(int(r[0]), int(r[1]))].append(int(r[2]))

    # -- small structural helpers ---------------------------------------------------
    def sole_referent(self, ident_nid):
        info = self.ident.get(ident_nid)
        if not info or len(info["refs"]) != 1:
            return None
        return info["refs"][0]

    def referent_name(self, owner, referent):
        if referent in self.locals_by_id:
            return self.locals_by_id[referent]
        for pid, _, pname in self.params_by_method.get(owner, ()):
            if pid == referent:
                return pname
        return None

    def is_napi_ok_operand(self, arg):
        """The enum constant side of a comparison: c2cpg binds `napi_ok` to a synthetic
        same-named local (verified against real frozen v4.0.608 facts); a literal 0 is
        also accepted as napi_ok's registered N-API ABI value."""
        if arg["kind"] == "IDENTIFIER" and arg["name"] == "napi_ok":
            return True
        if arg["kind"] == "LITERAL" and arg["code"].strip() == NAPI_OK_LITERAL:
            return True
        return False

    def arg_subtree_identifier_nids(self, call_id, depth=6):
        """All identifier node ids inside a call's own argument subtree (these are the
        call's operands, not later uses)."""
        out, frontier = set(), [call_id]
        for _ in range(depth):
            nxt = []
            for c in frontier:
                for a in self.args.get(c, {}).values():
                    if a["kind"] == "IDENTIFIER":
                        out.add(a["nid"])
                    elif a["kind"] == "CALL":
                        nxt.append(a["nid"])
            frontier = nxt
            if not frontier:
                break
        return out

    def assignment_writes(self, owner, referent):
        """Ids of assignment calls whose LHS identifier refers to `referent` --
        redefinitions of that variable (any `<operator>.assignment*` form)."""
        out = set()
        for cid in self.calls_by_method.get(owner, ()):
            c = self.calls[cid]
            if not c["name"].startswith(ASSIGN_PREFIX):
                continue
            lhs = self.args.get(cid, {}).get(1)
            if lhs and lhs["kind"] == "IDENTIFIER" and \
                    self.sole_referent(lhs["nid"]) == referent:
                out.add(cid)
        return out

    def local_method_body(self, call):
        """The called method's id, iff exactly one callee with a body in this fact
        base; None otherwise (external stub, no callee, or ambiguous)."""
        bodies = [m for m in call["callees"]
                  if m in self.methods and not self.methods[m]["external"]
                  and any(k[0] == m for k in self.cfg_next)]
        if len(bodies) == 1:
            return bodies[0]
        return None


# -- polarity / clearance ---------------------------------------------------------------
def resolve_check_clearance(F, owner, check_nid, base_polarity, depth=8):
    """Lifts a related check through logicalNot/logicalAnd/logicalOr wrappers (only
    where the implication is sound -- see module docstring) to its real branch node,
    and returns (clearance_edge or None, reason). The branch node's FIRST cfg
    successor is its TRUE target (pinned-exporter convention, gate-verified)."""
    node, pol = check_nid, base_polarity
    for _ in range(depth):
        parent = F.arg_parent.get(node)
        if not parent:
            break
        pcall = F.calls.get(parent[0])
        if not pcall:
            break
        pname = pcall["name"]
        if pname == "<operator>.logicalNot":
            pol = SUCCESS_ON_FALSE if pol == SUCCESS_ON_TRUE else SUCCESS_ON_TRUE
            node = pcall["id"]
        elif pname == "<operator>.logicalAnd":
            if pol != SUCCESS_ON_TRUE:
                return None, "COMPOUND_OR_AND_SHAPE_UNPROVABLE"
            node = pcall["id"]
        elif pname == "<operator>.logicalOr":
            if pol != SUCCESS_ON_FALSE:
                return None, "COMPOUND_OR_AND_SHAPE_UNPROVABLE"
            node = pcall["id"]
        else:
            break  # consumed by a non-logical parent (assignment, call arg, return)
    succs = F.cfg_next.get((owner, node), [])
    if len(succs) != 2:
        return None, "BRANCH_SHAPE_UNRESOLVED"
    target = succs[0] if pol == SUCCESS_ON_TRUE else succs[1]
    return (node, target), None


# -- wrapper proofs (from the wrapper's OWN body in the same fact base) -----------------
def prove_identity_filter(F, mid):
    """True iff method `mid` provably returns its single parameter unmodified on every
    path: one parameter, never reassigned, >=1 return, every return returns exactly
    that parameter's identifier."""
    params = F.params_by_method.get(mid, [])
    if len(params) != 1:
        return False
    pref = params[0][0]
    if F.assignment_writes(mid, pref):
        return False
    rets = F.returns_by_method.get(mid, {})
    if not rets:
        return False
    for _, children in rets.items():
        if len(children) != 1 or F.sole_referent(children[0]) != pref:
            return False
    return True


def prove_terminating_guard(F, mid):
    """True iff method `mid` provably reaches a registered terminating call on every
    path where its single napi_status parameter is a failure value: exactly one,
    uncompounded related check on the (never-reassigned) parameter; every entry path
    crosses that check before any exit; every failure-branch path dead-ends in a
    terminating call (never a return, never a non-terminating dead end).

    EXIT ENCODING (verified against the real frozen v4.0.608 facts, and re-verified by
    check_napi_status.py's structural probes on every gate run): this exporter's CFG
    emits NO edges into METHOD_RETURN anywhere -- return nodes and noreturn calls are
    terminal (no successors), and a condition whose false path falls through directly
    to a void method's end carries only its TRUE successor (the fall-through edge is
    omitted). So: a condition with 2 successors is [true, false]; with 1 successor,
    that successor is the TRUE target and the invisible fall-through is the normal
    exit -- which means a failure branch on the invisible side is unprovable and the
    proof fails closed."""
    params = F.params_by_method.get(mid, [])
    if len(params) != 1:
        return False
    pref = params[0][0]
    if F.assignment_writes(mid, pref):
        return False
    checks = []
    for cid in F.calls_by_method.get(mid, ()):
        c = F.calls[cid]
        if c["name"] not in CMP_OPS:
            continue
        a = F.args.get(cid, {})
        a1, a2 = a.get(1), a.get(2)
        if not a1 or not a2:
            continue
        sides = [(a1, a2), (a2, a1)]
        for status_side, const_side in sides:
            if status_side["kind"] == "IDENTIFIER" and \
                    F.sole_referent(status_side["nid"]) == pref and \
                    F.is_napi_ok_operand(const_side):
                pol = SUCCESS_ON_FALSE if c["name"] == "<operator>.notEquals" \
                    else SUCCESS_ON_TRUE
                checks.append((cid, pol))
                break
    if len(checks) != 1:
        return False
    check_nid, pol = checks[0]
    if F.arg_parent.get(check_nid) is not None:
        return False  # compound/consumed condition inside a guard body: fail closed
    succs = F.cfg_next.get((mid, check_nid), [])
    if len(succs) == 2:
        true_t, false_t = succs[0], succs[1]
    elif len(succs) == 1:
        true_t, false_t = succs[0], None  # fall-through edge omitted (see docstring)
    else:
        return False
    failure_target = true_t if pol == SUCCESS_ON_FALSE else false_t
    if failure_target is None:
        return False  # failure path is the invisible fall-through: unprovable
    term_nodes = {cid for cid in F.calls_by_method.get(mid, ())
                  if F.calls[cid]["name"] in TERMINATING_CALLS}
    rets = set(F.returns_by_method.get(mid, {}))

    def all_failure_paths_terminate(start):
        seen, frontier = set(), [start]
        for _ in range(200):
            nxt = []
            for n in frontier:
                if n in seen:
                    continue
                seen.add(n)
                if n in term_nodes:
                    continue  # this path provably terminates -- do not expand past
                if n in rets:
                    return False  # a failure path reaches a normal return
                succ = F.cfg_next.get((mid, n), [])
                if not succ:
                    return False  # non-terminating dead end == normal method exit
                nxt.extend(succ)
            frontier = nxt
            if not frontier:
                return True
        return False

    if not all_failure_paths_terminate(failure_target):
        return False
    # Every entry path must cross the check before any return or dead end (no bypass).
    indeg = defaultdict(int)
    nodes = set()
    for (m, frm), tos in F.cfg_next.items():
        if m != mid:
            continue
        nodes.add(frm)
        for t in tos:
            nodes.add(t)
            indeg[t] += 1
    entries = [n for n in nodes if indeg[n] == 0]
    if not entries:
        return False
    seen, frontier = set(), list(entries)
    for _ in range(200):
        nxt = []
        for n in frontier:
            if n in seen:
                continue
            seen.add(n)
            if n == check_nid:
                continue  # crossed the check -- fine beyond here
            if n in rets or not F.cfg_next.get((mid, n), []):
                return False  # exited without ever reaching the check
            nxt.extend(F.cfg_next.get((mid, n), []))
        frontier = nxt
        if not frontier:
            return True
    return False


# -- input-size origin (diagnostic only; no verdict depends on it) ----------------------
def input_size_origin(F, owner, size_arg, depth=4):
    if size_arg is None:
        return {"kind": "unresolved"}
    if size_arg["kind"] == "LITERAL":
        return {"kind": "literal", "code": size_arg["code"]}
    if size_arg["kind"] == "IDENTIFIER":
        ref = F.sole_referent(size_arg["nid"])
        if ref is None:
            return {"kind": "unresolved", "code": size_arg["code"]}
        param_ids = {p[0] for p in F.params_by_method.get(owner, ())}
        if ref in param_ids:
            return {"kind": "parameter", "code": size_arg["code"]}
        # a local: trace its assignments a few hops for the diagnostic label only
        seen = set()
        frontier = [ref]
        for _ in range(depth):
            nxt = []
            for r0 in frontier:
                if r0 in seen:
                    continue
                seen.add(r0)
                for wcid in F.assignment_writes(owner, r0):
                    rhs = F.args.get(wcid, {}).get(2)
                    if not rhs:
                        continue
                    if rhs["kind"] == "LITERAL":
                        return {"kind": "local_from_literal", "code": size_arg["code"]}
                    if rhs["kind"] == "CALL":
                        return {"kind": "local_from_call_result",
                                "code": size_arg["code"]}
                    if rhs["kind"] == "IDENTIFIER":
                        rref = F.sole_referent(rhs["nid"])
                        if rref in param_ids:
                            return {"kind": "local_from_parameter",
                                    "code": size_arg["code"]}
                        if rref is not None:
                            nxt.append(rref)
            frontier = nxt
            if not frontier:
                break
        return {"kind": "local_unresolved", "code": size_arg["code"]}
    return {"kind": "unresolved", "code": size_arg.get("code", "")}


# -- per-site analysis ------------------------------------------------------------------
def analyze_site(F, owner, cid, spec, wrapper_cache):
    c = F.calls[cid]
    site = {"method_id": owner, "method_name": F.methods.get(owner, {}).get("name"),
            "file": c["file"], "line": c["line"],
            "creation_call_id": cid, "creation_call_name": c["name"]}

    # --- call identity ---
    call_args = F.args.get(cid, {})
    if c["dispatch"] != "STATIC_DISPATCH" or \
            sorted(call_args) != list(range(1, spec["arity"] + 1)):
        return dict(site, verdict="ABSTAIN_CALL_IDENTITY_UNRESOLVED",
                    reason="ARITY_OR_DISPATCH_MISMATCH",
                    observed_arg_indices=sorted(call_args))

    site["input_size_origin"] = input_size_origin(F, owner,
                                                  call_args.get(spec["size_arg"]))

    # --- output identity (argument ROLE positions) ---
    out_refs, out_desc = set(), []
    for role, idx in zip(spec["out_roles"], spec["out_args"]):
        a = call_args.get(idx)
        ref = None
        if a["kind"] == "CALL":
            inner_call = F.calls.get(a["nid"])
            if inner_call and inner_call["name"] == "<operator>.addressOf":
                inner = F.args.get(a["nid"], {}).get(1)
                if inner and inner["kind"] == "IDENTIFIER":
                    ref = F.sole_referent(inner["nid"])
        elif a["kind"] == "IDENTIFIER":
            ref = F.sole_referent(a["nid"])
        if ref is None:
            return dict(site, verdict="ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED",
                        reason="OUT_ARG_NOT_A_RESOLVABLE_VARIABLE",
                        unresolved_role=role, unresolved_arg_code=a["code"])
        out_refs.add(ref)
        out_desc.append({"role": role, "arg_index": idx,
                          "variable": F.referent_name(owner, ref), "referent_id": ref})
    site["output_targets"] = out_desc

    # --- output uses (referent identity, outside the call's own argument subtree) ---
    excluded = F.arg_subtree_identifier_nids(cid)
    use_nids = set()
    for ref in out_refs:
        use_nids |= {n for n in F.idents_by_ref.get((owner, ref), ())
                     if n not in excluded}

    # --- status identity: the creation call node's structural consumer ---
    status_mode = None
    status_ref = None
    binding_assignment = None
    direct_checks = []          # (check node id, polarity) in condition-direct mode
    consumer = F.arg_parent.get(cid)
    ret_children = {ch for chs in F.returns_by_method.get(owner, {}).values()
                    for ch in chs}
    if consumer:
        pcall = F.calls.get(consumer[0])
        pname = pcall["name"] if pcall else ""
        if pname.startswith(ASSIGN_PREFIX) and consumer[1] == 2:
            lhs = F.args.get(consumer[0], {}).get(1)
            if lhs and lhs["kind"] == "IDENTIFIER":
                status_ref = F.sole_referent(lhs["nid"])
            if status_ref is None:
                return dict(site, verdict="ABSTAIN_STATUS_IDENTITY_UNRESOLVED",
                            reason="ASSIGNMENT_LHS_NOT_A_RESOLVABLE_VARIABLE")
            status_mode = "variable"
            binding_assignment = consumer[0]
        elif pname in CMP_OPS:
            other = [a for i, a in F.args.get(consumer[0], {}).items()
                     if a["nid"] != cid]
            if len(other) == 1 and F.is_napi_ok_operand(other[0]):
                pol = SUCCESS_ON_FALSE if pname == "<operator>.notEquals" \
                    else SUCCESS_ON_TRUE
                direct_checks.append((consumer[0], pol))
                status_mode = "condition_direct"
            else:
                return dict(site, verdict="ABSTAIN_STATUS_IDENTITY_UNRESOLVED",
                            reason="COMPARISON_NOT_AGAINST_NAPI_OK")
        elif pname.startswith("<operator>."):
            return dict(site, verdict="ABSTAIN_STATUS_IDENTITY_UNRESOLVED",
                        reason=f"STATUS_CONSUMED_BY_UNMODELED_OPERATOR:{pname}")
        elif pcall:
            # the status value flows into another function before any check
            body = F.local_method_body(pcall)
            if body is not None and wrapper_cache.identity(body):
                # filter(napi_create_buffer(...)) -- comparison on the filter's result
                fcons = F.arg_parent.get(consumer[0])
                fcall = F.calls.get(fcons[0]) if fcons else None
                if fcall and fcall["name"] in CMP_OPS:
                    other = [a for i, a in F.args.get(fcons[0], {}).items()
                             if a["nid"] != consumer[0]]
                    if len(other) == 1 and F.is_napi_ok_operand(other[0]):
                        pol = SUCCESS_ON_FALSE if fcall["name"] == "<operator>.notEquals" \
                            else SUCCESS_ON_TRUE
                        direct_checks.append((fcons[0], pol))
                        status_mode = "condition_direct"
            if status_mode is None:
                return dict(site, verdict="ABSTAIN_WRAPPER_UNRESOLVED",
                            reason="STATUS_CONSUMED_BY_UNPROVEN_CALLEE",
                            consumer_call=pcall["name"] if pcall else None)
    elif cid in ret_children:
        return dict(site, verdict="STATUS_PROPAGATED_BEFORE_USE",
                    reason="CREATION_CALL_RETURNED_DIRECTLY")
    else:
        status_mode = "discarded"

    # --- related checks + clearance edges + hazards -------------------------------
    clearance = {}              # branch node -> success target
    clearance_sources = []      # check node ids (evidence)
    polarity_unresolved = False
    wrapper_unresolved = False
    redefinitions = set()
    barrier_calls = set()
    unrelated_checks_present = False
    related_check_nids = []

    if status_mode == "variable":
        redefinitions = F.assignment_writes(owner, status_ref) - {binding_assignment}
        for nid in F.idents_by_ref.get((owner, status_ref), ()):
            parent = F.arg_parent.get(nid)
            if not parent:
                continue
            pcall = F.calls.get(parent[0])
            if not pcall:
                continue
            pname = pcall["name"]
            if pname in CMP_OPS:
                other = [a for i, a in F.args.get(parent[0], {}).items()
                         if a["nid"] != nid]
                if len(other) == 1 and F.is_napi_ok_operand(other[0]):
                    pol = SUCCESS_ON_FALSE if pname == "<operator>.notEquals" \
                        else SUCCESS_ON_TRUE
                    related_check_nids.append(parent[0])
                    edge, why = resolve_check_clearance(F, owner, parent[0], pol)
                    if edge:
                        clearance[edge[0]] = edge[1]
                        clearance_sources.append(parent[0])
                    else:
                        polarity_unresolved = True
                else:
                    unrelated_checks_present = True
            elif pname.startswith(ASSIGN_PREFIX):
                continue  # LHS (redefinition, handled above) or RHS reads -- neither checks
            elif pname.startswith("<operator>."):
                continue  # unmodeled operator over status: proves nothing, clears nothing
            else:
                body = F.local_method_body(pcall)
                if body is not None and wrapper_cache.identity(body):
                    fcons = F.arg_parent.get(parent[0])
                    fcall = F.calls.get(fcons[0]) if fcons else None
                    if fcall and fcall["name"] in CMP_OPS:
                        other = [a for i, a in F.args.get(fcons[0], {}).items()
                                 if a["nid"] != parent[0]]
                        if len(other) == 1 and F.is_napi_ok_operand(other[0]):
                            pol = SUCCESS_ON_FALSE \
                                if fcall["name"] == "<operator>.notEquals" \
                                else SUCCESS_ON_TRUE
                            related_check_nids.append(fcons[0])
                            edge, why = resolve_check_clearance(F, owner, fcons[0], pol)
                            if edge:
                                clearance[edge[0]] = edge[1]
                                clearance_sources.append(fcons[0])
                            else:
                                polarity_unresolved = True
                            continue
                    wrapper_unresolved = True
                elif body is not None and wrapper_cache.terminating(body):
                    barrier_calls.add(parent[0])
                    clearance_sources.append(parent[0])
                else:
                    wrapper_unresolved = True
        # truthiness branch directly on the status identifier (napi_ok == 0)
        for nid in F.idents_by_ref.get((owner, status_ref), ()):
            if len(F.cfg_next.get((owner, nid), [])) == 2 and \
                    F.arg_parent.get(nid) is None:
                related_check_nids.append(nid)
                edge, why = resolve_check_clearance(F, owner, nid, SUCCESS_ON_FALSE)
                if edge:
                    clearance[edge[0]] = edge[1]
                    clearance_sources.append(nid)
                else:
                    polarity_unresolved = True
    elif status_mode == "condition_direct":
        for check_nid, pol in direct_checks:
            related_check_nids.append(check_nid)
            edge, why = resolve_check_clearance(F, owner, check_nid, pol)
            if edge:
                clearance[edge[0]] = edge[1]
                clearance_sources.append(check_nid)
            else:
                polarity_unresolved = True

    # --- the value-sensitive state walk -------------------------------------------
    term_nodes = {x for x in F.calls_by_method.get(owner, ())
                  if F.calls[x]["name"] in TERMINATING_CALLS}
    rets = set(F.returns_by_method.get(owner, {}))
    exit_node = F.method_exit.get(owner)
    unguarded_use = None
    visited = set()
    frontier = [(cid, True, False)]
    steps, budget = 0, 4000
    exhausted = False
    while frontier:
        steps += 1
        if steps > budget:
            exhausted = True
            break
        node, intact, proven = frontier.pop()
        key = (node, intact, proven)
        if key in visited:
            continue
        visited.add(key)
        if node != cid:
            if node in use_nids and not proven:
                unguarded_use = node
                break
            if node in redefinitions:
                intact = False
            if node in barrier_calls and intact:
                proven = True
            if node in rets or node == exit_node or node in term_nodes:
                continue
        for nxt in F.cfg_next.get((owner, node), []):
            now_proven = proven or (intact and clearance.get(node) == nxt)
            frontier.append((nxt, intact, now_proven))

    if exhausted:
        return dict(site, verdict="ABSTAIN_BRANCH_POLARITY_UNRESOLVED",
                    reason="STATE_WALK_BUDGET_EXHAUSTED")

    status_returned = False
    if status_mode == "variable":
        for chs in F.returns_by_method.get(owner, {}).values():
            if any(F.sole_referent(ch) == status_ref for ch in chs):
                status_returned = True

    if unguarded_use is not None:
        # abstain-first downgrades: an unresolved element that COULD have guarded this
        # use forbids both flagging and clearing.
        if wrapper_unresolved:
            return dict(site, verdict="ABSTAIN_WRAPPER_UNRESOLVED",
                        reason="STATUS_CONSUMED_BY_UNPROVEN_CALLEE_BEFORE_USE")
        if polarity_unresolved:
            return dict(site, verdict="ABSTAIN_BRANCH_POLARITY_UNRESOLVED",
                        reason="RELATED_CHECK_PRESENT_BUT_POLARITY_UNPROVEN")
        if not unrelated_checks_present:
            # diagnostic only: does the method compare ANY OTHER value against
            # napi_ok (a check that exists but cannot govern this call's status)?
            for ocid in F.calls_by_method.get(owner, ()):
                oc = F.calls[ocid]
                if oc["name"] not in CMP_OPS or ocid in related_check_nids:
                    continue
                a = F.args.get(ocid, {})
                a1, a2 = a.get(1), a.get(2)
                if not a1 or not a2:
                    continue
                for va, ca in ((a1, a2), (a2, a1)):
                    if F.is_napi_ok_operand(ca) and va["kind"] == "IDENTIFIER" and \
                            F.sole_referent(va["nid"]) not in (None, status_ref):
                        unrelated_checks_present = True
        if status_mode == "discarded":
            sub = "STATUS_DISCARDED"
        elif not related_check_nids:
            sub = "UNRELATED_CHECK_ONLY" if unrelated_checks_present \
                else "NO_RELATED_CHECK"
        else:
            # a related, resolved check exists but did not clear this use: diagnose
            # whether it sits after the use on some path (evidence only).
            check_after_use = False
            seen, ff = set(), [unguarded_use]
            for _ in range(400):
                nn = []
                for n in ff:
                    if n in seen:
                        continue
                    seen.add(n)
                    if n in related_check_nids:
                        check_after_use = True
                    nn.extend(F.cfg_next.get((owner, n), []))
                ff = nn
                if not ff:
                    break
            sub = "RELATED_CHECK_AFTER_USE" if check_after_use \
                else "NON_TERMINATING_OR_BYPASSED_FAILURE_PATH"
        use_info = F.ident.get(unguarded_use, {})
        return dict(site, verdict="STATUS_GUARD_MISSING", sub_reason=sub,
                    unguarded_use_node=unguarded_use,
                    unguarded_use_variable=use_info.get("name"),
                    unguarded_use_line=use_info.get("line"),
                    related_check_nodes=sorted(related_check_nids),
                    evidence_note=(
                        "API-handling classification only: an output of this fallible "
                        "call is CFG-reachable at the cited use without a proven "
                        "napi_ok result on every incoming path. No claim is made about "
                        "runtime impact, severity, or exploitability, and none should "
                        "be inferred from this record."))

    if use_nids:
        if not clearance_sources and not barrier_calls:
            # no use was reached unguarded, yet nothing proved success either --
            # only possible when every use sits before the call or on no path from
            # it; classify by whether the status leaves the function.
            if status_returned:
                return dict(site, verdict="STATUS_PROPAGATED_BEFORE_USE",
                            reason="STATUS_RETURNED_NO_REACHABLE_USE")
            return dict(site, verdict="NO_OUTPUT_USE",
                        reason="USES_EXIST_BUT_NONE_REACHABLE_FROM_CALL")
        return dict(site, verdict="STATUS_GUARD_ESTABLISHED",
                    guard_evidence_nodes=sorted(set(clearance_sources)))
    if status_returned:
        return dict(site, verdict="STATUS_PROPAGATED_BEFORE_USE",
                    reason="STATUS_RETURNED_OUTPUTS_UNUSED_LOCALLY")
    return dict(site, verdict="NO_OUTPUT_USE")


class WrapperCache:
    def __init__(self, facts):
        self.F = facts
        self._identity = {}
        self._terminating = {}

    def identity(self, mid):
        if mid not in self._identity:
            self._identity[mid] = prove_identity_filter(self.F, mid)
        return self._identity[mid]

    def terminating(self, mid):
        if mid not in self._terminating:
            self._terminating[mid] = prove_terminating_guard(self.F, mid)
        return self._terminating[mid]


def analyze(raw):
    F = Facts(raw)
    wrapper_cache = WrapperCache(F)
    classification = defaultdict(int)
    findings = []
    for owner, call_ids in sorted(F.calls_by_method.items()):
        for cid in sorted(call_ids):
            c = F.calls[cid]
            spec = SUPPORTED_CREATION_CALLS.get(c["name"])
            if spec is None:
                continue
            classification["SUPPORTED_CREATION_CALL_FOUND"] += 1
            rec = analyze_site(F, owner, cid, spec, wrapper_cache)
            classification[rec["verdict"]] += 1
            findings.append(rec)
    return {"schema": "napi-status-verdict/0.1",
            "supported_calls": sorted(SUPPORTED_CREATION_CALLS),
            "classification": dict(classification),
            "findings": findings}


def main():
    raw, outp = sys.argv[1], sys.argv[2]
    result = analyze(raw)
    json.dump(result, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {result['classification']}")
    print(f"records: {len(result['findings'])}")


if __name__ == "__main__":
    main()
