#!/usr/bin/env python3
"""RESOURCE-GUARD-R01: a general evidence model for ONE representation shape --
FALLIBLE_BOUNDED_RESOURCE -- distinct from every existing capability in this project
(destination-capacity-write's memcpy-family/fixed-array shapes; the lock-safety track's
missing-unlock-before-return). Discovered as a real, confirmed coverage gap while measuring
the write-property scanner against CVE-2020-1896 (Facebook Hermes, hermesBuiltinApply):
`ScopedNativeCallFrame` allocates `len` (an attacker-influenced JS-array length) register
slots on a bounded runtime stack; if that allocation would overflow, the constructor sets
an internal flag and returns WITHOUT a usable frame, and the vulnerable revision writes
into that frame anyway because it never calls the object's own `overflowed()` predicate.

FALLIBLE_BOUNDED_RESOURCE, as implemented here, requires ALL of:
  1. a curated contract (resource_contracts.py) identifies the constructed class's
     constructor AND its validity predicate, BOTH pinned to a real signature and a real
     citation -- never "any RAII object" and never "any isValid()/overflowed()-NAMED
     method" (a same-named method on an uncontracted class, or a contracted class's
     constructor at an unrecognized signature, is explicitly rejected, not silently
     accepted -- see RESOURCE-TYPE-MATCH-R01 and RESOURCE-CTOR-MATCH-R01 below);
  2. the constructor's size/count argument, at the contract's curated index, is NOT a
     literal constant (a proxy for "runtime-determined," this project's established bar
     for "possibly attacker-influenced" -- see oob_runtime_capacity_verdict's own
     "symbolic write length" treatment; a BEST-EFFORT, BOUNDED, same-method backward trace
     additionally attaches "traces to parameter `<name>` within N hops" as stronger,
     disclosed-as-such evidence when it succeeds, but its ABSENCE never downgrades a
     non-literal size to "not attacker-influenced" -- non-literal is the actual bar);
  3. a real USE of the (possibly-alias-referenced) object is CFG-reachable from the
     constructor;
  4. NO dominating, correctly-polarized, terminating guard call (the contract's own
     predicate method, on the SAME object or a one-hop reference alias of it) is crossed
     on EVERY path from the constructor to that use.

Verdicts are RESOURCE_GUARD_MISSING / RESOURCE_GUARD_ESTABLISHED / RESOURCE_SEMANTICS_
UNRESOLVED -- explicitly NOT a CWE-787 write verdict. A RESOURCE_GUARD_MISSING finding is
additionally checked for whether the identified unguarded use is itself the LHS of an
assignment (`downstream_write_evidence`); only THEN does the finding carry any write-
shaped implication at all, and even so it is never auto-labeled CWE-787 -- connecting an
invalid-resource USE to an actual out-of-bounds WRITE is a separate, disclosed piece of
evidence, not an assumption.

Why not "any RAII object with an isValid()-shaped method"? Two real, distinct classes of
false positive that would follow from that heuristic, both covered by synthetic controls
(gate_resource_guard.py): (a) a class whose constructor genuinely cannot fail (no size
parameter at all, e.g. a plain lock guard) -- calling its own unrelated bool-returning
method proves nothing about resource validity; (b) an UNCONTRACTED class that happens to
also define a method literally named `overflowed`/`isValid` -- matching by method name
alone, ignoring the RECEIVER's resolved type, would treat totally unrelated code as this
pattern. Both are why every predicate/constructor match below is gated on the receiver's
`type_full_name` matching the CONTRACT's `class_name` (see type_matches() -- a trailing
reference marker is stripped, never anything more), not on name alone.

Object identity, alias handling, and branch-polarity determination -- all worth reading
before touching this file:

  RESOURCE-OBJ-ID-R01 (object identity): the constructor CALL node's own `this`/temp
  argument (arguments.tsv index 0) is an internal `<tmp>N` address, not the real variable
  name -- Joern's C++ lowering of `T x{...};` puts the real LHS name on a SEPARATE
  `<operator>.assignment` call. Resolved by finding the assignment call on the SAME LINE,
  in the SAME method, whose own LHS (argument index 1) is an IDENTIFIER with
  type_full_name == contract class_name; if no same-line assignment matches, falls back
  to a substring match (constructor call's own `code` appearing inside the assignment's
  RHS argument code) -- same conservative "text idiom, not general" posture as
  lock_balance_verdict.py's guard_success_start. Neither match -> RESOURCE_SEMANTICS_
  UNRESOLVED, never a guess.

  RESOURCE-ALIAS-R01 (aliasing): ONE hop only -- a local `L` whose OWN same-method
  assignment's RHS is exactly the resolved object's identifier code, and whose declared
  type (locals.tsv) equals the contract class_name, is added to the object's alias set.
  Deeper indirection (through a call, a container, a second hop of aliasing) is not
  resolved -- a predicate or use reached only through such an alias is invisible to this
  capability (silently not analyzed, not silently guessed either way).

  RESOURCE-BRANCH-R01 (finding the real 2-way branch from a predicate call): verified
  empirically against real Joern v4.0.608 output for the ACTUAL CVE-2020-1896 fix commit
  (study/js_c_transition/raw_case_hermes_apply -- see also the sibling _patched fixture
  built for this capability) that `if (LLVM_UNLIKELY(newFrame.overflowed())) return ...;`
  does NOT give the predicate call a clean 2-successor branch directly: the macro wrapper
  call sits at the SAME control-flow position as a to-be-expected duplicate of the
  predicate call itself (both independently carry edges to the same 2 real targets) --
  resolve_branch_targets() below collapses BOTH the logical/macro wrapper idiom already
  proven in lock_balance_verdict.py's branch_point() AND this same-predicate-duplicate
  idiom as pass-through, converging on the real 2 targets from either entry point.

  RESOURCE-POLARITY-R01 (which target is "the guard's own failure block", without an
  explicit true/false CFG edge label -- cfg_edges.tsv carries none as a labeled field).
  An EARLIER version of this rule tried to infer this structurally ("the short, non-
  branching branch is the then-block") and was PROVEN WRONG by a real synthetic control
  (a short function where BOTH branches are short and linear -- see gate_resource_guard.py
  history): that signature cannot distinguish a single-armed `if (cond) return;` from a
  double-armed `if (cond) {...} else return;`, which have OPPOSITE true/false-to-branch
  mappings. Replaced with a DIRECTLY VERIFIED, order-based rule instead: for a 2-way
  branch node, resolve_branch_targets()'s target list preserves each successor's own
  FILE ORDER in cfg_edges.tsv (never re-sorted) -- and empirically, across 3 independent
  real Joern fact sets (this project's own c02_correct_check and c03_inverted_check
  synthetic controls, PLUS the real CVE-2020-1896 patched Hermes fixture -- see
  study/resource_guard/ and study/js_c_transition/raw_case_hermes_apply), the FIRST-
  listed successor is consistently the "then"/cond-true branch and the SECOND is the
  "else"-or-fallthrough/cond-false branch. Negation count (real `<operator>.logicalNot` /
  literal-boolean-comparison CALL nodes encountered as pass-through between the predicate
  call and the branch, NOT text regex) maps "cond-true target" back to "predicate says
  invalid" (contract polarity) or its opposite (inverted check). The candidate "invalid"
  target is THEN independently sanity-checked via resolves_without_touching_object -- if
  it does NOT actually reach a return before touching the object (a checked-but-doesn't-
  terminate guard, or a check whose failure branch itself uses the object), this predicate
  call contributes no clearance at all, rather than a false ESTABLISHED.

Usage: resource_guard_verdict.py RAW_DIR OUT.json
"""
import base64
import json
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from resource_contracts import CONTRACTS

LOGICAL_PASSTHROUGH = {"<operator>.logicalAnd", "<operator>.logicalOr", "LLVM_UNLIKELY",
                       "LLVM_LIKELY"}
NEGATING_PASSTHROUGH = {"<operator>.logicalNot"}
BOOL_LITERALS_FALSE = {"false", "0"}
BOOL_LITERALS_TRUE = {"true", "1"}


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


def _param_count(method_full_name_sig):
    """Depth-aware count of top-level comma-separated parameters inside a
    `Class.Method:ReturnType(...)`-shaped signature's outermost parens."""
    inner = method_full_name_sig[method_full_name_sig.index("(") + 1:method_full_name_sig.rindex(")")]
    if not inner.strip():
        return 0
    depth, count = 0, 1
    for ch in inner:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def type_matches(type_full_name, contract):
    """A declared/expression type matches the contract's class iff it equals class_name
    once a trailing reference marker is stripped -- a reference ALIAS's own declared type
    (and an expression using it as a call receiver) carries a literal '&' suffix
    (`ScopedNativeCallFrame&`), confirmed real via c07_alias_use; the constructed object's
    own (non-reference) declaration never has one, so stripping is a no-op there."""
    return (type_full_name or "").rstrip("&").strip() == contract["class_name"]


def match_contract_for_ctor_name(name):
    for c in CONTRACTS.values():
        if c["class_name"] == name:
            return c
    return None


def main():
    raw, outp = sys.argv[1], sys.argv[2]

    methods = {int(r[0]): dec(r[1]) for r in rows(f"{raw}/methods.tsv", 10)}

    calls = {}
    calls_by_method = defaultdict(list)
    for r in rows(f"{raw}/calls.tsv", 11):
        cid, owner = int(r[0]), int(r[1])
        calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2]), "mfn": dec(r[3]),
                      "code": dec(r[6]), "line": r[8]}
        calls_by_method[owner].append(cid)

    # arguments.tsv: [arg_node_id, call_id, index, label(AST kind), code, name, type_full_name, line]
    # `node_id` (column 0) equals the argument's OWN cpg node id -- for a CALL-kind
    # argument this IS that nested call's real id (verified against real facts: a bare
    # `f(g())`-shaped argument's node_id resolves directly via `calls[node_id]`), letting
    # backward_attacker_trace and the write-evidence check below walk to the exact nested
    # call rather than re-matching by code text.
    args_by_call = defaultdict(dict)  # call_id -> {index: {kind, code, name, type, node_id}}
    for r in rows(f"{raw}/arguments.tsv", 8):
        call_id, idx = int(r[1]), int(r[2])
        args_by_call[call_id][idx] = {"kind": dec(r[3]), "code": dec(r[4]),
                                       "name": dec(r[5]), "type": dec(r[6]),
                                       "node_id": int(r[0])}

    # RETURNS-R01 (pre-existing exporter quirk -- see lock_balance_verdict.py's own note):
    # build per-method sets, never a global id->owner map.
    returns_by_method = defaultdict(set)
    for r in rows(f"{raw}/returns.tsv", 5):
        rid, owner = int(r[0]), int(r[1])
        returns_by_method[owner].add(rid)

    locals_by_method = defaultdict(list)  # (name, type_full_name, id)
    for r in rows(f"{raw}/locals.tsv", 6):
        lid, owner = int(r[0]), int(r[1])
        locals_by_method[owner].append((dec(r[2]), dec(r[4]), lid))

    params_by_method = defaultdict(set)  # names of this method's own parameters
    for r in rows(f"{raw}/parameters.tsv", 7):
        owner = int(r[1])
        params_by_method[owner].add(dec(r[3]))

    cfg_next = defaultdict(list)
    for r in rows(f"{raw}/cfg_edges.tsv", 3):
        owner, frm, to = int(r[0]), int(r[1]), int(r[2])
        cfg_next[(owner, frm)].append(to)

    findings = []
    classification = defaultdict(int)

    def resolves_without_touching_object(method_id, start, obj_names, rets, depth=60):
        """Same contract as lock_balance_verdict.py's helper of the same name (DEPTH-R01
        applies here too): True iff every forward path from `start` reaches a return
        before any call whose receiver (argument index 0) code is in obj_names. False if
        some path touches the object first, or depth is exhausted (abstain, not guess)."""
        seen = set(); frontier = [start]
        for _ in range(depth):
            nxt = []
            for n in frontier:
                if n in seen:
                    continue
                seen.add(n)
                nc = calls.get(n)
                if nc and nc["owner"] == method_id:
                    a0 = args_by_call.get(n, {}).get(0)
                    if a0 and a0["code"].strip() in obj_names:
                        return False
                if n in rets:
                    continue
                nxt.extend(cfg_next.get((method_id, n), []))
            frontier = nxt
            if not frontier:
                return True
        return False

    def resolve_branch_targets(method_id, predicate_call_id, predicate_name, depth=12):
        """RESOURCE-BRANCH-R01: BFS forward from a predicate call, treating logical/macro
        wrapper calls (LOGICAL_PASSTHROUGH) AND further calls to the SAME predicate name
        (the real, empirically-confirmed LLVM_UNLIKELY(x)-duplication idiom) as pass-
        through rather than real branch targets. Returns (targets, negation_count, seen):
        targets is an ORDER-PRESERVING list (first-discovery order, following each node's
        own cfg_edges.tsv row order) of the >=0 real (non-pass-through) successor node
        ids -- RESOURCE-POLARITY-R01 (see module docstring) relies on this order to be
        [cond-true target, cond-false target], verified against 3 independent real Joern
        fact sets (both this project's own c02/c03 synthetic controls and the real
        CVE-2020-1896 patched fixture -- see study/resource_guard/ and
        study/js_c_transition/raw_case_hermes_apply). negation_count counts
        <operator>.logicalNot / literal-boolean-comparison pass-through nodes crossed;
        seen is every pass-through node id visited (including predicate_call_id itself)."""
        def is_wrapper_call(node_id):
            nc2 = calls.get(node_id)
            return bool(nc2) and (nc2["name"] in LOGICAL_PASSTHROUGH or nc2["name"] in NEGATING_PASSTHROUGH
                                   or nc2["name"] == predicate_name)

        seen = {predicate_call_id}
        frontier = [predicate_call_id]
        targets = []
        negations = 0
        for _ in range(depth):
            nxt = []
            for n in frontier:
                succs = cfg_next.get((method_id, n), [])
                nc = calls.get(n)
                is_pass = (n == predicate_call_id) or (
                    nc and (nc["name"] in LOGICAL_PASSTHROUGH or nc["name"] in NEGATING_PASSTHROUGH
                            or nc["name"] == predicate_name))
                if not nc and not is_pass:
                    # RESOURCE-BRANCH-R01 (bridge nodes): a plain, non-call CFG node
                    # (Joern's own internal plumbing between an outer macro-wrapper call
                    # and an inner duplicate predicate call -- empirically confirmed real,
                    # see study/js_c_transition/raw_case_hermes_apply's patched sibling
                    # fixture: node 68719476852 sits between LLVM_UNLIKELY and a SECOND,
                    # duplicate `overflowed()` call with no semantic content of its own)
                    # is pass-through too, PROVIDED every one of its own successors is
                    # itself a recognized wrapper/duplicate-predicate call. This is a
                    # 1-hop lookahead, not a blanket "any non-call node is pass-through"
                    # rule -- a REAL branch target (the guard's own failure/continue
                    # entry point) is ALSO a non-call node, but its successors are real
                    # statement content, not another copy of the same predicate call.
                    is_pass = bool(succs) and all(is_wrapper_call(s) for s in succs)
                is_negating = nc and nc["name"] in NEGATING_PASSTHROUGH
                is_bool_cmp_flip = False
                if nc and nc["name"] in ("<operator>.equals", "<operator>.notEquals"):
                    a = args_by_call.get(n, {})
                    other = [a[i]["code"].strip().lower() for i in a if i != 0 and i in a]
                    if any(o in BOOL_LITERALS_FALSE for o in other):
                        is_bool_cmp_flip = (nc["name"] == "<operator>.equals")
                        is_pass = True
                    elif any(o in BOOL_LITERALS_TRUE for o in other):
                        is_bool_cmp_flip = (nc["name"] == "<operator>.notEquals")
                        is_pass = True
                if is_negating or is_bool_cmp_flip:
                    negations += 1
                if is_pass:
                    for s in succs:
                        if s not in seen:
                            seen.add(s); nxt.append(s)
                else:
                    if n not in targets:
                        targets.append(n)
            frontier = nxt
            if not frontier:
                break
        # `seen` (every pass-through node actually belonging to THIS predicate call's own
        # condition chain) is returned too -- RESOURCE-DOMINANCE-R01 needs it to define
        # clearance as a specific EDGE out of this chain, not mere arrival at a node id
        # (see the "non-dominating branch check" note where the walk uses this).
        return targets, negations, seen

    def backward_attacker_trace(method_id, start_arg, depth=8):
        """Best-effort, BOUNDED, SAME-METHOD-ONLY evidence for element 1 of
        FALLIBLE_BOUNDED_RESOURCE ("attacker-controlled ... reaches the ... size
        request") -- explicitly NOT a full inter-procedural taint proof (that is out of
        scope for a single capability script; see THREAD_SAFETY_R01.md's own honestly-
        documented boundaries for the same posture elsewhere in this project). Two mutually
        recursive expansions, alternating as needed: an IDENTIFIER expands via its most
        recent same-method `<operator>.assignment` RHS; a CALL expands via ALL of ITS OWN
        arguments (each possibly itself an IDENTIFIER or a further nested CALL), walked
        via `node_id` (equals the nested call's real id for a plain CALL-kind argument --
        verified against real facts, see the module docstring). Covers the real Hermes
        chain end-to-end: len [IDENTIFIER] <- JSArray::getLength(*argArray) [CALL] <-
        *argArray [CALL, the indirection op] <- argArray [IDENTIFIER] <-
        args.dyncastArg<JSArray>(1) [CALL] <- args [IDENTIFIER, matches a parameter].
        Returns {"traced_to_parameter", "hops"} on success, or None. ABSENCE of a trace
        never downgrades the "size is non-literal" finding -- see module docstring."""
        seen_names, seen_calls = set(), set()
        if start_arg["kind"] == "CALL":
            frontier = [("call", start_arg["node_id"], 0)]
        else:
            frontier = [("name", start_arg["code"].strip(), 0)]
        while frontier:
            kind, val, hops = frontier.pop(0)
            if hops > depth:
                continue
            if kind == "name":
                if val in seen_names:
                    continue
                seen_names.add(val)
                if val in params_by_method.get(method_id, ()):
                    return {"traced_to_parameter": val, "hops": hops}
                for cid in calls_by_method.get(method_id, ()):
                    c = calls[cid]
                    if c["name"] != "<operator>.assignment":
                        continue
                    a = args_by_call.get(cid, {})
                    lhs, rhs = a.get(1), a.get(2)
                    if not lhs or not rhs or lhs["code"].strip() != val:
                        continue
                    if rhs["kind"] == "IDENTIFIER":
                        frontier.append(("name", rhs["code"].strip(), hops + 1))
                    elif rhs["kind"] == "CALL":
                        frontier.append(("call", rhs["node_id"], hops + 1))
            else:  # kind == "call": expand every one of ITS OWN arguments
                if val in seen_calls:
                    continue
                seen_calls.add(val)
                for oa in args_by_call.get(val, {}).values():
                    if oa["kind"] == "IDENTIFIER":
                        frontier.append(("name", oa["code"].strip(), hops + 1))
                    elif oa["kind"] == "CALL":
                        frontier.append(("call", oa["node_id"], hops + 1))
        return None

    for method_id, call_ids in calls_by_method.items():
        rets = returns_by_method.get(method_id, set())
        for cid in call_ids:
            c = calls[cid]
            contract = match_contract_for_ctor_name(c["name"])
            if contract is None:
                continue
            classification["CTOR_NAME_MATCH_CANDIDATE"] += 1
            curated_param_counts = {_param_count(p) for p in contract["ctor_method_full_name_prefixes"]}
            try:
                this_param_count = _param_count(c["mfn"])
            except ValueError:
                this_param_count = None
            if this_param_count not in curated_param_counts:
                classification["RESOURCE_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "RESOURCE_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "ctor_call_id": cid, "class_name": contract["class_name"],
                                  "reason": "CONSTRUCTOR_SIGNATURE_UNRECOGNIZED"})
                continue
            classification["CTOR_CALL_FOUND"] += 1

            # RESOURCE-OBJ-ID-R01: resolve the constructed object's identity.
            object_var = None
            ctor_line = c["line"]
            for oc in call_ids:
                ocinfo = calls[oc]
                if ocinfo["name"] != "<operator>.assignment":
                    continue
                a = args_by_call.get(oc, {})
                lhs = a.get(1)
                if not lhs or lhs["kind"] != "IDENTIFIER" or not type_matches(lhs["type"], contract):
                    continue
                if ocinfo["line"] == ctor_line:
                    object_var = lhs["code"].strip(); break
            if object_var is None:
                for oc in call_ids:
                    ocinfo = calls[oc]
                    if ocinfo["name"] != "<operator>.assignment":
                        continue
                    a = args_by_call.get(oc, {})
                    lhs, rhs = a.get(1), a.get(2)
                    if not lhs or lhs["kind"] != "IDENTIFIER" or not type_matches(lhs["type"], contract):
                        continue
                    ctor_code, rhs_code = c["code"].strip(), (rhs["code"] or "").strip()
                    if rhs and ctor_code and rhs_code and (
                            ctor_code in rhs_code or rhs_code in ctor_code):
                        object_var = lhs["code"].strip(); break
            if object_var is None:
                classification["RESOURCE_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "RESOURCE_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "ctor_call_id": cid, "class_name": contract["class_name"],
                                  "reason": "OBJECT_IDENTITY_UNRESOLVED"})
                continue

            # Element 2: is the size argument attacker-plausible (non-literal)?
            ctor_args = args_by_call.get(cid, {})
            size_arg = ctor_args.get(contract["size_arg_index"])
            if size_arg is None:
                classification["RESOURCE_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "RESOURCE_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "ctor_call_id": cid, "class_name": contract["class_name"],
                                  "object": object_var, "reason": "SIZE_ARG_INDEX_OUT_OF_RANGE"})
                continue
            if size_arg["kind"] == "LITERAL":
                classification["SIZE_ATTACKER_INDEPENDENT"] += 1
                continue  # element 1 fails outright -- not this pattern, not a finding

            attacker_trace = backward_attacker_trace(method_id, size_arg)

            # RESOURCE-ALIAS-R01: one-hop reference aliases of object_var.
            alias_names = {object_var}
            for oc in call_ids:
                ocinfo = calls[oc]
                if ocinfo["name"] != "<operator>.assignment":
                    continue
                a = args_by_call.get(oc, {})
                lhs, rhs = a.get(1), a.get(2)
                if not lhs or not rhs:
                    continue
                # A reference alias's OWN declared type carries a trailing '&'
                # (`ScopedNativeCallFrame&`, verified real -- c07_alias_use), which must
                # be stripped before comparing against the contract's bare class_name.
                if rhs["code"].strip() == object_var and type_matches(lhs["type"], contract):
                    alias_names.add(lhs["code"].strip())

            predicate_calls = []
            use_calls = []
            for oc in call_ids:
                ocinfo = calls[oc]
                a0 = args_by_call.get(oc, {}).get(0)
                if not a0 or a0["code"].strip() not in alias_names or not type_matches(a0["type"], contract):
                    continue
                if ocinfo["name"] == contract["predicate_method"]:
                    predicate_calls.append(oc)
                elif oc != cid:
                    use_calls.append(oc)

            if not use_calls:
                classification["RESOURCE_ACQUIRED_NO_USE"] += 1
                continue

            # Resolve clearance EDGES from each recognized predicate-guard shape.
            # RESOURCE-DOMINANCE-R01: clearance is a specific (from, to) EDGE -- the
            # transition out of THIS predicate call's own pass-through chain onto its
            # long/valid target -- never mere arrival at the long_t node id. Two branches
            # can structurally converge on the SAME node (e.g. a guard nested one level
            # inside an unrelated `if (cond) { <guard> }` -- the outer if's own skip-edge
            # lands on the exact node the inner guard's valid-edge also lands on): if
            # clearance were node-keyed, that unrelated skip-edge would be indistinguishable
            # from actually having passed the guard, silently turning a real
            # non-dominating-check bug into a false RESOURCE_GUARD_ESTABLISHED. Edge-keyed
            # clearance cannot be fooled this way, since the skip-edge's SOURCE (the
            # outer if's own comparison) is never part of the guard's own pass-through set.
            clearance_edges = set()
            for pc in predicate_calls:
                targets, negations, chain = resolve_branch_targets(
                    method_id, pc, contract["predicate_method"])
                if len(targets) != 2:
                    classification["PREDICATE_UNRECOGNIZED_BRANCH_SHAPE"] += 1
                    continue
                # RESOURCE-POLARITY-R01: targets[0] is the cond-true (written condition
                # true) target, targets[1] is cond-false -- order-preserved, empirically
                # verified (see module docstring), never re-sorted. The AST's own
                # then-block (`if (COND) <body>`) is ALWAYS cond_true_t; if negation
                # parity says that's NOT where "predicate invalid" lands, the source's
                # written then-block corresponds to predicate-VALID instead -- an
                # inverted check, contributing no clearance.
                cond_true_t, cond_false_t = targets[0], targets[1]
                written_true_means_invalid = (negations % 2 == 0) == contract["predicate_true_means_invalid"]
                if not written_true_means_invalid:
                    classification["PREDICATE_INVERTED_POLARITY"] += 1
                    continue
                invalid_t, valid_t = cond_true_t, cond_false_t
                if not resolves_without_touching_object(method_id, invalid_t, alias_names, rets):
                    classification["PREDICATE_FAILURE_BRANCH_DOES_NOT_TERMINATE"] += 1
                    continue  # the "invalid" branch doesn't actually avoid the object
                for u in chain:
                    if valid_t in cfg_next.get((method_id, u), []):
                        clearance_edges.add((u, valid_t))

            # Core dominance walk: does EVERY path from the constructor to EVERY use cross
            # a clearance EDGE first?
            visited = set()
            frontier = [(cid, False)]
            state = "RESOURCE_GUARD_ESTABLISHED"
            evidence_use = None
            depth_budget = 400
            steps = 0
            unresolved = False
            while frontier and steps < depth_budget:
                node, cleared = frontier.pop()
                steps += 1
                key = (node, cleared)
                if key in visited:
                    continue
                visited.add(key)
                if node in use_calls and not cleared:
                    state = "RESOURCE_GUARD_MISSING"
                    evidence_use = node
                    break
                if node in use_calls:
                    continue  # cleared path reaching a use: fine, don't expand further
                for nxt in cfg_next.get((method_id, node), []):
                    now_cleared = cleared or ((node, nxt) in clearance_edges)
                    frontier.append((nxt, now_cleared))
            else:
                if frontier:
                    unresolved = True

            if unresolved:
                classification["RESOURCE_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "RESOURCE_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "ctor_call_id": cid, "class_name": contract["class_name"],
                                  "object": object_var, "reason": "DOMINANCE_WALK_DEPTH_EXHAUSTED"})
                continue

            classification[state] += 1
            finding = {"verdict": state, "method_id": method_id,
                       "method_name": methods.get(method_id), "ctor_call_id": cid,
                       "class_name": contract["class_name"], "object": object_var,
                       "contract_citation": contract["citation"]}
            if attacker_trace:
                finding["attacker_influence_evidence"] = attacker_trace
            if state == "RESOURCE_GUARD_MISSING":
                finding["unguarded_use_call_id"] = evidence_use
                # Is the unguarded use itself the LHS of an assignment (a WRITE through
                # the resource, not merely a read)? `node_id` (see arguments.tsv parsing
                # above) equals the nested call's real id for a plain CALL-kind argument,
                # so this is an exact id match, not a text-fragility fallback.
                write_evidence = None
                for oc in call_ids:
                    if calls[oc]["name"] != "<operator>.assignment":
                        continue
                    lhs = args_by_call.get(oc, {}).get(1)
                    if lhs and lhs["kind"] == "CALL" and lhs["node_id"] == evidence_use:
                        write_evidence = "direct_assignment_through_resource"
                        break
                finding["downstream_write_evidence"] = write_evidence
                if write_evidence:
                    finding["cwe_hint"] = ("CWE-787-shaped (unverified capacity) -- a write "
                                            "was established through the unguarded resource; "
                                            "the destination's actual byte capacity is NOT "
                                            "independently verified here")
            findings.append(finding)

    json.dump({"schema": "resource-guard-verdict/0.1",
               "classification": dict(classification),
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {dict(classification)}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
