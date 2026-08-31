#!/usr/bin/env python3
"""RESOURCE-GUARD-R06: adds a real SOURCE-BOUNDARY GATE on top of R05 -- NOT a rewrite of
R04/R05's own matching/dominance/tracing/verdict-construction/applicability-gate/structural-
recovery logic, same reason every version in this lineage (R02 copied R01, R03 copied R02,
R04 copied R03, R05 copied R04) stays byte-for-byte frozen while the next evolves
independently. The ONLY new logic is the source-boundary gate in `backward_attacker_trace`
below.

Why R06 exists (see study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md for the
full, real account): manual verification of a real R05 finding on `node-libcurl@5.1.2`
(`Easy::ReadFunction`) found `backward_attacker_trace` treats reaching ANY parameter of the
call's own enclosing method as proof of "attacker influence" (`attacker_influence_evidence`
/`traced_to_parameter`) -- with NO check on whether that method is itself reachable from JS
at all. `Easy::ReadFunction` is a real libcurl-invoked native callback
(`curl_easy_setopt(ch, CURLOPT_READFUNCTION, Easy::ReadFunction)`), never called by JS; its
own `size`/`nmemb` parameters are supplied by libcurl internally. Reaching a C++ function
PARAMETER is not evidence of attacker/JS control on its own -- a real, corpus-wide analyzer
defect, confirmed on this one real site but not specific to it.

R06's one addition: `backward_attacker_trace` no longer reports a reached parameter as
established attacker influence unconditionally. It checks the REACHED parameter's own real
`type_full_name` (already present in the same `parameters.tsv` facts this file already
loads, just not previously consulted) against `JS_CALLBACK_ORIGIN_TYPES` -- the real,
canonical node-addon-api N-API entry-point parameter type, `Napi::CallbackInfo` (matched as
a substring, tolerant of `const `/`&`/namespace-qualification variance, e.g.
`"const Napi::CallbackInfo &"`). A value that traces back to a `Napi::CallbackInfo`-typed
parameter has REAL, structural, verified JS-linkage -- N-API's own only mechanism for
passing JS-caller-supplied data into native code is `info[i]` access on exactly this
parameter type, confirmed real on Cartesi's own genuine, previously-recovered findings
(the required positive development case for this fix). Any OTHER reached parameter (an
ordinary C++ parameter of an internal helper or a native-library-invoked callback, exactly
`Easy::ReadFunction`'s own real shape) is reported as `SOURCE_BOUNDARY_UNRESOLVED` --
explicitly, not silently dropped -- rather than claimed as attacker-controlled evidence.
node-libcurl's own real `ReadFunction` finding is the required rejection case for this fix:
its `size` parameter is NOT `Napi::CallbackInfo`-typed, so it now correctly reports
`SOURCE_BOUNDARY_UNRESOLVED` instead of implying attacker/JS control.

This gate corrects the EVIDENCE FIELD's own claimed meaning; it does not suppress or change
the underlying `VALUE_ACQUISITION_GUARD_MISSING` (etc.) verdict itself, which was never
actually gated on `attacker_trace` succeeding (confirmed by reading R04/R05's own verdict-
construction code: `attacker_trace` is attached to the finding as supplementary evidence,
never used as a precondition for reporting the finding at all) -- the contract's own failure
predicate (an unguarded acquisition result) is a real, separate, still-valid claim
regardless of whether attacker influence on the SIZE argument specifically is proven.
Establishing real JS-source-to-native-argument linkage beyond the CallbackInfo-parameter
case (e.g. via the separate cross-language linker, `link_napi_facts.py`) is explicitly out
of scope for this file -- R05/R06 operate on C++-only facts and have no JS facts loaded at
all; a real, disclosed, bounded scope, not an oversight.

The original R05 docstring, describing the structural-recovery mechanism this file also
still carries unchanged, follows below for the real, complete record:

RESOURCE-GUARD-R05: adds STRUCTURED-EVIDENCE RECOVERY on top of R04 -- NOT a rewrite of
R04's matching/dominance/tracing/verdict-construction/applicability-gate logic. Every line
below through the R04 matching/dominance block is copied, not imported, from
`resource_guard_verdict_r04.py` (same reason R04 copied rather than imported R03's, R03
copied rather than imported R02's, and R02 copied rather than imported R01's -- each version
stays byte-for-byte frozen while the next evolves independently). The ONLY new logic is the
"R05 STRUCTURAL RECOVERY" block below, reached only when R04's own qualifier-prefix check
would otherwise abstain.

Why R05 exists (see `resource_contracts_r05.py` and `study/resource_guard_r05/R05_DESIGN.md`
for the full account): the corpus-wide header-staging fix (HDR_FIX_STATUS.md) revealed that
c2cpg leaves EVERY real `Napi::Buffer::New`/`Napi::TypeError::New`/etc. call as
`<unresolvedNamespace>.<name>:<unresolvedSignature>(N)`, even with real node-addon-api
headers correctly staged -- a real, disclosed, unisolated c2cpg frontend limitation
(`study/resource_guard_r05/AB_FIXTURE_RESULT.md`), NOT a header-vendoring gap. R04's own
qualifier check (`mfn.startswith(qualifier_type + "." + acquisition_call + ":")`) can never
match this shape, so every real acquisition call is silently left as
`ACQUISITION_SIGNATURE_UNRECOGNIZED` -- correct, honest abstention, but leaving R04 unable to
exercise its own matching/dominance/tracing logic against ANY real `Napi::Buffer::New` site
found so far.

R05's one addition: when a call's `name` matches a `RECOVERY_CONTRACTS` entry's
`acquisition_call` AND its `methodFullName` is the SPECIFIC `<unresolvedNamespace>.../
<unresolvedSignature>(...)` shape (not some OTHER, resolved-but-non-matching qualifier, which
is correctly left to R04's own existing rejection), R05 gathers STRUCTURAL evidence that does
NOT depend on the call's own resolution: the enclosing assignment's LHS identifier's own
independently-resolved `typeFullName` (result-object identity + type), the real argument
count (not `_param_count(mfn)`, meaningless here), and argument-index-1's own resolved type
(the environment-handle role). Only when ALL of these gates pass does R05 synthesize a
single-site contract dict (shaped exactly like an R04 contract, `result_type` set to
whichever real form THIS site showed) and hand it, UNCHANGED, to R04's own existing
object-identity/alias-resolution/failure-predicate/dominance-walk/attacker-trace machinery --
reused as-is, because that machinery already operates generically over any
`result_type`-shaped dict, not reimplemented a second time.

Usage: resource_guard_verdict_r05.py RAW_DIR OUT.json [--real] [--build-config PATH]
  Identical CLI to resource_guard_verdict_r04.py. --real uses resource_contracts_r04's
  REAL_CONTRACTS (R04 path) union resource_contracts_r05's RECOVERY_CONTRACTS (R05 path);
  default uses SYNTHETIC_CONTRACTS for the R04 path (RECOVERY_CONTRACTS has no synthetic
  pool -- recovery is a REAL-node-addon-api-specific mechanism, not exercised in synthetic
  mode; passing without --real simply reduces this file to R04's own synthetic-mode
  behavior, recovery contributes nothing).
"""
import base64
import json
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from resource_contracts_r04 import SYNTHETIC_CONTRACTS, REAL_CONTRACTS
from resource_contracts_r05 import RECOVERY_CONTRACTS

LOGICAL_PASSTHROUGH = {"<operator>.logicalAnd", "<operator>.logicalOr", "LLVM_UNLIKELY",
                       "LLVM_LIKELY"}
NEGATING_PASSTHROUGH = {"<operator>.logicalNot"}
BOOL_LITERALS_FALSE = {"false", "0"}
BOOL_LITERALS_TRUE = {"true", "1"}

VALID_EXCEPTION_CONFIGURATIONS = {"disabled", "enabled", "unresolved", "conflict"}

# The one real, structurally-recognizable shape R05 recovers from -- confirmed real, not
# assumed, on two independent corpus packages plus the committed r05_controls fixture (see
# module docstring). A call resolving to any OTHER, concrete qualifier is NOT this shape and
# is correctly left to R04's own existing rejection, never routed through recovery.
UNRESOLVED_MFN_PREFIX = "<unresolvedNamespace>."
UNRESOLVED_SIG_MARKER = ":<unresolvedSignature>("

# RESOURCE-GUARD-R06: the real, canonical node-addon-api N-API entry-point parameter
# type. N-API's own ONLY mechanism for a native function to receive JS-caller-supplied
# data is `info[i]` access on a parameter of exactly this type (`const Napi::CallbackInfo
# &info` in real node-addon-api source, confirmed on Cartesi's own genuine findings and
# on every real N-API function signature read during this fix's own verification) --
# matched as a substring so real `const `/`&`/whitespace/namespace-qualification
# variance in how c2cpg's own `type_full_name` renders it never causes a false miss.
# A reached parameter whose OWN type does not contain this string is NOT proven
# JS-reachable -- see `backward_attacker_trace`'s own docstring/module docstring.
JS_CALLBACK_ORIGIN_TYPES = ("Napi::CallbackInfo", "Napi.CallbackInfo")


def _is_js_callback_origin_type(type_full_name):
    t = type_full_name or ""
    return any(marker in t for marker in JS_CALLBACK_ORIGIN_TYPES)


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
    `Class.Method:ReturnType(...)`-shaped signature's outermost parens. UNCHANGED from R04 --
    used only on the R04 (already-resolved) matching path below. NEVER used on the R05
    recovery path: for an unresolved signature (`<unresolvedSignature>(2)`), the trailing
    `(2)` is c2cpg's own raw ARGUMENT COUNT marker, not a parenthesized param list -- calling
    this helper on it would silently misparse "2" as a single param, undercounting real
    arity. R05 computes arity directly from `arguments.tsv` instead (see the recovery block)."""
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
    """UNCHANGED from R04 -- see that file's docstring. Used both for R04's own matching path
    and, after a recovered contract dict is synthesized with a single concrete `result_type`,
    for R05's reuse of R04's downstream object-identity/alias/use-detection logic."""
    return (type_full_name or "").rstrip("&").strip() == contract["result_type"]


def _contracts_for(use_real):
    return REAL_CONTRACTS if use_real else SYNTHETIC_CONTRACTS


def match_recovery_contract(call_name):
    """R05-only: looks up RECOVERY_CONTRACTS by acquisition_call name. Returns None if no
    recovery contract's acquisition_call matches -- the call is then not an R05 candidate at
    all (falls through to R04's own ACQUISITION_SIGNATURE_UNRECOGNIZED classification if it
    also failed R04's own match, exactly as it would without R05 present)."""
    for c in RECOVERY_CONTRACTS.values():
        if c["acquisition_call"] == call_name:
            return c
    return None


# --- R04 APPLICABILITY GATE -- UNCHANGED from resource_guard_verdict_r04.py. ------------------
def load_build_config(raw, explicit_path):
    path = pathlib.Path(explicit_path) if explicit_path else (pathlib.Path(raw) / "build_config.json")
    if not path.exists():
        return {"exception_configuration": "unresolved", "evidence": [],
                "citation": f"no build_config.json found at {path} -- treated as unresolved, "
                            "never defaulted to disabled"}
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        return {"exception_configuration": "unresolved", "evidence": [],
                "citation": f"build_config.json at {path} failed to parse ({e}) -- treated as "
                            "unresolved, never defaulted to disabled"}
    value = cfg.get("exception_configuration")
    if value not in VALID_EXCEPTION_CONFIGURATIONS:
        return {"exception_configuration": "unresolved",
                "evidence": cfg.get("evidence", []),
                "citation": cfg.get("citation",
                                     f"build_config.json's exception_configuration value "
                                     f"({value!r}) is not one of {sorted(VALID_EXCEPTION_CONFIGURATIONS)} "
                                     "-- treated as unresolved, never defaulted to disabled")}
    return {"exception_configuration": value,
            "evidence": cfg.get("evidence", []),
            "citation": cfg.get("citation", path.as_posix())}
# ---------------------------------------------------------------------------------------------


def main():
    raw, outp = sys.argv[1], sys.argv[2]
    use_real = "--real" in sys.argv[3:]
    build_config_path = None
    if "--build-config" in sys.argv[3:]:
        idx = sys.argv.index("--build-config")
        build_config_path = sys.argv[idx + 1]
    build_config = load_build_config(raw, build_config_path)
    contract_pool = _contracts_for(use_real)

    def match_contract(call_name):
        for c in contract_pool.values():
            if c["acquisition_call"] == call_name:
                return c
        return None

    methods = {int(r[0]): dec(r[1]) for r in rows(f"{raw}/methods.tsv", 10)}

    calls = {}
    calls_by_method = defaultdict(list)
    for r in rows(f"{raw}/calls.tsv", 11):
        cid, owner = int(r[0]), int(r[1])
        calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2]), "mfn": dec(r[3]),
                      "dispatch": dec(r[4]), "code": dec(r[6]), "line": r[8]}
        calls_by_method[owner].append(cid)

    # arguments.tsv: [arg_node_id, call_id, index, label(AST kind), code, name, type_full_name, line]
    args_by_call = defaultdict(dict)  # call_id -> {index: {kind, code, name, type, node_id}}
    for r in rows(f"{raw}/arguments.tsv", 8):
        call_id, idx = int(r[1]), int(r[2])
        args_by_call[call_id][idx] = {"kind": dec(r[3]), "code": dec(r[4]),
                                       "name": dec(r[5]), "type": dec(r[6]),
                                       "node_id": int(r[0])}

    returns_by_method = defaultdict(set)
    for r in rows(f"{raw}/returns.tsv", 5):
        rid, owner = int(r[0]), int(r[1])
        returns_by_method[owner].add(rid)

    params_by_method = defaultdict(set)
    # RESOURCE-GUARD-R06: real parameter TYPE, keyed the same way, alongside the
    # existing name-only index -- see module docstring for why this is needed
    # (`backward_attacker_trace`'s own source-boundary gate below).
    param_types_by_method = defaultdict(dict)
    for r in rows(f"{raw}/parameters.tsv", 7):
        owner = int(r[1])
        pname = dec(r[3])
        params_by_method[owner].add(pname)
        param_types_by_method[owner][pname] = dec(r[5])

    cfg_next = defaultdict(list)
    for r in rows(f"{raw}/cfg_edges.tsv", 3):
        owner, frm, to = int(r[0]), int(r[1]), int(r[2])
        cfg_next[(owner, frm)].append(to)

    findings = []
    classification = defaultdict(int)

    def resolves_without_touching_object(method_id, start, obj_names, rets, depth=60):
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
        return targets, negations, seen

    def backward_attacker_trace(method_id, start_arg, depth=8):
        """RESOURCE-GUARD-R06 -- see module docstring for the full real account. Walks
        backward from `start_arg` exactly as R04/R05 always did; the ONLY change is what
        happens when the walk reaches a real parameter of `method_id`. Reaching a
        parameter is no longer, by itself, reported as attacker influence: the
        parameter's own real `type_full_name` (`param_types_by_method`) is checked
        against `JS_CALLBACK_ORIGIN_TYPES` (node-addon-api's own real `Napi::
        CallbackInfo` N-API entry-point convention -- the only real mechanism by which
        JS-caller-supplied data enters native code at all). A `Napi::CallbackInfo`-typed
        parameter is real, structural, verified JS-linkage -- `attacker_controlled:
        True`. Any OTHER reached parameter (an ordinary C++ parameter of an internal
        helper, or of a native-library-invoked callback such as libcurl's own
        `ReadFunction(char*, size_t, size_t, void*)` -- none of these are `Napi::
        CallbackInfo`) is reported explicitly as `SOURCE_BOUNDARY_UNRESOLVED`,
        `attacker_controlled: False` -- never silently dropped, never claimed as
        attacker evidence."""
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
                    ptype = param_types_by_method.get(method_id, {}).get(val, "")
                    if _is_js_callback_origin_type(ptype):
                        return {"traced_to_parameter": val, "hops": hops,
                                "parameter_type": ptype,
                                "source_boundary": "JS_CALLBACK_INFO_PARAMETER",
                                "attacker_controlled": True}
                    return {"traced_to_parameter": val, "hops": hops,
                            "parameter_type": ptype or None,
                            "source_boundary": "SOURCE_BOUNDARY_UNRESOLVED",
                            "attacker_controlled": False}
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
            else:
                if val in seen_calls:
                    continue
                seen_calls.add(val)
                for oa in args_by_call.get(val, {}).values():
                    if oa["kind"] == "IDENTIFIER":
                        frontier.append(("name", oa["code"].strip(), hops + 1))
                    elif oa["kind"] == "CALL":
                        frontier.append(("call", oa["node_id"], hops + 1))
        return None

    def find_object_identity(method_id, call_ids, cid, c, contract):
        """UNCHANGED logic from R04's own inline object-identity resolution (same-line
        assignment first, then code-substring fallback), factored out ONLY so R05's recovery
        path can call it with a synthesized contract too -- no behavior change for the R04
        matching path, which calls it identically to how R04 itself resolves it inline."""
        object_var = None
        acq_line = c["line"]
        for oc in call_ids:
            ocinfo = calls[oc]
            if ocinfo["name"] != "<operator>.assignment":
                continue
            a = args_by_call.get(oc, {})
            lhs = a.get(1)
            if not lhs or lhs["kind"] != "IDENTIFIER" or not type_matches(lhs["type"], contract):
                continue
            if ocinfo["line"] == acq_line:
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
                acq_code, rhs_code = c["code"].strip(), (rhs["code"] or "").strip()
                if rhs and acq_code and rhs_code and (
                        acq_code in rhs_code or rhs_code in acq_code):
                    object_var = lhs["code"].strip(); break
        return object_var

    def evaluate_acquisition(method_id, call_ids, cid, c, contract, evidence_source):
        """UNCHANGED R04 logic (object identity -> size-arg check -> alias resolution ->
        predicate/use detection -> dominance walk -> applicability gate -> finding
        construction), factored out of the main loop ONLY so both the R04 matching path and
        the R05 recovery path can share it after each has independently produced a
        `contract`-shaped dict with a single concrete `result_type`. `evidence_source` is
        either "r04_direct" or "r05_structural_recovery" and is stamped onto every finding
        this call produces, so a reader can always tell the two apart -- never silently
        merged. Returns nothing; appends to the enclosing `findings`/`classification` directly
        (same closures R04 itself used inline)."""
        rets = returns_by_method.get(method_id, set())
        object_var = find_object_identity(method_id, call_ids, cid, c, contract)
        if object_var is None:
            classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
            findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                              "method_id": method_id, "method_name": methods.get(method_id),
                              "acquisition_call_id": cid, "result_type": contract["result_type"],
                              "reason": "OBJECT_IDENTITY_UNRESOLVED_OR_TEMPORARY",
                              "evidence_source": evidence_source})
            return

        acq_args = args_by_call.get(cid, {})
        size_arg = acq_args.get(contract["size_arg_index"]) if contract.get("size_arg_index") is not None else None
        if contract.get("size_arg_index") is not None and size_arg is None:
            classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
            findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                              "method_id": method_id, "method_name": methods.get(method_id),
                              "acquisition_call_id": cid, "result_type": contract["result_type"],
                              "object": object_var, "reason": "SIZE_ARG_INDEX_OUT_OF_RANGE",
                              "evidence_source": evidence_source})
            return
        attacker_trace = None
        if size_arg is not None:
            if size_arg["kind"] == "LITERAL":
                classification["SIZE_ATTACKER_INDEPENDENT"] += 1
                return
            attacker_trace = backward_attacker_trace(method_id, size_arg)

        alias_names = {object_var}
        for oc in call_ids:
            ocinfo = calls[oc]
            if ocinfo["name"] != "<operator>.assignment":
                continue
            a = args_by_call.get(oc, {})
            lhs, rhs = a.get(1), a.get(2)
            if not lhs or not rhs:
                continue
            if rhs["code"].strip() == object_var and type_matches(lhs["type"], contract):
                alias_names.add(lhs["code"].strip())

        predicate_calls = []
        use_calls = []
        for oc in call_ids:
            ocinfo = calls[oc]
            a0 = args_by_call.get(oc, {}).get(0)
            if not a0 or a0["code"].strip() not in alias_names or not type_matches(a0["type"], contract):
                continue
            if ocinfo["name"] == contract["failure_predicate"]:
                predicate_calls.append(oc)
            elif oc != cid:
                use_calls.append(oc)

        if not use_calls:
            classification["RESOURCE_ACQUIRED_NO_USE"] += 1
            return

        clearance_edges = set()
        for pc in predicate_calls:
            targets, negations, chain = resolve_branch_targets(
                method_id, pc, contract["failure_predicate"])
            if len(targets) != 2:
                classification["PREDICATE_UNRECOGNIZED_BRANCH_SHAPE"] += 1
                continue
            cond_true_t, cond_false_t = targets[0], targets[1]
            true_means_invalid = contract["failure_polarity"] == "true_means_invalid"
            written_true_means_invalid = (negations % 2 == 0) == true_means_invalid
            if not written_true_means_invalid:
                classification["PREDICATE_INVERTED_POLARITY"] += 1
                continue
            invalid_t, valid_t = cond_true_t, cond_false_t
            if not resolves_without_touching_object(method_id, invalid_t, alias_names, rets):
                classification["PREDICATE_FAILURE_BRANCH_DOES_NOT_TERMINATE"] += 1
                continue
            for u in chain:
                if valid_t in cfg_next.get((method_id, u), []):
                    clearance_edges.add((u, valid_t))

        visited = set()
        frontier = [(cid, False)]
        state = "VALUE_ACQUISITION_GUARD_ESTABLISHED"
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
                state = "VALUE_ACQUISITION_GUARD_MISSING"
                evidence_use = node
                break
            if node in use_calls:
                continue
            for nxt in cfg_next.get((method_id, node), []):
                now_cleared = cleared or ((node, nxt) in clearance_edges)
                frontier.append((nxt, now_cleared))
        else:
            if frontier:
                unresolved = True

        if unresolved:
            classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
            findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                              "method_id": method_id, "method_name": methods.get(method_id),
                              "acquisition_call_id": cid, "result_type": contract["result_type"],
                              "object": object_var, "reason": "DOMINANCE_WALK_DEPTH_EXHAUSTED",
                              "evidence_source": evidence_source})
            return

        # --- R04 APPLICABILITY GATE -- UNCHANGED from resource_guard_verdict_r04.py. --------
        exc_config = build_config["exception_configuration"]
        if exc_config == "enabled":
            classification["CONTRACT_NOT_APPLICABLE"] += 1
            findings.append({
                "verdict": "CONTRACT_NOT_APPLICABLE", "reason": "ACQUISITION_FAILURE_THROWS",
                "method_id": method_id, "method_name": methods.get(method_id),
                "acquisition_call_id": cid, "acquisition_kind": contract["acquisition_kind"],
                "result_type": contract["result_type"], "object": object_var,
                "contract_citation": contract["citation"],
                "build_config_evidence": build_config["evidence"],
                "build_config_citation": build_config["citation"], "r03_would_be_verdict": state,
                "evidence_source": evidence_source,
                "evidence_note": (
                    "under an exceptions-ENABLED build (established by this run's own "
                    "build_config evidence, not assumed), a failed acquisition throws a C++ "
                    "exception directly -- code after the acquisition call is never reached "
                    "on failure, so a missing IsEmpty() check is not the same defect this "
                    "contract's empty-value failure signature describes. This is NOT a "
                    "vulnerability claim, NOT automatically CWE-787, and NOT proof of "
                    "exploitable memory corruption -- it is an applicability determination."
                ),
            })
            return
        if exc_config == "conflict":
            classification["BUILD_CONFIGURATION_CONFLICT"] += 1
            findings.append({
                "verdict": "BUILD_CONFIGURATION_CONFLICT", "method_id": method_id,
                "method_name": methods.get(method_id), "acquisition_call_id": cid,
                "result_type": contract["result_type"], "object": object_var,
                "build_config_evidence": build_config["evidence"],
                "build_config_citation": build_config["citation"], "r03_would_be_verdict": state,
                "evidence_source": evidence_source,
                "evidence_note": (
                    "this run's build_config evidence contains contradictory signals -- "
                    "applicability cannot be established either way, so no MISSING/"
                    "ESTABLISHED verdict is reported. This is an abstention, never a guess."
                ),
            })
            return
        if exc_config != "disabled":
            classification["BUILD_CONFIGURATION_UNRESOLVED"] += 1
            findings.append({
                "verdict": "BUILD_CONFIGURATION_UNRESOLVED", "method_id": method_id,
                "method_name": methods.get(method_id), "acquisition_call_id": cid,
                "result_type": contract["result_type"], "object": object_var,
                "build_config_evidence": build_config["evidence"],
                "build_config_citation": build_config["citation"], "r03_would_be_verdict": state,
                "evidence_source": evidence_source,
                "evidence_note": (
                    "this run carries no usable build-configuration evidence -- "
                    "applicability is not established, so no MISSING/ESTABLISHED verdict is "
                    "reported. This is an abstention, never a default to 'disabled'."
                ),
            })
            return
        # exc_config == "disabled": premise established. Report exactly as R04 always did.
        # --------------------------------------------------------------------------------------

        classification[state] += 1
        finding = {"verdict": state, "method_id": method_id,
                   "method_name": methods.get(method_id), "acquisition_call_id": cid,
                   "acquisition_kind": contract["acquisition_kind"],
                   "result_type": contract["result_type"], "object": object_var,
                   "contract_citation": contract["citation"],
                   "build_config_evidence": build_config["evidence"],
                   "build_config_citation": build_config["citation"],
                   "evidence_source": evidence_source}
        if attacker_trace:
            # RESOURCE-GUARD-R06: renamed from R04/R05's own `attacker_influence_evidence`
            # -- that name itself overclaimed once a reached parameter could mean EITHER
            # proven JS linkage OR an unresolved boundary; `source_boundary_evidence`
            # accurately describes what this field now always contains (see
            # `backward_attacker_trace`'s own docstring). A reader must check
            # `attacker_controlled`/`source_boundary` inside it, never infer attacker
            # control merely from this key's presence.
            finding["source_boundary_evidence"] = attacker_trace
        if state == "VALUE_ACQUISITION_GUARD_MISSING":
            finding["unguarded_use_call_id"] = evidence_use
            write_evidence = None
            for oc in call_ids:
                if calls[oc]["name"] != "<operator>.assignment":
                    continue
                lhs = args_by_call.get(oc, {}).get(1)
                if lhs and lhs["kind"] == "CALL" and lhs["node_id"] == evidence_use:
                    write_evidence = "direct_assignment_through_resource"
                    break
            finding["downstream_write_evidence"] = write_evidence
            finding["evidence_note"] = (
                "invalid-handle-use evidence only -- this contract's failure predicate "
                "proves acquisition/handle validity, not destination capacity; no CWE-787 or "
                "capacity claim is made here, and this finding alone is not a vulnerability "
                "claim. The contract's applicability (exceptions-disabled) IS established for "
                "this run -- see build_config_citation." +
                (" Result-object identity and type were RECOVERED from the enclosing "
                 "assignment's own resolved local type, not from the acquisition call's own "
                 "methodFullName (which c2cpg left unresolved for this call) -- see "
                 "study/resource_guard_r05/R05_DESIGN.md."
                 if evidence_source == "r05_structural_recovery" else "")
            )
        findings.append(finding)

    for method_id, call_ids in calls_by_method.items():
        for cid in call_ids:
            c = calls[cid]
            contract = match_contract(c["name"])
            if contract is not None:
                classification["ACQUISITION_NAME_MATCH_CANDIDATE"] += 1
                qualified_prefix = f"{contract['qualifier_type']}.{contract['acquisition_call']}:"
                if c["mfn"].startswith(qualified_prefix):
                    # --- R04's own matching path, UNCHANGED. ------------------------------
                    curated_param_counts = {_param_count(p) for p in contract["result_mfn_prefixes"]}
                    try:
                        this_param_count = _param_count(c["mfn"])
                    except ValueError:
                        this_param_count = None
                    if this_param_count not in curated_param_counts:
                        classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
                        findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                                          "method_id": method_id, "method_name": methods.get(method_id),
                                          "acquisition_call_id": cid, "result_type": contract["result_type"],
                                          "reason": "ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED",
                                          "evidence_source": "r04_direct"})
                        continue
                    classification["ACQUISITION_CALL_FOUND"] += 1
                    evaluate_acquisition(method_id, call_ids, cid, c, contract, "r04_direct")
                    continue
                # falls through: name matched a real contract, but qualifier did not --
                # exactly R04's own ACQUISITION_SIGNATURE_UNRECOGNIZED case. R05 still gets
                # a chance below (a call CAN match both an R04 contract by name and an R05
                # recovery contract by name, e.g. "New" -- they are tried independently).
                classification["ACQUISITION_SIGNATURE_UNRECOGNIZED"] += 1

            # --- R05 STRUCTURAL RECOVERY -- the one new path, no R04 counterpart. ---------
            # Gated on --real: RECOVERY_CONTRACTS is a real-node-addon-api-specific
            # mechanism with no synthetic pool (see resource_contracts_r05.py's module
            # docstring) -- never attempted in synthetic mode, so a synthetic fixture can
            # never be "recovered" by an incidental name/arity/type coincidence.
            if not use_real:
                continue
            recovery_contract = match_recovery_contract(c["name"])
            if recovery_contract is None:
                continue  # not even a candidate name for recovery -- nothing more to do
            if not (c["mfn"].startswith(UNRESOLVED_MFN_PREFIX) and UNRESOLVED_SIG_MARKER in c["mfn"]):
                continue  # resolved to some OTHER, concrete (non-matching) qualifier --
                          # already correctly counted above if a real contract also existed
                          # by name; either way, not this recovery's shape, never recovered.
            if c["dispatch"] != "STATIC_DISPATCH":
                continue  # structural evidence this isn't even a class-qualified call
            classification["R05_RECOVERY_CANDIDATE"] += 1

            # find_object_identity needs a single result_type to call type_matches with, but
            # R05 must accept MULTIPLE real forms -- so it is called once per accepted form
            # and the first hit wins, rather than widening type_matches itself (which stays
            # untouched, single-string, exactly as R04 defines it).
            object_var = None
            matched_form = None
            for form in recovery_contract["result_type_forms"]:
                candidate = find_object_identity(method_id, call_ids, cid, c, {"result_type": form})
                if candidate is not None:
                    object_var, matched_form = candidate, form
                    break
            if object_var is None:
                classification["R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED"] += 1
                continue

            arity = len(args_by_call.get(cid, {}))
            if arity != recovery_contract["required_arity"]:
                classification["R05_RECOVERY_ARITY_UNRECOGNIZED"] += 1
                continue

            arg0 = args_by_call.get(cid, {}).get(1)
            arg0_type = (arg0["type"] or "").rstrip("&").strip() if arg0 else None
            if arg0_type not in recovery_contract["arg0_env_type_forms"]:
                classification["R05_RECOVERY_ARG_ROLE_UNRECOGNIZED"] += 1
                continue

            classification["R05_ACQUISITION_CALL_RECOVERED"] += 1
            recovered_contract = {
                "acquisition_kind": recovery_contract["acquisition_kind"],
                "result_type": matched_form,
                "size_arg_index": recovery_contract["size_arg_index"],
                "failure_predicate": recovery_contract["failure_predicate"],
                "failure_polarity": recovery_contract["failure_polarity"],
                "citation": recovery_contract["citation"],
            }
            evaluate_acquisition(method_id, call_ids, cid, c, recovered_contract,
                                  "r05_structural_recovery")

    json.dump({"schema": "resource-guard-verdict-r05/0.1",
               "contract_pool": "real" if use_real else "synthetic",
               "build_config": build_config,
               "classification": dict(classification),
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {dict(classification)}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
