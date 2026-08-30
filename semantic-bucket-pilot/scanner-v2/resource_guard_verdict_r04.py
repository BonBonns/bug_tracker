#!/usr/bin/env python3
"""RESOURCE-GUARD-R04: adds APPLICABILITY ENFORCEMENT on top of R03 -- NOT a rewrite of R03's
matching/dominance/tracing/verdict-construction logic. Every one of those lines below is
IDENTICAL to `resource_guard_verdict_r03.py` (copied, not imported, so R03 stays byte-for-
byte frozen while R04 evolves independently -- same reason R03 copied rather than imported
R02's own machinery, and R02 copied rather than imported R01's). The ONLY new logic is the
build-configuration APPLICABILITY GATE applied immediately before a MISSING/ESTABLISHED
verdict would be finalized -- see the "R04 APPLICABILITY GATE" block below, the only block
in this file with no R03 counterpart.

Why R04 exists (see `resource_contracts_r04.py`'s own module docstring for the full account):
R03's own blind test against `@julusian/jpeg-turbo` (RESOURCE_GUARD_R03.md's "R03 blind
test") produced `VALUE_ACQUISITION_GUARD_MISSING` on a real site that most likely builds with
C++ exceptions ENABLED -- meaning the contract's own failure-representation premise (an empty
`Napi::Value` on failure, checkable via `IsEmpty()`) does not actually hold there; a real
allocation failure at that site would throw a C++ exception instead, and code after the
acquisition would never even run. That MISSING finding is a real, correctly-diagnosed
CONFIGURATION-DRIVEN FALSE POSITIVE, not evidence the algorithm generalizes semantically --
R03 (and R02 before it) only ever CARRIED the exceptions-disabled requirement as a disclosed,
NEVER-ENFORCED assumption on every finding; it never actually gated on it.

R04's one addition: before a MISSING/ESTABLISHED verdict is reported, the RUN's own
build-configuration evidence must ESTABLISH that the contract's premise (exceptions
disabled) actually holds for the code under analysis. That evidence:

  - CANNOT come from the exported CPG facts. Confirmed repeatedly since R02: calls.tsv,
    cfg_edges.tsv, locals.tsv, identifiers.tsv, members.tsv, aggregate_kinds.tsv, returns.tsv,
    parameters.tsv, method_returns.tsv, literals.tsv, type_decls.tsv, meta.tsv carry NO
    representation of preprocessor state or try/catch AST structure at all.
  - Must come from a separate, explicitly curated, per-run manifest: `build_config.json`,
    loaded from `--build-config PATH` if given, else `RAW_DIR/build_config.json` if it
    exists. Schema:
        {"exception_configuration": "disabled" | "enabled" | "unresolved" | "conflict",
         "evidence": [{"source": "...", "detail": "...", "citation": "..."}, ...],
         "citation": "human summary of how this was determined"}
    Built from REAL, independently-verified build files (binding.gyp, CMakeLists.txt,
    compiler flags, package build scripts, node-addon-api configuration macros, or an
    explicit trusted build manifest) -- e.g. Cartesi's real, verified
    `NAPI_DISABLE_CPP_EXCEPTIONS` in `binding.gyp`, or jpeg-turbo's real, verified ABSENCE of
    either macro anywhere in `CMakeLists.txt` combined with node-addon-api's own real
    default-resolution logic (napi.h: absent either macro, exceptions are enabled if the
    compiler itself was built with exceptions on -- the near-universal C++ default absent an
    explicit `-fno-exceptions`, which neither project's build sets).
  - Is NEVER inferred from the absence of a try/catch in the analyzed SOURCE -- a source-level
    signal with no bearing on the actual compiled BUILD configuration (R02/R03's own
    `r02c10_exceptions_enabled_try_catch` control already proved the exported facts can't even
    see try/catch AST structure at all, so there is nothing there to infer from either way).
  - Is NEVER silently defaulted to "disabled" (the permissive choice that would let a finding
    through) when missing, ambiguous, or self-contradictory: `build_config.json` absent, its
    `exception_configuration` field missing/unrecognized, or containing unrelated flags that
    do not bear on `NAPI_CPP_EXCEPTIONS`/`NAPI_DISABLE_CPP_EXCEPTIONS` specifically, all
    resolve to `"unresolved"`; both macros present for the same build resolves to `"conflict"`.

New verdict categories: `CONTRACT_NOT_APPLICABLE` (exceptions established enabled --
acquisition failure throws directly; a missing `IsEmpty()` is not a defect under this
contract), `BUILD_CONFIGURATION_UNRESOLVED` (no usable applicability evidence either way),
`BUILD_CONFIGURATION_CONFLICT` (contradictory evidence). None of these three is a
memory-safety/CWE/vulnerability claim -- they are applicability/abstention classifications,
exactly as `ACQUISITION_SIGNATURE_UNRECOGNIZED` and `VALUE_ACQUISITION_SEMANTICS_UNRESOLVED`
already are. A `VALUE_ACQUISITION_GUARD_MISSING`/`..._ESTABLISHED` verdict is reported ONLY
when `exception_configuration == "disabled"` -- the one case where R03's own algorithm
(unchanged below) already computed the correct answer, exactly as it always did.

Everything else -- acquisition/qualifier matching, param-count checking, object identity
resolution, alias handling, branch-polarity resolution, edge-keyed dominance, the
depth-bounded backward attacker-influence trace, the reaching-return sanity check -- is BYTE-
FOR-BYTE UNCHANGED from `resource_guard_verdict_r03.py`. Do not look for a logic diff there;
there isn't one.

Usage: resource_guard_verdict_r04.py RAW_DIR OUT.json [--real] [--build-config PATH]
  --real uses resource_contracts_r04.py's REAL_CONTRACTS; default uses SYNTHETIC_CONTRACTS.
  --build-config PATH points at a build_config.json manifest; defaults to
  RAW_DIR/build_config.json. If neither exists, exception_configuration is "unresolved".
"""
import base64
import json
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from resource_contracts_r04 import SYNTHETIC_CONTRACTS, REAL_CONTRACTS

LOGICAL_PASSTHROUGH = {"<operator>.logicalAnd", "<operator>.logicalOr", "LLVM_UNLIKELY",
                       "LLVM_LIKELY"}
NEGATING_PASSTHROUGH = {"<operator>.logicalNot"}
BOOL_LITERALS_FALSE = {"false", "0"}
BOOL_LITERALS_TRUE = {"true", "1"}

VALID_EXCEPTION_CONFIGURATIONS = {"disabled", "enabled", "unresolved", "conflict"}


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
    """A declared/expression type matches the contract's ACQUIRED VALUE iff it equals
    `result_type` once a trailing reference marker is stripped -- see R01's identical
    helper/rationale (a reference alias's own declared type carries a literal '&' suffix).
    Deliberately matched against `result_type`, NOT `acquisition_call` -- the field split
    this whole file exists to make (see module docstring)."""
    return (type_full_name or "").rstrip("&").strip() == contract["result_type"]


def match_contract_for_acquisition(call_name):
    for c in list(SYNTHETIC_CONTRACTS.values()) + list(REAL_CONTRACTS.values()):
        if c["acquisition_call"] == call_name:
            return c
    return None


def _contracts_for(use_real):
    return REAL_CONTRACTS if use_real else SYNTHETIC_CONTRACTS


# --- R04 APPLICABILITY GATE -- the one block in this file with no R03 counterpart. ---------
def load_build_config(raw, explicit_path):
    """Loads the per-run build-configuration evidence manifest. NEVER inferred from CPG
    facts, NEVER defaulted to "disabled" (the permissive choice). Missing file, missing
    field, or an unrecognized value all resolve to "unresolved" -- an abstention, not a
    guess. See module docstring for the full schema and the real evidence this project's own
    development/regression cases (Cartesi, jpeg-turbo) were built from."""
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
                      "code": dec(r[6]), "line": r[8]}
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

    for method_id, call_ids in calls_by_method.items():
        rets = returns_by_method.get(method_id, set())
        for cid in call_ids:
            c = calls[cid]
            contract = match_contract(c["name"])
            if contract is None:
                continue
            classification["ACQUISITION_NAME_MATCH_CANDIDATE"] += 1

            # RESOURCE-ACQ-SIG-R02: match by parameter count (R01's RESOURCE-CTOR-TYPEINFER-
            # R01 reasoning applies identically here -- a literal argument's own c2cpg-
            # inferred type can silently differ from the declared parameter type) AND
            # require the methodFullName to be qualified by the contract's `qualifier_type`
            # -- this is the check that lets a contract disambiguate its own acquisition_
            # call name from an unrelated class's own same-named method (see "unrelated
            # class" control). RESOURCE-ACQ-KIND-R02: qualifier_type is NOT always
            # result_type -- a STATIC_FACTORY call's methodFullName is qualified by the
            # RESULT's own class ("Buffer.New:...", the static method belongs to the type
            # it constructs), but an INSTANCE_FACTORY call's is qualified by the RECEIVER's
            # class instead ("Factory.Make:...", confirmed empirically -- see
            # resource_contracts_r02.py's "Factory.Make" entry). Each contract states its
            # own correct value; the algorithm does not derive one from the other. R03/R04
            # add NO new logic here -- R03 only corrected one contract's stated
            # qualifier_type value; R04 adds an applicability gate further below, unrelated
            # to this matching step.
            qualified_prefix = f"{contract['qualifier_type']}.{contract['acquisition_call']}:"
            if not c["mfn"].startswith(qualified_prefix):
                classification["ACQUISITION_SIGNATURE_UNRECOGNIZED"] += 1
                continue  # a different, unrelated same-named call -- not a candidate at all
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
                                  "reason": "ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED"})
                continue
            classification["ACQUISITION_CALL_FOUND"] += 1

            # RESOURCE-OBJ-ID-R02: resolve the acquired RESULT's identity. Same technique
            # as R01's RESOURCE-OBJ-ID-R01 (same-line assignment, LHS type match, substring
            # fallback), matched against `result_type` (not `acquisition_call` -- the split
            # this file exists to make). No implicit receiver argument to consult for
            # STATIC_FACTORY calls -- identity comes ONLY from the enclosing assignment,
            # never inferred from code text otherwise.
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
            if object_var is None:
                # RESOURCE-OBJ-ID-R02 (unresolved/temporary result): the acquisition's own
                # result is never bound to a named local at all (e.g. a chained, un-named
                # temporary: `if (Type::Method(args).predicate()) return;`) -- identity
                # cannot be resolved from real facts, so this abstains rather than guessing
                # which later object_var, if any, "probably" refers to the same value.
                classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "acquisition_call_id": cid, "result_type": contract["result_type"],
                                  "reason": "OBJECT_IDENTITY_UNRESOLVED_OR_TEMPORARY"})
                continue

            acq_args = args_by_call.get(cid, {})
            size_arg = acq_args.get(contract["size_arg_index"]) if contract.get("size_arg_index") is not None else None
            if contract.get("size_arg_index") is not None and size_arg is None:
                classification["VALUE_ACQUISITION_SEMANTICS_UNRESOLVED"] += 1
                findings.append({"verdict": "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED",
                                  "method_id": method_id, "method_name": methods.get(method_id),
                                  "acquisition_call_id": cid, "result_type": contract["result_type"],
                                  "object": object_var, "reason": "SIZE_ARG_INDEX_OUT_OF_RANGE"})
                continue
            attacker_trace = None
            if size_arg is not None:
                if size_arg["kind"] == "LITERAL":
                    classification["SIZE_ATTACKER_INDEPENDENT"] += 1
                    continue
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
                continue

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
                                  "object": object_var, "reason": "DOMINANCE_WALK_DEPTH_EXHAUSTED"})
                continue

            # --- R04 APPLICABILITY GATE ---------------------------------------------------
            # R03's own algorithm (everything above, unchanged) has just determined what the
            # verdict WOULD be if this contract's exceptions-disabled premise held. It is
            # reported as-is ONLY when the run's own build_config evidence ESTABLISHES that
            # premise. Otherwise the applicability classification below is reported INSTEAD
            # of MISSING/ESTABLISHED -- never alongside it, and never silently defaulted.
            exc_config = build_config["exception_configuration"]
            if exc_config == "enabled":
                classification["CONTRACT_NOT_APPLICABLE"] += 1
                findings.append({
                    "verdict": "CONTRACT_NOT_APPLICABLE",
                    "reason": "ACQUISITION_FAILURE_THROWS",
                    "method_id": method_id, "method_name": methods.get(method_id),
                    "acquisition_call_id": cid, "acquisition_kind": contract["acquisition_kind"],
                    "result_type": contract["result_type"], "object": object_var,
                    "contract_citation": contract["citation"],
                    "build_config_evidence": build_config["evidence"],
                    "build_config_citation": build_config["citation"],
                    "r03_would_be_verdict": state,
                    "evidence_note": (
                        "under an exceptions-ENABLED build (established by this run's own "
                        "build_config evidence, not assumed), a failed acquisition throws a "
                        "C++ exception directly -- code after the acquisition call is never "
                        "reached on failure, so a missing IsEmpty() check is not the same "
                        "defect this contract's empty-value failure signature describes. "
                        "This is NOT a vulnerability claim, NOT automatically CWE-787, and "
                        "NOT proof of exploitable memory corruption -- it is an applicability "
                        "determination: this contract does not apply to this call site."
                    ),
                })
                continue
            if exc_config == "conflict":
                classification["BUILD_CONFIGURATION_CONFLICT"] += 1
                findings.append({
                    "verdict": "BUILD_CONFIGURATION_CONFLICT",
                    "method_id": method_id, "method_name": methods.get(method_id),
                    "acquisition_call_id": cid, "result_type": contract["result_type"],
                    "object": object_var, "build_config_evidence": build_config["evidence"],
                    "build_config_citation": build_config["citation"],
                    "r03_would_be_verdict": state,
                    "evidence_note": (
                        "this run's build_config evidence contains contradictory signals "
                        "(e.g. both NAPI_CPP_EXCEPTIONS and NAPI_DISABLE_CPP_EXCEPTIONS "
                        "defined for the same build) -- applicability cannot be established "
                        "either way, so no MISSING/ESTABLISHED verdict is reported. This is "
                        "an abstention, never a guess at which definition wins."
                    ),
                })
                continue
            if exc_config != "disabled":  # "unresolved", or anything else load_build_config
                                            # did not already normalize to a valid value.
                classification["BUILD_CONFIGURATION_UNRESOLVED"] += 1
                findings.append({
                    "verdict": "BUILD_CONFIGURATION_UNRESOLVED",
                    "method_id": method_id, "method_name": methods.get(method_id),
                    "acquisition_call_id": cid, "result_type": contract["result_type"],
                    "object": object_var, "build_config_evidence": build_config["evidence"],
                    "build_config_citation": build_config["citation"],
                    "r03_would_be_verdict": state,
                    "evidence_note": (
                        "this run carries no usable build-configuration evidence bearing on "
                        "NAPI_CPP_EXCEPTIONS/NAPI_DISABLE_CPP_EXCEPTIONS specifically -- "
                        "applicability is not established, so no MISSING/ESTABLISHED verdict "
                        "is reported. This is an abstention, never a default to 'disabled'."
                    ),
                })
                continue
            # exc_config == "disabled": the contract's premise is established. Report exactly
            # as R03 always did -- this branch is otherwise byte-for-byte R03's own tail.
            # ---------------------------------------------------------------------------------

            classification[state] += 1
            finding = {"verdict": state, "method_id": method_id,
                       "method_name": methods.get(method_id), "acquisition_call_id": cid,
                       "acquisition_kind": contract["acquisition_kind"],
                       "result_type": contract["result_type"], "object": object_var,
                       "contract_citation": contract["citation"],
                       "build_config_evidence": build_config["evidence"],
                       "build_config_citation": build_config["citation"]}
            if attacker_trace:
                finding["attacker_influence_evidence"] = attacker_trace
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
                    "proves acquisition/handle validity, not destination capacity; no "
                    "CWE-787 or capacity claim is made here, and this finding alone is not "
                    "a vulnerability claim -- runtime behavior and security impact are "
                    "separate, unestablished questions. The contract's applicability "
                    "(exceptions-disabled) IS established for this run -- see "
                    "build_config_citation."
                )
            findings.append(finding)

    json.dump({"schema": "resource-guard-verdict-r04/0.1",
               "contract_pool": "real" if use_real else "synthetic",
               "build_config": build_config,
               "classification": dict(classification),
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {dict(classification)}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
