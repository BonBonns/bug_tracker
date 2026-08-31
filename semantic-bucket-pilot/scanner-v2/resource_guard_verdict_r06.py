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
established attacker influence unconditionally -- EVERY reached parameter, with NO
exception, is now reported as `SOURCE_BOUNDARY_UNRESOLVED`, `attacker_controlled: False`.

An EARLIER revision of this fix tried to draw a line here: a parameter whose own real
`type_full_name` (`parameters.tsv`) matches `JS_CALLBACK_ORIGIN_TYPES` (`Napi::CallbackInfo`,
node-addon-api's own real N-API entry-point parameter type) was auto-promoted to
`attacker_controlled: True`, on the theory that reaching this ONE specific parameter type is
itself real, structural, verified JS-linkage. Direct, real re-verification against Cartesi's
own cached raw facts (`/tmp/cartesi_raw`, the SAME real corpus package this fix's own prior
revision cited as already confirming that theory) found this claim was NOT actually true:
Cartesi's 3 real `ReadMemory`/`ReadVirtualMemory`/`ReadConsoleOutput` findings all trace to
`None` (the walk never reaches ANY parameter, `Napi::CallbackInfo`-typed or otherwise) --
the real code path is `get_u64(env, info[1], "length", &length)`, an OUT-PARAMETER helper
call (`&length` passed by address, populated internally by `get_u64` from `info[1]`), a
dataflow shape `backward_attacker_trace`'s own identifier/call walk does not model at all.
The prior revision's claim of a confirmed Cartesi positive case was therefore never actually
exercised by real code -- an overclaim caught by direct re-verification, not by a failing
fixture, and corrected here rather than left standing. More generally: even where a reached
parameter genuinely IS `Napi::CallbackInfo`-typed, that alone proves the ENCLOSING FUNCTION
is a real N-API entry point -- it does NOT by itself prove that THIS SPECIFIC traced value
came from a JS-caller-supplied argument (the function could equally derive it from a fixed
policy, an internal computation, or a `CallbackInfo`-typed parameter that is never actually
indexed for this particular value) -- too permissive a promotion rule for what the evidence
actually establishes. `JS_CALLBACK_ORIGIN_TYPES`/`_is_js_callback_origin_type` are kept in
this file (the parameter's own real type is still recorded on every `SOURCE_BOUNDARY_
UNRESOLVED` result, as `parameter_type`) because a real, separate, ADDITIONAL layer --
implemented on `claude/r06-fix01i-integration`, never merged into this frozen R06 lineage --
uses exactly this signal, combined with real cross-language linking evidence
(`link_napi_facts.py`) and a real, structural check for the `info[N]`-plus-out-parameter
call shape Cartesi's own code actually uses, to promote a specific finding only when a real
JS argument demonstrably reaches the traced value. That promotion logic is explicitly out of
scope for this file: R05/R06 operate on C++-only facts and have no JS facts loaded at all --
a real, disclosed, bounded scope, not an oversight.

node-libcurl's own real `ReadFunction` finding remains the required rejection case for this
fix: its `size` parameter is an ordinary `size_t`, not `Napi::CallbackInfo`-typed, and
`Easy::ReadFunction` is never called by JS at all (registered with libcurl via
`curl_easy_setopt`) -- it correctly reports `SOURCE_BOUNDARY_UNRESOLVED` either way, now for
the same reason every other reached parameter does.

This gate corrects the EVIDENCE FIELD's own claimed meaning; it does not suppress or change
the underlying `VALUE_ACQUISITION_GUARD_MISSING` (etc.) verdict itself, which was never
actually gated on `attacker_trace` succeeding (confirmed by reading R04/R05's own verdict-
construction code: `attacker_trace` is attached to the finding as supplementary evidence,
never used as a precondition for reporting the finding at all) -- the contract's own failure
predicate (an unguarded acquisition result) is a real, separate, still-valid claim
regardless of whether attacker influence on the SIZE argument specifically is proven.

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
import os
import pathlib
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from resource_contracts_r04 import SYNTHETIC_CONTRACTS, REAL_CONTRACTS
from resource_contracts_r05 import RECOVERY_CONTRACTS

# R06 TARGET-SCOPING FIX: reuse npm_corpus/extract_build_config.py's own real, already-tested
# per-target gyp matcher, rather than re-implementing it here -- single source of truth, no
# drift risk between the pipeline's own extraction and this scanner's own resolution.
sys.path.insert(0, os.path.join(__file__.rsplit("/", 1)[0], "npm_corpus"))
from extract_build_config import resolve_build_config_for_targets

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


# --- R04 APPLICABILITY GATE -- package-wide fields UNCHANGED from resource_guard_verdict_r04.py.
def load_build_config(raw, explicit_path):
    """R06 TARGET-SCOPING FIX: now also passes through `gyp_targets`/`gyp_path` (real,
    per-target classification from run_pipeline_one_r06.py's own build_config.json, absent
    on an older/non-gyp build_config.json -- both real, disclosed cases) alongside the
    ORIGINAL package-wide `exception_configuration`/`evidence`/`citation` fields, which
    remain the required fallback for a finding whose own source file cannot be resolved to
    a specific gyp target (see `resolve_exc_config_for_method` below). `gyp_targets` is kept
    even when the package-wide `exception_configuration` itself is invalid/unresolved --
    per-target resolution can still give a DEFINITIVE per-finding answer even when the
    flat, package-wide classifier could only report "unresolved"/"conflict" for the whole
    package, which is exactly the real problem item 1 exists to fix."""
    path = pathlib.Path(explicit_path) if explicit_path else (pathlib.Path(raw) / "build_config.json")
    if not path.exists():
        return {"exception_configuration": "unresolved", "evidence": [],
                "citation": f"no build_config.json found at {path} -- treated as unresolved, "
                            "never defaulted to disabled",
                "gyp_targets": None, "gyp_path": None}
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        return {"exception_configuration": "unresolved", "evidence": [],
                "citation": f"build_config.json at {path} failed to parse ({e}) -- treated as "
                            "unresolved, never defaulted to disabled",
                "gyp_targets": None, "gyp_path": None}
    gyp_targets = cfg.get("gyp_targets")
    gyp_path = cfg.get("gyp_path")
    value = cfg.get("exception_configuration")
    if value not in VALID_EXCEPTION_CONFIGURATIONS:
        return {"exception_configuration": "unresolved",
                "evidence": cfg.get("evidence", []),
                "citation": cfg.get("citation",
                                     f"build_config.json's exception_configuration value "
                                     f"({value!r}) is not one of {sorted(VALID_EXCEPTION_CONFIGURATIONS)} "
                                     "-- treated as unresolved, never defaulted to disabled"),
                "gyp_targets": gyp_targets, "gyp_path": gyp_path}
    return {"exception_configuration": value,
            "evidence": cfg.get("evidence", []),
            "citation": cfg.get("citation", path.as_posix()),
            "gyp_targets": gyp_targets, "gyp_path": gyp_path}


def resolve_exc_config_for_method(build_config, methods_filename, method_id):
    """R06 TARGET-SCOPING FIX -- the real, required per-finding resolution: associates
    THIS finding's own enclosing method's real source `filename` (from methods.tsv) with
    the SPECIFIC real gyp target that compiles it, via `resolve_build_config_for_targets`.
    FAILS CLOSED exactly per the standing requirement (never a package-wide guess):
      - No `gyp_targets` at all (non-gyp build, or no binding.gyp found) -> falls back to
        the package-wide `exception_configuration`/`evidence`/`citation`, the same real,
        disclosed scope boundary `classify_target_aware`/`resolve_build_config_for_file`
        already document (cmake/meson/gn packages are not target-scoped by this mechanism).
        `resolution_scope` records this as `"package_wide_fallback"`, never silently
        indistinguishable from a real per-target resolution.
      - `gyp_targets` present but this method's own `filename` is missing/empty, or no
        real gyp target's own `sources` list names it, or multiple real targets name it
        with DIFFERING configuration -> `BUILD_CONFIGURATION_UNRESOLVED`/`"conflict"`
        (`resolve_build_config_for_targets`'s own fail-closed cases), NEVER the package-
        wide value substituted in as a guess.

    The package-wide value is ALWAYS returned too, under `package_wide_diagnostic` --
    DIAGNOSTIC ONLY, never itself the authoritative verdict when real per-target data
    exists (`resolution_scope == "per_target"`). This lets a reader see, and a test
    assert, that the package-wide flat classification and the per-target resolution can
    genuinely differ (exactly the real node-libcurl case: package-wide `"unresolved"`,
    `Easy.cc`'s own real target `"enabled"`) without the package-wide value ever being
    the one actually applied.

    Returns a dict: `{"exception_configuration", "evidence", "citation",
    "resolution_scope", "resolved_target_name", "package_wide_diagnostic"}`.
    `resolution_scope` is one of `"per_target"` (a single real target, or multiple real
    targets that agree, compiles this file), `"per_target_unresolved"` (gyp_targets data
    exists but this specific finding's target identity could not be resolved -- fails
    closed), or `"package_wide_fallback"` (no gyp_targets data at all for this package)."""
    package_wide_diagnostic = {
        "exception_configuration": build_config["exception_configuration"],
        "evidence": build_config["evidence"],
        "citation": build_config["citation"],
    }
    gyp_targets = build_config.get("gyp_targets")
    if not gyp_targets:
        return {
            "exception_configuration": build_config["exception_configuration"],
            "evidence": build_config["evidence"],
            "citation": build_config["citation"],
            "resolution_scope": "package_wide_fallback",
            "resolved_target_name": None,
            "package_wide_diagnostic": package_wide_diagnostic,
        }
    filename = methods_filename.get(method_id)
    if not filename:
        return {
            "exception_configuration": "BUILD_CONFIGURATION_UNRESOLVED",
            "evidence": [],
            "citation": f"method {method_id} has no recorded source filename -- cannot "
                        f"resolve against this package's own real per-target gyp data "
                        f"({build_config.get('gyp_path')!r}); fails closed rather than "
                        f"falling back to the package-wide value",
            "resolution_scope": "per_target_unresolved",
            "resolved_target_name": None,
            "package_wide_diagnostic": package_wide_diagnostic,
        }
    result = resolve_build_config_for_targets(gyp_targets, filename)
    citation = (f"target-resolved against {build_config.get('gyp_path')!r}: "
                f"{result['reason']}" +
                (f" (target={result['resolved_target_name']!r})"
                 if result.get("resolved_target_name") else ""))
    return {
        "exception_configuration": result["exception_configuration"],
        "evidence": result.get("matching_targets", []),
        "citation": citation,
        "resolution_scope": ("per_target_unresolved"
                              if result["exception_configuration"] == "BUILD_CONFIGURATION_UNRESOLVED"
                              else "per_target"),  # "conflict" still counts as per_target --
                                                     # target IDENTITY is resolved, only the
                                                     # configs among those targets disagree.
        "resolved_target_name": result.get("resolved_target_name"),
        "package_wide_diagnostic": package_wide_diagnostic,
    }
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
    # R06 TARGET-SCOPING FIX: real source filename per method (methods.tsv column 4), used to
    # associate each finding with the SPECIFIC gyp target that compiles its enclosing method.
    methods_filename = {int(r[0]): dec(r[4]) for r in rows(f"{raw}/methods.tsv", 10)}

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
        parameter is no longer, by itself, reported as attacker influence, WITH NO
        EXCEPTION -- every reached parameter is reported as `SOURCE_BOUNDARY_UNRESOLVED`,
        `attacker_controlled: False`. The parameter's own real `type_full_name`
        (`param_types_by_method`) is still recorded (`parameter_type`), including whether
        it matches `JS_CALLBACK_ORIGIN_TYPES` (node-addon-api's own real `Napi::
        CallbackInfo` N-API entry-point convention) -- but that signal ALONE is no longer
        treated as sufficient proof this SPECIFIC traced value came from a JS-caller-
        supplied argument (see module docstring for why a prior revision's promotion rule
        here was an overclaim, caught by direct re-verification against Cartesi's own real
        facts). Promoting a SOURCE_BOUNDARY_UNRESOLVED finding to attacker-controlled,
        when real evidence supports it, is handled entirely OUTSIDE this file -- never
        silently dropped, never claimed as attacker evidence here."""
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
                    return {"traced_to_parameter": val, "hops": hops,
                            "parameter_type": ptype or None,
                            "is_js_callback_origin_type": _is_js_callback_origin_type(ptype),
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

        # --- R06 TARGET-SCOPING FIX: exc_config/evidence/citation now resolved PER FINDING,
        # against the specific gyp target that compiles THIS method's own source file, not a
        # single package-wide value -- see resolve_exc_config_for_method's own docstring for
        # the real fail-closed semantics. Falls back to the original package-wide R04
        # behavior when this package has no real gyp_targets data at all (disclosed scope).
        cfg = resolve_exc_config_for_method(build_config, methods_filename, method_id)
        exc_config = cfg["exception_configuration"]

        # PHASE B REFINEMENT: source_boundary_evidence and the per-target resolution metadata
        # are now attached to EVERY finding this gate can produce -- an abstention (exceptions-
        # enabled/conflict/unresolved) and a real source-boundary determination are SEPARATE,
        # independent pieces of real evidence; a reader must be able to see BOTH regardless of
        # which one this run happens to report as the primary verdict. Neither implies or
        # suppresses the other -- e.g. node-libcurl correctly carries BOTH "exceptions enabled"
        # (build_config_evidence) AND "SOURCE_BOUNDARY_UNRESOLVED" (source_boundary_evidence)
        # on the SAME CONTRACT_NOT_APPLICABLE finding.
        common_evidence = {
            "resolution_scope": cfg["resolution_scope"],
            "resolved_target_name": cfg["resolved_target_name"],
            "package_wide_diagnostic": cfg["package_wide_diagnostic"],
        }
        if attacker_trace:
            common_evidence["source_boundary_evidence"] = attacker_trace

        if exc_config == "enabled":
            classification["CONTRACT_NOT_APPLICABLE"] += 1
            findings.append({
                "verdict": "CONTRACT_NOT_APPLICABLE", "reason": "ACQUISITION_FAILURE_THROWS",
                "method_id": method_id, "method_name": methods.get(method_id),
                "acquisition_call_id": cid, "acquisition_kind": contract["acquisition_kind"],
                "result_type": contract["result_type"], "object": object_var,
                "contract_citation": contract["citation"],
                "build_config_evidence": cfg["evidence"],
                "build_config_citation": cfg["citation"], "r03_would_be_verdict": state,
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
                **common_evidence,
            })
            return
        if exc_config == "conflict":
            classification["BUILD_CONFIGURATION_CONFLICT"] += 1
            findings.append({
                "verdict": "BUILD_CONFIGURATION_CONFLICT", "method_id": method_id,
                "method_name": methods.get(method_id), "acquisition_call_id": cid,
                "result_type": contract["result_type"], "object": object_var,
                "build_config_evidence": cfg["evidence"],
                "build_config_citation": cfg["citation"], "r03_would_be_verdict": state,
                "evidence_source": evidence_source,
                "evidence_note": (
                    "this run's build_config evidence contains contradictory signals -- "
                    "applicability cannot be established either way, so no MISSING/"
                    "ESTABLISHED verdict is reported. This is an abstention, never a guess."
                ),
                **common_evidence,
            })
            return
        if exc_config != "disabled":
            classification["BUILD_CONFIGURATION_UNRESOLVED"] += 1
            findings.append({
                "verdict": "BUILD_CONFIGURATION_UNRESOLVED", "method_id": method_id,
                "method_name": methods.get(method_id), "acquisition_call_id": cid,
                "result_type": contract["result_type"], "object": object_var,
                "build_config_evidence": cfg["evidence"],
                "build_config_citation": cfg["citation"], "r03_would_be_verdict": state,
                "evidence_source": evidence_source,
                "evidence_note": (
                    "this run carries no usable build-configuration evidence for the "
                    "specific target compiling this finding's source file -- applicability "
                    "is not established, so no MISSING/ESTABLISHED verdict is reported. "
                    "This is an abstention, never a default to 'disabled', and never a "
                    "package-wide guess when target identity could not be resolved."
                ),
                **common_evidence,
            })
            return
        # exc_config == "disabled": premise established (for THIS finding's own target, or
        # package-wide if no gyp_targets data exists). Report exactly as R04/R05 always did.
        # --------------------------------------------------------------------------------------

        classification[state] += 1
        finding = {"verdict": state, "method_id": method_id,
                   "method_name": methods.get(method_id), "acquisition_call_id": cid,
                   "acquisition_kind": contract["acquisition_kind"],
                   "result_type": contract["result_type"], "object": object_var,
                   "contract_citation": contract["citation"],
                   "build_config_evidence": cfg["evidence"],
                   "build_config_citation": cfg["citation"],
                   "evidence_source": evidence_source,
                   "resolution_scope": cfg["resolution_scope"],
                   "resolved_target_name": cfg["resolved_target_name"],
                   "package_wide_diagnostic": cfg["package_wide_diagnostic"]}
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
