#!/usr/bin/env python3
"""Capability 3 -- advancing-pointer STRUCT-MEMBER writes  (NO model calls).

The uncovered remainder from CAP3_DOMAIN_AUDIT.md: a write through an ADVANCING pointer
whose target is a struct/union MEMBER (`p->field = ...` / `p.field = ...`) with the
pointer advanced separately (`p++` / `++p` / `p += 1`). This is the PNG003
`png_handle_PLTE` palette-population shape, which the frozen cursor producer
(`oob_cursor_write_verdict`, dereference-syntax + byte-buffer only) does not model.

SCOPE (deliberately narrow):
  * OWNS only advancing-pointer struct-member writes `p->field = x` / `p.field = x`.
    It does NOT claim general "non-byte aggregate writes" -- e.g. `*p++ = struct_value`
    (whole-aggregate cursor writes) are NOT handled here and would need their own model
    and controls.
  * The pointer's declaration is resolved through Joern reference-target
    (`cap_write_site_dedup.resolve_dest_declaration`), never by name.
  * Capacity is bound ONLY from an independently-established fixed-array or literal-count
    allocation extent (element count). Unknown struct-field / parameter / alias / realloc /
    symbolic-allocation capacity stays UNRESOLVED (abstain), never assumed.
  * The cursor trajectory is examined explicitly: a single base binding, a single unit
    advance, a loop counter+bound, write-before-advance (no one-past), no reset, no alias
    conflict. Anything else abstains with a specific reason.
  * All member writes through ONE cursor (e.g. PNG003 red/green/blue) are ONE operation
    with ONE capacity obligation and ONE proof family -- NOT three independent families.

Additive: emits `attribution="direct"` records that flow through
`cap_write_site_dedup.dedup`, where the frozen PRECEDENCE keeps the cursor producer
canonical on any site it already recognizes (cursor_producer > direct > call_site_summary).
Never emits VULNERABLE.
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

import subprocess
from collections import defaultdict as _dd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
import cap_write_site_dedup as WSD

MEMBER_WRITE = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*[A-Za-z_]\w*\s*$")
INC_OPS = ("<operator>.postIncrement", "<operator>.preIncrement")
PLUS_OPS = ("<operator>.assignmentPlus",)
LT_OPS = ("<operator>.lessThan", "<operator>.lessEqualsThan")
GT_OPS = ("<operator>.greaterThan", "<operator>.greaterEqualsThan")
NE_OPS = ("<operator>.notEquals",)
CMP_SYM = {"<operator>.lessThan": "<", "<operator>.lessEqualsThan": "<=",
           "<operator>.greaterThan": ">", "<operator>.greaterEqualsThan": ">=",
           "<operator>.notEquals": "!="}
DEC_OPS = ("<operator>.postDecrement", "<operator>.preDecrement")
MINUS_OPS = ("<operator>.assignmentMinus",)
INT_RE = re.compile(r"^\s*[+-]?\d+\s*$")
UNSIGNED_HINTS = ("unsigned", "size_t", "uint")


def _lit(s):
    s = (s or "").strip()
    return int(s) if INT_RE.match(s) else None


def _cmp(a, sym, b):
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "!=": a != b}[sym]


def _trip_count(i0, sym, bound, step):
    """CLOSED-FORM trip count (number of body executions) for a literal counter loop
    `for (i=i0; i OP bound; i+=step)`, computed over MATHEMATICAL integers in O(1) -- NO
    simulation, so an astronomically large literal bound cannot cause analysis-time DoS.
    Returns: an int >= 0 (exact count); the string 'infinite' (loop never terminates in the
    ideal integer model -- it writes without bound, so it exceeds any finite capacity); or
    None (a comparison/step combination this closed form does not resolve -> abstain).
    NOTE: this is the IDEAL-integer count; C wrap/overflow safety is proven separately by the
    caller before any deterministic promotion (a wrapping counter is NOT modeled here)."""
    if step == 0:
        return "infinite" if _cmp(i0, sym, bound) else 0
    if sym in ("<", "<="):
        if not _cmp(i0, sym, bound):
            return 0
        if step < 0:                      # condition true but moving away -> never exits
            return "infinite"
        span = bound - i0 + (1 if sym == "<=" else 0)
        return (span + step - 1) // step  # ceil(span/step), span>0 here
    if sym in (">", ">="):
        if not _cmp(i0, sym, bound):
            return 0
        if step > 0:
            return "infinite"
        st = -step
        span = i0 - bound + (1 if sym == ">=" else 0)
        return (span + st - 1) // st
    if sym == "!=":
        if i0 == bound:
            return 0
        diff = bound - i0
        if diff % step == 0 and diff // step > 0:  # lands exactly on bound, moving toward it
            return diff // step
        return "infinite"                 # steps over / away from bound -> never equals it
    return None


_INT_WIDTH = (("long long", 64), ("int64", 64), ("uint64", 64), ("size_t", 64),
              ("ssize_t", 64), ("ptrdiff", 64), ("intptr", 64),
              ("short", 16), ("int16", 16), ("uint16", 16),
              ("char", 8), ("int8", 8), ("uint8", 8),
              ("long", 64), ("int32", 32), ("uint32", 32), ("int", 32))


def _counter_range(name, index, fid):
    """Representable range of the counter's declared C type as (min, max, unsigned:bool),
    or None if the type is unknown/unrecognized (then no-overflow cannot be proven -> the
    caller stays conservative). Resolved from the counter's parameter/local type_full_name."""
    t = None
    f = index["funcs"].get(fid, {})
    for p in (f.get("parameters") or []):
        if p.get("name") == name:
            t = p.get("type_full_name"); break
    if t is None:
        for l in index["locals_by_id"].values():
            if l.get("method_id") == fid and l.get("name") == name:
                t = l.get("type_full_name"); break
    if not t:
        return None
    tl = t.lower()
    unsigned = ("unsigned" in tl) or ("uint" in tl) or ("size_t" in tl)
    width = next((w for key, w in _INT_WIDTH if key in tl), None)
    if width is None:
        return None
    if unsigned:
        return (0, (1 << width) - 1, True)
    return (-(1 << (width - 1)), (1 << (width - 1)) - 1, False)


def _cursor_start_offset(base_binding_call):
    """Cursor start offset from `cursor = <base>` : `array` -> 0, `array + k` -> k,
    `&array[k]` -> k (literal k only). Returns (offset:int or None, reason)."""
    a = sorted(base_binding_call.get("arguments", []), key=lambda x: x.get("index", 0))
    if len(a) < 2:
        return None, "base_binding_unreadable"
    rhs = WSD._norm_code(a[1].get("code") or "")
    if re.fullmatch(r"[A-Za-z_]\w*", rhs):
        return 0, "array_base"
    m = re.fullmatch(r"[A-Za-z_]\w*\s*\+\s*(\d+)", rhs)
    if m:
        return int(m.group(1)), "array_plus_literal"
    m = re.fullmatch(r"&\s*[A-Za-z_]\w*\s*\[\s*(\d+)\s*\]", rhs)
    if m:
        return int(m.group(1)), "addr_of_indexed_literal"
    return None, "cursor_offset_unresolved"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


def load_for_structure(cpp):
    """FOR control-structure AST membership from the CPG (a SEPARATE analysis on cpg.bin,
    NOT a change to the frozen exporter). Returns a dict {by_method, witnesses, cpg_sha,
    cpp_sha} or None if unavailable (fail closed). cpg.bin is a sibling of cpp.json; the
    result is cached next to it as for_structure.json and re-generated if the cpg.bin sha
    changed (stale-artifact protection). The `witnesses` are (node_id, code) pairs from the
    CPG that analyze_member_walks re-checks against cpp.json as a SEMANTIC CONSISTENCY witness;
    the full cross-artifact binding is the two-file SHA-256 manifest (both cpg_sha and cpp_sha),
    re-verified against the live files at analysis time (node ids mean nothing across CPGs)."""
    out_dir = os.path.dirname(os.path.abspath(cpp))
    fs_json = os.path.join(out_dir, "for_structure.json")
    cpg = os.path.join(out_dir, "cpg.bin")
    if not os.path.exists(cpg):
        return None
    cpg_sha = _sha256(cpg)
    cpp_sha = _sha256(cpp)
    cached = None
    if os.path.exists(fs_json):
        try:
            cached = json.load(open(fs_json))
        except Exception:
            cached = None
    # (re)generate if missing or the cached artifact is bound to a different cpg.bin
    if not (isinstance(cached, dict) and cached.get("cpg_sha") == cpg_sha):
        joern = os.environ.get("JOERN", "/tmp/joern-cli/joern")
        sc = os.path.join(HERE, "export_for_structure.sc")
        raw_out = fs_json + ".raw"
        try:
            subprocess.run([joern, "--script", sc, "--param", f"cpgFile={cpg}",
                            "--param", f"outFile={raw_out}"],
                           capture_output=True, text=True, timeout=900)
        except Exception:
            return None
        if not os.path.exists(raw_out):
            return None
        try:
            raw = json.load(open(raw_out))
        except Exception:
            return None
        cached = {"cpg_sha": cpg_sha, "cpp_sha": cpp_sha, "fors": raw}
        json.dump(cached, open(fs_json, "w"))
    by_method = _dd(list)
    witnesses = []
    for r in cached["fors"]:
        by_method[r["method"]].append(
            {"for_id": r["for_id"], "init": set(r.get("init", [])),
             "cond": set(r["cond"]), "update": set(r["update"]), "body": set(r["body"])})
        if r.get("witness_id", -1) != -1:
            witnesses.append((r["witness_id"], r.get("witness_code", "")))
    # Return the PERSISTED manifest hashes (what was recorded when the structural facts were
    # generated), so analyze_member_walks can re-verify BOTH the current cpp.json and the
    # current cpg.bin against them -- a genuine two-file binding manifest, not just witnesses.
    return {"by_method": dict(by_method), "witnesses": witnesses,
            "cpg_sha": cached["cpg_sha"], "cpp_sha": cached["cpp_sha"]}


def _resolve(idid, ident_by_id):
    ident = ident_by_id.get(idid)
    refs = (ident.get("ref_target_ids") if ident else None) or []
    return refs[0] if len(refs) == 1 else None


def _decl_of_name_use(call, index):
    """Resolve the identifier at a call's arg0 root to its declaration node via ref-target."""
    args = sorted(call.get("arguments", []), key=lambda a: a.get("index", 0))
    if not args:
        return None
    idid = WSD._descend_to_identifier(args[0], index["call_by_id"])
    return _resolve(idid, index["ident_by_id"])


def _base_capacity(base_decl_node, base_binding_call, index, d, stack_ext, heap_ext):
    """Independently-established capacity (element count) of the cursor's base, or
    (None, reason). Only fixed arrays and literal-count allocations qualify."""
    # base binding RHS: cursor = <X>
    args = sorted(base_binding_call.get("arguments", []), key=lambda a: a.get("index", 0))
    if len(args) < 2:
        return None, "base_binding_unreadable"
    rhs = args[1]
    rhs_code = (rhs.get("code") or "").strip()
    # X an identifier referencing a fixed array local?
    rid = WSD._descend_to_identifier(rhs, index["call_by_id"])
    rdecl = _resolve(rid, index["ident_by_id"]) if rid else None
    fid = base_binding_call.get("enclosing_function_id")
    if rdecl is not None and (fid, rdecl) in stack_ext:
        e = stack_ext[(fid, rdecl)]
        return {"element_count": e["element_count"], "element_type": e["element_type"],
                "provenance": "stack_fixed_array"}, "ok"
    # X a literal-count allocation bound to the cursor's base name?
    he = heap_ext.get((fid, WSD._root_ident(rhs_code)))
    if he and he.get("establishment_status") == "ESTABLISHED" and isinstance(he.get("element_count"), int):
        return {"element_count": he["element_count"], "element_type": he.get("element_type"),
                "provenance": "heap_literal_allocation"}, "ok"
    # struct-field / parameter / alias / realloc / symbolic alloc -> unresolved
    return None, "capacity_of_base_unresolved"


def _is_unsigned(bound_code, index, fid):
    """Is the loop bound provably non-negative (unsigned type)?"""
    for f in [index["funcs"].get(fid, {})]:
        for p in (f.get("parameters") or []):
            if p.get("name") == bound_code:
                t = (p.get("type_full_name") or "").lower()
                return any(h in t for h in UNSIGNED_HINTS)
    for l in index["locals_by_id"].values():
        if l.get("method_id") == fid and l.get("name") == bound_code:
            t = (l.get("type_full_name") or "").lower()
            return any(h in t for h in UNSIGNED_HINTS)
    return False


def analyze_member_walks(cpp, for_struct="AUTO"):
    d = json.load(open(cpp))
    if for_struct == "AUTO":
        for_struct = load_for_structure(cpp)   # None -> fail closed downstream
    index = WSD.build_index(d)
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    heap_ext = AE.compute_allocation_extents(d)
    calls_by_fn = defaultdict(list)
    call_by_id = {}
    for c in d.get("calls", []):
        calls_by_fn[c.get("enclosing_function_id")].append(c)
        call_by_id[c.get("id")] = c
    fns = index["funcs"]

    # HASH-BOUND CPG WITH SEMANTIC WITNESSES. Two independent checks bind the facts:
    #  (a) TWO-FILE BINDING MANIFEST: the structural facts record the SHA-256 of BOTH the
    #      cpp.json AND the cpg.bin they were generated from; here we recompute both current
    #      files and require an exact match, so a swapped/edited cpp.json or cpg.bin is caught.
    #  (b) SEMANTIC WITNESSES: per-FOR condition (node_id, code) pairs from the CPG, re-checked
    #      against cpp.json's calls -- node ids are meaningful only within one CPG generation,
    #      so this catches same-hash-manifest-but-wrong-generation node id reuse.
    # Any failure -> binding="mismatch" -> fail closed.
    by_method, binding = {}, "unavailable"
    if for_struct is not None:
        by_method = for_struct.get("by_method", {})
        binding = "ok"
        man_cpp, man_cpg = for_struct.get("cpp_sha"), for_struct.get("cpg_sha")
        cur_cpp = _sha256(cpp) if isinstance(cpp, str) and os.path.exists(cpp) else None
        cpg_path = (os.path.join(os.path.dirname(os.path.abspath(cpp)), "cpg.bin")
                    if isinstance(cpp, str) else None)
        cur_cpg = _sha256(cpg_path) if cpg_path and os.path.exists(cpg_path) else None
        if (man_cpp is not None and cur_cpp is not None and man_cpp != cur_cpp) or \
           (man_cpg is not None and cur_cpg is not None and man_cpg != cur_cpg):
            binding = "mismatch"
        else:
            for wid, wcode in for_struct.get("witnesses", []):
                c = call_by_id.get(wid)
                if c is None or WSD._norm_code(c.get("code")) != WSD._norm_code(wcode):
                    binding = "mismatch"
                    break

    # 1. member-write calls grouped by (function, resolved cursor decl node)
    groups = defaultdict(list)
    for c in d.get("calls", []):
        if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
            continue
        tgt = (sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "")
        if not MEMBER_WRITE.match(tgt):
            continue
        cursor_decl = _decl_of_name_use(c, index)
        if cursor_decl is None:
            continue
        groups[(c.get("enclosing_function_id"), cursor_decl)].append(c)

    ops = []
    for (fid, cursor_decl), writes in groups.items():
        body = calls_by_fn[fid]
        cursor_name = WSD._root_ident(
            (sorted(writes[0]["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or ""))

        # 2. advances of THIS cursor (resolved via ref-target)
        advances = []
        for c in body:
            if c.get("name") in INC_OPS + PLUS_OPS and c.get("arguments"):
                if _decl_of_name_use(c, index) == cursor_decl:
                    advances.append(c)
        # 3. base bindings: cursor = X  (LHS ref-> cursor_decl, not a member/deref target)
        base_bindings = []
        for c in body:
            if c.get("name") != "<operator>.assignment" or not c.get("arguments"):
                continue
            a = sorted(c["arguments"], key=lambda x: x.get("index", 0))
            lhs = (a[0].get("code") or "").strip()
            if lhs == cursor_name and _decl_of_name_use(c, index) == cursor_decl:
                base_bindings.append(c)

        member_ids = [WSD.physical_write_identity(c, index)[0] for c in writes]
        member_nodes = [c.get("id") for c in writes]
        # family: ONE per cursor obligation (base shape x bound shape), NOT per member write
        rec = {"capability": "member_pointer_walk", "attribution": "direct",
               "function": fns.get(fid, {}).get("name"), "cursor": cursor_name,
               "cursor_decl_node": cursor_decl,
               "member_writes": member_ids, "n_member_writes": len(writes),
               "member_write_nodes": member_nodes,
               "line": min(c.get("line") for c in writes)}

        def emit(route, reason, disposition=None, **extra):
            sig = f"member_pointer_walk|{extra.get('base_prov','?')}|{extra.get('bound_shape','?')}"
            rec.update(route=route, reason=reason, disposition=disposition,
                       family_signature=sig,
                       family_id="fam_" + hashlib.sha256(sig.encode()).hexdigest()[:12],
                       **extra)
            ops.append(rec)

        # ---- trajectory gates (abstain with a specific reason) ---------------------------
        # No advance at all -> a single struct-member write, NOT a pointer WALK -> outside
        # capability 3's domain entirely; emit nothing (additive).
        if len(advances) == 0:
            continue
        if len({(_decl_of_name_use(bb, index)) for bb in base_bindings}) == 0:
            emit("additional_evidence_required", "capacity_of_base_unresolved",
                 base_prov="no_base_binding"); continue
        distinct_bases = {WSD._norm_code(
            sorted(bb["arguments"], key=lambda a: a.get("index", 0))[1].get("code") or "")
            for bb in base_bindings}
        if len(base_bindings) > 1 and len(distinct_bases) > 1:
            emit("additional_evidence_required", "destination_identity_ambiguous",
                 detail="cursor base bound from multiple distinct sources (alias conflict/reset)")
            continue
        if len(base_bindings) > 1:
            emit("additional_evidence_required", "cursor_trajectory_reset",
                 detail="cursor re-based more than once"); continue
        if len(advances) != 1:
            emit("additional_evidence_required", "cursor_advance_ambiguous",
                 detail=f"{len(advances)} advance sites (multiple/conditional increments)")
            continue
        adv = advances[0]
        # unit stride only: p++ / ++p, or p += 1
        if adv.get("name") in PLUS_OPS:
            aargs = sorted(adv["arguments"], key=lambda a: a.get("index", 0))
            stride = (aargs[1].get("code") or "").strip() if len(aargs) > 1 else "?"
            if stride != "1":
                emit("additional_evidence_required", "cursor_advance_non_unit",
                     detail=f"stride {stride}"); continue

        # capacity of the base (established array / literal allocation only)
        cap, why = _base_capacity(cursor_decl, base_bindings[0], index, d, stack_ext, heap_ext)
        if cap is None:
            emit("additional_evidence_required", why, base_prov="unresolved"); continue

        # ---- STRUCTURAL trajectory proof via the CPG/AST (NOT source-line coincidence) ---
        # Fail closed if the control-structure facts are unavailable or not bound to this cpp.
        if for_struct is None or binding == "unavailable":
            emit("additional_evidence_required", "for_structure_unavailable",
                 base_prov=cap["provenance"],
                 detail="CPG control-structure facts required for a structural proof"); continue
        if binding == "mismatch":
            emit("additional_evidence_required", "for_structure_cpp_cpg_mismatch",
                 base_prov=cap["provenance"],
                 detail="cpp.json and cpg.bin witnesses disagree (stale/mismatched artifacts)")
            continue
        fors = by_method.get(fns.get(fid, {}).get("name"), [])
        adv_id = adv.get("id")
        # (2) the increment must be inside a FOR's UPDATE component (proven, not line-based)
        the_for = next((F for F in fors if adv_id in F["update"]), None)
        if the_for is None:
            in_body = any(adv_id in F["body"] for F in fors)
            emit("additional_evidence_required",
                 "cursor_advance_in_loop_body_not_update" if in_body
                 else "cursor_advance_not_in_structured_for",
                 base_prov=cap["provenance"],
                 detail="increment is not in a for-loop UPDATE component "
                        "(conditional / body increment / while-loop / macro)"); continue
        # (3) all member writes must be in THAT for's BODY component
        if not all(c.get("id") in the_for["body"] for c in writes):
            emit("additional_evidence_required", "member_writes_not_in_loop_body",
                 base_prov=cap["provenance"],
                 detail="a member write is not in the same for-loop's body"); continue
        # (4) write-before-update is established by the for-loop's structured semantics:
        #     the UPDATE component executes AFTER the BODY on every iteration.
        rec["proof"] = {"for_id": the_for["for_id"], "advance_in_update": True,
                        "writes_in_body": True, "write_before_update": "for_structured_semantics"}

        cap_n = cap["element_count"]
        # loop-condition comparison in THIS for's CONDITION component: op + counter + bound
        cond_cmp = next((c for c in body if c.get("id") in the_for["cond"]
                         and c.get("name") in (LT_OPS + GT_OPS + NE_OPS) and c.get("arguments")),
                        None)
        if cond_cmp is None:
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="no_loop_bound"); continue
        ca = sorted(cond_cmp["arguments"], key=lambda x: x.get("index", 0))
        counter = WSD._root_ident(ca[0].get("code") or "")
        bound_code = (ca[1].get("code") or "").strip() if len(ca) > 1 else ""
        sym = CMP_SYM[cond_cmp["name"]]

        # PROVE THE ITERATION COUNT (not just the bound token): need literal bound, literal
        # counter init in the for-INIT, a single unit/step counter update in the for-UPDATE,
        # the counter NOT modified in the body, and a literal cursor start offset.
        offset, off_reason = _cursor_start_offset(base_bindings[0])
        i0 = None
        for c in body:  # counter init inside the for-INIT
            if (c.get("id") in the_for["init"] and c.get("name") == "<operator>.assignment"
                    and c.get("arguments")):
                a = sorted(c["arguments"], key=lambda x: x.get("index", 0))
                if WSD._root_ident(a[0].get("code") or "") == counter and len(a) > 1:
                    i0 = _lit(a[1].get("code")); break
        # counter step from the for-UPDATE (on the counter, not the cursor)
        step, step_ops = None, 0
        for c in body:
            if c.get("id") not in the_for["update"] or not c.get("arguments"):
                continue
            root = WSD._root_ident(c["arguments"][0].get("code") or "")
            if root != counter:
                continue
            if c.get("name") in INC_OPS:
                step, step_ops = 1, step_ops + 1
            elif c.get("name") in DEC_OPS:
                step, step_ops = -1, step_ops + 1
            elif c.get("name") in PLUS_OPS and len(c["arguments"]) > 1:
                step, step_ops = _lit(c["arguments"][1].get("code")), step_ops + 1
            elif c.get("name") in MINUS_OPS and len(c["arguments"]) > 1:
                k = _lit(c["arguments"][1].get("code"))
                step, step_ops = (-k if k is not None else None), step_ops + 1
        # counter modified in the BODY (breaks a clean count) -> abstain
        counter_in_body = any(
            c.get("id") in the_for["body"] and (
                (c.get("name") in (INC_OPS + DEC_OPS + PLUS_OPS + MINUS_OPS) and c.get("arguments")
                 and WSD._root_ident(c["arguments"][0].get("code") or "") == counter)
                or (c.get("name") == "<operator>.assignment" and c.get("arguments")
                    and WSD._root_ident(sorted(c["arguments"], key=lambda a: a.get("index", 0))[0].get("code") or "") == counter))
            for c in body)

        bound_lit = _lit(bound_code)
        exact = (bound_lit is not None and i0 is not None and step is not None
                 and step_ops == 1 and offset is not None and not counter_in_body)
        if not exact:
            # cannot prove the exact iteration count -> conservative OPEN CANDIDATE flag,
            # never a false safe. Record why the count is not exactly provable.
            if counter_in_body:
                shape = "counter_modified_in_body"
            elif bound_lit is None:
                arithmetic = not re.match(r"^[A-Za-z_]\w*$", bound_code)
                shape = ("symbolic_expr" if arithmetic else
                         ("symbolic_unsigned" if _is_unsigned(bound_code, index, fid)
                          else "symbolic_signed"))
            elif offset is None:
                shape = "cursor_offset_unresolved"
            elif step_ops != 1 or step is None:
                shape = "counter_step_ambiguous"
            else:
                shape = "counter_init_unresolved"
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape=shape,
                 iteration_count="not_provable", cursor_start_offset=offset); continue

        # CLOSED-FORM trip count (O(1), no simulation -> no DoS on a billion-sized bound).
        count = _trip_count(i0, sym, bound_lit, step)
        if count is None:
            # comparison/step combination not resolved by the closed form -> abstain.
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="trip_count_indeterminate",
                 iteration_count="not_provable", cursor_start_offset=offset); continue
        if count == "infinite":
            # never terminates over the integers -> writes without bound -> exceeds capacity.
            emit("range_arithmetic_review", "write_count_within_destination_capacity",
                 disposition="proven_oversized", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="nonterminating",
                 iteration_count="nonterminating", cursor_start_offset=offset,
                 note=f"loop does not terminate over the integers -> exceeds capacity {cap_n}")
            continue

        # C INTEGER SEMANTICS: the ideal count is trustworthy only if stepping the counter of
        # its declared type from i0 to the exit value cannot overflow/wrap, and the bound is
        # representable in that type (no signed<->unsigned conversion surprise). The counter
        # takes values i0 .. E (monotonic), where E = i0 + count*step is the first value that
        # fails the condition; bounding the endpoints bounds the whole trajectory. If the type
        # is unknown or any bound is exceeded, we CANNOT prove no-wrap -> stay conservative.
        rng = _counter_range(counter, index, fid)
        exit_val = i0 + count * step
        overflow_safe = (rng is not None
                         and rng[0] <= i0 <= rng[1]
                         and rng[0] <= exit_val <= rng[1]
                         and rng[0] <= bound_lit <= rng[1])
        if not overflow_safe:
            emit("open_candidate", "write_count_bound_not_established",
                 disposition="relationship_unresolved", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="counter_overflow_unproven",
                 iteration_count=count, cursor_start_offset=offset,
                 counter_type_range=(list(rng) if rng else None),
                 note="cannot prove the counter cannot overflow/wrap in its C type"); continue

        # write positions are offset, offset+1, ..., offset+count-1 (unit-advance cursor);
        # in-bounds iff offset + count <= capacity.
        if offset + count <= cap_n:
            emit("deterministic_complete", "write_count_within_destination_capacity",
                 disposition="deterministic_complete", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="literal_count",
                 iteration_count=count, cursor_start_offset=offset,
                 note=f"{count} writes at offset {offset} -> max index {offset+count-1} "
                      f"< capacity {cap_n}")
        else:
            emit("range_arithmetic_review", "write_count_within_destination_capacity",
                 disposition="proven_oversized", base_prov=cap["provenance"],
                 base_capacity=cap_n, bound_shape="literal_count",
                 iteration_count=count, cursor_start_offset=offset,
                 note=f"{count} writes at offset {offset} -> reaches index {offset+count-1} "
                      f">= capacity {cap_n}")
    return ops


if __name__ == "__main__":
    for o in analyze_member_walks(sys.argv[1]):
        print(json.dumps({k: o[k] for k in o if k != "member_writes"}, sort_keys=True))
