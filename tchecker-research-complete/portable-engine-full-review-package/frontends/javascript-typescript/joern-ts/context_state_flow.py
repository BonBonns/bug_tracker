#!/usr/bin/env python3
"""JS-PROV-R12 — Context State-Flow Join.

Joins middleware context WRITES to downstream READS within an established
framework registration.

FROZEN INVARIANT (JS-PROV-R11, source-confirmed on Corpus B)
------------------------------------------------------------
State provenance does NOT live at the object level. `ctx.validatedData` is a
CONTAINER whose members can have genuinely different origins:

    ctx.validatedData.email  <- validate(schema)          <- DERIVED_FROM_HTTP_BODY
    ctx.validatedData.user   <- forgot-password validator <- DB_LOOKUP

The unit of provenance is therefore:

    (context identity, property path, writer middleware, origin family,
     write strength, ordering)

never `ctx.validatedData -> HTTP_BODY`.

PROOF RULE (deliberately narrow)
--------------------------------
    same established route (FrameworkRegistrationFact)
  + same established Koa context identity (parameter index 1, positional)
  + compatible property path (prefix semantics, below)
  + writer executes BEFORE next()
  + reader is in a DOWNSTREAM callback position
  + writer identity is ESTABLISHED (defined, non-external METHOD)
  -> candidate state flow

STRENGTH (classified separately, never merged into the rule)
    unconditional write before next   -> MUST_WRITE
    conditional/nested write before next -> MAY_WRITE
    write after next                  -> cannot establish downstream availability

PROPERTY-PATH PREFIX SEMANTICS
------------------------------
    writer=validatedData        reader=validatedData.email     COMPATIBLE (whole-object write)
    writer=validatedData.user   reader=validatedData.email      INCOMPATIBLE (siblings)
    writer=validatedData.user   reader=validatedData.user.id    COMPATIBLE (ancestor write)
    writer=validatedData.user.id reader=validatedData.user      INCOMPATIBLE (writer is a
                                                                descendant; it does not
                                                                establish the parent)

i.e. a write establishes a read iff writer_path is a PREFIX of reader_path.

The context parameter is identified POSITIONALLY (index 1 after Joern's
implicit `this`), never by name -- `ctx`, `c`, `a`, `banana` all behave alike.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from framework_registration import derive as derive_regs  # noqa: E402
from module_specifier_resolution import derive as derive_modexp  # noqa: E402
from transform_input_origin import build as _tio_build, build_exprs as _tio_exprs, classify as _tio_classify  # noqa: E402


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) == n:
            out.append(xs)
    return out


def _is_prefix(writer_path, reader_path):
    """writer establishes reader iff writer_path is a path-prefix of reader_path."""
    w = writer_path.split(".")
    r = reader_path.split(".")
    return len(w) <= len(r) and r[: len(w)] == w


def derive(raw):
    raw = Path(raw)
    regs = derive_regs(raw)["registrations"]

    # method_fullname -> [param rows]; used for the stub gate (R10 prerequisite)
    params_by_method = {}
    for m, idx, name, ty, hint in _rows(raw / "method_params.tsv", 5):
        params_by_method.setdefault(m, []).append((int(idx), name, ty))

    # A callback identity is ESTABLISHED only if it resolves to a DEFINED method.
    # A generic (p0,p1,p2) stub signature is the observable marker of an external
    # stub resolution -- the shared root cause of R10's `42 as any` false
    # positive and its wrapper-resolution error.
    def is_defined_method(fullname):
        ps = params_by_method.get(fullname)
        if not ps:
            return False
        names = [n for i, n, _ in sorted(ps) if i > 0]
        if not names:
            return False
        return not all(n.startswith("p") and n[1:].isdigit() for n in names)

    # callback arguments per registration call
    # JS-PROV-R15: ModuleExportIdentityFact, keyed by the ARGUMENT call's own id.
    # For a require-crossing call the explicit module/export identity is PREFERRED
    # over the frontend's callee inference, which JS-PROV-R13 measured as
    # fabricating a same-file callee. Callback identity is never broadened by
    # filename or name coincidence -- only an exact call-id match is used.
    modexp = {}
    for f in derive_modexp(raw)["facts"]:
        modexp[f["call_id"]] = f

    # JS-PROV-R30 (INTEGRATION ONLY): a callback argument may be a FIELD ACCESS
    # on an imported module object -- `router.get('/x', ctrl.get)` where
    # `ctrl = require('../controllers/x')`. Resolve (file, base local, member)
    # through the SAME export facts R14/R25 already produce. R14/R25 semantics
    # are unmodified; this only reads them.
    #
    # Keyed on the ESTABLISHED export record, never on the mere presence of an
    # import: a member the target module does not actually export resolves to
    # nothing, and the callback stays unidentified (JS-PROV-R25 negative control).
    _exports = {}
    for row in _rows(raw / "module_exports.tsv", 7):
        _exports.setdefault(row[0], {})[row[1]] = (row[2], row[3])
    # JS-PROV-R33 (SOUNDNESS): a local bound by `require(spec).member` denotes
    # the MEMBER, not the module. `require_bindings.tsv` records only
    # `local -> spec`, which is FALSE for such locals -- consumers would look
    # members up in the wrong module and, where names overlap, fabricate an
    # identity. Read the opt-in selector file and REFUSE those locals as module
    # bindings. Abstention, not resolution: resolving `local` to the member's
    # own module requires JS-PROV Defect B, which is out of scope here.
    _selected = set()
    for _r in _rows(raw / "require_member_selection.tsv", 5):
        _selected.add((_r[0], _r[1]))
    _modlocal = {}
    for f_, spec_, local_, cid_ in _rows(raw / "require_bindings.tsv", 4):
        if local_ and (f_, local_) not in _selected:
            _modlocal[(f_, local_)] = spec_
    import posixpath as _pp

    def _cands(f_, spec_):
        def v(c):
            return [c + ".js", c + ".ts", _pp.join(c, "index.js"),
                    _pp.join(c, "index.ts"), c]
        if spec_.startswith("."):
            b = _pp.dirname(f_)
            return v(_pp.normpath(_pp.join(b, spec_)) if b else _pp.normpath(spec_))
        return v(_pp.normpath(spec_))

    # JS-PROV-R36: consume R35's alias + R36's selector resolution so a callback
    # written `ctrl.get`, where `ctrl = require("../controllers").articles`,
    # reaches the controller's own declaration. Both joins are derived from
    # require bindings; neither guesses a module.
    _r36_alias = {}
    for _a in _rows(raw / "export_member_alias.tsv", 3):
        _r36_alias[(_a[0], _a[1])] = _a[2]
    _r36_sel = {}
    for _a in _rows(raw / "require_member_selection.tsv", 5):
        _r36_sel[(_a[0], _a[1])] = (_a[2], _a[3])

    def _r36_alias_target(file_, member):
        rn = _r36_alias.get((file_, member))
        if rn is None:
            return None
        sp = _modlocal.get((file_, rn))
        if sp is None:
            return None
        return next((c for c in _cands(file_, sp) if c in _exports), None)

    def _r36_selector_target(file_, local):
        got = _r36_sel.get((file_, local))
        if got is None:
            return None
        sp, mem = got
        outer = next((c for c in _cands(file_, sp) if c in _exports), None)
        if outer is None or mem not in _exports.get(outer, {}):
            return None          # unresolved member -> abstain, no outer fallback
        return _r36_alias_target(outer, mem)

    def resolve_module_member(file_, code_):
        """`ctrl.get` -> the METHOD that module exports as `get`, or None."""
        parts = (code_ or "").strip().split(".")
        if len(parts) < 2:
            return None
        base, member = parts[0], parts[-1]
        # R36: the base may be a SELECTOR binding (`require(x).member`), which
        # R33 correctly refuses to treat as a module binding. Resolve it here.
        tgt_sel = _r36_selector_target(file_, base)
        if tgt_sel is not None:
            entry_s = _exports.get(tgt_sel, {}).get(member)
            if entry_s and entry_s[0] and entry_s[1] != "BLOCK":
                return {"exported_method": entry_s[0], "target_file": tgt_sel,
                        "exported_member": member}
            return None
        spec = _modlocal.get((file_, base))
        if spec is None:
            return None
        tgt = next((c for c in _cands(file_, spec) if c in _exports), None)
        if tgt is None:
            return None
        entry = _exports[tgt].get(member)
        if entry is None or not entry[0] or entry[1] == "BLOCK":
            return None                      # not an ESTABLISHED export member
        return {"exported_method": entry[0], "target_file": tgt,
                "exported_member": member}

    cbs_file = {}
    for row in _rows(raw / "registrations.tsv", 9):
        cbs_file[int(row[0])] = row[3].split("::")[0]

    cbs = {}
    for cid, cname, aidx, node, code, resolved, ftype, aid in _rows(raw / "callback_args.tsv", 8):
        entry = {"index": int(aidx), "node": node, "code": code, "resolved": resolved,
                 "identity_source": "FRONTEND_CALLEE"}
        me = modexp.get(int(aid))
        if me is None and node == "CALL" and "." in code:
            mm = resolve_module_member(cbs_file.get(int(cid), ""), code)
            if mm:
                entry["resolved"] = mm["exported_method"]
                entry["identity_source"] = "MODULE_EXPORT_IDENTITY"
                entry["exported_member"] = mm["exported_member"]
                entry["target_file"] = mm["target_file"]
        if me is not None:
            target = me.get("returned_function") or me.get("exported_method")
            if target:
                entry["resolved"] = target
                entry["identity_source"] = "MODULE_EXPORT_IDENTITY"
                entry["exported_member"] = me["exported_member"]
                entry["target_file"] = me["target_file"]
        cbs.setdefault(int(cid), []).append(entry)

    # context writes/reads per method
    writes, reads = {}, {}
    for m, kind, path, src, order, nextord, cond in _rows(raw / "ctx_state.tsv", 7):
        rec = {"method": m, "path": path, "source": src, "order": int(order),
               "next_order": int(nextord), "conditional": cond.strip().lower() == "true"}
        (writes if kind == "WRITE" else reads).setdefault(m, []).append(rec)

    # JS-PROV-R19: origin evidence for a write's RHS, via JS-PROV-R17/R18.
    # Carried through the join UNCHANGED -- a reader inherits the writer's
    # transform-input evidence but NEVER an upgraded origin_family, and
    # output_origin_established never becomes true by propagation.
    _defs, _exprs = _tio_build(raw), _tio_exprs(raw)
    _ctx_by_method = {}
    for m, idx, name, ty, hint in _rows(raw / "method_params.tsv", 5):
        if int(idx) == 1:
            _ctx_by_method[m] = name

    def origin_evidence(method, src):
        ctx_names = [_ctx_by_method.get(method, "ctx")]
        try:
            return _tio_classify(_defs, method, (src or "").strip(), ctx_names, _exprs)
        except Exception:
            return {"origin_family": "UNKNOWN", "transform_input_origins": [],
                    "unconstrained_input": True, "transform": None,
                    "output_origin_established": False}

    def origin_family(src):
        s = (src or "")
        if ".request.body" in s or s.endswith(".body"):
            return "HTTP_BODY" if s.count("(") == 0 else "DERIVED_FROM_HTTP_BODY"
        if ".query" in s:
            return "HTTP_QUERY" if s.count("(") == 0 else "DERIVED_FROM_HTTP_QUERY"
        if s.startswith('"') or s.startswith("'"):
            return "NO_EXTERNAL_ORIGIN"
        return "UNKNOWN"

    flows, abstentions = [], []
    for reg in regs:
        cid = reg["registration_call_id"]
        callbacks = sorted([c for c in cbs.get(cid, []) if c["index"] >= 2],
                           key=lambda c: c["index"])
        for w_pos, wcb in enumerate(callbacks):
            wm = wcb["resolved"]
            if not is_defined_method(wm):
                abstentions.append({"registration": cid, "writer_arg": wcb["index"],
                                    "reason": "WRITER_IDENTITY_UNKNOWN_OR_STUB",
                                    "resolved": wm[:60]})
                continue
            for wr in writes.get(wm, []):
                # ordering vs next(): a write after next() cannot be seen downstream
                if wr["next_order"] == -1:
                    rel = "NO_NEXT"
                elif wr["order"] < wr["next_order"]:
                    rel = "BEFORE_NEXT"
                else:
                    rel = "AFTER_NEXT"
                if rel != "BEFORE_NEXT":
                    abstentions.append({"registration": cid, "writer": wm, "path": wr["path"],
                                        "reason": f"WRITE_{rel}_NOT_AVAILABLE_DOWNSTREAM"})
                    continue
                # reader must be in a DOWNSTREAM callback position on the SAME route
                for r_pos, rcb in enumerate(callbacks):
                    if r_pos <= w_pos:
                        continue
                    rm = rcb["resolved"]
                    if not is_defined_method(rm):
                        continue
                    for rd in reads.get(rm, []):
                        if not _is_prefix(wr["path"], rd["path"]):
                            continue
                        _oe = origin_evidence(wm, wr["source"])
                        flows.append({
                            "registration_call_id": cid,
                            "route_verb": reg["verb"],
                            "framework_family": reg["framework_family"],
                            "writer_method": wm, "writer_arg_index": wcb["index"],
                            "writer_identity_source": wcb.get("identity_source"),
                            "writer_path": wr["path"], "writer_source": wr["source"],
                            "origin_family": _oe["origin_family"],
                            "origin_families": _oe.get("origin_families", []),
                            "transform_input_origins": _oe["transform_input_origins"],
                            "transform": _oe["transform"],
                            "output_origin_established": _oe["output_origin_established"],
                            "unconstrained_input": _oe["unconstrained_input"],
                            "origin_evidence_carried_from_writer": True,
                            "relative_to_next": rel,
                            "reader_method": rm, "reader_arg_index": rcb["index"],
                            "reader_path": rd["path"],
                            "path_relation": ("EXACT" if wr["path"] == rd["path"]
                                              else "ANCESTOR_WRITE"),
                            "resolution": "MAY" if wr["conditional"] else "MUST",
                            # JS-PROV-R19: TWO INDEPENDENT AXES. State-flow
                            # certainty must never imply origin certainty.
                            "state_flow_strength": "MAY" if wr["conditional"] else "MUST",
                            "origin_strength": (
                                "ESTABLISHED" if _oe["output_origin_established"]
                                else ("TRANSFORM_INPUT_ONLY" if _oe["transform_input_origins"]
                                      else "UNKNOWN")),
                            "matched_writer": wm,
                            "writer_specificity": len(wr["path"].split(".")),
                        })
    # JS-PROV-R19 writer precedence: for a given (reader, read path), the MOST
    # SPECIFIC prefix-matching writer shadows broader ones. A `.user` write must
    # not leave a `.user` read also inheriting the whole-object writer's
    # evidence. Broader flows are RETAINED but marked shadowed, so the
    # precedence decision stays inspectable rather than silently dropping data.
    best = {}
    for f in flows:
        k = (f["registration_call_id"], f["reader_method"], f["reader_path"])
        if f["writer_specificity"] > best.get(k, -1):
            best[k] = f["writer_specificity"]
    for f in flows:
        k = (f["registration_call_id"], f["reader_method"], f["reader_path"])
        f["effective"] = f["writer_specificity"] == best[k]
        f["shadowed_by_more_specific_writer"] = not f["effective"]

    return {
        "schema": "portable-context-state-flow/0.2",
        "note": ("Property-path granular. A write establishes a read only if the writer "
                 "path is a PREFIX of the reader path; siblings never join. Scoped to a "
                 "single established registration; context identity is positional "
                 "(parameter index 1), never by name. AFTER_NEXT writes never establish "
                 "downstream availability. Conditional writes yield MAY, never MUST."),
        "flows": flows,
        "abstentions": abstentions,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2, default=str))
