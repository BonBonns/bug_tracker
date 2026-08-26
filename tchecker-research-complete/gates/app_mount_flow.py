#!/usr/bin/env python3
"""JS-PROV-R38 — App-Mount Relation and App-Upstream-of-Router State Flow.

WHAT R37 MEASURED (the blocker this closes)
-------------------------------------------
The writer (`app.use(userMiddleware)`, APP-level) and the readers
(`router.get(..., ctrl.get)`, ROUTER-level) live in DIFFERENT registration
calls. R12's join is scoped to a single established registration -- its
preregistered tooth NEG-2 ("different route -> no join") is CORRECT and is
deliberately not weakened here. What was incomplete is the MODEL: Koa's
app-level middleware genuinely runs, per request, before any handler of a
router mounted on that app, and no relation expressed that.

THE NEW RELATION (a relation, not a fact)
-----------------------------------------
    MountFact:      app file A mounts router module F
                    via  app.use(<base>.routes())  at line L_mount
    Upstream order: app.use(<middleware>) in A at line L_mw JOINS routers of F
                    iff L_mw < L_mount           (registration order, same app)

EVIDENCE CHAIN (every hop is a recorded fact; nothing is guessed)
    <base>            is a require-bound local of A        (require_bindings)
    <base>'s spec     resolves to file F                   (R14 candidates)
    F's default export names local X                       (default_export_identifier, NEW)
    F's router regs   are ESTABLISHED KOA_ROUTER regs      (framework_registration)
                      whose receiver local == X            <- two-routers-one-file guard
    middleware        resolves to a DEFINED method through
                      F_mw's default METHOD_REF export     (module_exports)
    writes            BEFORE_NEXT only; conditional -> MAY (R12 semantics, unchanged)

PREREGISTERED TEETH (all four must hold; see gate_r38.py)
    T-POS   app.use middleware BEFORE the mount flows into EVERY mounted
            router's downstream readers (both routers in the fixture).
    T-NEG2  UNCHANGED: a route-scoped writer on router A never joins a reader
            on router B, same app, same property. R12's output is byte-identical.
    T-ORPH  a required-but-never-mounted router receives NO middleware flow.
    T-ORD   app.use registered AFTER the mount does not flow into it.

CEILING, STATED IN ADVANCE (so a result is not over-read)
    * A conditional middleware write yields MAY, never MUST -- app-upstream
      ordering certainty must not upgrade write-strength certainty
      (the R19 two-axes rule, applied across the mount).
    * Mount recognition covers `app.use(<router>.routes())` on a require-bound
      router local. `app.use(mount('/p', r))`, spread mounts, and routers
      passed through intermediate locals are ABSTAINED, never guessed.
    * Path-prefix mounts do not constrain matching here (Koa's koa-router
      .routes() dispatches by registered path, not by mount arg), so no
      path-based narrowing is fabricated.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE / "portable-engine-full-review-package/frontends/javascript-typescript/joern-ts"
sys.path.insert(0, str(PKG if PKG.exists() else HERE))
from framework_registration import derive as derive_regs  # noqa: E402
import posixpath as _pp  # noqa: E402


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


def _cands(f_, spec_):
    """R14 candidate resolution, unchanged from context_state_flow."""
    def v(c):
        return [c + ".js", c + ".ts", _pp.join(c, "index.js"),
                _pp.join(c, "index.ts"), c]
    if spec_.startswith("."):
        b = _pp.dirname(f_)
        return v(_pp.normpath(_pp.join(b, spec_)) if b else _pp.normpath(spec_))
    return v(_pp.normpath(spec_))


def _is_prefix(writer_path, reader_path):
    w, r = writer_path.split("."), reader_path.split(".")
    return len(w) <= len(r) and r[: len(w)] == w


def derive(raw):
    raw = Path(raw)
    regs = derive_regs(raw)["registrations"]

    order = {int(cid): (f, int(ln)) for cid, f, ln in _rows(raw / "registration_order.tsv", 3) if ln}
    reg_file = {}
    for r in _rows(raw / "registrations.tsv", 9):
        reg_file[int(r[0])] = r[3].split("::")[0]

    # JS-PROV-R33: a local bound by `require(spec).member` denotes the MEMBER,
    # not the module. Refuse those locals as module bindings; resolve them via
    # the selector + R35 alias path instead (R36 semantics, unchanged).
    _selected = set()
    sel = {}
    for f_, local_, spec_, member_, _cid in _rows(raw / "require_member_selection.tsv", 5):
        _selected.add((f_, local_))
        sel[(f_, local_)] = (spec_, member_)
    modlocal = {}
    for f_, spec_, local_, _cid in _rows(raw / "require_bindings.tsv", 4):
        if local_ and (f_, local_) not in _selected:
            modlocal[(f_, local_)] = spec_
    alias = {(a[0], a[1]): a[2] for a in _rows(raw / "export_member_alias.tsv", 3)}
    routes_export_local = {f: n for f, n in _rows(raw / "router_routes_export.tsv", 2)}
    # JS-PROV-R40: dotted export paths for nested object-literal members.
    nested = {}
    for f_, path_, method_, kind_ in _rows(raw / "nested_member_exports.tsv", 4):
        nested.setdefault(f_, {})[path_] = (method_, kind_)

    exports = {}          # file -> member -> (method_fullname, node_kind)
    for row in _rows(raw / "module_exports.tsv", 7):
        exports.setdefault(row[0], {})[row[1]] = (row[2], row[3])

    default_export_local = {f: n for f, n in _rows(raw / "default_export_identifier.tsv", 2)}

    params_by_method = {}
    for m, idx, name, ty, hint in _rows(raw / "method_params.tsv", 5):
        params_by_method.setdefault(m, []).append((int(idx), name))

    def is_defined_method(fullname):
        """R12's stub gate, verbatim semantics."""
        ps = params_by_method.get(fullname)
        if not ps:
            return False
        names = [n for i, n in sorted(ps) if i > 0]
        if not names:
            return False
        return not all(n.startswith("p") and n[1:].isdigit() for n in names)

    cbs = {}
    for cid, cname, aidx, node, code, resolved, ftype, aid in _rows(raw / "callback_args.tsv", 8):
        cbs.setdefault(int(cid), []).append(
            {"index": int(aidx), "node": node, "code": code, "resolved": resolved})

    writes, reads = {}, {}
    for m, kind, path, src, o, no, cond in _rows(raw / "ctx_state.tsv", 7):
        rec = {"path": path, "source": src, "order": int(o), "next_order": int(no),
               "conditional": cond.strip().lower() == "true"}
        (writes if kind == "WRITE" else reads).setdefault(m, []).append(rec)

    def resolve_default_export_method(file_, local_name):
        """IDENTIFIER middleware arg -> the METHOD its module default-exports.
        Identity comes from require bindings + export records (R14), never from
        the frontend's type string."""
        spec = modlocal.get((file_, local_name))
        if spec is None:
            return None
        tgt = next((c for c in _cands(file_, spec) if c in exports), None)
        if tgt is None:
            return None
        entry = exports[tgt].get("")          # default export
        if entry and entry[1] == "METHOD_REF" and entry[0]:
            return entry[0]
        return None

    def _alias_target(file_, member):
        """R35: barrel member -> the module its require-bound alias names."""
        rn = alias.get((file_, member))
        if rn is None:
            return None
        sp = modlocal.get((file_, rn))
        if sp is None:
            return None
        return next((c for c in _cands(file_, sp) if c in exports), None)

    def _module_of_base(file_, base):
        """The module file a require-bound (or selector-bound) base names."""
        got = sel.get((file_, base))
        if got is not None:
            sp, mem = got
            outer = next((c for c in _cands(file_, sp) if c in exports), None)
            if outer is None or mem not in exports.get(outer, {}):
                return None
            return _alias_target(outer, mem)
        spec = modlocal.get((file_, base))
        if spec is None:
            return None
        return next((c for c in _cands(file_, spec) if c in exports), None)

    def resolve_member_export_method(file_, code_):
        """`ctrl.get`, `ctrl.feed.get`, `ctrl.comments.byComment` -> the METHOD.
        The base resolves to a module (bare or selector binding, R33/R36); the
        remaining path is matched FIRST against that module's nested export
        paths (R40), then walked member->alias->member for cross-module hops."""
        parts = (code_ or "").strip().split(".")
        if len(parts) < 2:
            return None
        base, rest = parts[0], parts[1:]
        tgt = _module_of_base(file_, base)
        if tgt is None:
            return None

        # R40: whole remaining path as a nested export of the base module.
        dotted = ".".join(rest)
        nend = nested.get(tgt, {}).get(dotted)
        if nend and nend[1] == "METHOD_REF" and nend[0]:
            return nend[0]

        # Otherwise walk: consume path members, following aliases across modules.
        cur_file = tgt
        for i, member in enumerate(rest):
            entry = exports.get(cur_file, {}).get(member)
            remaining = rest[i + 1:]
            if entry and entry[1] == "METHOD_REF" and entry[0] and not remaining:
                return entry[0]
            # nested path rooted here?
            nsub = nested.get(cur_file, {}).get(".".join(rest[i:]))
            if nsub and nsub[1] == "METHOD_REF" and nsub[0]:
                return nsub[0]
            # member is an alias to another module -> hop and continue
            hop = _alias_target(cur_file, member)
            if hop is not None:
                cur_file = hop
                continue
            return None
        return None

    def resolve_callback(file_, cb):
        if cb["node"] == "IDENTIFIER":
            m = resolve_default_export_method(file_, cb["code"])
            if m:
                return m, "MODULE_EXPORT_IDENTITY"
            if is_defined_method(cb["resolved"]):
                return cb["resolved"], "FRONTEND_TYPE_DEFINED_METHOD"
            return None, None
        if cb["node"] == "CALL" and "." in cb["code"] and cb["code"].count("(") == 0:
            m = resolve_member_export_method(file_, cb["code"])
            if m:
                return m, "MODULE_EXPORT_IDENTITY"
        return None, None

    # ---- app-level registrations, partitioned into mounts vs middleware -----
    app_use = [r for r in regs if r["framework_family"] == "KOA_APP" and r["verb"] == "use"]
    router_regs = [r for r in regs if r["framework_family"] == "KOA_ROUTER"]
    router_regs_by_file = {}
    for r in router_regs:
        f = reg_file[r["registration_call_id"]]
        router_regs_by_file.setdefault(f, []).append(r)

    # ---- JS-PROV-R39: router-composition relation ---------------------------
    # A ROUTER-level `use` composes a child router into a parent:
    #   parent.use([path,] child.routes())   child a same-file router local
    #   parent.use(mod) / parent.use(mod.routes())
    #       mod a require-bound local whose module exports the child router
    #       (default_export_identifier) or its routes middleware
    #       (router_routes_export). Path-prefix args do not constrain state
    #       flow (koa-router dispatches by registered path), so they are
    #       recorded facts, never used to narrow.
    # Raw rows are read from registrations.tsv directly: `use` is not a
    # KOA_ROUTER registration VERB (framework_registration abstains there,
    # correctly) -- composition is a RELATION between routers, not a route.
    # Router-hood of a local comes from RECEIVER-TYPE EVIDENCE (the R29
    # own-initializer class), not from having registered a route: a purely
    # compositional router (`api` -- only `use` calls) is still a router.
    router_locals_by_file = {}
    for row in _rows(raw / "registrations.tsv", 9):
        if row[5] in ("koa-router", "@koa/router") and not row[6]:
            router_locals_by_file.setdefault(row[3].split("::")[0], set()).add(row[4])

    comp_edges = []          # ((file, parent_local) -> (file, child_local))
    for row in _rows(raw / "registrations.tsv", 9):
        cid, name, _mfn, in_m, recv, rtype, pm, pi, nargs = row
        if name != "use" or rtype not in ("koa-router", "@koa/router") or pm:
            continue
        cid = int(cid)
        f = in_m.split("::")[0]
        args = sorted((c for c in cbs.get(cid, [])), key=lambda c: c["index"])
        if not args:
            continue
        a = args[-1]         # optional path literal precedes the child arg
        code = a["code"].strip()
        child = None
        if a["node"] == "CALL" and code.endswith(".routes()"):
            base = code[: -len(".routes()")]
            if "." not in base and "(" not in base:
                if base in router_locals_by_file.get(f, set()) or (f, base) in modlocal or base == recv:
                    if base in router_locals_by_file.get(f, set()):
                        child = (f, base)
                    else:
                        spec = modlocal.get((f, base))
                        if spec is not None:
                            tgt = next((c for c in _cands(f, spec)
                                        if c in default_export_local or c in routes_export_local), None)
                            if tgt is not None:
                                child = (tgt, default_export_local.get(tgt) or routes_export_local.get(tgt))
        elif a["node"] == "IDENTIFIER":
            spec = modlocal.get((f, code))
            if spec is not None:
                tgt = next((c for c in _cands(f, spec)
                            if c in routes_export_local or c in default_export_local), None)
                if tgt is not None:
                    # module exports either the routes middleware or the router
                    local_ = routes_export_local.get(tgt) or default_export_local.get(tgt)
                    if local_ in router_locals_by_file.get(tgt, set()):
                        child = (tgt, local_)
        if child is not None:
            comp_edges.append({"parent": (f, recv), "child": child, "use_call_id": cid})

    def closure(root):
        """All (file, router_local) pairs reachable from root via composition."""
        seen, todo = set(), [root]
        while todo:
            cur = todo.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in comp_edges:
                if e["parent"] == cur and e["child"] not in seen:
                    todo.append(e["child"])
        return seen

    mounts, middleware, abstentions = [], [], []
    for r in app_use:
        cid = r["registration_call_id"]
        app_file, line = order.get(cid, (reg_file.get(cid, ""), -1))
        args = [c for c in cbs.get(cid, []) if c["index"] == 1]
        if len(args) != 1:
            abstentions.append({"registration": cid, "reason": "USE_ARG_SHAPE_UNSUPPORTED"})
            continue
        a = args[0]
        code = a["code"].strip()
        # mount shape: <base>.routes()
        if a["node"] == "CALL" and code.endswith(".routes()"):
            base = code[: -len(".routes()")]
            if "." in base or "(" in base:
                abstentions.append({"registration": cid, "reason": "MOUNT_BASE_NOT_A_SIMPLE_LOCAL",
                                    "code": code})
                continue
            spec = modlocal.get((app_file, base))
            if spec is None:
                abstentions.append({"registration": cid, "reason": "MOUNT_BASE_NOT_REQUIRE_BOUND",
                                    "base": base})
                continue
            tgt = next((c for c in _cands(app_file, spec) if c in exports
                        or c in router_regs_by_file), None)
            if tgt is None:
                abstentions.append({"registration": cid, "reason": "MOUNT_MODULE_UNRESOLVED",
                                    "spec": spec})
                continue
            exported_local = default_export_local.get(tgt)
            if exported_local is None:
                abstentions.append({"registration": cid, "reason": "MOUNT_TARGET_EXPORT_IDENTITY_UNKNOWN",
                                    "target_file": tgt})
                continue
            reach = closure((tgt, exported_local))
            target_regs = [rr for rr in router_regs
                           if (reg_file[rr["registration_call_id"]],
                               rr["receiver_local"]) in reach]
            if not target_regs:
                abstentions.append({"registration": cid,
                                    "reason": "MOUNT_ESTABLISHED_BUT_NO_REACHABLE_REGISTRATIONS",
                                    "target_file": tgt, "closure_size": len(reach)})
            mounts.append({"mount_call_id": cid, "app_file": app_file, "mount_line": line,
                           "router_file": tgt, "router_local": exported_local,
                           "composition_closure": sorted(map(list, reach)),
                           "mounted_registrations": [rr["registration_call_id"] for rr in target_regs],
                           "resolution": "ESTABLISHED"})
            continue
        # middleware shape: a resolvable callable
        wm, src = resolve_callback(app_file, a)
        if wm is None or not is_defined_method(wm):
            abstentions.append({"registration": cid,
                                "reason": "MIDDLEWARE_IDENTITY_UNKNOWN_OR_STUB",
                                "code": code})
            continue
        middleware.append({"use_call_id": cid, "app_file": app_file, "use_line": line,
                           "method": wm, "identity_source": src})

    # ---- the join: middleware BEFORE mount -> mounted router's readers ------
    flows = []
    for mw in middleware:
        for mt in mounts:
            if mw["app_file"] != mt["app_file"]:
                continue
            if not (0 <= mw["use_line"] < mt["mount_line"]):
                abstentions.append({"middleware": mw["method"], "mount": mt["mount_call_id"],
                                    "reason": "MIDDLEWARE_REGISTERED_AFTER_MOUNT",
                                    "use_line": mw["use_line"], "mount_line": mt["mount_line"]})
                continue
            for wr in writes.get(mw["method"], []):
                if wr["next_order"] == -1:
                    rel = "NO_NEXT"
                elif wr["order"] < wr["next_order"]:
                    rel = "BEFORE_NEXT"
                else:
                    rel = "AFTER_NEXT"
                if rel != "BEFORE_NEXT":
                    abstentions.append({"middleware": mw["method"], "path": wr["path"],
                                        "reason": f"WRITE_{rel}_NOT_AVAILABLE_DOWNSTREAM"})
                    continue
                for reg in (r for r in router_regs
                            if r["registration_call_id"] in mt["mounted_registrations"]):
                    rcid = reg["registration_call_id"]
                    rfile = reg_file[rcid]
                    for cb in sorted((c for c in cbs.get(rcid, []) if c["index"] >= 2),
                                     key=lambda c: c["index"]):
                        rm, _src = resolve_callback(rfile, cb)
                        if rm is None or not is_defined_method(rm):
                            continue
                        for rd in reads.get(rm, []):
                            if not _is_prefix(wr["path"], rd["path"]):
                                continue
                            flows.append({
                                "relation": "APP_MOUNT_UPSTREAM",
                                "writer_method": mw["method"],
                                "writer_use_call_id": mw["use_call_id"],
                                "writer_identity_source": mw["identity_source"],
                                "writer_path": wr["path"], "writer_source": wr["source"],
                                "relative_to_next": rel,
                                "mount_call_id": mt["mount_call_id"],
                                "mount_evidence": {
                                    "app_file": mt["app_file"],
                                    "use_line": mw["use_line"],
                                    "mount_line": mt["mount_line"],
                                    "router_file": mt["router_file"],
                                    "router_local": mt["router_local"]},
                                "reader_registration": rcid,
                                "reader_verb": reg["verb"],
                                "reader_method": rm, "reader_arg_index": cb["index"],
                                "reader_path": rd["path"],
                                "path_relation": ("EXACT" if wr["path"] == rd["path"]
                                                  else "ANCESTOR_WRITE"),
                                # R19 two-axes rule across the mount: ordering
                                # certainty never upgrades write strength.
                                "state_flow_strength": "MAY" if wr["conditional"] else "MUST",
                            })
    return {
        "schema": "portable-app-mount-flow/0.1",
        "note": ("APP-level middleware joins ROUTER-level readers ONLY through an "
                 "ESTABLISHED mount (require-bound router local -> resolved module "
                 "-> default-export local identity -> that local's registrations) "
                 "and ONLY when the middleware registration precedes the mount. "
                 "NEG-2 is untouched: route-scoped writers never cross routers, "
                 "and R12's within-route output is unchanged."),
        "mounts": mounts,
        "middleware": middleware,
        "flows": flows,
        "abstentions": abstentions,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2, default=str))
