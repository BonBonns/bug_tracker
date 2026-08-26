#!/usr/bin/env python3
"""Guard-fallthrough verdict — the JS/TS analogue of the Pods pods_error() bypass.

PATTERN
-------
A GUARD calls a helper it treats as a request-terminator. The helper is
CONDITIONAL (some path returns a value instead of throwing/exiting). The caller
invokes it as a BARE STATEMENT (discards the return, no `return`/`throw`). A
SENSITIVE SINK is reachable after the guard. => execution falls through a
"failed" check into the sink. This is precisely the shape of the Pods
`admin_ajax()` bypass, where `pods_error()` returns false on the meta-box path
and the bare `pods_error(...)` calls let every access check fall through to the
dynamic API dispatch.

VERDICT (never "VULNERABLE" -- always CANDIDATE, matching the engine's stance)
    CANDIDATE_GUARD_FALLTHROUGH  a bare guard call to a CONDITIONAL terminator,
        with a sink reachable afterwards in the enclosing method.
    SAFE_RETURNED                the guard call's value is returned (halts).
    SAFE_ALWAYS_TERMINATES       the callee ALWAYS terminates (bare call fine).
    ABSTAIN_CALLEE_UNRESOLVED    the callee identity can't be established from
        require bindings -- reported, never guessed (JS-PROV-R13 lesson: the
        frontend's same-file callee string is NOT trusted).

CEILINGS (stated so results aren't over-read)
  * Reachability is SOURCE-ORDER (guard line < sink line), a conservative proxy
    for CFG reachability. A guarded early-return between guard and sink could
    make the sink unreachable; a sound CFG pass is future work.
  * The CONDITIONAL classification is intraprocedural: a helper that delegates
    termination to something it calls is under-approximated as its own body.
  * Callee resolution uses require bindings + default export identity; dynamic
    dispatch (`handlers[name](ctx)`) is abstained, not guessed.
"""
import json, sys, posixpath as pp
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required guard-fallthrough fact file missing: {p}")
    out = []
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            out.append(ln.split("\t"))
    return out


def _cands(f_, spec_):
    def v(c):
        return [c + ".js", c + ".ts", pp.join(c, "index.js"), pp.join(c, "index.ts"), c]
    if spec_.startswith("."):
        b = pp.dirname(f_)
        return v(pp.normpath(pp.join(b, spec_)) if b else pp.normpath(spec_))
    return v(pp.normpath(spec_))


def derive(raw):
    raw = Path(raw)

    # terminator verdict per method fullname
    term = {}
    for f_, full, verdict, evid in _rows(raw / "terminator_profile.tsv", 4):
        term[full] = (verdict, evid)

    # require bindings: (file, local) -> spec ; default exports: file -> method
    modlocal = {}
    for f_, spec_, local_, _cid in _rows(raw / "require_bindings.tsv", 4):
        if local_:
            modlocal[(f_, local_)] = spec_
    # named exports: file -> member -> (method_fullname, kind)
    exports = {}
    for r in _rows(raw / "module_exports.tsv", 7):
        exports.setdefault(r[0], {})[r[1]] = (r[2], r[3])

    def resolve_callee(file_, callee_name):
        """Resolve a called helper NAME to its defining method via require
        bindings + the target module's named export. Never trusts the
        frontend's (often same-file) callee string.

        Destructured imports (`const { denyRequest } = require("x")`) bind to a
        synthetic `_tmp_N` local, so the member name is not individually
        recorded. We therefore resolve by: for each module REQUIRED in this
        file, if that module exports a member of the callee's name, that export
        is the callee. Ambiguity (two required modules export the same name) is
        reported, not guessed."""
        # 1) direct local binding of the whole module, then `.name` is a member
        spec = modlocal.get((file_, callee_name))
        if spec is not None:
            tgt = next((c for c in _cands(file_, spec) if c in exports), None)
            if tgt is not None:
                ent = exports[tgt].get(callee_name)
                if ent and ent[0]:
                    return ent[0], "REQUIRE_BINDING"
        # 2) destructured import: search exports of every module required here
        hits = []
        for (f2, local2), spec2 in modlocal.items():
            if f2 != file_:
                continue
            tgt = next((c for c in _cands(file_, spec2) if c in exports), None)
            if tgt is None:
                continue
            ent = exports[tgt].get(callee_name)
            if ent and ent[0]:
                hits.append(ent[0])
        hits = sorted(set(hits))
        if len(hits) == 1:
            return hits[0], "DESTRUCTURED_IMPORT"
        if len(hits) > 1:
            return None, "AMBIGUOUS_ACROSS_IMPORTS"
        # 3) same-file local function of that name
        for full in term:
            if full.endswith(":" + callee_name) and full.split("::")[0] == file_:
                return full, "SAME_FILE_LOCAL"
        return None, "UNRESOLVED"

    # sink lines per method
    sink_max = {}
    for f_, meth, gline, sline in _rows(raw / "method_guard_sink_lines.tsv", 4):
        sink_max[meth] = int(sline)

    findings = []
    for f_, meth, name, calleeFull, line, in_if, is_bare, is_ret in _rows(raw / "guard_calls.tsv", 8):
        if not name:
            continue
        line = int(line) if line else -1
        bare = is_bare == "true"
        returned = is_ret == "true"

        resolved, rsource = resolve_callee(f_, name)
        if resolved is None:
            findings.append({"file": f_, "method": meth, "guard_call": name, "line": line,
                             "verdict": "ABSTAIN_CALLEE_UNRESOLVED", "reason": rsource})
            continue
        tv = term.get(resolved, ("NEVER", ""))[0]

        if returned and not bare:
            verdict = "SAFE_RETURNED"
        elif tv == "ALWAYS":
            verdict = "SAFE_ALWAYS_TERMINATES"
        elif tv == "CONDITIONAL" and bare:
            # sink reachable after the guard, source-order proxy
            smax = sink_max.get(meth)
            if smax is not None and smax > line:
                verdict = "CANDIDATE_GUARD_FALLTHROUGH"
            else:
                verdict = "BARE_CONDITIONAL_NO_SINK_AFTER"
        elif tv == "NEVER":
            verdict = "SAFE_CALLEE_NOT_A_TERMINATOR"
        else:
            verdict = "BARE_CONDITIONAL_NO_SINK_AFTER"

        findings.append({"file": f_, "method": meth, "guard_call": name, "line": line,
                         "callee_resolved": resolved, "callee_resolution": rsource,
                         "terminator_verdict": tv,
                         "is_bare": bare, "is_returned": returned,
                         "sink_after_line": sink_max.get(meth),
                         "verdict": verdict})

    return {
        "schema": "guard-fallthrough-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags a bare guard call to a "
                 "CONDITIONAL terminator with a sink reachable afterwards -- the "
                 "JS/TS shape of the Pods pods_error() access-control bypass. "
                 "Callee identity comes from require bindings, never the "
                 "frontend's same-file guess."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "guard-out/raw"), indent=2))
