#!/usr/bin/env python3
"""JS-PROV-R14 — ModuleExportIdentityFact: resolve a call through a require().

Closes the link JS-PROV-R13 measured as missing:

    CALL validate(schema)
      -> imported binding identity      <-- THIS MODULE
      -> exported symbol identity
      -> validate METHOD
      -> ReturnedFunctionIdentityFact   (JS-PROV-R12-1, direct-return only)
      -> validate:<lambda>1

The frontend's own `methodFullName`/`callee` MUST NOT be consulted at these
sites: JS-PROV-R13 measured that `m2.validate(1)`, `m3.validate(1)` and
`m4.validate(1)` all resolve to `app.js::program:validate`, a function that does
not exist, collapsing three modules onto one fabricated identity. This module
OVERRIDES that, deriving identity from explicit program relations only:

    require(SPEC) assigned to LOCAL      (specifier literal + binding)
    SPEC + importing file -> target file (path relation, not a name match)
    target file's export assignment      (member name + RHS method identity)

`module.exports = {a, b}` exports as a BLOCK; member identity is not exposed at
that level, so it ABSTAINS rather than guessing (JS-PROV-R13).
"""
import json, sys, posixpath
from pathlib import Path


from import_binding_identity import derive as _ibi  # noqa: E402


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    return [x for x in (ln.split("\t") for ln in p.read_text().splitlines() if ln.strip()) if len(x) == n]


def _resolve_spec(importing_file, spec):
    """Module specifier -> candidate file paths.

    Relative specifiers resolve against the importing file's directory.
    NON-relative specifiers are ALSO tried as project-root-relative paths,
    because Node projects commonly make internal modules importable without
    `./` (e.g. via `app-module-path` or NODE_PATH) -- JS-PROV-R14 measured this
    on Corpus B, where `require('middlewares/validate.middleware')` denotes an
    internal file. A root-relative candidate is still a PATH relation, not a
    name match, and it only resolves if a file with an export assignment
    actually exists at that path; otherwise the specifier abstains as an
    external package."""
    def variants(c):
        return [c + ".js", c + ".ts", posixpath.join(c, "index.js"), c]
    if spec.startswith("."):
        base = posixpath.dirname(importing_file)
        cand = posixpath.normpath(posixpath.join(base, spec)) if base else posixpath.normpath(spec)
        return variants(cand)
    return variants(posixpath.normpath(spec))


def derive(raw):
    raw = Path(raw)
    # file -> {member_or_"" : (rhs_method, rhs_kind)}
    # JS-PROV-R26 widened module_exports.tsv from 5 to 7 columns (re-export base
    # + member). Read both widths so the CommonJS path is width-agnostic --
    # a fixed-width read here silently zeroed Corpus B, which invariant J2 caught.
    exports = {}
    for row in _rows(raw / "module_exports.tsv", 7):
        exports.setdefault(row[0], {})[row[1]] = (row[2], row[3])
    for f, member, rhs, kind, code in _rows(raw / "module_exports.tsv", 5):
        exports.setdefault(f, {}).setdefault(member, (rhs, kind))
    # (file, local) -> spec
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
    binds = {}
    for f, spec, local, cid in _rows(raw / "require_bindings.tsv", 4):
        if local and (f, local) not in _selected:
            binds[(f, local)] = spec
    returned = {}
    for w, r, t in _rows(raw / "returned_function_identity.tsv", 3):
        returned[w] = r

    # JS-PROV-R25 (INTEGRATION ONLY): consume ESTABLISHED
    # ImportBindingIdentityFact records wherever the CommonJS require_bindings
    # path would supply equivalent binding identity. Keyed on
    # (importing_file, local_binding) -> the exported METHOD the import
    # resolves to.
    #
    # This consumes the established FACT, never the mere PRESENCE of an import:
    # abstained bindings (namespace, default, re-export, unresolved) are absent
    # from `facts` and therefore contribute nothing. No semantics of either
    # producer are changed here.
    esm_bindings = {}
    try:
        for bf in _ibi(raw)["facts"]:
            esm_bindings[(bf["importing_file"], bf["local_binding"])] = bf
    except Exception:
        esm_bindings = {}

    facts, abstentions = [], []
    for cid, f, base, mem, cname, code in _rows(raw / "import_calls.tsv", 6):
        # ESM path first: the local was bound by an ESM import whose member
        # identity R23b ESTABLISHED.
        eb = esm_bindings.get((f, cname)) or esm_bindings.get((f, base))
        if eb is not None:
            facts.append({
                "call_id": int(cid), "code": code,
                "importing_file": f, "specifier": eb["specifier"],
                "target_file": eb["target_file"],
                "exported_member": eb["imported_member"],
                "exported_method": eb["exported_method"],
                "returned_function": returned.get(eb["exported_method"]),
                "identity_evidence": "ESM_IMPORT_BINDING_IDENTITY",
                "enabled_by_import_binding": {
                    "local": eb["local_binding"], "member": eb["imported_member"],
                    "target": eb["target_file"]},
                "resolution": "ESTABLISHED",
            })
            continue
        spec = binds.get((f, base))
        default_call = False
        if spec is None:
            # A DIRECT call `m1(1)` places `this` at argument 0, so the bound
            # local appears as the call's own name rather than as the receiver.
            if binds.get((f, cname)) is not None:
                spec, base, default_call = binds[(f, cname)], cname, True
            else:
                continue                  # receiver is not a require-bound local
        cands = _resolve_spec(f, spec)
        if cands is None:
            abstentions.append({"call_id": int(cid), "code": code, "spec": spec,
                                "reason": "BARE_SPECIFIER_EXTERNAL_PACKAGE"}); continue
        target = next((c for c in cands if c in exports), None)
        if target is None:
            abstentions.append({"call_id": int(cid), "code": code, "spec": spec,
                                "reason": "TARGET_FILE_HAS_NO_EXPORT_ASSIGNMENT"}); continue
        # member = the call's own name when it differs from the bound local,
        # otherwise a default-export call  (m1(1) -> name m1 == local m1)
        member = "" if (default_call or cname == base) else cname
        entry = exports[target].get(member)
        if entry is None:
            abstentions.append({"call_id": int(cid), "code": code, "target": target,
                                "member": member or "<default>",
                                "reason": "NO_MATCHING_EXPORT_MEMBER"}); continue
        rhs_method, rhs_kind = entry
        if rhs_kind == "BLOCK" or not rhs_method:
            abstentions.append({"call_id": int(cid), "code": code, "target": target,
                                "member": member or "<default>",
                                "reason": "OBJECT_LITERAL_EXPORT_MEMBER_NOT_EXPOSED"}); continue
        facts.append({
            "call_id": int(cid), "code": code,
            "importing_file": f, "specifier": spec, "target_file": target,
            "exported_member": member or "<default>",
            "exported_method": rhs_method,
            "returned_function": returned.get(rhs_method),
            "identity_evidence": "REQUIRE_BINDING+EXPORT_ASSIGNMENT",
            "resolution": "ESTABLISHED",
        })
    return {"schema": "portable-module-export-identity/0.1",
            "note": ("Derived from require() specifier + export assignment only. The "
                     "frontend's methodFullName/callee is deliberately NOT consulted: "
                     "JS-PROV-R13 measured it fabricating a same-file callee across "
                     "require boundaries."),
            "facts": facts, "abstentions": abstentions}


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
