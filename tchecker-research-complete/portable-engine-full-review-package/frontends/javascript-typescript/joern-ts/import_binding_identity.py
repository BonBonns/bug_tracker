#!/usr/bin/env python3
"""JS-PROV-R23b — ImportBindingIdentityFact.

Closes the gap JS-PROV-R23a localized: ESM EXPORT identity was already
representation-portable (jssrc2cpg lowers exports to `exports.X = Y`), but
IMPORT BINDING was not, because named imports lower to
`local = require(spec).member`, binding the local to the module object.

Built on IMPORT nodes, which carry the semantic tuple directly:
    module specifier + imported member + local binding

FROZEN CONTRACT
---------------
    An import establishes member identity ONLY when its imported entity can be
    matched to an independently established export identity in the resolved
    target module.

`cpg.imports` emitting `./lib:ns` is NOT sufficient; `./lib` must actually
export `ns`. This single rule handles the fabrication cases uniformly.

MEASURED, NOT ASSUMED (JS-PROV-R23a discipline)
-----------------------------------------------
`cpg.imports` does NOT semantically distinguish default from namespace imports:

    import fDefault from './lib'   ->  member=fDefault  as=fDefault  isWildcard=false
    import * as ns   from './lib'  ->  member=ns        as=ns        isWildcard=false

Both emit member == local alias, and `isWildcard` is false in both. Since
neither `fDefault` nor `ns` is a real exported member (the export is keyed
`default`), the contract abstains on both. Default imports are therefore NOT
establishable by this route -- recorded as a measured limitation, not designed
behaviour.
"""
import json, posixpath, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    return [x for x in (l.split("\t") for l in p.read_text().splitlines() if l.strip()) if len(x) == n]


def _candidates(importing_file, spec):
    def variants(c):
        return [c + ".ts", c + ".js", posixpath.join(c, "index.ts"),
                posixpath.join(c, "index.js"), c]
    if spec.startswith("."):
        base = posixpath.dirname(importing_file)
        c = posixpath.normpath(posixpath.join(base, spec)) if base else posixpath.normpath(spec)
        return variants(c)
    return variants(posixpath.normpath(spec))     # project-root-relative (JS-PROV-R14)


_MAX_REEXPORT_DEPTH = 8      # JS-PROV-R26 J6: bounded, and recorded on the fact


def _resolve_export(exports, modlocals, file, member, depth=0, seen=None):
    """JS-PROV-R26 -- follow a re-export chain to a declaration identity.

    `export { f } from './x'` lowers to `exports.f = _x.f`: the RHS is a field
    access on an imported module object, carrying no declaration identity. One
    hop (applied transitively, BOUNDED) resolves the base local to its
    specifier, then looks the member up in that file's exports.

    Returns (rhs_method, kind, chain) or (None, reason, chain).
    Cycles terminate and abstain (J5); depth is bounded (J6); a member the
    target does not actually export abstains (J3); `export *` has no member
    entry to chain to and therefore abstains (J4).
    """
    seen = seen or []
    key = (file, member)
    if key in seen:
        return None, "REEXPORT_CYCLE", seen + [key]
    if depth > _MAX_REEXPORT_DEPTH:
        return None, "REEXPORT_DEPTH_EXCEEDED", seen + [key]
    entry = exports.get(file, {}).get(member)
    if entry is None:
        return None, "MEMBER_NOT_EXPORTED_BY_TARGET", seen + [key]
    rhs, kind, base, remem = entry
    if kind != "CALL" or not base or not remem:
        return rhs, kind, seen + [key]              # terminal declaration identity
    spec = modlocals.get((file, base))
    if spec is None:
        return None, "REEXPORT_BASE_UNRESOLVED", seen + [key]
    target = next((c for c in _candidates(file, spec) if c in exports), None)
    if target is None:
        return None, "REEXPORT_TARGET_UNRESOLVED", seen + [key]
    return _resolve_export(exports, modlocals, target, remem, depth + 1, seen + [key])


def derive(raw):
    raw = Path(raw)
    # file -> {member: (rhs, kind, reexport_base, reexport_member)}
    exports = {}
    for row in _rows(raw / "module_exports.tsv", 7):
        f, member, rhs, kind, code, rbase, rmem = row
        exports.setdefault(f, {})[member] = (rhs, kind, rbase, rmem)
    for f, member, rhs, kind, code in _rows(raw / "module_exports.tsv", 5):
        exports.setdefault(f, {}).setdefault(member, (rhs, kind, "", ""))
    # (file, local) -> specifier, for resolving re-export base locals
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
    modlocals = {}
    for f, spec, local, cid in _rows(raw / "require_bindings.tsv", 4):
        if local and (f, local) not in _selected:
            modlocals[(f, local)] = spec

    # JS-PROV-R35: (file, member) -> RHS identifier name, for object-literal
    # export members. A member is a MODULE ALIAS only if that identifier is a
    # BARE require binding in the same file -- checked against `modlocals`,
    # which already excludes selector-bearing locals (R33). Conditioning on the
    # require binding rather than on "the RHS is an identifier" is what leaves
    # plain-function members (already correct) untouched.
    _alias = {}
    for f, member, rhs_name in _rows(raw / "export_member_alias.tsv", 3):
        _alias[(f, member)] = rhs_name

    def alias_target(file, member):
        """-> target file this member aliases, or None."""
        rhs_name = _alias.get((file, member))
        if rhs_name is None:
            return None
        spec = modlocals.get((file, rhs_name))
        if spec is None:
            return None                      # not a bare require binding
        return next((c for c in _candidates(file, spec) if c in exports), None)

    # JS-PROV-R36: SELECTOR RESOLUTION (Defect A's T2b, left open by R33).
    # `const ctrl = require(spec).member` -- R33 refused the binding as a module
    # binding, which was correct but incomplete. Resolve it properly:
    #     spec -> target file -> its `member` -> (R35 alias) -> the member's OWN module
    # This is only possible now that R35 establishes barrel-member aliases; it
    # could not have been done inside R33.
    #
    # If the member is not a module alias (a plain function, a literal, an
    # unresolved name), this returns None and the binding still ABSTAINS -- it
    # never falls back to the outer module, which is the fabrication R33 removed.
    _selector_rows = {}
    for _r in _rows(raw / "require_member_selection.tsv", 5):
        _selector_rows[(_r[0], _r[1])] = (_r[2], _r[3])   # (file, local) -> (spec, member)

    def selector_target(file, local):
        """`const x = require(spec).member` -> the module `x` denotes, or None."""
        got = _selector_rows.get((file, local))
        if got is None:
            return None
        spec, member = got
        outer = next((c for c in _candidates(file, spec) if c in exports), None)
        if outer is None:
            return None
        if member not in exports.get(outer, {}):
            return None                      # e.g. `.nope` -- abstain, no fallback
        return alias_target(outer, member)   # None unless it is a module alias

    facts, abstentions = [], []
    observed = 0
    for file, spec, member, alias, code, expl, wild in _rows(raw / "import_bindings.tsv", 7):
        observed += 1

        def abstain(reason, extra=None):
            abstentions.append({"file": file, "specifier": spec, "member": member,
                                "local": alias, "code": code, "reason": reason,
                                "detail": extra})
        if not spec:
            abstain("NO_SPECIFIER"); continue
        if wild.strip().lower() == "true":
            abstain("WILDCARD_IMPORT"); continue
        target = next((c for c in _candidates(file, spec) if c in exports), None)
        if target is None:
            abstain("UNRESOLVED_MODULE_OR_NO_EXPORT_ASSIGNMENTS"); continue
        if not member:
            abstain("NO_IMPORTED_MEMBER"); continue
        entry = exports[target].get(member)
        if entry is None:
            # covers namespace imports (`ns`), default imports (member == local
            # alias, while the export is keyed `default`), and genuinely missing
            # exports. All abstain by the SAME rule -- no special cases.
            abstain("MEMBER_NOT_EXPORTED_BY_TARGET",
                    {"target": target, "available": sorted(exports[target])}); continue
        rhs_method, rhs_kind = entry[0], entry[1]
        chain = None
        if rhs_kind == "CALL":
            # JS-PROV-R26 re-export hop
            rhs_method, rhs_kind, chain = _resolve_export(exports, modlocals, target, member)
            if rhs_method is None:
                abstain(str(rhs_kind),
                        {"target": target, "chain": [f"{a}:{b}" for a, b in (chain or [])]}); continue
        if rhs_kind == "BLOCK" or not rhs_method:
            abstain("EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION", {"target": target}); continue
        facts.append({
            "importing_file": file, "specifier": spec, "target_file": target,
            "imported_member": member, "local_binding": alias,
            "exported_method": rhs_method,
            "identity_evidence": ("IMPORT_NODE+EXPORT_ASSIGNMENT+REEXPORT_CHAIN"
                                  if chain and len(chain) > 1 else
                                  "IMPORT_NODE+EXPORT_ASSIGNMENT"),
            "reexport_chain": [f"{a}:{b}" for a, b in (chain or [])],
            "reexport_depth_bound": _MAX_REEXPORT_DEPTH,
            "resolution": "ESTABLISHED",
        })
    return {"schema": "portable-import-binding-identity/0.1",
            "note": ("An import establishes member identity ONLY when its imported "
                     "entity matches an independently established export identity in "
                     "the resolved target module. Default imports are NOT establishable "
                     "by this route (measured: cpg.imports reports the local alias as "
                     "the member, not `default`)."),
            "import_bindings_observed": observed,
            "identities_established": len(facts),
            "facts": facts, "abstentions": abstentions}


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
