#!/usr/bin/env python3
"""JS-PROV-R35 gate: module-alias export member identity (Defect B).

An object-literal export member whose RHS is a BARE require-bound local is a
module alias. Conditioning on the require binding -- not on "the RHS is an
identifier" -- is what leaves plain-function members untouched.

The shared-name control is load-bearing: leaf.js and other.js BOTH export
`leafFn`, so a guessed module link returns the wrong declaration.
"""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from import_binding_identity import _rows, _candidates  # noqa: E402

def main():
    raw = Path(sys.argv[1])
    exports = {}
    for r in _rows(raw / "module_exports.tsv", 7):
        exports.setdefault(r[0], {})[r[1]] = (r[2], r[3])
    sel = {(r[0], r[1]) for r in _rows(raw / "require_member_selection.tsv", 5)}
    modlocals = {}
    for f, spec, local, cid in _rows(raw / "require_bindings.tsv", 4):
        if local and (f, local) not in sel:
            modlocals[(f, local)] = spec
    alias = {(r[0], r[1]): r[2] for r in _rows(raw / "export_member_alias.tsv", 3)}

    def alias_target(file, member):
        rn = alias.get((file, member))
        if rn is None:
            return None
        spec = modlocals.get((file, rn))
        if spec is None:
            return None
        return next((c for c in _candidates(file, spec) if c in exports), None)

    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("P1 `module.exports = { leaf }` with `leaf = require('./leaf')` links to ./leaf",
       alias_target("barrel.js", "leaf") == "leaf.js", alias_target("barrel.js", "leaf"))
    ck("N1 SHARED-NAME CONTROL: both leaf.js and other.js export `leafFn`",
       "leafFn" in exports.get("leaf.js", {}) and "leafFn" in exports.get("other.js", {}))
    ck("N1 the alias resolves via ./leaf and NEVER other.js",
       alias_target("barrel.js", "leaf") != "other.js")
    ck("N1 leaf.js:leafFn and other.js:leafFn are genuinely DIFFERENT declarations",
       exports["leaf.js"]["leafFn"][0] != exports["other.js"]["leafFn"][0],
       (exports["leaf.js"]["leafFn"][0], exports["other.js"]["leafFn"][0]))
    ck("N2 selector-bearing local abstains (R33 guard holds)",
       alias_target("barrel.js", "sel") is None, alias_target("barrel.js", "sel"))
    ck("N3 non-module member abstains", alias_target("barrel.js", "plain") is None)
    ck("N4 plain-function member is NOT treated as a module alias",
       alias_target("barrel.js", "localFn") is None)
    ck("N4 plain-function member still resolves as an ordinary member",
       exports["barrel.js"]["localFn"][0].endswith(":localFn"),
       exports["barrel.js"]["localFn"][0])
    ck("N5 module_exports.tsv schema unchanged (7 cols)",
       all(len(r) == 7 for r in _rows(raw / "module_exports.tsv", 7)) and
       len(_rows(raw / "module_exports.tsv", 7)) > 0)
    ck("N5 alias lives in a SEPARATE file", (raw / "export_member_alias.tsv").exists())
    ck("N8 every alias target names a file that exists in the export table",
       all(alias_target(f, m) in exports
           for (f, m) in alias if alias_target(f, m) is not None))

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R35={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
