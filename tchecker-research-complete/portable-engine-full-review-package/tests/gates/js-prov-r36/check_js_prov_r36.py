#!/usr/bin/env python3
"""JS-PROV-R36 gate: selector resolution (Defect A's T2b).

R33 REFUSED `require(spec).member` bindings -- correct but incomplete. R36
RESOLVES them, using R35's barrel-member alias. The shared-name control is
load-bearing: outer.js and inner.js both export `shared`, so a wrong resolution
returns a different declaration."""
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
    ml = {}
    for f, sp, l, c in _rows(raw / "require_bindings.tsv", 4):
        if l and (f, l) not in sel:
            ml[(f, l)] = sp
    al = {(r[0], r[1]): r[2] for r in _rows(raw / "export_member_alias.tsv", 3)}
    sr = {(r[0], r[1]): (r[2], r[3]) for r in _rows(raw / "require_member_selection.tsv", 5)}

    def alias_target(f, m):
        rn = al.get((f, m))
        sp = ml.get((f, rn)) if rn else None
        return next((c for c in _candidates(f, sp) if c in exports), None) if sp else None

    def selector_target(f, l):
        g = sr.get((f, l))
        if not g:
            return None
        sp, mem = g
        o = next((c for c in _candidates(f, sp) if c in exports), None)
        if not o or mem not in exports.get(o, {}):
            return None
        return alias_target(o, mem)

    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))
    t = selector_target("use.js", "ctrl")

    ck("S1 `require('./outer').inner` RESOLVES to ./inner (no longer refused)",
       t == "inner.js", t)
    ck("S2 SHARED-NAME: outer.js and inner.js BOTH export `shared`",
       "shared" in exports.get("outer.js", {}) and "shared" in exports.get("inner.js", {}))
    ck("S2 they are genuinely different declarations",
       exports["outer.js"]["shared"][0] != exports["inner.js"]["shared"][0],
       (exports["outer.js"]["shared"][0], exports["inner.js"]["shared"][0]))
    ck("S2 ctrl.shared reaches inner.js:innerShared",
       t and exports.get(t, {}).get("shared", (None,))[0].endswith("innerShared"),
       exports.get(t, {}).get("shared"))
    ck("S2 ctrl.shared NEVER reaches outer.js:outerShared", t != "outer.js")
    ck("S3 unresolved selection (`.nope`) ABSTAINS, no outer fallback",
       selector_target("use.js", "missingSel") is None,
       selector_target("use.js", "missingSel"))
    ck("S4 bare `require('./outer')` is not a selector binding",
       ("use.js", "whole") not in sr)
    ck("R36 selector resolution is derived from require bindings, not guessed",
       all(selector_target(f, l) is None or selector_target(f, l) in exports
           for (f, l) in sr))

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R36={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
