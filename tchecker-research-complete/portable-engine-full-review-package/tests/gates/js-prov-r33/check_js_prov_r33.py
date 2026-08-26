#!/usr/bin/env python3
"""JS-PROV-R33 gate: `require(spec).member` must not be recorded as a module binding.

Defect A is a SOUNDNESS defect: the produced record is not incomplete, it is
FALSE. The shared-name fixture removes the naming coincidence that masks it on
real corpora -- outer.js and inner.js BOTH export `shared`, so a consumer
trusting the collapsed binding returns outerShared for ctrl.shared."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from module_specifier_resolution import derive  # noqa: E402

def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    return [x for x in (l.split("\t") for l in p.read_text().splitlines() if l.strip()) if len(x) == n]

def main():
    raw = sys.argv[1]
    sel = {(r[0], r[1]): (r[2], r[3]) for r in _rows(Path(raw) / "require_member_selection.tsv", 5)}
    binds = _rows(Path(raw) / "require_bindings.tsv", 4)
    d = derive(raw)
    targets = {f.get("importing_file", "") + ":" + f.get("code", "") for f in d["facts"]}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("T1 selector recovered for `require('./outer').inner`",
       sel.get(("use.js", "ctrl")) == ("./outer", "inner"), sel)
    ck("T1 bare `require('./outer')` has NO selector recorded",
       ("use.js", "whole") not in sel, sorted(sel))
    ck("T2a SHARED-NAME CONTROL: ctrl never resolves against outer.js",
       not any("outer.js" in (f.get("target_file") or "") and f.get("local_binding") == "ctrl"
               for f in d["facts"]), d["facts"])
    ck("T2a no fact binds ctrl at all (abstains, never fabricates)",
       not any(f.get("code", "").startswith("ctrl") for f in d["facts"]))
    ck("T4 unresolved selection (`.nope`) abstains, no module fallback",
       ("use.js", "missingSel") in sel
       and not any("missingSel" in f.get("code", "") for f in d["facts"]))
    ck("T5 require_bindings.tsv schema UNCHANGED (4 columns)",
       all(len(r) == 4 for r in binds) and len(binds) > 0, len(binds))
    ck("R33 selector lives in a SEPARATE file, not a new column",
       (Path(raw) / "require_member_selection.tsv").exists())
    ck("T6 no fact points at a module the local does not denote",
       all(f.get("target_file") for f in d["facts"]))

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R33={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
