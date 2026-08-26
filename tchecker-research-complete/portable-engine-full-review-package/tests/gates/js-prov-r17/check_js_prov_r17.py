#!/usr/bin/env python3
"""JS-PROV-R17 gate. Freezes the three-way distinction: DERIVED / TRANSFORM_INPUT / UNKNOWN."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from transform_input_origin import build, build_exprs, classify  # noqa: E402

def main():
    d = build(sys.argv[1]); e = build_exprs(sys.argv[1]); M = "t.ts::program:mw"
    r = {n: classify(d, M, n, ["ctx"], e) for n in
         ["a1", "a2", "a3", "a4", "a5", "value", "error", "p"]}
    M18 = "t.ts::program:mw18"
    q = {n: classify(d, M18, n, ["ctx"], e) for n in
         ["i1", "i2", "i3", "i4", "i5", "i6"]}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("body-only spread -> {HTTP_BODY}, established",
       r["a1"]["origin_family"] == "HTTP_BODY" and r["a1"]["output_origin_established"], r["a1"])
    ck("query-only spread -> {HTTP_QUERY}", r["a2"]["origin_family"] == "HTTP_QUERY", r["a2"])
    ck("body+query spread -> BOTH origins as a SET",
       set(r["a3"].get("origin_families", [])) == {"HTTP_BODY", "HTTP_QUERY"}, r["a3"])
    ck("literal member does not dilute the set",
       r["a4"]["origin_family"] == "HTTP_BODY", r["a4"])
    ck("unrelated spread invents no HTTP origin",
       r["a5"]["origin_family"] == "UNKNOWN" and not r["a5"]["transform_input_origins"], r["a5"])
    ck("opaque transform NEVER becomes DERIVED_FROM_*",
       r["value"]["origin_family"] == "UNKNOWN" and not r["value"]["output_origin_established"], r["value"])
    ck("opaque transform carries INPUT origins as a set",
       set(r["value"]["transform_input_origins"]) == {"HTTP_BODY", "HTTP_QUERY"}, r["value"])
    ck("sibling destructure carries the same transform inputs",
       set(r["error"]["transform_input_origins"]) == {"HTTP_BODY", "HTTP_QUERY"}, r["error"])
    ck("value-preserving wrapper is NOT distinguished from opaque (T9==T8 shape)",
       r["p"]["transform"] == "UNMODELLED_CALL" and not r["p"]["output_origin_established"], r["p"])
    ck("wrapper input origins preserved", r["p"]["transform_input_origins"] == ["HTTP_BODY"], r["p"])
    ck("established-origin paths are NOT downgraded to transform-input evidence",
       all(not r[n]["transform_input_origins"] for n in ["a1", "a2", "a3", "a4"]))
    ck("open-world flag present on every classification",
       all("unconstrained_input" in v for v in r.values()))

    # --- JS-PROV-R18: inline expression arguments, resolved by NODE IDENTITY ---
    ck("R18 inline {...body,...query} -> both transform inputs",
       set(q["i1"]["transform_input_origins"]) == {"HTTP_BODY", "HTTP_QUERY"}, q["i1"])
    ck("R18 inline literal-only -> no HTTP input origin",
       not q["i2"]["transform_input_origins"], q["i2"])
    ck("R18 inline unrelated spread -> no HTTP origin invented",
       not q["i3"]["transform_input_origins"], q["i3"])
    ck("R18 identical inline objects at different callsites stay distinct nodes",
       q["i4"]["transform_input_origins"] == ["HTTP_BODY"]
       and q["i5"]["transform_input_origins"] == ["HTTP_BODY"], (q["i4"], q["i5"]))
    ck("R18 spread inside a NESTED call is NOT harvested as the outer argument",
       not q["i6"]["transform_input_origins"], q["i6"])
    ck("R18 opaque-transform gate intact: no inline case establishes output",
       all(not q[n]["output_origin_established"] for n in q), q)

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R17={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
