#!/usr/bin/env python3
"""JS-PROV-R21 gate: ExternalInputOriginFact via NestJS parameter decorators.
Every negative control here is load-bearing: R20 proved four cases where a
name-based fallback would give the WRONG family."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from external_input_origin import derive  # noqa: E402

def main():
    d = derive(sys.argv[1])
    by = {}
    for f in d["facts"]:
        by[(f["value"]["method"].split(":")[-1], f["value"]["parameter_name"])] = f
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))
    def fam(m, p): 
        f = by.get((m, p)); return f["origin_family"] if f else None

    ck("@Query() named `body`   -> HTTP_QUERY   (not BODY)", fam("a1", "body") == "HTTP_QUERY", fam("a1","body"))
    ck("@Body()  named `query`  -> HTTP_BODY    (not QUERY)", fam("a2", "query") == "HTTP_BODY", fam("a2","query"))
    ck("@Param() named `headers`-> HTTP_PARAM   (not HEADERS)", fam("a3", "headers") == "HTTP_PARAM", fam("a3","headers"))
    ck("@Headers() named `param`-> HTTP_HEADERS (not PARAM)", fam("a4", "param") == "HTTP_HEADERS", fam("a4","param"))
    ck("undecorated sibling parameter gets NOTHING", ("a7", "unrelated") not in by, list(by))
    ck("three families on one method bind independently",
       fam("a8","id") == "HTTP_PARAM" and fam("a8","b") == "HTTP_BODY" and fam("a8","q") == "HTTP_QUERY")
    ck("origin_key is ALWAYS UNKNOWN (never parsed from annotation code)",
       all(f["origin_key"] == "UNKNOWN" for f in d["facts"]))
    ck("every fact is NESTJS_PARAMETER_DECORATOR evidence and established",
       all(f["evidence"] == "NESTJS_PARAMETER_DECORATOR" and f["established"] for f in d["facts"]))
    ck("undecorated class of identical shape yields NOTHING",
       not any("NotAController" in f["value"]["method"] for f in d["facts"]))
    ck("undecorated method in a decorated class yields NOTHING",
       ("helper", "x") not in by)
    ck("derived local consumes the boundary fact, not a fresh decorator fact",
       any(x["local"] == "alias" and x["evidence"] == "DATAFLOW_FROM_ESTABLISHED_ORIGIN"
           and x["origin_family"] == "HTTP_BODY" for x in d["derived"]), d["derived"])
    ck("no derived entry claims NESTJS_PARAMETER_DECORATOR evidence",
       all(x["evidence"] != "NESTJS_PARAMETER_DECORATOR" for x in d["derived"]))

    # R26-FIXTURE-INTEGRITY: this gate keys assertions on (method short name, parameter), which is
    # NOT globally unique in general -- it collides on real corpora. The gate is
    # correct only while its fixture keeps these keys distinct. Assert that, so
    # a future fixture addition fails LOUDLY instead of silently overwriting a
    # lookup entry and checking the wrong record (JS-PROV-R26).
    _keys = [(f["value"]["method"].split(":")[-1], f["value"]["parameter_name"]) for f in d["facts"]]
    _dupes = sorted({k for k in _keys if _keys.count(k) > 1})
    ck("R26-FIXTURE-INTEGRITY: assertion keys unique in this fixture", not _dupes, _dupes)

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R21={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
