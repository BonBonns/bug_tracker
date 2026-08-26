#!/usr/bin/env python3
"""JS-PROV-R12 gate: context state-flow join. All 8 negative controls are load-bearing."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from context_state_flow import derive  # noqa: E402

def main():
    d = derive(sys.argv[1]); F = d["flows"]
    def has(w, r, **kw):
        return any(f["writer_method"].endswith(w) and f["reader_method"].endswith(r)
                   and all(f.get(k) == v for k, v in kw.items()) for f in F)
    def rmeth(r): return [f for f in F if f["reader_method"].endswith(r)]
    reasons = {a["reason"] for a in d["abstentions"]}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("POSITIVE whole-object write establishes .email read (prefix/ancestor)",
       has("wholeWriter", "readsEmail", path_relation="ANCESTOR_WRITE", resolution="MUST"))
    ck("POSITIVE origin family carried as HTTP_BODY",
       has("wholeWriter", "readsEmail", origin_family="HTTP_BODY"))
    ck("NEG-7 SIBLINGS: .user write must NOT establish .email read", not rmeth("readsEmail2"), rmeth("readsEmail2"))
    ck("POSITIVE ancestor: .user write establishes .user.id read",
       has("siblingWriter2", "readsUserId", path_relation="ANCESTOR_WRITE"))
    ck("NEG-3 AFTER_NEXT writer establishes nothing downstream", not rmeth("readsAfter"), rmeth("readsAfter"))
    ck("NEG-3 AFTER_NEXT recorded as an abstention",
       "WRITE_AFTER_NEXT_NOT_AVAILABLE_DOWNSTREAM" in reasons, reasons)
    ck("NEG-4 conditional writer yields MAY, never MUST",
       all(f["resolution"] == "MAY" for f in rmeth("readsCond")) and rmeth("readsCond"), rmeth("readsCond"))
    ck("NEG-5 stub callback (42 as any) establishes nothing", not rmeth("readsEmail4"), rmeth("readsEmail4"))
    ck("NEG-5 stub recorded as an abstention", "WRITER_IDENTITY_UNKNOWN_OR_STUB" in reasons, reasons)
    ck("NEG-6 wrapper-returned validate(schema) DOES join (R11 hop wired)",
       bool(rmeth("readsEmail3")), rmeth("readsEmail3"))
    ck("NEG-2 route A write does not reach route B reader",
       not has("routeAWriter", "routeBReader") and not has("routeBWriter", "routeAReader"))
    ck("NEG-2 same property path on separate routes keeps distinct origins",
       has("routeAWriter", "routeAReader", origin_family="HTTP_BODY")
       and has("routeBWriter", "routeBReader", origin_family="HTTP_QUERY"))
    ck("NEG-1 unregistered object never joins",
       not any("other" in f["writer_method"] or "other" in f["reader_method"] for f in F))
    ck("ORDER: reader positioned BEFORE writer establishes nothing", not rmeth("readsEmail5"), rmeth("readsEmail5"))

    # --- JS-PROV-R19: origin evidence carried through the join, never upgraded ---
    ck("R19 every flow carries origin evidence fields",
       all("transform_input_origins" in f and "output_origin_established" in f for f in F))
    ck("R19 established-origin writes propagate origin_family to the reader",
       any(f["origin_family"] == "HTTP_BODY" and f["output_origin_established"] for f in F), 
       [(f["writer_path"], f["origin_family"]) for f in F])
    ck("R19 distinct routes keep DISTINCT origins after propagation",
       has("routeAWriter", "routeAReader", origin_family="HTTP_BODY")
       and has("routeBWriter", "routeBReader", origin_family="HTTP_QUERY"))
    ck("R19 no flow claims output established without an established writer origin",
       all((not f["output_origin_established"]) or f["origin_family"] != "UNKNOWN" for f in F))
    ck("R19 a transform-fed flow never reports origin_family as a DERIVED family",
       all(f["transform"] != "UNMODELLED_CALL" or f["origin_family"] == "UNKNOWN" for f in F))
    ck("R19 transform-fed flows never set output_origin_established",
       all(f["transform"] != "UNMODELLED_CALL" or not f["output_origin_established"] for f in F))

    # --- JS-PROV-R19 overwrite tooth + two-axis independence ---
    ov = [f for f in F if "ov" in f["reader_method"]]
    def ovf(path, eff=True):
        return [f for f in ov if f["reader_path"] == path and f["effective"] == eff]
    u_eff = ovf("validatedData.user")
    ck("R19 OVERWRITE: .user read uses the MORE SPECIFIC .user writer",
       len(u_eff) == 1 and u_eff[0]["matched_writer"].endswith("ovNarrow"), u_eff)
    ck("R19 OVERWRITE: broad whole-object writer is SHADOWED for the .user read",
       any(f["matched_writer"].endswith("ovBroad") and not f["effective"]
           for f in ov if f["reader_path"] == "validatedData.user"), ov)
    e_eff = ovf("validatedData.email")
    ck("R19 OVERWRITE: .email read DOES inherit the whole-object writer (no specific writer)",
       len(e_eff) == 1 and e_eff[0]["matched_writer"].endswith("ovBroad"), e_eff)
    ck("R19 transform-fed whole-object writer is TRANSFORM_INPUT_ONLY with BOTH inputs",
       e_eff and e_eff[0]["origin_strength"] == "TRANSFORM_INPUT_ONLY"
       and set(e_eff[0]["transform_input_origins"]) == {"HTTP_BODY", "HTTP_QUERY"}, e_eff)
    ck("R19 TWO AXES: MUST state-flow coexists with TRANSFORM_INPUT_ONLY origin",
       e_eff and e_eff[0]["state_flow_strength"] == "MUST"
       and e_eff[0]["origin_strength"] == "TRANSFORM_INPUT_ONLY", e_eff)
    ck("R19 TWO AXES: MUST never upgrades origin to ESTABLISHED",
       all(f["origin_strength"] != "ESTABLISHED" or f["output_origin_established"] for f in F))
    ck("R19 conditional writer keeps MAY on the state-flow axis",
       all(f["state_flow_strength"] == "MAY" for f in rmeth("readsCond")), rmeth("readsCond"))
    ck("R19 every flow carries both axes explicitly",
       all("state_flow_strength" in f and "origin_strength" in f for f in F))

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R12={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
