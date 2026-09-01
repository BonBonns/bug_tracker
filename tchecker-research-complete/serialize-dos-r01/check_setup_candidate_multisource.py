#!/usr/bin/env python3
"""SERIALIZE-DOS-R03 control gate for the source-occurrence correction.

Validates `producers/setup_candidate_multisource.sc` (a NEW producer revision; the
frozen `tchecker-property-adjudicator/producers/setup_candidate.sc` is untouched and
still runnable exactly as before) against real-Joern-compiled fact tables and, where
applicable, real `adjudicate_js.py` evidence -- both produced externally by the
standard, unmodified pipeline (Joern invocation lives outside this reducer, same
convention as every other property in this session) and stored under
`fixtures_multisource/raw/<name>/` and `fixtures_multisource/evidence/<name>/`.

  M1  ms-first-no-second-yes: the ternary CONDITION occurrence has NO flow, the
      JSON.stringify ARGUMENT occurrence (same text, different node id) DOES --
      exactly the real motifer@26.1.1 bug pattern in miniature. The frozen downstream
      pipeline (export_property_propagation.sc/adjudicate_js.py, unmodified) resolves
      ESTABLISHED/RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS from the flowing occurrence
      alone.
  M2  ms-both-same-sink: two DISTINCT source node ids both flow to the SAME sink --
      source_facts.tsv carries two rows, but adjudicate_js.py's own (frozen,
      pre-existing) per-sink multi-origin join produces exactly ONE evidence_final.json
      for that one sink -- one deduplicated finding, not two.
  M3  ms-different-sinks: two functions, two sinks, two sources -- each source flows
      ONLY to its own function's sink, never the other's (cross-function isolation),
      confirmed both by multisource_evidence.tsv (has_flow correctly split across the
      full 2x2 cross-product) and by two independent, correctly-scoped
      evidence_final.json runs.
  M4  ms-unrelated-earlier: an earlier occurrence, isolated inside a different,
      never-invoked-from-this-path closure, has NO flow; the real, later, direct
      occurrence in the outer function DOES -- the new producer never lets the earlier
      occurrence's absence of a real candidate suppress the real one it never even
      considers "first".
  M5  ms-no-flow: `req.body` is present in the file but never reaches the sink at
      all -- multisource_evidence.tsv shows has_flow=false for the only pair
      considered, and source_facts.tsv is correctly empty (nothing for the frozen
      downstream pipeline to even adjudicate -- no evidence_final.json is expected or
      produced, matching this session's "skip the expensive stage when there is
      nothing to check" convention).
  M6  Multiple occurrences with byte-identical `.code` text ("req.body") remain
      distinct BY NODE ID in multisource_evidence.tsv (M1's own two rows: different
      source ids, same text) -- never silently merged.
  M7  The REAL motifer@26.1.1 package (the exact file the frozen taint engine
      previously misreported as NO_FLOW -- see
      study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md Sec.3) reproduces
      ESTABLISHED/RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS AUTOMATICALLY through this
      corrected producer plus the unmodified downstream pipeline -- no manual
      diagnostic override needed anymore.
  M8  Historical interprocedural positive (demo_member_transform.js, from the
      recovered snapshot's own re-verified evidence) remains present, unregressed:
      OPEN/CANDIDATE_OPEN.
  M9  Historical fixed/negative case (demo_lookup_falsepos.js) remains negative,
      unregressed: no flowing occurrence found, source_facts.tsv empty, matching its
      documented REJECTED_NO_STRUCTURAL_FLOW outcome (no adjudication run needed or
      attempted, same reasoning as M5).
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures_multisource"
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def rows(name, path, n):
    p = FIX / "raw" / name / path
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        if ln.strip():
            xs = ln.split("\t")
            if len(xs) >= n:
                out.append(xs)
    return out


def evidence(name, sink_id):
    p = FIX / "evidence" / name / f"evidence_{sink_id}.json"
    return json.loads(p.read_text()) if p.exists() else None


# M1 -----------------------------------------------------------------------
ev1 = rows("ms-first-no-second-yes", "multisource_evidence.tsv", 7)
sf1 = rows("ms-first-no-second-yes", "source_facts.tsv", 5)
e1 = evidence("ms-first-no-second-yes", "30064771075")
tooth("M1 ternary condition has_flow=false, argument has_flow=true (two rows, one sink)",
      len(ev1) == 2 and sorted(r[5] for r in ev1) == ["false", "true"]
      and len(sf1) == 1 and sf1[0][2] == "30064771076",
      str(ev1))
tooth("M1 frozen downstream resolves ESTABLISHED/RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      e1 is not None and e1["property_outcome"] == "ESTABLISHED"
      and e1["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str(e1 and (e1["property_outcome"], e1["disposition"])))

# M2 -----------------------------------------------------------------------
sf2 = rows("ms-both-same-sink", "source_facts.tsv", 5)
e2 = evidence("ms-both-same-sink", "30064771077")
tooth("M2 two distinct flowing source ids, same sink, one deduplicated evidence file",
      len(sf2) == 2 and len({r[2] for r in sf2}) == 2 and len({r[0] for r in sf2}) == 1
      and e2 is not None and e2["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str((sf2, e2 and e2["disposition"])))

# M3 -----------------------------------------------------------------------
ev3 = rows("ms-different-sinks", "multisource_evidence.tsv", 7)
sinks3 = {r[0] for r in ev3}
e3a = evidence("ms-different-sinks", "30064771074")
e3b = evidence("ms-different-sinks", "30064771077")
tooth("M3 two sinks, cross-product correctly split (each source flows only to its own sink)",
      len(sinks3) == 2 and len(ev3) == 4
      and sum(1 for r in ev3 if r[5] == "true") == 2
      and e3a is not None and e3b is not None
      and e3a["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS"
      and e3b["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str(ev3))

# M4 -----------------------------------------------------------------------
ev4 = rows("ms-unrelated-earlier", "multisource_evidence.tsv", 7)
e4 = evidence("ms-unrelated-earlier", "30064771080")
tooth("M4 closure-isolated earlier occurrence has_flow=false, real later occurrence has_flow=true",
      len(ev4) == 2 and sorted(r[5] for r in ev4) == ["false", "true"]
      and e4 is not None and e4["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str((ev4, e4 and e4["disposition"])))

# M5 -----------------------------------------------------------------------
ev5 = rows("ms-no-flow", "multisource_evidence.tsv", 7)
sf5 = rows("ms-no-flow", "source_facts.tsv", 5)
tooth("M5 no occurrence reaches the sink: has_flow=false, source_facts.tsv empty, no evidence file",
      len(ev5) == 1 and ev5[0][5] == "false" and len(sf5) == 0
      and not (FIX / "evidence" / "ms-no-flow").exists(),
      str(ev5))

# M6 -----------------------------------------------------------------------
tooth("M6 identical .code text ('req.body') stays distinct by node id in M1's own evidence",
      len(ev1) == 2 and ev1[0][4] == ev1[1][4] == "req.body" and ev1[0][2] != ev1[1][2],
      str(ev1))

# M7 -----------------------------------------------------------------------
ev7 = rows("motifer", "multisource_evidence.tsv", 7)
e7 = evidence("motifer", "30064771302")
tooth("M7 real motifer@26.1.1 reproduces ESTABLISHED/RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS automatically",
      len(ev7) == 2 and sorted(r[5] for r in ev7) == ["false", "true"]
      and e7 is not None and e7["property_outcome"] == "ESTABLISHED"
      and e7["disposition"] == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS",
      str((ev7, e7 and (e7["property_outcome"], e7["disposition"]))))

# M8 -----------------------------------------------------------------------
e8 = evidence("demo_member_transform", "30064771082")
tooth("M8 historical interprocedural positive (demo_member_transform.js) unregressed: OPEN/CANDIDATE_OPEN",
      e8 is not None and e8["property_outcome"] == "OPEN" and e8["disposition"] == "CANDIDATE_OPEN",
      str(e8 and (e8["property_outcome"], e8["disposition"])))

# M9 -----------------------------------------------------------------------
sf9 = rows("demo_lookup_falsepos", "source_facts.tsv", 5)
ev9 = rows("demo_lookup_falsepos", "multisource_evidence.tsv", 7)
tooth("M9 historical fixed/negative (demo_lookup_falsepos.js) unregressed: no flow, empty source_facts.tsv",
      len(sf9) == 0 and len(ev9) == 1 and ev9[0][5] == "false"
      and not (FIX / "evidence" / "demo_lookup_falsepos").exists(),
      str(ev9))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"SETUP_CANDIDATE_MULTISOURCE={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
