#!/usr/bin/env python3
"""Structural check for Fable's promotion gate (docs/PROMOTION_GATE.md).

Verifies that every PROMOTED fact has the artifacts stages 1-5 require:
a characterization/verdict report, a registered gate with a runner and a
checker, and a TRACKS entry. It cannot verify that stage 5 (spec re-read) was
performed with judgement -- it only ensures the evidence trail exists.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMOTED = {
    "ObservedParameterTypeFact":    ("js-prov-r08", "js-prov-r08"),
    "FrameworkRegistrationFact":    ("js-prov-r09", "js-prov-r09"),
    "ModuleExportIdentityFact":     ("js-prov-r14", "js-prov-r14"),
    "ContextStateFlowFact":         ("js-prov-r12", "js-prov-r12"),
    "TransformInputOriginFact":     ("js-prov-r17", "js-prov-r17"),
    "ExternalInputOriginFact":      ("js-prov-r21", "js-prov-r21"),
    "ImportBindingIdentityFact":    ("js-prov-r23b", "js-prov-r23b"),
}

def main():
    fails = []
    for fact, (gate, doc) in sorted(PROMOTED.items()):
        g = ROOT / "tests" / "gates" / gate
        for p, what in [(g / "run.sh", "gate runner"),
                        (g, "gate directory")]:
            if not p.exists():
                fails.append(f"{fact}: missing {what} ({p})")
        if g.exists() and not list(g.glob("check_*.py")):
            fails.append(f"{fact}: gate has no checker script")
        docs = list((ROOT / "docs" / "corpus-scans").glob(f"{doc}*/*.md"))
        if not docs:
            fails.append(f"{fact}: no verdict/characterization report under docs/corpus-scans/{doc}*")
        print(f"{'OK  ' if not any(fact in f for f in fails) else 'FAIL'} {fact}")
    t = ROOT / "tests" / "gates" / "TRACKS.md"
    if not t.exists():
        fails.append("TRACKS.md missing")
    else:
        txt = t.read_text()
        for fact in PROMOTED:
            if fact not in txt:
                fails.append(f"{fact}: no TRACKS.md entry")
    pg = ROOT / "docs" / "PROMOTION_GATE.md"
    if not pg.exists():
        fails.append("docs/PROMOTION_GATE.md missing")
    for f in fails:
        print("FAIL", f)
    print(f"PROMOTION_GATE={'PASS' if not fails else 'FAIL'} ({len(PROMOTED)} promoted facts)")
    sys.exit(0 if not fails else 1)

if __name__ == "__main__":
    main()
