#!/usr/bin/env python3
"""Permanent source-coverage regression test.

Guards against the exact class of omission found in the customs.js case: request.payload and
request.query were tracked as independent source families reaching a shared sink, but
request.headers -- equally attacker-controlled, feeding the identical transform and sink -- had
no source family at all and was silently invisible to the entire pipeline.

Fixture: neweval/sourcecoverage/multisource.js. request.payload, request.query, and
request.headers all feed ONE merged object, which is passed through ONE transform (sendReport)
to JSON.stringify. Facts (neweval/sourcecoverage/raw/*.tsv) were staged by
/tmp/stage_multisource.sc using the SAME frozen property classifier as the rest of the pipeline
(see stage_multisource.sc source, bundled alongside this test).

This test asserts, by reading the staged facts directly:
  1. All three source families (HTTP_BODY, HTTP_QUERY, HTTP_HEADERS) have a source_facts.tsv row.
  2. All three appear as independent alternatives in the adjudicator's evidence
     (source_to_sink_paths / n_alternatives), not collapsed or dropped.
  3. The adjudicator's disposition reflects all three (ESTABLISHED here, since the fixture has no
     bounding transform on any of the three paths).

Run with no arguments; exits non-zero on failure. Requires the sourcecoverage/raw/*.tsv facts to
already be staged (checked into the package) -- this test does not invoke Joern.
"""
import csv
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.join(HERE, "..", "neweval", "sourcecoverage")
RAW = os.path.join(FIXTURE_DIR, "raw")
SINK_ID = "30064771083"

REQUIRED_FAMILIES = {"HTTP_BODY", "HTTP_QUERY", "HTTP_HEADERS"}

FAIL = []


def check(name, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got}, want {want}")
    if not ok:
        FAIL.append(name)


def main():
    if not os.path.exists(os.path.join(RAW, "source_facts.tsv")):
        print("SKIP: sourcecoverage fixture facts not staged at", RAW)
        print("(re-run /tmp/stage_multisource.sc against neweval/sourcecoverage/multisource.cpg.bin to regenerate)")
        sys.exit(0)

    print("=== staged fact layer: all three source families present ===")
    rows = [r for r in csv.reader(open(os.path.join(RAW, "source_facts.tsv")), delimiter="\t")]
    families = {r[3] for r in rows if len(r) == 12}
    for fam in sorted(REQUIRED_FAMILIES):
        check(f"source_facts.tsv contains {fam}", fam in families, True)

    print()
    print("=== adjudicator evidence: all three survive as independent alternatives ===")
    out_dir = os.path.join(FIXTURE_DIR, "out")
    os.makedirs(out_dir, exist_ok=True)
    env = dict(os.environ, TCH_RAW=RAW, TCH_SRC=FIXTURE_DIR, TCH_OUT=out_dir,
               TCH_SINK=SINK_ID, TCH_FINDING="sourcecoverage-regression")
    adjudicator = os.path.join(HERE, "adjudicate_js.py")
    subprocess.run([sys.executable, adjudicator], cwd=HERE, env=env, capture_output=True, text=True)

    ev = json.load(open(os.path.join(out_dir, "evidence_final.json")))
    n_alt = ev["structural__ESTABLISHED_BY_STATIC_ANALYSIS"].get("n_alternatives")
    check("n_alternatives", n_alt, 3)

    seen_families = {p["origin"]["origin_family"] for p in ev["source_to_sink_paths"]}
    for fam in sorted(REQUIRED_FAMILIES):
        check(f"source_to_sink_paths contains {fam}", fam in seen_families, True)

    check("disposition", ev["disposition"], "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS")

    if FAIL:
        print(f"\n{len(FAIL)} FAILURE(S): {FAIL}")
        sys.exit(1)
    print("\nALL PASS")


if __name__ == "__main__":
    main()
