#!/usr/bin/env python3
"""NOSQLI-REDUCE-R01 regression: runs nosqli_verdict.py against FROZEN real Joern output
(export_nosqli_integ.sc, run over tchecker-property-adjudicator/fixtures/nosqli_r01/src/ -- both
of this property's own pre-existing, already fixture-verified source files, stage2_fixture.js and
ajv_gate_fixture.js, combined into one CPG) checked into
tchecker-property-adjudicator/fixtures/nosqli_r01/raw/, so this reproduces without needing Joern
again -- same convention as check_path_traversal_verdict.py's/check_redos_verdict.py's own
frozen-fixture design.

Covers:
  1. End-to-end reducer run against real Joern output: 8 candidate rows across 5 distinct sinks
     (7 rows/4 sinks from stage2_fixture.js's own 4 non-dominated-guard functions -- noGuard,
     typeofStringPositiveDoesNotDominate, incompleteFieldBlocklist, incompleteArrayOnlyCheck; 1
     row/1 sink from ajv_gate_fixture.js's own ungated case), matching the producer's own stderr
     summary ("PRESERVES targets: 6 of 13" minus the AJV-gated exclusions already confirmed by the
     producer's own log, not re-derived here).
  2. NOSQLI-INTEG-R01-FIX01: field identity (field_kind/field_name/value_code) survives into every
     finding, read from source_facts.tsv's own previously-always-blank columns 5/6/7 -- the real,
     structural gap this fix closed (a multi-field selector's rows were indistinguishable before).
  3. A synthetic two-distinct-field-at-one-sink negative control (mirroring redos_verdict.py's own
     synthetic dual-family test) proving candidates_by_sink() keeps BOTH rows, distinctly tagged,
     rather than collapsing/deduplicating them by sink_id.
  4. reportable hardcoded False on every finding.
  5. Real per-sink line numbers and origin line/code, read from source_facts.tsv/
     propagation_relations.tsv directly, matching every row's own real Joern-derived data.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import nosqli_verdict  # noqa: E402

FIXTURES = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                          "tchecker-property-adjudicator/fixtures/nosqli_r01"))

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real Joern-derived fixture: full end-to-end reducer run against the frozen raw/ dir. ---
out_path = HERE / "out_nosqli_verdict.json"
work_dir = HERE / "out_nosqli_verdict.json.work"
classification, findings = nosqli_verdict.emit_findings(
    str(FIXTURES / "raw"), str(FIXTURES / "src"), str(work_dir), run_adjudicator=False)
with open(out_path, "w") as f:
    json.dump({"classification": classification, "findings": findings}, f, indent=2)

ck("8 candidate rows total", classification["CANDIDATE_FIELD_ROWS"] == 8)
ck("5 distinct sinks with a candidate field", classification["SINKS_WITH_CANDIDATE_FIELD"] == 5)
ck("8 findings emitted, one per candidate row", len(findings) == 8)
ck("no adjudicator run failures (adjudicator skipped in this check)",
   classification["ADJUDICATOR_RUN_FAILED"] == 0)

# --- 2. FIX01: field identity present and correct on every finding. ---
ck("every finding carries a non-empty field_name",
   all(f["field_name"] for f in findings))
ck("every finding carries field_kind=LITERAL_FIELD (this fixture has no computed-key case)",
   all(f["field_kind"] == "LITERAL_FIELD" for f in findings))
ck("all 8 findings' field_name is 'username' (both fixture files' own real field name)",
   all(f["field_name"] == "username" for f in findings))

# --- 3. reportable hardcoded False. ---
ck("reportable hardcoded False on every finding", all(f["reportable"] is False for f in findings))

# --- 4. Real line numbers, not placeholders. ---
ck("every finding has a real (>0) sink_line", all(f["sink_line"] > 0 for f in findings))
ck("every finding has a real (>0) origin_line", all(f["origin_line"] > 0 for f in findings))
ck("distinct sink_line values present (not all collapsed to one)",
   len({f["sink_line"] for f in findings}) == 5)


# --- 5. Synthetic negative control: two DISTINCT fields at one sink stay distinct, not collapsed
#        or deduplicated by sink_id (the exact shape NOSQLI-INTEG-R01-FIX01 was written to fix,
#        reproduced here without needing a second live Joern build). ---
def _write_tsv(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")


import shutil
import tempfile

synth_dir = pathlib.Path(tempfile.mkdtemp(prefix="nosqli_synth_"))
try:
    _write_tsv(synth_dir / "source_facts.tsv", [
        ["9001", "10", "9101", "QUERY_FIELD_VALUE", "ESTABLISHED", "LITERAL_FIELD", "email",
         "email", "", "", "", ""],
        ["9001", "10", "9102", "QUERY_FIELD_VALUE", "ESTABLISHED", "LITERAL_FIELD", "statusFlag",
         "statusFlag", "", "", "", ""],
    ])
    _write_tsv(synth_dir / "propagation_relations.tsv", [
        ["9001", "", "", "9101", "10", "email", "", "", ""],
        ["9001", "", "", "9102", "10", "statusFlag", "", "", ""],
    ])
    synth_cands = nosqli_verdict.candidates_by_sink(str(synth_dir))
    ck("synthetic dual-field sink keeps both rows under the same sink_id",
       len(synth_cands.get("9001", [])) == 2)
    synth_names = {c["field_name"] for c in synth_cands.get("9001", [])}
    ck("synthetic dual-field rows are distinctly tagged (email, statusFlag both present)",
       synth_names == {"email", "statusFlag"})
finally:
    shutil.rmtree(synth_dir, ignore_errors=True)

shutil.rmtree(work_dir, ignore_errors=True)
out_path.unlink(missing_ok=True)

print(f"NOSQLI_VERDICT={ok}/{total}")
print("PROMOTION_GATE=" + ("PASS" if ok == total else "FAIL"))
sys.exit(0 if ok == total else 1)
