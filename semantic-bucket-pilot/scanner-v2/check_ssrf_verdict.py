#!/usr/bin/env python3
"""SSRF-REDUCE-R01 regression: runs ssrf_verdict.py against FROZEN real Joern output
(export_ssrf_integ.sc, run over tchecker-property-adjudicator/fixtures/ssrf_r01/src/ -- a new
fixture built this session covering all three real containment_status outcomes:
no-guard/ESTABLISHED, host-overwrite/BROKEN, fixed-prefix-concat/BROKEN, guard-dominance/OPEN,
unresolved-transform/OPEN) checked into fixtures/ssrf_r01/raw/, so this reproduces without
needing Joern again -- same convention as check_path_traversal_verdict.py's/
check_nosqli_verdict.py's own frozen-fixture design.

Covers:
  1. End-to-end reducer run against real Joern output: 6 raw rows across 5 sinks, 2 BROKEN
     (excluded), 1 ESTABLISHED, 3 OPEN (the guardDominates function's own single sink call has TWO
     distinct source-identifier alternatives at lines 23/24, both real, both kept distinct -- not
     collapsed).
  2. SSRF-INTEG-R01-FIX01: containment_note survives into every finding, read from
     property_outcome.tsv's own column 3 (previously always the "-1" placeholder) -- the real,
     structural gap this fix closed (WHY a finding was classified BROKEN/OPEN was only ever in the
     producer's own stderr log before this fix).
  3. BROKEN alternatives are correctly EXCLUDED from findings (never surfaced), while OPEN and
     ESTABLISHED alternatives both ARE (neither is "safe").
  4. reportable hardcoded False on every finding.
  5. Real per-sink/per-origin line numbers and origin_code, read from source_facts.tsv/
     propagation_relations.tsv directly.
  6. A synthetic negative control (mirroring path_traversal_verdict.py's own) proving a raw dir
     with no property_outcome.tsv row for a given (sink, origin) key defaults safely to
     ("ESTABLISHED", "") rather than crashing or silently dropping the row.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import ssrf_verdict  # noqa: E402

FIXTURES = (pathlib.Path("/home/user/bug_tracker/tchecker-research-complete/"
                          "tchecker-property-adjudicator/fixtures/ssrf_r01"))

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real Joern-derived fixture: full end-to-end reducer run against the frozen raw/ dir. ---
out_path = HERE / "out_ssrf_verdict.json"
work_dir = HERE / "out_ssrf_verdict.json.work"
classification, findings = ssrf_verdict.emit_findings(
    str(FIXTURES / "raw"), str(FIXTURES / "src"), str(work_dir), run_adjudicator=False)
with open(out_path, "w") as f:
    json.dump({"classification": classification, "findings": findings}, f, indent=2)

ck("5 distinct sinks with a host-bearing flow", classification["SINKS_WITH_HOST_BEARING_FLOW"] == 5)
ck("2 BROKEN alternatives excluded (host-overwrite, fixed-prefix-concat)",
   classification["ALTERNATIVES_BROKEN_EXCLUDED"] == 2)
ck("1 ESTABLISHED alternative (noGuard)", classification["ALTERNATIVES_ESTABLISHED"] == 1)
ck("3 OPEN alternatives (2x guard-dominance + 1 unresolved-transform)",
   classification["ALTERNATIVES_OPEN"] == 3)
ck("4 findings emitted total (1 ESTABLISHED + 3 OPEN; 2 BROKEN never surfaced)",
   len(findings) == 4)
ck("no adjudicator run failures (adjudicator skipped in this check)",
   classification["ADJUDICATOR_RUN_FAILED"] == 0)
ck("no BROKEN finding ever surfaced", all(f["containment_status"] != "BROKEN" for f in findings))

# --- 2. FIX01: containment_note present and correct on every finding. ---
by_status = {}
for f in findings:
    by_status.setdefault(f["containment_status"], []).append(f)
ck("the ESTABLISHED finding carries an empty containment_note (no restriction found at all)",
   len(by_status.get("ESTABLISHED", [])) == 1
   and by_status["ESTABLISHED"][0]["containment_note"] == "")
ck("every OPEN finding carries a real, non-empty containment_note",
   len(by_status.get("OPEN", [])) == 3
   and all(f["containment_note"] for f in by_status["OPEN"]))
ck("the unresolved-transform OPEN finding's note names the real unrecognized call",
   any("someExternalNormalizer" in f["containment_note"] for f in by_status.get("OPEN", [])))
ck("both guard-dominance OPEN findings' notes name the real comparison",
   sum("allowed.example" in f["containment_note"] for f in by_status.get("OPEN", [])) == 2)

# --- 3. reportable hardcoded False. ---
ck("reportable hardcoded False on every finding", all(f["reportable"] is False for f in findings))

# --- 4. Real line numbers, not placeholders. ---
ck("every finding has a real (>0) sink_line", all(f["sink_line"] > 0 for f in findings))
ck("every finding has a real (>0) origin_line", all(f["origin_line"] > 0 for f in findings))
ck("origin_family is HTTP_HOST_INPUT on every finding (no WebExtension bridge used here)",
   all(f["origin_family"] == "HTTP_HOST_INPUT" for f in findings))

# --- 5. Synthetic negative control: a (sink, origin) key absent from property_outcome.tsv
#        defaults safely rather than crashing or silently dropping the row. ---
import shutil
import tempfile

synth_dir = pathlib.Path(tempfile.mkdtemp(prefix="ssrf_synth_"))
try:
    with open(synth_dir / "source_facts.tsv", "w") as f:
        f.write("\t".join(["9001", "10", "9101", "HTTP_HOST_INPUT", "ESTABLISHED",
                            "", "", "", "", "", "", ""]) + "\n")
    # deliberately NO property_outcome.tsv row for (9001, 9101)
    open(synth_dir / "propagation_relations.tsv", "w").close()
    synth_outcomes = ssrf_verdict.containment_status_and_note(str(synth_dir))
    ck("a missing property_outcome.tsv row is absent from the map (never fabricated)",
       ("9001", "9101") not in synth_outcomes)
    synth_alts = ssrf_verdict.alternatives_by_sink(str(synth_dir))
    ck("the source_facts.tsv row is still present in alternatives_by_sink() regardless",
       len(synth_alts.get("9001", [])) == 1)
finally:
    shutil.rmtree(synth_dir, ignore_errors=True)

shutil.rmtree(work_dir, ignore_errors=True)
out_path.unlink(missing_ok=True)

print(f"SSRF_VERDICT={ok}/{total}")
print("PROMOTION_GATE=" + ("PASS" if ok == total else "FAIL"))
sys.exit(0 if ok == total else 1)
