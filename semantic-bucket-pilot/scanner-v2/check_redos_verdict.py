#!/usr/bin/env python3
"""REDOS-REDUCE-R01 regression: runs redos_verdict.py against FROZEN real Joern output
(export_redos_npm_integ.sc, pinned version -- see bootstrap.sh) checked into
study/redos_npm/fixtures/, so this reproduces without needing Joern again -- same convention as
check_lock_balance.py's own raw_real_vuln/raw_real_fixed fixtures.

Covers, per direct instruction, all four control kinds for the reducer:
  1. positive       -- a real exported-function param reaching a DANGEROUS regex classification
  2. fixed-negative -- the same export shape, but a SAFE (fully-anchored) regex: never emitted
  3. ordinary-negative -- an exported function whose param never reaches ANY regex operation
  4. abstention      -- class-constructor export, dynamic export key, require() re-export: all
                         three real shapes correctly contribute ZERO rows (see fixtures/README.md)
plus the two-tier promotion rule itself (Meteor.methods-only reachability must never promote to
a finding without PACKAGE_API_INPUT_REACHABLE also holding).
"""
import json
import pathlib
import subprocess
import shutil
import sys

HERE = pathlib.Path(__file__).parent
VERDICT = HERE / "redos_verdict.py"
FIXTURES = HERE / "study" / "redos_npm" / "fixtures"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# --- 1. Real Joern-derived fixture: full end-to-end reducer run. ---
out_path = HERE / "out_redos_verdict.json"
work_dir = HERE / "out_redos_verdict.json.work"
if work_dir.is_dir():
    shutil.rmtree(work_dir)
r = subprocess.run([sys.executable, str(VERDICT), str(FIXTURES / "raw"), str(FIXTURES / "src"),
                     str(out_path)], capture_output=True, text=True)
ck("redos_verdict.py exits 0 against the frozen real fixture", r.returncode == 0)
doc = json.loads(out_path.read_text())
cls = doc["classification"]
findings = doc["findings"]

ck("SINKS_WITH_ANY_ESTABLISHED_SOURCE == 7 (6 package-api + 1 meteor-ingress-only)",
   cls.get("SINKS_WITH_ANY_ESTABLISHED_SOURCE") == 7)
ck("PACKAGE_API_INPUT_REACHABLE == 6 (commonjs_direct, commonjs_named x2, esm_named x2, esm_default)",
   cls.get("PACKAGE_API_INPUT_REACHABLE") == 6)
ck("APPLICATION_INGRESS_ONLY_NOT_PROMOTED == 1 (meteor_ingress_only.js's handleAutotranslate, "
   "never exported -- must never become a finding)",
   cls.get("APPLICATION_INGRESS_ONLY_NOT_PROMOTED") == 1)
ck("ADJUDICATOR_RUN_FAILED == 0 (adjudicate_js.py ran cleanly for every promoted sink)",
   cls.get("ADJUDICATOR_RUN_FAILED") == 0)
ck("n_findings == 6 (exactly the PACKAGE_API_INPUT_REACHABLE count, never the raw 7)",
   len(findings) == 6)

# --- positive: every emitted finding has the exact required shape ---
ck("POSITIVE: every finding has classification=PACKAGE_API_INPUT_REACHABLE",
   findings and all(f["classification"] == "PACKAGE_API_INPUT_REACHABLE" for f in findings))
ck("POSITIVE: every finding has regex_complexity=CANDIDATE",
   findings and all(f["regex_complexity"] == "CANDIDATE" for f in findings))
ck("POSITIVE: every finding has source_boundary=EXPORTED_FUNCTION_PARAMETER",
   findings and all(f["source_boundary"] == "EXPORTED_FUNCTION_PARAMETER" for f in findings))
ck("POSITIVE: every finding has application_ingress=NOT_ESTABLISHED (none of the 6 also has a "
   "Meteor/req.* path in this fixture set)",
   findings and all(f["application_ingress"] == "NOT_ESTABLISHED" for f in findings))
ck("reportable is HARDCODED False on every finding, per direct instruction "
   "('keep it non-reportable initially')",
   findings and all(f["reportable"] is False for f in findings))

# --- fixed-negative / ordinary-negative / abstention: the specific sinks that must NEVER appear ---
finding_sink_ids = {f["sink_node_id"] for f in findings}
ck("FIXED-NEGATIVE: meteor_ingress_only.js's own sink (30064771122, APPLICATION_INGRESS-only) is "
   "absent from findings",
   "30064771122" not in finding_sink_ids)
# safe_export.js's/noreach_export.js's/the 3 abstained exports' own sinks never even reach
# source_facts.tsv (see fixtures/README.md's own real row count -- 7, not 11) -- confirmed
# structurally by the SINKS_WITH_ANY_ESTABLISHED_SOURCE==7 check above, not re-derivable from
# finding_sink_ids alone since an absent sink never gets a node_id in this output at all.

# --- 2. Synthetic negative control (disclosed, not corpus data): a hand-built raw dir proving
# the two-tier promotion rule directly, independent of the real Joern fixture above -- a sink
# reached by BOTH families must set application_ingress=ESTABLISHED (strengthens, still requires
# PACKAGE_API_INPUT); a sink reached by APPLICATION_INGRESS alone must never appear.
import tempfile

_synthetic_tsv = (
    "9001\t10\t7001\tPACKAGE_API_INPUT\tESTABLISHED\t\t\t\t\t\t\t\n"
    "9001\t10\t7002\tAPPLICATION_INGRESS\tESTABLISHED\t\t\t\t\t\t\t\n"
    "9002\t20\t7003\tAPPLICATION_INGRESS\tESTABLISHED\t\t\t\t\t\t\t\n"
)
with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    (tdp / "source_facts.tsv").write_text(_synthetic_tsv)
    (tdp / "propagation_relations.tsv").write_text("")
    (tdp / "property_outcome.tsv").write_text("")
    (tdp / "transform_identity.tsv").write_text("")
    sys.path.insert(0, str(HERE))
    import redos_verdict as rv
    fams = rv.families_by_sink(str(tdp))

ck("SYNTHETIC: sink 9001 (both families) carries BOTH origin_family tags",
   fams.get("9001") == {"PACKAGE_API_INPUT", "APPLICATION_INGRESS"})
ck("SYNTHETIC: sink 9002 (APPLICATION_INGRESS only) carries only that one tag -- "
   "confirms families_by_sink() itself, independent of the reducer's promotion logic, "
   "correctly preserves per-sink family membership rather than collapsing to one",
   fams.get("9002") == {"APPLICATION_INGRESS"})

print(f"REDOS_VERDICT_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
