#!/usr/bin/env python3
"""Real regression for the required reporting boundary: `node-libcurl` must count as ZERO
security findings in the final aggregator (`count_actionable_findings`), even though its own
real record remains present, inspectable, and fully evidenced as a diagnostic candidate --
`CONTRACT_NOT_APPLICABLE`, real `SOURCE_BOUNDARY_UNRESOLVED` source-boundary evidence, and
real per-target `enabled` configuration evidence, ALL on the same record.

Uses real cached facts (node-libcurl's own real raw C++ facts + real build_config.json;
Cartesi's own real raw facts, as a POSITIVE control proving the aggregator is not simply
always returning 0). SKIPPED (not FAILED) if the real cached facts aren't present in this
environment -- same discipline as this project's other real-data-dependent regressions.

Run: python3 tests/test_aggregation_boundary.py   (exit 0 = PASS or SKIP)
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from resource_guard_verdict_r06 import count_actionable_findings, ACTIONABLE_VERDICTS  # noqa: E402

LIBCURL_RAW = "/tmp/npm_corpus_pilot/99910/work/cpp_raw"
LIBCURL_BUILD_CONFIG = "/tmp/npm_corpus_pilot/99910/work/build_config.json"
CARTESI_RAW = "/tmp/cartesi_raw"
CARTESI_BUILD_CONFIG = "/tmp/bc_cartesi.json"


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


def run_scanner(raw_dir, build_config_path, out_path):
    scanner = os.path.join(os.path.dirname(HERE), "resource_guard_verdict_r06.py")
    rc = subprocess.run([sys.executable, scanner, raw_dir, out_path, "--real",
                         "--build-config", build_config_path],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        return None
    with open(out_path) as f:
        return json.load(f)


def all_present(*paths):
    return all(os.path.exists(p) for p in paths)


ok = True

# --- Unit: ACTIONABLE_VERDICTS/count_actionable_findings against a hand-built, real-shaped
# set of every verdict this file's own main() actually appends to `findings` -- proves the
# aggregator's own definition is exactly the one real actionable verdict, no more, no less. ---
print('=== Unit: aggregator counts ONLY VALUE_ACQUISITION_GUARD_MISSING ===')
ok &= check("ACTIONABLE_VERDICTS is exactly {VALUE_ACQUISITION_GUARD_MISSING}",
            ACTIONABLE_VERDICTS == {"VALUE_ACQUISITION_GUARD_MISSING"}, str(ACTIONABLE_VERDICTS))
all_real_verdicts = [
    "VALUE_ACQUISITION_SEMANTICS_UNRESOLVED", "CONTRACT_NOT_APPLICABLE",
    "BUILD_CONFIGURATION_CONFLICT", "BUILD_CONFIGURATION_UNRESOLVED",
    "VALUE_ACQUISITION_GUARD_ESTABLISHED", "VALUE_ACQUISITION_GUARD_MISSING",
]
synthetic_findings = [{"verdict": v} for v in all_real_verdicts]
ok &= check("exactly 1 of 6 real verdict shapes counts as actionable",
            count_actionable_findings(synthetic_findings) == 1,
            str(count_actionable_findings(synthetic_findings)))
ok &= check("an abstention/confirmed-safe record carrying REAL diagnostic sub-fields "
            "(source_boundary_evidence, build_config_evidence) still does not count",
            count_actionable_findings([{
                "verdict": "CONTRACT_NOT_APPLICABLE",
                "source_boundary_evidence": {"source_boundary": "SOURCE_BOUNDARY_UNRESOLVED",
                                              "attacker_controlled": False},
                "build_config_evidence": [{"exception_configuration": "enabled"}],
            }]) == 0)

# --- Real: node-libcurl -- the required negative case. ---
print('=== Real: node-libcurl must count as ZERO actionable findings ===')
if all_present(LIBCURL_RAW, LIBCURL_BUILD_CONFIG):
    out = run_scanner(LIBCURL_RAW, LIBCURL_BUILD_CONFIG, "/tmp/agg_test_libcurl_out.json")
    ok &= check("scanner ran cleanly", out is not None)
    if out is not None:
        ok &= check("actionable_findings field present in the real output JSON",
                    "actionable_findings" in out)
        ok &= check("actionable_findings == 0 (the required reporting boundary)",
                    out["actionable_findings"] == 0, str(out["actionable_findings"]))
        ok &= check("count_actionable_findings(out['findings']) independently agrees",
                    count_actionable_findings(out["findings"]) == 0)
        ok &= check("classification carries NO VALUE_ACQUISITION_GUARD_MISSING count at all",
                    "VALUE_ACQUISITION_GUARD_MISSING" not in out["classification"],
                    str(out["classification"]))
        ok &= check("no finding in the real findings list has verdict VALUE_ACQUISITION_GUARD_MISSING",
                    all(f.get("verdict") != "VALUE_ACQUISITION_GUARD_MISSING" for f in out["findings"]))

        # The record must still REMAIN, as a real, fully-evidenced diagnostic candidate --
        # this is not a case of the evidence being dropped, only of it not being counted.
        ok &= check("exactly 1 real diagnostic record present (not dropped)",
                    len(out["findings"]) == 1, str(len(out["findings"])))
        rec = out["findings"][0]
        ok &= check("record's own verdict is CONTRACT_NOT_APPLICABLE",
                    rec.get("verdict") == "CONTRACT_NOT_APPLICABLE", str(rec.get("verdict")))
        sbe = rec.get("source_boundary_evidence") or {}
        ok &= check("record still carries real SOURCE_BOUNDARY_UNRESOLVED evidence",
                    sbe.get("source_boundary") == "SOURCE_BOUNDARY_UNRESOLVED", str(sbe))
        cfg_evidence = rec.get("build_config_evidence") or []
        ok &= check("record still carries real per-target 'enabled' configuration evidence",
                    bool(cfg_evidence) and cfg_evidence[0].get("exception_configuration") == "enabled",
                    str(cfg_evidence))
        ok &= check("record's own resolution_scope is 'per_target' (the real target-scoped "
                    "resolution, not a package-wide guess)",
                    rec.get("resolution_scope") == "per_target", str(rec.get("resolution_scope")))
else:
    print("SKIP (real cached facts not present in this environment)")

# --- Real: Cartesi -- positive control proving the aggregator is not simply always 0. ---
print('=== Real: Cartesi -- positive control (3 real actionable findings) ===')
if all_present(CARTESI_RAW, CARTESI_BUILD_CONFIG):
    out = run_scanner(CARTESI_RAW, CARTESI_BUILD_CONFIG, "/tmp/agg_test_cartesi_out.json")
    ok &= check("scanner ran cleanly", out is not None)
    if out is not None:
        ok &= check("actionable_findings == 3 (real VALUE_ACQUISITION_GUARD_MISSING findings "
                    "DO count -- the aggregator is not vacuously always 0)",
                    out["actionable_findings"] == 3, str(out["actionable_findings"]))
        ok &= check("all 3 real findings are VALUE_ACQUISITION_GUARD_MISSING",
                    all(f.get("verdict") == "VALUE_ACQUISITION_GUARD_MISSING" for f in out["findings"]))
else:
    print("SKIP (real cached facts not present in this environment)")

print()
print('OVERALL:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
