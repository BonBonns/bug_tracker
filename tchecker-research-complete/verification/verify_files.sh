#!/usr/bin/env bash
# verify_files.sh -- confirm every required file is present. Missing = FAILURE, never SKIP.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
req() { if [ -e "$ROOT/$1" ]; then echo "OK    $1"; else echo "FAIL  MISSING $1"; FAIL=1; fi }

echo "=== Component A: TChecker property adjudicator ==="
req tchecker-property-adjudicator/adjudicator/adjudicate_js.py
req tchecker-property-adjudicator/adjudicator/test_abstention_collapse.py
req tchecker-property-adjudicator/adjudicator/test_source_coverage.py
req tchecker-property-adjudicator/adjudicator/portable_ssrf_source_bridge.py
req tchecker-property-adjudicator/adjudicator/test_portable_ssrf_source_bridge.py
req tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_bridge.py
req tchecker-property-adjudicator/adjudicator/gate_webext_external_ssrf_bridge.py
req tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_llm_handoff.py
req tchecker-property-adjudicator/adjudicator/gate_fail_open_security_control.py
req tchecker-property-adjudicator/adjudicator/adjudicate_fail_open.py
req tchecker-property-adjudicator/adjudicator/no_hints.json
for p in ssrf path_traversal cmdinj redos nosqli; do
  req tchecker-property-adjudicator/producers/characterize_${p}_sinks.sc 2>/dev/null || true
done
req tchecker-property-adjudicator/producers/export_serialize_facts.sc
req tchecker-property-adjudicator/producers/export_path_code_context.sc
req tchecker-property-adjudicator/producers/export_path_flow_context.sc
req tchecker-property-adjudicator/property_configs/serialize_dos.json
req tchecker-property-adjudicator/property_configs/ssrf_host.json
req tchecker-property-adjudicator/property_configs/path_traversal_host.json
req tchecker-property-adjudicator/property_configs/redos_complexity.json
req tchecker-property-adjudicator/property_configs/nosqli_query_op.json
req tchecker-property-adjudicator/neweval/sourcecoverage/raw/source_facts.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/raw/source_facts.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/evidence_final.json
req tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/real_no_sink/raw/source_facts.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/external_controlled/raw/source_facts.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_transform/external-message-rewrite-fetch.js
req tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/source_facts.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/transform_identity.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/path_code_context.tsv
req tchecker-property-adjudicator/fixtures/webext_ssrf_transform/llm_input_1.json
req tchecker-property-adjudicator/fixtures/fail_open_security_control/raw/fail_open_candidates.tsv
req tchecker-property-adjudicator/fixtures/fail_open_security_control/llm_input_1.json

echo "=== Component B: Portable Engine / Fable ==="
req portable-engine-full-review-package/HOW_TO_RUN.md
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/export_ts_facts.sc
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/import_binding_identity.py
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/dispatch_resolution.py
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/framework_registration.py
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/state_facts.py
req portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/security_sink_profile.py

echo "=== Examples ==="
req examples/A_full_evidence_fxa_customs/corpus-scan/c1/customs.js
req examples/A_full_evidence_fxa_customs/cand1-ps/raw/path_code_context.tsv
req examples/A_full_evidence_fxa_customs/cand1-ps/raw/path_flow_context.tsv
req examples/A_full_evidence_fxa_customs/generated_llm_input_1.json
req examples/B_nosql_ajv_gate_fixture/ajv_gate_fixture.js
req examples/C_redos_stage1_stage2_fixtures/stage1_sinks/sink_shapes.js
req examples/C_redos_stage1_stage2_fixtures/stage2_prop_effects/stage2_fixture.js

echo ""
echo "=== Gates (vulnerability-detector + R38/R39/R40 milestone gates) ==="
req gates/gate_r38.py
req gates/gate_r39.py
req gates/gate_r40.py
req gates/app_mount_flow.py
req gates/gate_serialize_dos.py
req gates/gate_malicious_npm.py
req gates/NOT_SELF_CONTAINED.md
if [ -L "$ROOT/gates/portable-engine-full-review-package" ] || [ -d "$ROOT/gates/portable-engine-full-review-package" ]; then
  echo "OK    gates/portable-engine-full-review-package (symlink to Component B, R38's cross-component dependency)"
else
  echo "FAIL  MISSING gates/portable-engine-full-review-package symlink"; FAIL=1
fi

echo ""
if [ $FAIL -eq 0 ]; then echo "VERIFY_FILES=PASS"; else echo "VERIFY_FILES=FAIL"; fi
exit $FAIL
