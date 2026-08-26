#!/usr/bin/env python3
"""verify_workspace_closure.py -- checks the SECOND invariant, distinct from verify_tchecker.sh/
verify_fable.sh/verify_gates.sh (which check "does the bundle work?"). This checks "does the
bundle contain what WORKSPACE_INVENTORY.md and MILESTONE_INDEX.md claim it contains?" -- i.e.
whether anything got forgotten between inventory and archive, not whether the included parts run.

Per the packaging instruction: fails (not skips) if a required local import target is absent, if
a fixture is absent without being explicitly marked historical/missing, or if a known
cross-component path is broken.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAIL = []
OK = []


def check(label, condition):
    (OK if condition else FAIL).append(label)
    print(("OK    " if condition else "FAIL  ") + label)


# --- 1. All 10 gates present as files -------------------------------------------------------
gates = ["gate_denylist_bypass.py", "gate_globalmut.py", "gate_guard_fallthrough.py",
         "gate_malicious_npm.py", "gate_serialize_dos.py", "gate_validation_bypass.py",
         "gate_r38.py", "gate_r39.py", "gate_r40.py"]
for g in gates:
    check(f"gates/{g} present", (ROOT / "gates" / g).is_file())
check("tchecker-property-adjudicator/adjudicator/gate_llm_input.py present (10th gate)",
      (ROOT / "tchecker-property-adjudicator/adjudicator/gate_llm_input.py").is_file())

# --- 2. Every gate's own verdict/dependency module present -----------------------------------
verdicts = ["denylist_bypass_verdict.py", "globalmut_verdict.py", "guard_fallthrough_verdict.py",
            "malicious_npm_verdict.py", "serialize_dos_verdict.py", "validation_bypass_verdict.py",
            "app_mount_flow.py"]
for v in verdicts:
    check(f"gates/{v} present", (ROOT / "gates" / v).is_file())

# --- 3. Fixtures for the 8 reproducible gates present; R39/R40 explicitly marked missing -----
reproducible_fixtures = ["deny-out", "gmut-out", "guard-out", "mal-out", "mal-fixture",
                          "ser-out", "loop-out", "r38-out", "r38-fixture"]
for f in reproducible_fixtures:
    check(f"gates/fixtures/{f}/ present", (ROOT / "gates/fixtures" / f).is_dir())
check("R39/R40 fixture absence is explicitly documented (not silently missing)",
      (ROOT / "gates/NOT_SELF_CONTAINED.md").is_file()
      and "NOT REPRODUCIBLE" in (ROOT / "gates/NOT_SELF_CONTAINED.md").read_text()
      and "gate_r39" in (ROOT / "gates/NOT_SELF_CONTAINED.md").read_text()
      and "gate_r40" in (ROOT / "gates/NOT_SELF_CONTAINED.md").read_text())

# --- 3b. User-provided, not-self-discovered gate39 (different numbering track than JS-PROV-R39) --
check("gates/user_provided_unverified/gate39_state_provenance.py present",
      (ROOT / "gates/user_provided_unverified/gate39_state_provenance.py").is_file())
check("its provenance is honestly documented (not presented as self-discovered)",
      (ROOT / "gates/user_provided_unverified/README.md").is_file()
      and "NOT SELF-DISCOVERED" in (ROOT / "gates/user_provided_unverified/README.md").read_text())

# --- 4. The known cross-component path is not broken -----------------------------------------
cc_path = ROOT / "gates/portable-engine-full-review-package"
check("gates/portable-engine-full-review-package symlink exists", cc_path.exists())
check("cross-component symlink resolves to a real directory", cc_path.is_dir())
check("context_state_flow.py reachable through the cross-component path",
      (cc_path / "frontends/javascript-typescript/joern-ts/context_state_flow.py").is_file())
check("framework_registration.py reachable through the cross-component path",
      (cc_path / "frontends/javascript-typescript/joern-ts/framework_registration.py").is_file())

# --- 5. scan_pkg.sh present, and its own non-self-containment is documented (not silently broken)
check("gates/scan_pkg.sh present", (ROOT / "gates/scan_pkg.sh").is_file())
check("scan_pkg.sh's non-self-containment is explicitly documented",
      (ROOT / "gates/SCAN_PKG_NOT_SELF_CONTAINED.md").is_file())
# 2026-08-24: joern-install.sh (pure upstream) removed per third-party policy; the
# closure requirement is now the pinned-download note in ENVIRONMENT.md instead.
check("Joern provisioning documented (pinned v4.0.608 download note in ENVIRONMENT.md)",
      "joern-cli-linux-x86_64.zip" in (ROOT / "ENVIRONMENT.md").read_text()
      and "v4.0.608" in (ROOT / "ENVIRONMENT.md").read_text())

# --- 5b. Artifacts recovered from prior output archives this pass ----------------------------
recovered = ["export_r38_facts.sc", "corpus-d-flows.json", "corpus-d-r40-flows.json",
             "guard-fallthrough-findings.json", "ORIGINAL_R40_GUARD_README.md"]
for r in recovered:
    check(f"gates/recovered_from_prior_outputs/{r} present",
          (ROOT / "gates/recovered_from_prior_outputs" / r).is_file())
check("NOT_SELF_CONTAINED.md documents how the typedecls.tsv bridge was found and resolved",
      "typedecls" in (ROOT / "gates/NOT_SELF_CONTAINED.md").read_text()
      and "RESOLVED" in (ROOT / "gates/NOT_SELF_CONTAINED.md").read_text())

for f in ["r39-out/raw", "r40-out/raw", "corpus_d_src"]:
    check(f"gates/fixtures/{f}/ present (R39/R40 now genuinely reproducible)",
          (ROOT / "gates/fixtures" / f).is_dir())
check("real Corpus D source bundled (koa-knex-realworld-example, for full reproducibility)",
      (ROOT / "gates/fixtures/corpus_d_src/lib/app.js").is_file())

# --- 6. Milestone documentation and historical scripts present -------------------------------
milestone_docs = ["ARCHITECTURE_SPECIFICATION.md", "CORPUS_REPLAY_REPORT.md",
                  "DEFINITION_RESOLVER_MILESTONE.md", "IDENTITY_GAP_CHARACTERIZATION.md",
                  "JS_ADJUDICATOR_MILESTONE.md", "PATH_CODE_CONTEXT_MILESTONE.md",
                  "PATH_FLOW_CONTEXT_MILESTONE.md", "PATH_SCOPED_TRANSFORM_IDENTITY_MILESTONE.md",
                  "PAYLOAD_SURFACING_MILESTONE.md", "PROPERTY_PROPAGATION.md",
                  "REPORT_denylist_bypass.md", "SOURCE_TO_SINK_PATH_RENDERING_MILESTONE.md",
                  "VALUE_PRESERVATION_AUDIT.md"]
docs_dir = ROOT / "tchecker-property-adjudicator/docs/milestones"
for d in milestone_docs:
    check(f"docs/milestones/{d} present", (docs_dir / d).is_file())

historical = ["build_customs_packet.py", "build_customs_pair.py", "build_evidence.py",
              "build_evidence_denylist.py", "build_evidence_globalmut.py", "build_evidence_guard.py",
              "build_evidence_mo.py", "build_evidence_prod.py", "build_evidence_src.py",
              "build_evidence_validation.py", "make_ablation.py", "path_transform_identity.py",
              "resolver_loop.py", "resolver_mo.py", "triage_pkg.py"]
hist_dir = ROOT / "tchecker-property-adjudicator/historical"
for h in historical:
    check(f"historical/{h} present", (hist_dir / h).is_file())

# --- 7. The three closure-specific documents this task itself requires -----------------------
for doc in ["WORKSPACE_INVENTORY.md", "MILESTONE_INDEX.md", "CROSS_COMPONENT_DEPENDENCIES.md"]:
    check(f"{doc} present at bundle root", (ROOT / doc).is_file())

# --- 8. Cross-check: every gate referenced in WORKSPACE_INVENTORY.md's matrix is really here --
inv_text = (ROOT / "WORKSPACE_INVENTORY.md").read_text() if (ROOT / "WORKSPACE_INVENTORY.md").exists() else ""
for g in gates + ["gate_llm_input.py"]:
    check(f"{g} referenced in WORKSPACE_INVENTORY.md's gate matrix", g in inv_text)

print()
print(f"CLOSURE_CHECKS_PASSED={len(OK)}")
print(f"CLOSURE_CHECKS_FAILED={len(FAIL)}")
if FAIL:
    print("VERIFY_WORKSPACE_CLOSURE=FAIL")
    for f in FAIL:
        print(f"  MISSING: {f}")
    sys.exit(1)
else:
    print("VERIFY_WORKSPACE_CLOSURE=PASS")
    sys.exit(0)
