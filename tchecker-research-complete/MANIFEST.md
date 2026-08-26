# MANIFEST

Per-file inventory. "Exercised" = actually run during this packaging pass's verification.

See WORKSPACE_INVENTORY.md for the full workspace-closure accounting and gate matrix,
MILESTONE_INDEX.md for the 50 design-milestone identifiers found, and
CROSS_COMPONENT_DEPENDENCIES.md for the 5 real cross-component references.

| Path | Component | Kind | Exercised | Purpose |
|---|---|---|---|---|
| `CHECKSUMS.sha256` | Both | documentation | n/a |  |
| `CROSS_COMPONENT_DEPENDENCIES.md` | Both | documentation | n/a |  |
| `ENVIRONMENT.md` | Both | documentation | n/a |  |
| `MANIFEST.md` | Both | documentation | n/a |  |
| `MILESTONE_INDEX.md` | Both | documentation | n/a |  |
| `README.md` | Both | documentation | n/a |  |
| `RUNBOOK.md` | Both | documentation | n/a |  |
| `WORKSPACE_INVENTORY.md` | Both | documentation | n/a |  |
| `examples/A_full_evidence_fxa_customs/adjudication_trace.json` | A | generated evidence | yes |  |
| `examples/A_full_evidence_fxa_customs/audit_evidence_1.json` | A | generated evidence | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/definition_resolution.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/path_code_context.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/path_flow_context.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/propagation_relations.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/property_outcome.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/source_facts.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/trace_identity.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/cand1-ps/raw/transform_identity.tsv` | A | fixture (facts) | yes |  |
| `examples/A_full_evidence_fxa_customs/corpus-scan/c1/customs.js` | A | fixture (source) | yes |  |
| `examples/A_full_evidence_fxa_customs/corpus-scan/c2/emails.js` | A | fixture (source) | yes |  |
| `examples/A_full_evidence_fxa_customs/evidence_final.json` | A | generated evidence | yes |  |
| `examples/A_full_evidence_fxa_customs/generated_llm_input_1.json` | A | generated evidence | yes |  |
| `examples/B_nosql_ajv_gate_fixture/ajv_gate_fixture.js` | A | fixture (source) | yes |  |
| `examples/C_redos_stage1_stage2_fixtures/stage1_sinks/sink_shapes.js` | A | fixture (source) | yes |  |
| `examples/C_redos_stage1_stage2_fixtures/stage2_prop_effects/stage2_fixture.js` | A | fixture (source) | yes |  |
| `examples/D_plugin_scan_gemini/generated_verdict.json` | A | generated evidence | yes |  |
| `examples/D_plugin_scan_gemini/llm_call_sites.tsv` | A | fixture (source) | yes |  |
| `examples/D_plugin_scan_gemini/llm_output_sinks.tsv` | A | fixture (source) | yes |  |
| `examples/D_plugin_scan_gemini/prompt_injection.tsv` | A | fixture (source) | yes |  |
| `examples/D_plugin_scan_gemini/source/GeminiApp.ts` | A | fixture (source) | yes |  |
| `examples/D_plugin_scan_gemini/source/commands/GeminiCommand.ts` | A | fixture (source) | yes |  |
| `gates/NOT_SELF_CONTAINED.md` | Gates | documentation | n/a |  |
| `gates/SCAN_PKG_NOT_SELF_CONTAINED.md` | Gates | documentation | n/a |  |
| `gates/app_mount_flow.py` | Gates | source (gate/dependency) | yes |  |
| `gates/denylist_bypass_verdict.py` | Gates | source (verdict) | yes |  |
| `gates/fixtures/deny-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/collection_flow.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/denylist_guards.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/loop_collections.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/loop_exits.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/loop_sink_sites.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/loopctl.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/deny-out/raw/pattern_consumers.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/export_member_alias.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/import_calls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/module_exports.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/percall_overrides.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/require_bindings.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/require_member_selection.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/security_member_reads.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/gmut-out/raw/singleton_writes.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/export_member_alias.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/guard_calls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/import_calls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/method_guard_sink_lines.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/module_exports.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/require_bindings.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/require_member_selection.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/sink_sites.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/guard-out/raw/terminator_profile.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/loop-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/loop-out/raw/loop_collections.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/loop-out/raw/loop_exits.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/loop-out/raw/loop_sink_sites.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/loop-out/raw/loopctl.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-network/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-network/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-osinfo/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-osinfo/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-postinstall/build.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-postinstall/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/benign-postinstall/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/cpexec-benign/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/cpexec-benign/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/cpexec-mal/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/cpexec-mal/run.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/eval-benign/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/eval-benign/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/eval-mal/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/eval-mal/setup.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/launder-benign/index.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/launder-benign/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/launder-mal/collect.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/launder-mal/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/mal-pkg/dc.js` | Gates | fixture | yes |  |
| `gates/fixtures/mal-fixture/mal-pkg/package.json` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/decode_eval_sinks.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/exec_sites.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/exfil_links.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/helper_launder.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/identifier_reads.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/mal-out/raw/outbound_requests.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/controllers/articles-controller.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/lib/app.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/lib/audit-middleware.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/lib/late-middleware.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/lib/user-middleware.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/routes/articles-router.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/routes/multi-router.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/routes/orphan-router.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-fixture/routes/tags-router.js` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/arguments.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/call_argument_identifiers.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/call_blocks.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/calls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/closure_bindings.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/condition_identifiers.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/control_structures.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/guard_then_branch_members.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/identifiers.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/literals.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/local_closure.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/locals.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/members.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/meta.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/method_refs.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/method_returns.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/methods.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/parameters.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/returns.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/type_decls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/char/type_hints.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/callback_args.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/callsites.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/ctx_state.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/default_export_identifier.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/export_member_alias.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/import_calls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/method_params.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/module_exports.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/registration_order.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/registrations.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/require_bindings.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/require_member_selection.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/r38-out/raw/typedecls.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/ser-out/cpg.bin` | Gates | fixture | yes |  |
| `gates/fixtures/ser-out/raw/depth_guards.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/ser-out/raw/serialize_sinks.tsv` | Gates | fixture | yes |  |
| `gates/fixtures/ser-out/raw/uncaught_handlers.tsv` | Gates | fixture | yes |  |
| `gates/gate_denylist_bypass.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_globalmut.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_guard_fallthrough.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_malicious_npm.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_r38.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_r39.py` | Gates | source (gate/dependency) | no (fixture absent) |  |
| `gates/gate_r40.py` | Gates | source (gate/dependency) | no (fixture absent) |  |
| `gates/gate_serialize_dos.py` | Gates | source (gate/dependency) | yes |  |
| `gates/gate_validation_bypass.py` | Gates | source (gate/dependency) | yes |  |
| `gates/globalmut_verdict.py` | Gates | source (verdict) | yes |  |
| `gates/guard_fallthrough_verdict.py` | Gates | source (verdict) | yes |  |
| `gates/malicious_npm_verdict.py` | Gates | source (verdict) | yes |  |
| `gates/portable-engine-full-review-package` | Gates | symlink -> Component B | yes (verified via tar round-trip) | The cross-component dependency point. |
| `gates/scan_pkg.sh` | Gates | utility script | not self-contained, documented |  |
| `gates/serialize_dos_verdict.py` | Gates | source (verdict) | yes |  |
| `gates/validation_bypass_verdict.py` | Gates | source (verdict) | yes |  |
| `joern-install.sh` | Both | utility script | not re-run this pass, real installer |  |
| `portable-engine-full-review-package/HOW_TO_RUN.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/PHPASTDefUseAnalyzer.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/AssignmentWithOpEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/CatchEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/DoEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/FieldDeclarationEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/FunctionDefEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/PropertyEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/detector/joern-php/src/main/java/udg/php/useDefAnalysis/environments/VariableEnvironment.java` | B | source (Java) | no - core absent |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/LICENSE` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/README.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/conf/batch.properties` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/php2ast` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/src/CSVExporter.php` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/src/Exporter.php` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/src/GraphMLExporter.php` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/src/Parser.php` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/parser/src/util.php` | B | other | no |  |
| `portable-engine-full-review-package/engine/legacy-detector/tchecker/run_recall.sh` | B | test/gate script | no - deps absent |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/closure_resolution.js` | B | source (frontend helper) | no |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/README.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/capture_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/context_state_flow.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/dispatch_resolution.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/export_ts_facts.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/external_input_origin.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/failure_state_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/framework_registration.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/identity_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/import_binding_identity.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/import_bindings.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/js_prov_r08.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/js_state_r07.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/local_definitions.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/module_export_identity.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/module_specifier_resolution.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/normalize_ts_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/observed_parameter_types.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/parameter_decorators.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/returned_function_identity.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/returned_function_identity.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/run_real_joern_ts.sh` | B | test/gate script | no - deps absent |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/security_sensitive_reachability.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/security_sink_profile.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/state_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern-ts/transform_input_origin.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern/NEUTRAL_IR.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern/README.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern/export_neutral.sc` | B | source (Joern script) | no - needs Java core |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern/normalize_joern_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/joern/run_real_joern_frontend.sh` | B | test/gate script | no - deps absent |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/ts2legacycsv.js` | B | source (frontend helper) | no |  |
| `portable-engine-full-review-package/frontends/javascript-typescript/tsc-sidecar/tsc_union_types.js` | B | source (frontend helper) | no |  |
| `portable-engine-full-review-package/frontends/php/README.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/frontends/polyglot/link_napi_facts.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/profiles/wordpress/README.md` | B | documentation | n/a |  |
| `portable-engine-full-review-package/profiles/wordpress/instrumentation/adjudicate.py` | B | source (JS/TS frontend) | framework_registration.py + context_state_flow.py: yes, used LIVE by gates/gate_r38.py |  |
| `portable-engine-full-review-package/verify_canonical_engine.sh` | B | test/gate script | no - deps absent |  |
| `tchecker-property-adjudicator/adjudicator/adjudicate_js.py` | A | source (adjudicator) | yes |  |
| `tchecker-property-adjudicator/adjudicator/gate_llm_input.py` | A | source (adjudicator) | yes |  |
| `tchecker-property-adjudicator/adjudicator/llm_input_verdict.py` | A | source (adjudicator) | yes |  |
| `tchecker-property-adjudicator/adjudicator/no_hints.json` | A | config | yes |  |
| `tchecker-property-adjudicator/adjudicator/test_abstention_collapse.py` | A | test | yes |  |
| `tchecker-property-adjudicator/adjudicator/test_source_coverage.py` | A | test | yes |  |
| `tchecker-property-adjudicator/docs/LLM_INPUT_REALWORLD_PLUGIN_SCAN.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/NOSQLI_SCANNER_FIXES.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/NOSQLI_SINK_SEMANTICS_MATRIX.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/NOSQLI_STAGE2_PROPERTY_EFFECTS.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/NOSQLI_STAGE3_RESULT_AND_AJV_GAP.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/REDOS_PROPERTY_FROZEN.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/REDOS_SINK_SEMANTICS_MATRIX.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/REDOS_STAGE2_SUFFIX_DELIMITER_FIX.md` | A | documentation | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/ARCHITECTURE_SPECIFICATION.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/CORPUS_REPLAY_REPORT.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/DEFINITION_RESOLVER_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/IDENTITY_GAP_CHARACTERIZATION.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/JS_ADJUDICATOR_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/PATH_CODE_CONTEXT_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/PATH_FLOW_CONTEXT_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/PATH_SCOPED_TRANSFORM_IDENTITY_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/PAYLOAD_SURFACING_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/PROPERTY_PROPAGATION.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/REPORT_denylist_bypass.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/SOURCE_TO_SINK_PATH_RENDERING_MILESTONE.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/docs/milestones/VALUE_PRESERVATION_AUDIT.md` | A | documentation (milestone) | n/a |  |
| `tchecker-property-adjudicator/fixtures/cmdinj_prop_effects/stage2a_fixture.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/cmdinj_sinks/sink_shapes.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/cmdinj_stage2b/stage2b_fixture.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/definition_resolution.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/path_code_context.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/path_flow_context.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/propagation_relations.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/property_outcome.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/source_facts.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/trace_identity.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/cand1-ps/raw/transform_identity.tsv` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/corpus-scan/c1/customs.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/customs_dos_serialize/corpus-scan/c2/emails.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-eval-vuln/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-no-llm/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-output-safe/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-sysinject-vuln/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-twilio-safe/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_input/llm-userrole-safe/handler.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_plugin_realworld/GeminiApp.ts` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/llm_plugin_realworld/commands/GeminiCommand.ts` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/nosqli_ajv_gate/ajv_gate_fixture.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/nosqli_prop_effects/stage2_fixture.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/nosqli_sinks/sink_shapes.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/path_traversal_prop_effects/property_effects.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/path_traversal_sinks/sink_shapes.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/redos_prop_effects/stage2_fixture.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/redos_sinks/sink_shapes.js` | A | fixture (source) | yes |  |
| `tchecker-property-adjudicator/fixtures/ssrf_prop_effects/property_effects.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/fixtures/ssrf_sinks/sink_shapes.js` | A | fixture (source) | no |  |
| `tchecker-property-adjudicator/historical/build_customs_packet.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_customs_pair.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_denylist.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_globalmut.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_guard.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_mo.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_prod.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_src.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/build_evidence_validation.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/make_ablation.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/path_transform_identity.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/resolver_loop.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/resolver_mo.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/historical/triage_pkg.py` | A (historical) | source (superseded) | no - not imported by any working script |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/multisource.js` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/out/adjudication_trace.json` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/out/evidence_final.json` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/out/evidence_v0.json` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/definition_resolution.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/propagation_relations.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/property_outcome.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/source_facts.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/trace_identity.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/raw/transform_identity.tsv` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/neweval/sourcecoverage/stage_multisource.sc` | A | fixture (facts) | yes |  |
| `tchecker-property-adjudicator/producers/batch_stage_candidates.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_cmdinj_property_effects.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_cmdinj_sinks.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_cmdinj_stage2b.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_nosqli_property_effects.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/characterize_nosqli_sinks.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/characterize_path_traversal_property_effects.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_path_traversal_sinks.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_redos_sinks.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/characterize_redos_stage2.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/characterize_regex_slice.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_ssrf_property_effects.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/characterize_ssrf_sinks.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_binding_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_definition_resolver.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_denylist_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_enumeration_audit.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_framework_sink_audit.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_globalmut_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_guard_cfg.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_guard_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_identity_gap.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_iteration_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_llm_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_loop_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_loopctl.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_mal_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_matcher_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_nosqli_integ.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/export_path_code_context.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/export_path_flow_context.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/export_path_traversal_integ.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_proof_propagation.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_propagation.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_property_propagation.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_r38_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_redos_integ.sc` | A | source (producer) | yes |  |
| `tchecker-property-adjudicator/producers/export_serialize_facts.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_source_prov_r01.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_sourcefact.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_ssrf_integ.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_trace_identity.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_transform_identity.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/export_value_flow_audit.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/measure_multi_alternative.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/regen_all_alternatives.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/resolve_instance_property.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/resolve_ts_overload.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/setup_candidate.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/producers/test_ajv_gate_detection.sc` | A | source (producer) | no |  |
| `tchecker-property-adjudicator/property_configs/nosqli_query_op.json` | A | config | yes |  |
| `tchecker-property-adjudicator/property_configs/path_traversal_host.json` | A | config | no |  |
| `tchecker-property-adjudicator/property_configs/redos_complexity.json` | A | config | no |  |
| `tchecker-property-adjudicator/property_configs/serialize_dos.json` | A | config | no |  |
| `tchecker-property-adjudicator/property_configs/ssrf_host.json` | A | config | no |  |
| `verification/verify_fable.sh` | Both | test | yes |  |
| `verification/verify_files.sh` | Both | test | yes |  |
| `verification/verify_gates.sh` | Both | test | yes |  |
| `verification/verify_tchecker.sh` | Both | test | yes |  |
| `verification/verify_workspace_closure.py` | Both | test | yes |  |
| `workspace/nosqli.cpg.bin/cpg.bin` | ? | other | no |  |
| `workspace/nosqli.cpg.bin/cpg.bin.tmp` | ? | other | no |  |
| `workspace/nosqli.cpg.bin/project.json` | ? | other | no |  |

| `tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_bridge.py` | A/B bridge | test | yes | Frozen live-run integration and real Mozilla no-sink holdout. |
| `tchecker-property-adjudicator/adjudicator/portable_ssrf_source_bridge.py` | A/B bridge | source (adapter) | yes | Fail-closed adapter for established `WEBEXT_TAB_URL_INPUT` state reads. |
| `tchecker-property-adjudicator/adjudicator/test_portable_ssrf_source_bridge.py` | A/B bridge | test | yes | Nine source-class acceptance and contamination controls. |
| `tchecker-property-adjudicator/docs/milestones/JS_SSRF_SOURCE_R01_WEBEXT_BRIDGE.md` | A/B bridge | documentation (milestone) | n/a | Scope and measured behavior for JS-SSRF-SOURCE-R01. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/evidence_final.json` | A/B bridge | fixture (evidence) | yes | Deterministically closed controlled finding. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/raw/propagation_relations.tsv` | A/B bridge | fixture (facts) | yes | Live Joern source-to-sink relation. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/raw/property_outcome.tsv` | A/B bridge | fixture (facts) | yes | Established request-host property. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/raw/source_facts.tsv` | A/B bridge | fixture (facts) | yes | One class-separated tab-URL source fact. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/controlled/raw/transform_identity.tsv` | A/B bridge | fixture (facts) | yes | Empty: direct path has no transform. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/real_no_sink/raw/propagation_relations.tsv` | A/B bridge | fixture (facts) | yes | Empty real Mozilla holdout. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/real_no_sink/raw/property_outcome.tsv` | A/B bridge | fixture (facts) | yes | Empty real Mozilla holdout. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/real_no_sink/raw/source_facts.tsv` | A/B bridge | fixture (facts) | yes | Empty real Mozilla holdout. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_bridge/real_no_sink/raw/transform_identity.tsv` | A/B bridge | fixture (facts) | yes | Empty real Mozilla holdout. |
| `tchecker-property-adjudicator/adjudicator/gate_webext_external_ssrf_bridge.py` | A/B bridge | test | yes | Strict external-message source separation and propagation controls. |
| `tchecker-property-adjudicator/docs/milestones/JS_SSRF_SOURCE_R02_EXTERNAL_MESSAGES.md` | A/B bridge | documentation (milestone) | n/a | Scope and measured behavior for JS-SSRF-SOURCE-R02. |
| `tchecker-property-adjudicator/adjudicator/gate_webext_ssrf_llm_handoff.py` | A evidence handoff | test | yes | Complete code-and-hint packet regression for an `OPEN` SSRF path. |
| `tchecker-property-adjudicator/docs/milestones/JS_SSRF_HANDOFF_R01_LLM_CONTEXT.md` | A evidence handoff | documentation (milestone) | n/a | Scope, defect, and invariants for JS-SSRF-HANDOFF-R01. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/external-message-rewrite-fetch.js` | A evidence handoff | fixture (source) | yes | Controlled external-message path through two unresolved transforms. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/source_facts.tsv` | A evidence handoff | fixture (facts) | yes | Class-separated live source/sink identity. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/propagation_relations.tsv` | A evidence handoff | fixture (facts) | yes | Live source-to-sink propagation relation. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/property_outcome.tsv` | A evidence handoff | fixture (facts) | yes | Expected `OPEN` request-host property. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/transform_identity.tsv` | A evidence handoff | fixture (facts) | yes | Two ordered unresolved transform identities. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/raw/path_code_context.tsv` | A evidence handoff | fixture (facts) | yes | Source, transform, and sink code joined by node ID. |
| `tchecker-property-adjudicator/fixtures/webext_ssrf_transform/llm_input_1.json` | A evidence handoff | fixture (evidence) | yes | Exact manual LLM input packet from live adjudication. |

**Total entries: 388**

## Known external dependencies not bundled

| Dependency | Version used | Why not bundled |
|---|---|---|
| Joern / jssrc2cpg | **4.0.608** (exact pin) | ~1.9 GB distribution. Download command in RUNBOOK.md. |
| JDK | OpenJDK 21.0.10 | Present in this environment. Component B's Java core is absent regardless. |
| Python | 3.12.3 | Standard library only for adjudicate_js.py and the 6 self-contained detector gates. |
| Node.js | v22.22.2 | Only needed by Component B frontend helpers. |
| LLM API / model config | none bundled | The bundle generates llm_input_N.json and stops. |
| Component B Java core | **MISSING** | PortableProvenanceEngine/ProgramGraphLoader/build.sh/tests/ referenced but absent. |
| R39/R40 fixture data | **MISSING** | r39-out/, r40-out/ absent from the source workspace. Code included regardless. |
| External corpora | not bundled | RocketChat, full FxA excluded; examples reproduce offline with what's bundled. |
