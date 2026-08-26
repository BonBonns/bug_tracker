# RUNBOOK

Every command below was executed during packaging; expected outputs are what was actually observed.

## 0. Prerequisites

    # Joern 4.0.608 (exact pin; download verified reachable during packaging)
    mkdir -p ~/joern-install && cd ~/joern-install
    curl -sL -o joern-cli.zip \
      "https://github.com/joernio/joern/releases/download/v4.0.608/joern-cli-linux-x86_64.zip"
    unzip -q joern-cli.zip
    export JOERN_HOME=~/joern-install/joern-cli
    chmod +x $JOERN_HOME/joern $JOERN_HOME/jssrc2cpg.sh

    # confirm (note: --version is NOT supported; it hangs in a REPL. pipe input instead)
    echo "" | timeout 60 $JOERN_HOME/joern 2>&1 | grep "Version:"    # -> Version: 4.0.608

Python 3.12 stdlib only — no pip installs needed. Component B also requires JDK 21. If
`javac` is missing on Ubuntu/Debian, refresh package metadata before installing it:

    apt-get update && apt-get install -y openjdk-21-jdk-headless

## 1. Verify the bundle

    bash verification/verify_files.sh      # -> VERIFY_FILES=PASS
    bash verification/verify_tchecker.sh   # -> VERIFY_TCHECKER=PASS
    bash verification/verify_fable.sh      # -> VERIFY_FABLE=PASS (with JDK 21)

## 2. Component A — reproduce the full-evidence LLM packet (Example A)

This is the case where deterministic analysis establishes the dataflow but leaves the *property*
UNKNOWN, so the adjudicator emits a semantic-review packet.

    cd tchecker-property-adjudicator/adjudicator
    TCH_RAW=../../examples/A_full_evidence_fxa_customs/cand1-ps/raw \
    TCH_SRC=../../examples/A_full_evidence_fxa_customs/corpus-scan/c1 \
    TCH_OUT=/tmp/fxa_out TCH_SINK=30064771145 \
    TCH_FINDING="fxa/packages/fxa-auth-server/lib/customs.js" \
    TCH_HINTS=no_hints.json python3 adjudicate_js.py

Expected:

    rounds: 1
    FINAL: CANDIDATE_OPEN  (deterministic layer: SEMANTICALLY_OPEN)

Then inspect `/tmp/fxa_out/llm_input_1.json`. It must contain:
- `"schema": "tchecker-llm-input/1.4"`
- 4 entries in `SOURCE_TO_SINK_PATHS` (request.payload x2, request.query, request.headers)
- `PATH_CODE_CONTEXT` with the real `sanitizePayload()` and `makeRequest()` bodies
- `PATH_FLOW_CONTEXT` with real `transitions` (ARGUMENT_TO_PARAMETER, ALIAS, PROPERTY_READ, ...)
- a `QUESTION` asking specifically whether `sanitizePayload` bounds serialized size
- `answer_contract` with `SAFE | UNSAFE | UNKNOWN`

A pre-generated copy is at `examples/A_full_evidence_fxa_customs/generated_llm_input_1.json`.

## 3. Component A — per-property pipelines

Pattern for every property: build a CPG from a fixture, run the producer, read the matrix.

    export JOERN_HOME=...
    TC=tchecker-property-adjudicator

    # NoSQL injection: Stage 1 (10 rows), Stage 2 (9/9), Stage 3 (4 of 9 PRESERVES, 7 EMIT)
    $JOERN_HOME/jssrc2cpg.sh $TC/fixtures/nosqli_sinks -o /tmp/n1.bin
    $JOERN_HOME/joern --script $TC/producers/characterize_nosqli_sinks.sc \
        --param cpgFile=/tmp/n1.bin --param outFile=/tmp/n1.tsv
    $JOERN_HOME/jssrc2cpg.sh $TC/fixtures/nosqli_prop_effects -o /tmp/n2.bin
    $JOERN_HOME/joern --script $TC/producers/characterize_nosqli_property_effects.sc \
        --param cpgFile=/tmp/n2.bin --param outFile=/tmp/n2.tsv
    mkdir -p /tmp/n_raw
    $JOERN_HOME/joern --script $TC/producers/export_nosqli_integ.sc \
        --param cpgFile=/tmp/n2.bin --param rawDir=/tmp/n_raw \
        --param srcLabel=RUN --param skipCount=0

    # AJV route-schema-gate check (Example B): expect "excluded 2 targets", "2 of 4"
    $JOERN_HOME/jssrc2cpg.sh examples/B_nosql_ajv_gate_fixture -o /tmp/ajv.bin
    mkdir -p /tmp/ajv_raw
    $JOERN_HOME/joern --script $TC/producers/export_nosqli_integ.sc \
        --param cpgFile=/tmp/ajv.bin --param rawDir=/tmp/ajv_raw \
        --param srcLabel=AJV --param skipCount=0

    # ReDoS (Example C): Stage 1 -> 9 rows; Stage 2 -> 8 rows all correct
    $JOERN_HOME/jssrc2cpg.sh examples/C_redos_stage1_stage2_fixtures/stage1_sinks -o /tmp/r1.bin
    $JOERN_HOME/joern --script $TC/producers/characterize_redos_sinks.sc \
        --param cpgFile=/tmp/r1.bin --param outFile=/tmp/r1.tsv
    $JOERN_HOME/jssrc2cpg.sh examples/C_redos_stage1_stage2_fixtures/stage2_prop_effects -o /tmp/r2.bin
    $JOERN_HOME/joern --script $TC/producers/characterize_redos_stage2.sc \
        --param cpgFile=/tmp/r2.bin --param outFile=/tmp/r2.tsv

SSRF, path traversal, and command injection follow the identical pattern with their own
`characterize_*_sinks.sc` / `characterize_*_property_effects.sc` and `fixtures/` directories.
These were verified extensively earlier in the project's history but were NOT re-run end-to-end
during this packaging pass — see MANIFEST.md's "exercised during verification" column.

## 4. Component A — property configs

The serialize-DoS config is hardcoded as the default inside `adjudicate_js.py` (so omitting
`TCH_PROPERTY_CONFIG` reproduces historical behavior byte-for-byte). All others are selected via:

    TCH_PROPERTY_CONFIG=property_configs/ssrf_host.json          # ATTACKER_CONTROL_OF_REQUEST_HOST
    TCH_PROPERTY_CONFIG=property_configs/path_traversal_host.json # ..._FILESYSTEM_LOCATION
    TCH_PROPERTY_CONFIG=property_configs/redos_complexity.json    # ATTACKER_CONTROLLED_REGEX_COMPLEXITY
    TCH_PROPERTY_CONFIG=property_configs/nosqli_query_op.json     # ..._QUERY_OPERATOR_STRUCTURE

### 4.1 WebExtension tab-URL source bridge (JS-SSRF-SOURCE-R01)

The portable scanner and the property adjudicator are intentionally separate. To let the
existing SSRF producer consume only the established JS-SOURCE-R03 tab-URL class, first adapt
the portable source facts, then pass the four-column TSV through the producer's optional
`browserSourceTsv` parameter:

    TC=tchecker-property-adjudicator
    python3 $TC/adjudicator/portable_ssrf_source_bridge.py \
        /tmp/js.json.source.json /tmp/webext-ssrf-sources.tsv
    mkdir -p /tmp/ssrf-raw
    $JOERN_HOME/joern --script $TC/producers/export_ssrf_integ.sc \
        --param cpgFile=/tmp/js.cpg.zip --param rawDir=/tmp/ssrf-raw \
        --param srcLabel=WEBEXT --param skipCount=0 \
        --param browserSourceTsv=/tmp/webext-ssrf-sources.tsv

The adapter accepts only `WEBEXT_TAB_URL_INPUT` + `STATE_READ` facts at the three frozen
`tabs.onCreated`/`tabs.onUpdated` URL locations. Other source classes remain separate. Run the
self-contained controls with:

    python3 $TC/adjudicator/test_portable_ssrf_source_bridge.py
    python3 $TC/adjudicator/gate_webext_ssrf_bridge.py
    python3 $TC/adjudicator/gate_webext_external_ssrf_bridge.py
    python3 $TC/adjudicator/gate_webext_ssrf_llm_handoff.py
    # -> PORTABLE_SSRF_BRIDGE_CONTROLS=16/16; WEBEXT_SSRF_BRIDGE=9/9
    # -> WEBEXT_EXTERNAL_SSRF_BRIDGE=10/10; WEBEXT_SSRF_LLM_HANDOFF=10/10

The controlled direct `tab.url -> fetch()` fixture is property-`ESTABLISHED`, so adjudication
closes in zero hint rounds and correctly emits no `llm_input_*.json`. An LLM packet is produced
only when an on-path transform leaves the modeled property deterministically `UNKNOWN`.

### 4.2 External-message transform handoff (JS-SSRF-HANDOFF-R01)

`fixtures/webext_ssrf_transform/` freezes a live Joern path from an external message payload,
through two unresolved calls, to `fetch`. The property outcome stays `OPEN`; this is the expected
abstention, not a scanner failure. Its `llm_input_1.json` is the exact file to pass manually to an
LLM or reviewer. It contains source-to-sink code plus the host-scoped question and answer
contract. The answer is consumed only as a semantic hint on a later adjudication round.

Code-context generation reads canonical `transform_identity.tsv` first. Historical fixtures that
only contain `path_transform_identity.tsv` remain supported as a fallback. The handoff gate fails
if source, either ordered transform, or sink code disappears from the packet.

## 5. LLM01/LLM02 detector gate — generate required facts, then run

The bundled `tchecker-property-adjudicator/fixtures/llm_input/` directory contains JS source,
not pre-generated TSV facts. The gate intentionally fails closed if either required TSV is
missing. Generate the facts with Joern before running it. Unlike most integration producers,
`export_llm_facts.sc` takes `--param outDir=`, not `rawDir=`:

    TC=tchecker-property-adjudicator
    $JOERN_HOME/jssrc2cpg.sh $TC/fixtures/llm_input -o /tmp/llm-input.bin
    mkdir -p /tmp/llm-out/raw
    $JOERN_HOME/joern --script $TC/producers/export_llm_facts.sc \
        --param cpgFile=/tmp/llm-input.bin --param outDir=/tmp/llm-out/raw
    python3 $TC/adjudicator/gate_llm_input.py /tmp/llm-out/raw
    # -> LLM_INPUT=7/7, PROMOTION_GATE=PASS

Required fact files are `llm_output_sinks.tsv` and `prompt_injection.tsv`. Supplying a missing
or wrong raw directory is a hard error; negative-control teeth cannot pass vacuously.

## 6. Component B — run and verify

The Java core and JavaScript/TypeScript frontend are bundled and can be run:

    cd portable-engine-full-review-package/frontends/javascript-typescript/joern-ts
    python3 -c "import import_binding_identity, dispatch_resolution, framework_registration"
    python3 -c "import security_sink_profile as s; print(s.classify_sink('authenticate'))"  # AUTHENTICATION

Run `bash verification/verify_fable.sh` for the bundled core compilation and gate tests. The full
canonical suite takes longer and remains an explicit manual step; see the final section printed by
that verification script.

For repository scans, both front doors must load every explicit engine-consumed
sidecar. In particular, JS requires `js.json.expression.json` and
`js.json.source.json`; C/C++ requires `p.json.source.json` in addition to memory,
expression and reaching-definition facts. `tools/scan_repo.py` and
`scanner/provenance_scan.py` do this automatically. The source schema is
`portable-source-facts/0.1`; every row must include `target_kind` (`LOCAL`,
`MEMORY`, or `PARAMETER`). Missing target class and unknown origin kinds fail
closed. See `portable-engine-full-review-package/docs/JS_SOURCE_R02_WEBEXT_EXTERNAL_MESSAGES.md`
for the bounded WebExtension source class and its exclusions.

## 7. LLM adjudication — the human/model step

The bundle stops at generating the packet. `llm_input_N.json` is a *request for a semantic hint*,
not a resolution. Answering it (by a model or by hand) per its `answer_contract`, then re-running
with `TCH_HINTS=<answers.json>` instead of `no_hints.json`, drives the next round. Per the
adjudicator's own design, an accepted hint sets `semantic_hint` and `adjudication_use`
(ACCEPTED_HINT | REJECTED_HINT | NEEDS_MORE_REVIEW) while `deterministic_status` stays UNKNOWN —
a hint never becomes an established fact. No API key or model config is bundled.

## 8. Packaging without destroying symlinks

Two bundle paths are intentional relative symlinks:

- `gates/portable-engine-full-review-package` -> `../portable-engine-full-review-package`
- `gates/fixtures/r40-out` -> `r39-out`

On a POSIX host, preserve them when creating a release ZIP:

    cd /path/to/parent
    zip -ry tchecker-research-complete.zip tchecker-research-complete \
        -x '*/__pycache__/*' '*.pyc'

Do not use an archiver that follows or materializes these links as ordinary files. After packaging,
inspect the ZIP metadata and verify both entries have POSIX symlink mode `0120777` and contain only
their relative target strings.
