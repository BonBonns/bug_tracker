# TChecker — Serialize-DoS Security-Property Adjudication (JS/TS)

Static adjudication pipeline that decides whether an HTTP-input-to-JSON.stringify path is a real
serialize-DoS candidate, by propagating the *security property* (attacker control of serialized
size/structure) rather than generic taint. See docs/TCHECKER_WRITEUP.md for the full design.

## Layout
    producers/
      setup_candidate.sc            generic front-door: finds sink/source/transforms, writes fact tables
      export_property_propagation.sc  security-property propagation layer (the lattice)
      export_trace_identity.sc        trace-backed exact-callee identity (second identity mechanism)
      export_identity_gap.sc          identity-gap characterization (analysis, optional)
    adjudicator/
      adjudicate_js.py              consumes the fact tables -> evidence + disposition
    fixtures/                       demo cases, one per outcome class
    docs/                           the writeup and per-arc notes
    run.sh                          end-to-end runner for one file

## Requirements
- Java 21 and an installed Joern 4.x (tested with 4.0.608). Download from
  https://github.com/joernio/joern/releases and unpack; set JOERN_HOME to the `joern-cli` dir.
- Python 3.10+ (standard library only; no third-party packages).
- NO modification of the Joern install is required. The producers are standalone `.sc` scripts run
  via `joern --script`; nothing is patched inside Joern.

## Run
    export JOERN_HOME=/path/to/joern-cli
    ./run.sh fixtures/demo_direct.js            "req.body"    # -> ESTABLISHED, RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS
    ./run.sh fixtures/demo_member_transform.js  "req.body"    # -> OPEN, CANDIDATE_OPEN (awaits semantic review)
    ./run.sh fixtures/demo_lookup_falsepos.js   "req.body"    # -> BROKEN, REJECTED_FALSE_POSITIVE
    ./run.sh fixtures/demo_ambiguous.js         "req.body"    # -> OPEN, identity DENIED (ambiguous dispatch)

## Pipeline
    jssrc2cpg -> setup_candidate -> export_property_propagation -> export_trace_identity -> adjudicate_js
Outcomes: NO_FLOW / BROKEN (reject) ; OPEN (semantic review) ; ESTABLISHED (confirmed candidate).
A semantic answer for an OPEN transform can be supplied via TCH_HINTS=<json> (see adjudicator).

## Semantic-review answers (optional)
For OPEN candidates the adjudicator emits llm_input_1.json (the semantic packet) and, if a hint file
is provided, folds it:
    TCH_HINTS=hint.json ...   # {"xf0.bounds_serialized_size":{"proposed_value":"UNSAFE|SAFE","confidence":"HIGH","rationale":"..."}}
