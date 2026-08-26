# Fresh-sandbox verification record

This package was verified by extracting the zip into a PRISTINE directory (not the build tree),
adding a brand-new fixture that was never part of the package, and running ./run.sh end-to-end with
JOERN_HOME pointing at a separate Joern install. If any file were missing, these runs would fail.

## Procedure
    mkdir -p /tmp/fresh_verify && cd /tmp/fresh_verify
    unzip -q tchecker-serialize-dos.zip
    export JOERN_HOME=/path/to/joern-cli          # external to the package
    ./run.sh fixtures/demo_direct.js           "req.body"
    ./run.sh fixtures/demo_lookup_falsepos.js  "req.body"
    ./run.sh fixtures/demo_member_transform.js "req.body"
    ./run.sh fixtures/demo_ambiguous.js        "req.body"
    ./run.sh newfixture/plugin.js              "req.body"   # brand-new, unseen file
    TCH_HINTS=fold_answer.json ./run.sh newfixture/plugin.js "req.body"

## Results (all PASS)
| fixture | property outcome | trace identity | disposition |
|---|---|---|---|
| demo_direct.js            | ESTABLISHED | (none; direct)             | RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS |
| demo_lookup_falsepos.js   | NO_FLOW     | -                          | REJECTED_NO_STRUCTURAL_FLOW |
| demo_member_transform.js  | OPEN        | UNIQUE (Audit:redact)      | CANDIDATE_OPEN |
| demo_ambiguous.js         | OPEN        | DENIED (A \| B union)      | CANDIDATE_OPEN |
| newfixture/plugin.js      | OPEN        | UNIQUE (Forwarder:wrap)    | CANDIDATE_OPEN |
| newfixture + HIGH answer  | OPEN        | UNIQUE (Forwarder:wrap)    | RESOLVED_CANDIDATE_BY_ACCEPTED_HINT |

The brand-new plugin.js (a member-method transform straight to a serialization sink) was correctly
classified OPEN with a uniquely trace-identified callee, and folding a HIGH-confidence answer moved it
to RESOLVED_CANDIDATE_BY_ACCEPTED_HINT — exercising the property layer, the trace-identity layer, and
the semantic-review acceptance path, all from the extracted package.

## Environment used for verification
- Joern 4.0.608 (jssrc2cpg), Java 21, Python 3.10, standard library only.
- No files outside the package were needed except the Joern install (JOERN_HOME).
