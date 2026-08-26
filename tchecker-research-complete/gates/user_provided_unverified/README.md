# user_provided_unverified/

`gate39_state_provenance.py` was provided directly by the user in-conversation, NOT found by
this bundle's own systematic workspace search. That search was thorough (see
../../WORKSPACE_INVENTORY.md) and did not locate this file, a `gate20/` sibling, `state_results.json`,
or the `raw/*.tsv` fixture facts it requires anywhere on the accessible disk.

**What's consistent**: its import (`from state_facts import derive, load, _d`) genuinely matches
real functions in the bundled `portable-engine-full-review-package/.../state_facts.py` --
checked directly, not assumed.

**What's missing and unverifiable from here**: `state_results.json` (ground truth) and the raw
fact tables it reads (`parameters.tsv`, `method_returns.tsv`, plus whatever `state_facts.derive()`
itself needs). Without them this cannot be run, so it has NOT been run, and its PASS/FAIL status
is genuinely unknown -- not assumed passing, not assumed broken.

Status: **CODE PRESERVED / PROVENANCE: USER-PROVIDED, NOT SELF-DISCOVERED / FIXTURE DATA MISSING
/ NOT REPRODUCIBLE / NOT RUN**.
