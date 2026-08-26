# provenance_scan.py — one-command scanner (task A) + summary layer (task D)

## A — what it does
Wraps the manual pipeline (scan_repo.py -> frontend facts -> EndToEndRunner with
a SINKS query -> triage) into a single command. Engine semantics UNCHANGED; this
is packaging only.

    python3 scanner/provenance_scan.py TARGET \
        --lang {c,js,auto} \
        --sinks memcpy:0,memcpy:2,sprintf:1 \
        [--summary-lib scanner/summaries/libs.json] \
        [--json out.json] [--work DIR]

Output groups every queried sink into:
    PROVEN_ORIGIN       EXACT with a parameter or typed out-of-band origin
    MAY_ORIGIN          AMBIGUOUS/POSSIBLE_UNBOUNDED, including MAY origins
    PROVEN_SOURCE_FREE  EXACT with no parameter origin (constants)
    DISPATCH_ONLY       HEURISTIC
    ABSTAINED           UNRESOLVED
Validated: reproduces the hand-run simdissdk numbers exactly
(2 PROVEN_ORIGIN, 2 MAY_ORIGIN, 8 PROVEN_SOURCE_FREE, 4 ABSTAINED).

JS-SOURCE-R02 correction: the JS sidecar list includes both
`js.json.expression.json` and `js.json.source.json`, and parsed rows preserve
`origins` / `may_origins`. Previously the frontend generated source facts but
both repository scanner entry points silently dropped them (and this wrapper
also discarded origin fields from the engine's output).

## D — curated external-library summary layer
scanner/summaries/libs.json (schema portable-library-summary/0.1), default OPAQUE.
Motivating entry: sqlite3_column_blob = DATABASE_INPUT — the exact boundary where
provenance died in SECURITY-R03.

IMPORTANT DESIGN CORRECTION found while building:
The strict loader REFUSES unknown fact schemas (fail-loud). So the summary file is
NOT passed to the engine — that would (correctly) crash it. Instead the scanner
loads the summaries itself and ANNOTATES abstained rows whose function calls a
summarised library function:

    readDataBuffer memcpy#0 UNRESOLVED  <- external: sqlite3_column_blob=DATABASE_INPUT

This tells the human WHY the engine abstained (external boundary) and what class
the value WOULD carry if the summary layer were consumed — WITHOUT changing any
resolution. The engine's abstention stands untouched.

## What is NOT done (kept honest)
- The engine does not CONSUME summaries; wiring it to do so is a separate gated
  milestone needing negative controls (OPAQUE default must still abstain; a
  VALUE_PRESERVING entry must not manufacture EXACT). Annotation != inference.
- Feature freeze intact: baseline 1e80bf15739f343c, canonical 31/31, unchanged.
