# Gate 6 — explicit frontend call-resolution bridge

## Goal
Carry language-frontend resolution facts across the typed-property boundary identified by Gate 5 without inventing TypeScript-specific behavior inside `ParseVar` and without flattening ambiguous/unresolved dispatch into legacy hard edges.

## Bridge contract
The engine optionally reads a TSV sidecar when `WP_FRONTEND_CALL_RESOLUTION` is set:

```
callNodeId    EXACT|HEURISTIC|AMBIGUOUS|UNRESOLVED    targetId[,targetId...]
```

All facts are retained in `frontendCallResolution` / `frontendCallTargets`. Only an `EXACT` record with exactly one valid function/method target is admitted to legacy `call2mtd`. It is added through the existing `addCallEdge()` path, so the engine's normal arity, vendor, visibility, and test-code guards still apply. `HEURISTIC`, `AMBIGUOUS`, and `UNRESOLVED` never become hard edges in this gate.

## Fixture
Reuses Gate 5:

- call 86: `h: Holder -> h.worker: A -> process` = EXACT -> `A.process` (node 13)
- call 111: untyped `h.worker.process` = AMBIGUOUS -> `{A.process, B.process}`
- call 137: `UnionHolder.worker: A | B` = AMBIGUOUS -> `{A.process, B.process}`
- call 163: typed `A` receiver calling missing method = UNRESOLVED

`generate_bridge.py` joins the frontend manifest to the emitted CSV node IDs; the mapping is not hard-coded in the engine.

## Run-verified result
With the environment variable **unset**, the Gate-5 behavior is unchanged: no frontend resolution facts are loaded and no property-receiver method edge is produced.

With the bridge enabled, the engine reports:

```
FRONTEND_RESOLUTION loaded=4 exact_edges_added=1 rejected=0 classes={AMBIGUOUS=2, EXACT=1, UNRESOLVED=1}
```

and the probe observes exactly one legacy call edge:

```
EDGE 86 -> [13]
```

There are **zero** hard edges for calls 111, 137, and 163. Their AMBIGUOUS/UNRESOLVED classifications and candidate targets remain available in the frontend sidecar maps.

## Gate status
- frontend fact ingestion: PASS
- typed-property EXACT -> real engine `call2mtd`: PASS
- AMBIGUOUS anti-flattening: PASS
- UNRESOLVED anti-flattening: PASS
- gate-off behavior on fixture: PASS
- PHP corpus regression/promotion: NOT RUN; this remains gated and opt-in

## Architectural result
Gate 5 showed that `ParseVar` loses TypeScript property receiver type at `AST_PROP` (`-1::worker`). Gate 6 demonstrates that the engine does not need TypeScript-specific property logic to recover that precision. A frontend can supply an explicit resolution fact through a narrow, language-neutral seam. The legacy graph receives only exact facts; uncertainty remains represented as uncertainty rather than guessed edges.
