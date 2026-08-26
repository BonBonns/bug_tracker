# Gate 11 — state-summary bridge into the real return-provenance engine

## Goal
Consume the receiver-sensitive state results from Gate 10 inside the real PHPCGFactory return-provenance layer, behind an opt-in gate, without converting property names into global taint.

## Bridge
`WP_FRONTEND_STATE_RETURN_SUMMARY=/path/frontend_state_return.tsv`

TSV rows are:

`functionNodeId<TAB>COMPLETE<TAB>comma-separated parameter positions`

`COMPLETE` is intentionally strong. Only state-model results with a decisive PARAM or CONST origin are emitted. `STATE_UNKNOWN` cases are omitted, so the legacy engine remains conservative there.

The bridge is injected into the existing return-taint fixed point. A frontend COMPLETE summary replaces the legacy param-position result for that function during each fixed-point pass, so downstream consumers see the state-sensitive result through the same `returnTaintPositions` / `returnTaintAnalyzed` interface they already use.

## Measured result
Gate on vs gate off:

- `topState(h, source)`: `[0] -> [1]`
- `topConstantOverwrite(h, source)`: `[0] -> []`
- `directState(h, source)`: `[0] -> [1]`
- `directConstant(h, source)`: `[0] -> []`
- `sameObject(source)`: `[] -> [0]`
- `differentField(h, source)`: remains `[0]` (state model was UNKNOWN; no source position injected)
- `twoObjects(source)`: remains `[]` (distinct-allocation control remains clean)

`gate11_test.py`: **7/7 PASS**.

The engine reports `FRONTEND_STATE_RETURN loaded=5 rejected=0 complete=5` and all existing frontend call-resolution facts remain EXACT.

## What this proves
The real engine can consume a language-neutral, receiver-sensitive state proof and expose it through its existing interprocedural return-provenance summary. Constant overwrites can kill a false source dependency, and same-object state can introduce the correct source dependency, without global property-name taint.

## What this does not prove
This is not native heap DDG construction. The frontend state model still computes the heap/state effect; Gate 11 is the integration seam that lets the existing provenance engine consume those proven effects. `STATE_UNKNOWN` / partial state results are deliberately not promoted.

No security source/sink semantics were added.
