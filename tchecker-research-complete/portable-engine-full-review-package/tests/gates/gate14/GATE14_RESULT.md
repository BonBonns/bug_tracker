# Gate 14 — uncertain return-provenance channel

## Goal
Allow state-derived `AMBIGUOUS` / `UNKNOWN` provenance to travel through the real engine without laundering it into the legacy hard `returnTaintPositions` summary.

No security source/sink semantics are involved.

## Engine change
A second, explicitly uncertain return-summary channel was added to `PHPCGFactory`:

- `returnMayTaintPositions`
- `returnMayTaintResolution`

Input is opt-in through:

`WP_FRONTEND_STATE_RETURN_UNCERTAIN=/path/frontend_state_return_uncertain.tsv`

Format:

`fid<TAB>AMBIGUOUS|UNKNOWN<TAB>comma-separated-param-positions`

These facts are never copied into `returnTaintPositions` / `returnTaintAnalyzed`.

## Propagation rule
Gate 14 supports direct return-call wrappers and iterates to a fixed point:

```ts
function wrapMay(cond, source) {
  return mayAliasWrite(cond, source);
}

function wrapMay2(cond, source) {
  return wrapMay(cond, source);
}
```

If the callee return is uncertain, the caller receives a MAY summary for the corresponding caller parameter. Resolution is weakened, never strengthened. Multiple call targets cap the result at `AMBIGUOUS`.

## Measured result
The frontend sidecar seeds four non-exact state summaries:

- `mayAliasWrite` -> `AMBIGUOUS`, position `[1]`
- `mayAliasDifferentField` -> `UNKNOWN`, positions `[]`
- `mayAliasOverwrite` -> `AMBIGUOUS`, position `[1]`
- `mayAliasRead` -> `AMBIGUOUS`, position `[1]`

The real engine then derives:

- `wrapMay` -> `AMBIGUOUS`, position `[1]`
- `wrapMay2` -> `AMBIGUOUS`, position `[1]` after fixed-point propagation
- `wrapUnknown` -> `UNKNOWN`, positions `[]`

The exact control remains on the old hard channel:

- `wrapExact` -> hard return position `[1]`

Critically, the MAY cases remain hard-return positions `[]`; neither the seed functions nor the wrappers are hardened into exact taint facts.

Runtime:

`FRONTEND_STATE_MAY loaded=4 rejected=0 uncertain=4`

`RETURN_MAY_SUMMARY functions=7 rounds=2`

`gate14_test.py`: **10/10 PASS**.

## What this establishes
The portable core now has separate representations for:

- proven/exact caller-parameter-to-return flow;
- possible/ambiguous caller-parameter-to-return flow;
- unknown return provenance.

Uncertain heap provenance can survive more than one ordinary function-return boundary without becoming a hard edge.

## Boundary
This gate intentionally handles only direct return-call wrappers. It does not yet propagate MAY provenance through local assignments such as `const x = mayAliasWrite(...); return x;`, nor does the vulnerability/finding layer consume the MAY channel yet.

The next gate should extend the uncertain fixed point through local assignment/return chains while retaining the same non-hardening invariant. Only after that should a downstream consumer be allowed to display or reason about MAY provenance.
