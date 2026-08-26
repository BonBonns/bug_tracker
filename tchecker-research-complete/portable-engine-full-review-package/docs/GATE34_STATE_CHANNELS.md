# Gate 34 — State-channel abstraction

Gate 34 separates non-durable/out-of-band state from ordinary call/dataflow and from durable persistence.

## Core model

`StateChannelKind` currently distinguishes `REQUEST`, `SESSION`, `ENVIRONMENT`, and `PROCESS`.
A `StateChannelLocation` is identified by kind + namespace + object identity + slot.

A read must declare one of three source modes:

- `EXTERNAL_SOURCE` — the channel itself is an origin supplied outside ordinary program flow.
- `WRITE_LINKED` — provenance is established only through explicitly demonstrated writes.
- `UNMODELED` — the channel is recognized, but its origin model is unavailable; the engine returns UNKNOWN rather than guessing.

The provenance core never infers a state-channel origin merely because a function contains a source-like value.

## Evidence integration

State-channel reads are represented as the first-class relation `STATE_CHANNEL`.
Unmodeled channels emit an explicit `ABSTENTION / UNMODELED_STATE_CHANNEL` relation instead of falling back to generic evidence.

## Verification

Gate 34 verifies:

1. request state can be an explicit external origin;
2. environment state can be an explicit external origin;
3. session state can be linked to a demonstrated prior write;
4. competing source/constant writes remain AMBIGUOUS/MAY;
5. ambiguous state never hardens;
6. an unmodeled session channel remains UNKNOWN;
7. location mismatch abstains;
8. heuristic external origin is MAY-only;
9. process state can be write-linked;
10. different channel slots remain distinct;
11. ordinary return relevance remains unchanged;
12. state-channel provenance is a first-class evidence relation;
13. unmodeled state emits a typed abstention;
14. state channels remain a distinct abstraction from durable persistence;
15. the portable core retains no AST/Joern dependency.

Observed result: `GATE34=15/15`, `ANALYSIS_STATUS=COMPLETE`.
