# Gate 28 — Portable persistence/state channel

Gate 28 imports the PHP-engine lesson that stored/second-order flow must be represented explicitly rather than discovered incidentally.

The neutral API adds:

- `PersistenceLocation`
- `PersistenceWriteFact`
- `PersistenceReadFact`
- `ValueRef.PERSISTENCE_READ`
- `OriginRef.PERSISTED_PARAMETER`

A read does not guess which historical write produced its value. The frontend/framework state model supplies candidate reaching writes and a resolution class; the provenance core checks location identity and propagates only the demonstrated semantics.

Verified cases:

- write in one function -> read in a parameterless later function preserves the writer's parameter as an out-of-band origin;
- the origin survives an ordinary return wrapper;
- constant writes produce no source origin;
- source-vs-constant ambiguous writes become MAY only;
- unresolved reads stay UNKNOWN;
- mismatched object/slot locations abstain;
- heuristic reads remain MAY only;
- write expressions may themselves use semantic call summaries;
- ordinary parameter provenance is unchanged;
- the neutral core still has no AST/Joern dependency.

Pass criterion: `GATE28=12/12` and `ANALYSIS_STATUS=COMPLETE`.
