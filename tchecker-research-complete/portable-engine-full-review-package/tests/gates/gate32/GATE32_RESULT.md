# Gate 32 — Nested parser/context-stack semantics

## Goal

Carry the PHP-engine lesson about nested parser contexts into the portable core without encoding PHP, WordPress, or security-specific rules.

A value can cross multiple interpretation boundaries.  A transformation that is adequate for an earlier layer must not be reused for a later layer merely because its operation appears somewhere on the path.

## Contract added

`ContextStack` is an ordered list of `EffectRequirement` layers. `ContextStackEvaluator` receives the transformations structurally located before each layer and evaluates every layer independently.

Key invariants:

- every declared layer must have a corresponding structural segment;
- transformations are owned by one segment and are not reused across later boundaries;
- missing/extra segments make the observation incomplete rather than guessed;
- any inadequate layer makes the path inadequate;
- unknown and conditional layers remain explicit;
- the model contains no PHP/WordPress/security-specific names.

## Result

`GATE32=13/13`

`ANALYSIS_STATUS=COMPLETE`

This strengthens Gate 31 by making the parser/use-context stack an explicit first-class object rather than only an inferred sequence of `ContextBoundary` expression nodes.
