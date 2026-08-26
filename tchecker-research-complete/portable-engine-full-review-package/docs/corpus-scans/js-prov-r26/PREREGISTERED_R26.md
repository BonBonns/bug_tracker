# JS-PROV-R26 — preregistered BEFORE implementation

## Scope (isolated revision)
Resolve ONE additional hop for `export { x } from './y'`, whose RHS is a field
access on an imported module local (`_y.x`) rather than a declaration.

    exports.x = _y.x   ->   resolve _y -> './y'   ->   look up x in y's exports

NOTHING else. No new syntax support, no consumer changes.

## Preregistered invariants
```text
J1  R23b/R25 gate results unchanged (17/17), R14 9/9, R12 28/28
J2  CommonJS Corpus B unchanged (45 facts)
J3  no member identity without a real export entry in the RESOLVED target
J4  `export *` still abstains (no per-member identity exists)
J5  chained re-export terminates; a CYCLE must abstain, never loop
J6  unresolvable module local -> abstain
J7  WRONG = 0
```

## Preregistered expectation
Corpus C had 9 of 13 relative abstentions as
EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION. If all 9 are single-hop re-exports,
established should rise 63 -> up to 72. It is NOT predicted that all 9 resolve;
some may be `export *` or chains.

## Decisive negative controls
- re-export naming a member the target does NOT export -> abstain
- re-export chain containing a CYCLE -> abstain, terminate
- `export * from` -> abstain (unchanged)
