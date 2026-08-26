# JS-PROV-R26 — re-export hop. Preregistered BEFORE implementation.

## Gap (identified R23a, quantified R23c, parked through R25)
`export { fDecl } from './lib'` lowers to `exports.fDecl = _lib.fDecl` — the RHS
is a FIELD ACCESS on an imported module object, not a declaration identity.
9 of 13 Corpus-C relative abstentions are this shape.

## Scope
ONE hop, applied transitively with an explicit bound:
resolve the RHS base local -> its module specifier -> that file's export
assignment -> declaration identity.

## Preregistered invariants
```text
J1  R25 closeout criteria C2-C9 all still hold afterwards
J2  Corpus B CommonJS results unchanged (45 facts / 9 validate())
J3  no member established that the target file does not actually export
J4  `export *` still abstains (no member identity exists to chain to)
J5  cycles terminate and abstain, never loop or fabricate
J6  chain depth is BOUNDED and the bound is recorded on the fact
J7  WRONG = 0
J8  every re-export-derived fact records its full chain, not just the endpoint
```

## Preregistered expectation
Fixture `viaReexport` (currently ABSTAINED) should become ESTABLISHED, resolving
to `lib.ts::program:fDecl` through `reexport.ts`.
Corpus C: EXPORT_MEMBER_NOT_A_RESOLVABLE_DECLARATION abstentions should FALL
from 9. It is NOT expected that all 9 resolve — some may chain to bare packages
or to `export *`.

## Negative controls (must all abstain)
```text
export * from './x'          no member identity to chain to
re-export of a MISSING member target does not export it
cyclic re-export a->b->a     terminates, abstains
chain exceeding the depth bound
re-export from a BARE package specifier
```
