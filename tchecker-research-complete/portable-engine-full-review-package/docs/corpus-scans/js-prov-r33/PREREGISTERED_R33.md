# JS-PROV-R33 — preregistered BEFORE implementation

## Scope (narrow, SOUNDNESS not coverage)
> Preserve field-access identity in require bindings. A binding created from
> `require(spec).member` must represent the SELECTED MEMBER, not the containing
> module object.

Defect B (object-literal member whose RHS is a require-bound local) is
explicitly OUT OF SCOPE and follows separately.

## Justification independent of coverage
Defect A is a soundness defect: the produced record is not incomplete, it is
FALSE. R33 is justified even if Corpus D does not move. Any Corpus-D movement is
reported as a side effect, never as the reason.

## Load-bearing teeth
```text
T1  `require("./outer").inner` must NOT establish `local -> ./outer`
T2  SHARED-NAME adversarial control: outer and inner both export `shared`;
    `ctrl = require("./outer").inner; ctrl.shared` must resolve to INNER's
    member, never OUTER's same-named member
T3  bare `require("./outer")` behaviour unchanged
T4  unresolved member selection ABSTAINS rather than falling back to the whole
    module
T5  all existing CommonJS facts from TRUE bare requires remain identical
T6  demonstrably wrong = 0
```

T2 is decisive: it proves that dropping the member selector CHANGES SEMANTIC
IDENTITY and can manufacture a false positive. Merely asserting that `.inner`
survives parsing would be far weaker.

## Corpus invariants
```text
Corpus B: existing facts identical (45 module-identity, 23 state flows)
Corpus D: movement permitted but NOT required; if it moves, each new fact must
          be traced to a corrected binding and verified against source
```

## Defect class named
**representation-collapse defect** -- distinct source-level meanings collapsed
into the same intermediate fact shape, producing a record that appears
internally valid but denotes the WRONG PROGRAM ENTITY.
Instances: R09 receiver typing, R13 callee identity, R23a `isWildcard`,
R32/R33 `require(spec).member`.
