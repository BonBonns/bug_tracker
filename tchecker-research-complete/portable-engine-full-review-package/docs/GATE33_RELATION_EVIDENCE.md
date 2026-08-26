# Gate 33 — Complete relation/evidence taxonomy + mandatory abstention

Gate 33 carries forward the PHP-engine lesson that missing relation branches must not silently degrade to generic evidence.

## Added

- `RelationKind` semantic taxonomy:
  - `DIRECT_VALUE`
  - `ASSIGNMENT`
  - `ARGUMENT_PARAMETER`
  - `RETURN_VALUE`
  - `PROPERTY_STATE`
  - `INDEX_STATE`
  - `PERSISTENCE`
  - `TRANSFORMATION`
  - `CONTROL_JOIN`
  - `CALL_RESOLUTION`
  - `ABSTENTION`
- `RelationStatus`: `ESTABLISHED`, `POSSIBLE`, `ABSTAINED`
- `AbstentionReason` machine-readable reasons.
- `EvidenceRelation` typed relation record with invariants preventing an abstention from hiding under an ordinary relation kind.
- `RelationEvidenceBuilder`, which projects neutral `ProgramGraph` facts into relation evidence without AST-shape guesses or generic fallback.

`RETURN_PROVENANCE` remains only as a compatibility aggregate label for Gate 29; it cannot be instantiated as a path `EvidenceRelation`.

## Fail-closed behavior

- competing local definitions -> `ABSTENTION/COMPETING_DEFINITIONS`
- ambiguous call target -> `CALL_RESOLUTION/POSSIBLE` plus `ABSTENTION/AMBIGUOUS_CALL_TARGET`
- unresolved call -> `ABSTENTION/UNRESOLVED_CALL_TARGET`
- unknown semantic value -> `ABSTENTION/MISSING_SEMANTIC_FACT`
- multiple return sites without control discrimination -> `ABSTENTION/MULTIPLE_RETURN_VALUES`
- unresolved persistence read -> `ABSTENTION/UNRESOLVED_PERSISTENCE_WRITE`
- missing return fact -> explicit abstention

There is deliberately no `GENERIC_FALLBACK` relation.

## Verification

`Gate33RelationEvidenceTest` covers 18 assertions and emits:

```
GATE33=18/18
ANALYSIS_STATUS=COMPLETE
```

Adjacent neutral-core/evidence regressions Gate 29–32 were rerun and remain green.
