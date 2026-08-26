# Gate 30 — class/context-aware transformation effects

Gate 30 carries forward the legacy PHP-engine lesson that a flat sanitizer set is the wrong abstraction, while keeping the portable engine non-security-specific.

## Contract

```text
operation × effect_class × use_context -> adequacy
```

Types added under `core/effects/`:

- `EffectClass`
- `EffectContext`
- `Adequacy`
- `TransformationRule`
- `TransformationAssessment`
- `TransformationRegistry`
- `BranchEffectSummary`

`Adequacy` is one of:

- `GUARANTEED`
- `CONDITIONAL`
- `INADEQUATE`
- `UNKNOWN`

Missing relations abstain as `UNKNOWN`.

## Important invariants

1. Adequacy never transfers from one context to another merely because the operation name matches.
2. Adequacy never transfers from one effect class to another merely because the operation name matches.
3. Conflicting duplicate rules are rejected.
4. Conditional rules must say what condition makes them conditional.
5. A multi-branch wrapper is `GUARANTEED` only when every branch is guaranteed; a pass-through/raw branch prevents promotion.
6. The portable effect layer contains no WordPress function names and no vulnerability verdict.

## Verification

```text
GATE30=13/13
ANALYSIS_STATUS=COMPLETE
```
