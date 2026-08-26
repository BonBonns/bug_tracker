# Gate 29 — Typed evidence / abstention contract

Gate 29 introduces a language-neutral, read-only evidence contract between the provenance core and downstream consumers.

The core lesson carried forward from the PHP engine is that these are independent facts and must never be collapsed:

- **identity precision** — did we identify the specific value being discussed?
- **origin status** — did we establish where it came from?
- **resolution** — how confidently was the path/call relation resolved?
- **analysis completeness** — did the analysis finish, abstain, or truncate?

## Types

`core/evidence/` adds:

- `RelationKind`
- `IdentityPrecision`
- `OriginStatus`
- `EvidenceSubject`
- `ContextFrame`
- `ProvenanceEvidence`
- `ProvenanceEvidenceBuilder`
- `EvidenceJsonWriter`

`OriginStatus` is explicitly one of:

- `ESTABLISHED`
- `POSSIBLE`
- `NONE`
- `NOT_ESTABLISHED`
- `PARTIAL`

This prevents a complete constant/no-dependency result (`NONE`) from being confused with an unresolved origin (`NOT_ESTABLISHED`), and prevents truncation (`PARTIAL`) from masquerading as either.

## Hard-path rule

`originEstablished()` and `hardPathEligible()` are deliberately different.

A dependency can be proven across every ambiguous call target while the exact call path remains ambiguous. Such evidence has:

```text
origin_status = ESTABLISHED
resolution    = AMBIGUOUS
hard_path_eligible = false
```

Only value-specific, exact, complete evidence with an established origin is eligible for strict hard-path projection.

## Security separation

The evidence contract contains no vulnerability verdict. `ContextFrame` is only a typed place to attach later interpretation layers; provenance itself does not decide whether a value is safe or vulnerable.

The machine representation is `portable-evidence/0.1` and includes identity precision, origin status, path resolution, completeness, proven/MAY parameter positions, out-of-band origins, context stack, and truncation records.

## Verification

Gate 29 tests:

- value-specific identity + established origin;
- complete constant -> `NONE`, not UNKNOWN;
- value identified while origin remains `NOT_ESTABLISHED`;
- ambiguous path with a dependency proven across all alternatives;
- distinction between proven origin and exact hard path;
- heuristic origin remains `POSSIBLE`;
- multiple returns do not fabricate value-specific identity;
- persistence origins survive as typed established origins;
- context stack is preserved without changing provenance;
- truncation reports `PARTIAL`;
- evidence projection is read-only;
- JSON exposes all four independent dimensions;
- no security verdict is present;
- invalid `ESTABLISHED` evidence without an actual proof is rejected.

Observed result:

```text
GATE29=15/15
ANALYSIS_STATUS=COMPLETE
```

Cumulative runnable regression after Gate 29:

```text
EXECUTED 19/19
HISTORICAL_RECORDED 8/8
REGRESSIONS 0
GATE 24 BLOCKED
GATE 24-TS BLOCKED
```

The canonical legacy detector was rebuilt afterward and its Gate-23 closure probe still passes.
