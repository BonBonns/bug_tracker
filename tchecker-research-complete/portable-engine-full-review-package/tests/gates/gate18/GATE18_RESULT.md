# Gate 18 — downstream uncertain-provenance evidence consumer

## Goal
Expose the `MAY` / `UNKNOWN` provenance channel to a downstream consumer without converting uncertain provenance into a hard source path or mutating the engine's hard return-taint summaries.

## Change
Added `cg.ProvenanceEvidenceReporter`, a read-only consumer over the Gate-17 provenance maps. It emits four states:

- `PROVEN` / `EXACT` / `hard_source=true`
- `MAY` / inherited non-hard resolution / `hard_source=false`
- `UNKNOWN` / `UNKNOWN` / `hard_source=false`
- `NONE` / no provenance evidence

The reporter does not feed anything back into `returnTaintPositions`, `returnMayTaintPositions`, finding creation, or vulnerability-source emission.

## Real-engine run
The Gate-17 engine was rebuilt with the reporter and executed against the Gate-17 JavaScript/TypeScript-derived CSV plus the exact and uncertain state sidecars.

Representative records:

```text
wrapMayConcat       status=MAY     resolution=AMBIGUOUS positions=[1]   hard_source=false
wrapMayConcatTwo    status=MAY     resolution=AMBIGUOUS positions=[1,3] hard_source=false
wrapUnknownConcat   status=UNKNOWN resolution=UNKNOWN   positions=[]    hard_source=false
identity            status=PROVEN  resolution=EXACT     positions=[0]   hard_source=true
concatExactOnly     status=PROVEN  resolution=EXACT     positions=[0,1] hard_source=true
binaryUnrelated     status=NONE    resolution=NONE      positions=[]    hard_source=false
```

The probe snapshots the hard and uncertain propagation maps before reporting and compares them afterward:

```text
REPORT_MUTATED_HARD=false
REPORT_MUTATED_MAY=false
```

`gate18_test.py`: **10/10 PASS**.

## What this establishes
The portable core can expose uncertainty downstream without collapsing it into the legacy binary source model. A consumer can now distinguish "proven parameter provenance" from "parameter may contribute" and "origin unknown" while the existing hard propagation/finding state remains untouched.

This is intentionally a reporting boundary, not a security verdict mechanism. `MAY` and `UNKNOWN` are evidence states only.

## Next boundary
The next useful gate is occurrence/path-level evidence: attach the weakest provenance resolution to an actual traced path segment (assignment/call/return), not only a function-level return summary. The invariant should remain: a path containing an `AMBIGUOUS` or `UNKNOWN` segment can be displayed as uncertain evidence but cannot be serialized as a hard `Vul Source` path.
