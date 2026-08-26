# Gate 19 — path-level uncertainty evidence

## Goal
Attach uncertainty to the actual provenance path rather than only the function-level return summary, while preserving the invariant that an AMBIGUOUS or UNKNOWN path is evidence-only and cannot be projected as a hard source path by this consumer.

## Change
Added `cg.ProvenancePathReporter`, a read-only path tracer over the existing Gate-18/Gate-17 facts. It renders concrete path segments for supported forms:

- `RETURN`
- `PARAM`
- `LOCAL_ASSIGN`
- `CALL`
- `CALLEE_PROVEN_RETURN`
- `CALLEE_MAY_RETURN`
- `CONDITIONAL`
- `BINARY`
- ordinary terminal values

Every segment carries a resolution class. Path resolution is the weakest segment encountered (`EXACT` < `HEURISTIC` < `AMBIGUOUS` < `UNKNOWN/UNRESOLVED`).

`hardSourceProjection(Path)` returns a value only when the underlying evidence is `PROVEN`, the complete rendered path remains `EXACT`, and no uncertain segment was observed. MAY/UNKNOWN paths are structurally ineligible.

The reporter does not mutate `returnTaintPositions`, `returnMayTaintPositions`, `returnMayTaintResolution`, `call2mtd`, or `StaticAnalysis.vulSources`.

## Real-engine run
The existing Gate-18 engine was run against the Gate-17 JS/TS-derived graph with the exact and uncertain state sidecars.

Representative path:

```text
wrapMayThroughIdentity
status=MAY path_resolution=AMBIGUOUS hard_source_eligible=false
RETURN
  CALL identity                       EXACT
  CALLEE_PROVEN_RETURN identity       EXACT
  LOCAL_ASSIGN y                      EXACT
  CALL mayAliasWrite                  EXACT
  CALLEE_MAY_RETURN mayAliasWrite     AMBIGUOUS
  PARAM source                        EXACT
HARD_PROJECTION=false
```

The exact wrapper does not erase the weaker callee segment; the whole path remains `AMBIGUOUS`.

Conditional composition records the join explicitly:

```text
wrapMayConditional
RETURN                              AMBIGUOUS
  CONDITIONAL branch join          AMBIGUOUS
  LOCAL_ASSIGN y                   EXACT
  CALL mayAliasWrite               EXACT
  CALLEE_MAY_RETURN                AMBIGUOUS
  PARAM source                     EXACT
```

UNKNOWN remains UNKNOWN:

```text
wrapUnknownConcat
status=UNKNOWN path_resolution=UNKNOWN hard_source_eligible=false
HARD_PROJECTION=false
```

Exact controls remain eligible:

```text
identity
status=PROVEN path_resolution=EXACT positions=[0]
hard_source_eligible=true
HARD_PROJECTION=true

concatExactOnly
status=PROVEN path_resolution=EXACT positions=[0, 1]
hard_source_eligible=true
HARD_PROJECTION=true
```

Read-only checks after path reporting:

```text
PATH_REPORT_MUTATED_HARD=false
PATH_REPORT_MUTATED_MAY=false
PATH_REPORT_MUTATED_VUL_SOURCES=false
```

Automated result: **GATE19=12/12**.

## What this establishes
Uncertainty is now visible at the path level. A consumer can explain *where* a path became ambiguous/unknown instead of exposing only a function-level MAY flag. An exact step before or after an ambiguous step cannot restore the path to exactness.

This gate does **not** wire uncertain paths into the legacy `StaticAnalysis` vulnerability serializer. That is deliberate. The reporter's hard projection API refuses uncertain paths, and the run confirms reporting does not mutate the existing `vulSources` state.

## Next boundary
The next useful gate is occurrence-level provenance through **collections/indexed state**: arrays/objects such as `obj[key]`, `arr[i]`, and destructuring. The key precision question is whether a known property/index can remain exact while a dynamic key becomes AMBIGUOUS/UNKNOWN without globally tainting every member of the container.
