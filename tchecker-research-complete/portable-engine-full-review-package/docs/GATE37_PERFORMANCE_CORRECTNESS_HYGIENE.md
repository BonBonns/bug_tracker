# Gate 37 — Performance / correctness hygiene

Purpose: carry the measured PHP-engine engineering lessons into the portable core without assuming old optimizations transfer automatically.

## Audit result

The portable core did **not** contain the old `LinkedList.contains()` or boxed-`Long ==` patterns in its active neutral Java packages. Its records already snapshot list/set inputs defensively.

The audit did find one concrete structural performance issue: `ProgramGraph`'s default lookup helpers (`function(id)`, `call(id)`, `local(id)`, `returnsIn(fid)`, etc.) are stream/filter scans over complete fact lists. That recreates the same *class* of repeated linear lookup cost observed in the PHP engine, even though the exact old `keySet()` code is gone.

## Change

Added `IndexedProgramGraph`, an immutable behavior-preserving view that builds hash indexes/grouped indexes once and overrides the lookup helpers. Duplicate stable IDs fail closed instead of being overwritten by the index.

This is not forced on every frontend yet; callers can wrap a graph explicitly. That keeps the change measurable and makes comparison against the unindexed semantics trivial.

## Verification

Gate 37 verifies:

1. function/call/local lookups return identical facts;
2. grouped call/return/assignment queries are identical;
3. `PortableProvenanceEngine` produces byte-for-byte equal `ProvenanceSummary` values on base vs indexed graphs;
4. duplicate IDs are rejected;
5. `InMemoryProgramGraph`, `FunctionFact`, and `CallFact` defensively snapshot caller-owned lists;
6. a counted synthetic 20,000-function graph demonstrates repeated default lookup scans while indexed lookups perform no backing-list reads after the one-time build;
7. source audit forbids `LinkedList`, boxed `Long`/`Integer` identity comparison, and legacy PHP AST dependencies in active neutral packages.

The synthetic read-count comparison is a complexity measurement, not a runtime-speed claim. Real speedup must still be established by corpus/profile runs once real Joern corpora are available.
