// JS-STATE-R06 characterization fixture.
//
// Built directly from the JS-REAL-R01 false positive (routes/account.ts:1759,
// `seen.has(key)` deduping `${bounce.email}:${bounce.createdAt}`), reduced to
// a minimal, isolated shape, plus the known R01/R02 true-positive shape for
// contrast. Two candidate distinguishing signals are characterized:
//
//   SIGNAL A (GUARD SHAPE): is the guard's own condition a member of a closed
//   set of failure-style comparison operators (instanceof, strict equality/
//   inequality against null/undefined, etc.), or an arbitrary boolean-
//   returning method call (like `.has()`)? This needs no type information at
//   all -- purely structural, from the condition's own top-level CALL name.
//
//   SIGNAL B (RETURN CONTRACT): does the erasing transformation's argument's
//   type trace back to something that could carry a failure state (a union
//   type, an Error-related type, a nullable type), or is it a plain scalar/
//   object-field type with no failure shape anywhere in its provenance?

type Result = number | Error;
function create(ok: boolean): Result {
  return ok ? 7 : new Error("failed");
}

declare function authenticate(id: number): void;
declare const flag: boolean;

// ---------------------------------------------------------------------------
// TRUE POSITIVE (unchanged from JS-STATE-R01/R02's case2): union return,
// instanceof-style guard. Both signals should classify this as a real
// candidate: GUARD SHAPE = failure-style comparison, RETURN CONTRACT =
// established (Result = number | Error).
// ---------------------------------------------------------------------------
function truePositive_unionReturnInstanceofGuard(): void {
  const r = create(flag);
  const id = Number(r);
  if (id instanceof Error) return;
  authenticate(id);
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE, reduced from the real JS-REAL-R01 finding: a plain object
// field (no union, no Error, no null anywhere in its type) is
// template-string-coerced and used as a Set-dedup key. The guard is a
// `.has()` method call, not a failure-style comparison at all.
// SIGNAL A alone would correctly exclude this (the condition is a `.has()`
// call, not instanceof/equality/etc.).
// SIGNAL B alone would also correctly exclude this (the field's type,
// `{ id: string; label: string }`, carries no failure shape).
// ---------------------------------------------------------------------------
type PlainRecord = { id: string; label: string };
declare function getRecords(): PlainRecord[];
function falsePositive_plainFieldDedupKey(): void {
  const seen = new Set<string>();
  const records = getRecords();
  const deduped = records.filter((record: PlainRecord) => {
    const key = `${record.id}:${record.label}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  authenticate(deduped.length);
}

// ---------------------------------------------------------------------------
// ISOLATION CASE (tests SIGNAL A alone, RETURN CONTRACT absent): a plain
// scalar local (no union, no Error type anywhere) fed through a
// failure-style comparison operator (instanceof). This is contrived --
// `y instanceof Error` can never be true given the types -- but that is
// exactly the point: if SIGNAL A (guard shape) were used ALONE, without
// SIGNAL B (return contract), this would still be flagged as a candidate,
// because the guard IS a failure-style comparison. Only SIGNAL B can
// exclude this one.
// ---------------------------------------------------------------------------
declare function plainMath(): number;
function isolation_guardShapeOnlyNoReturnContract(): void {
  const x = plainMath();
  const y = Number(x);
  if (y instanceof Error) return; // structurally a failure-style guard, but
                                   // x/y's type never carried a failure state
  authenticate(y);
}

// ---------------------------------------------------------------------------
// ISOLATION CASE (tests SIGNAL B alone, GUARD SHAPE not failure-style): a
// union-returning callee (real return contract) whose result is coerced and
// checked with a NON-comparison guard (`.has()`-shaped), same as the real
// bug's guard shape but with a genuine failure-carrying origin this time.
// If SIGNAL B (return contract) were used ALONE, without SIGNAL A (guard
// shape), this would still be flagged, because the origin DOES have a real
// union return type -- even though the guard here is not actually checking
// failure state, it is (contrived, but structurally valid) checking Set
// membership of the coerced value. Only SIGNAL A can exclude this one.
// ---------------------------------------------------------------------------
function isolation_returnContractOnlyNonComparisonGuard(): void {
  const seenKeys = new Set<string>();
  const r = create(flag);
  const key = String(r);
  if (seenKeys.has(key)) return;
  seenKeys.add(key);
  authenticate(Number(r));
}
