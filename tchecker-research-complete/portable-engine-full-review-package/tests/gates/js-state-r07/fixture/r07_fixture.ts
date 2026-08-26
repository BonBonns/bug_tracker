// JS-STATE-R07 permanent regression fixture.
//
// Built on JS-STATE-R06's characterization fixture (the four-way isolation
// matrix: A=yes/B=yes, A=no/B=no, A=yes/B=no, A=no/B=yes) plus a fifth case
// retained from JS-STATE-R01/R02 (the null|number case, case4b's shape) that
// proved Signal B survives even where methodReturn.typeFullName is broken.
//
// This is now a PERMANENT gate fixture, not a one-off characterization probe.
// The isolation_returnContractOnlyNonComparisonGuard case was fixed relative
// to its original R06 form: the guarded local now reaches authenticate()
// directly, so its exclusion under R07 is attributable to guard-shape alone,
// not confounded by never reaching a sensitive sink in the first place.
//
//   SIGNAL A (GUARD SHAPE): is the guard's own condition a member of a closed
//   set of failure-style comparison operators (instanceof, strict equality/
//   inequality), or an arbitrary boolean-returning method call (like
//   `.has()`)? Purely structural, no type information needed.
//
//   SIGNAL B (RETURN CONTRACT): does the erasing transformation's argument
//   carry a per-use-site dynamicTypeHintFullName containing a union with a
//   failure-capable alternative (Error/Null/Undefined/Exception/Failure), a
//   clearly non-union scalar hint, or no hint at all (UNKNOWN -- never
//   treated as proof of safety)?

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
  // R07 fix (vs the original R06 characterization fixture): the guarded
  // local `key` itself must reach authenticate() directly, or exclusion here
  // would be confounded by sink-non-reachability rather than cleanly
  // isolating the guard-shape signal. The original R06 fixture instead
  // passed a FRESH Number(r) call to authenticate(), so `key` never reached
  // a sensitive sink at all under the base R02/R03 pipeline -- meaning R07
  // would have excluded this case for the wrong reason (no sink reached),
  // not for the reason this case exists to test (guard shape not failure-
  // style). Fixed by passing `key` itself.
  authenticate(key as unknown as number);
}

// ---------------------------------------------------------------------------
// NULL/NUMBER CASE, retained deliberately (per instruction): reproduces
// JS-STATE-R01/R02's case4b, the strongest evidence that Signal B (use-site
// dynamicTypeHintFullName) survives even where the callee's own
// methodReturn.typeFullName is malformed (createN's return type exports as
// the garbled "__ecma.Boolean:<operator>.conditional:<returnValue>", not
// "number | null" -- a real bug found in JS-STATE-R01). If Signal B were
// implemented against methodReturn instead of the per-use-site hint, this
// case would wrongly fail to establish RETURN_CONTRACT. It must still emit
// under R07.
// ---------------------------------------------------------------------------
function createN(ok: boolean): number | null {
  return ok ? 11 : null;
}
function nullNumber_survivesMalformedReturnType(): void {
  const r5 = createN(flag);
  const id5 = Number(r5);
  if (id5 === null) return; // never true at runtime (Number(null) is 0), but
                             // this is exactly the erasure shape under test
  authenticate(id5);
}
