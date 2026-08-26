// JS-STATE-R01 characterization fixture.
// Deliberately no security-suggestive naming beyond what the spec requires
// ("authenticate" is required by the spec as the sink shape; everything else
// is kept neutral so name-based shortcuts cannot accidentally "work").

// ---------------------------------------------------------------------------
// Callee shapes with distinct success/failure return states
// ---------------------------------------------------------------------------

// Plain union return: number (success) | Error (failure).
type Result = number | Error;
function create(ok: boolean): Result {
  return ok ? 7 : new Error("failed");
}

// Discriminated union return.
type DResult = { ok: true; value: number } | { ok: false; reason: string };
function createD(ok: boolean): DResult {
  return ok ? { ok: true, value: 9 } : { ok: false, reason: "bad" };
}

// null-sentinel failure return.
function createN(ok: boolean): number | null {
  return ok ? 11 : null;
}

// ---------------------------------------------------------------------------
// External sink shape (declared, not defined here on purpose: the frontend
// must not need the sink's body to demonstrate SECURITY_SENSITIVE_USE).
// ---------------------------------------------------------------------------
declare function authenticate(id: number): void;
declare function unrelatedSink(x: unknown): void;

declare const flag: boolean;

// ---------------------------------------------------------------------------
// CASE 1 (SAFE): guard the original result before any transformation.
// ---------------------------------------------------------------------------
function case1_safeGuardBeforeTransform(): void {
  const r1 = create(flag);
  if (r1 instanceof Error) return;
  const id1 = Number(r1);
  authenticate(id1);
}

// ---------------------------------------------------------------------------
// CASE 2 (CANDIDATE SHAPE): transform first, guard the transformed value.
// Number(new Error(...)) is NaN, so the instanceof Error check on id2 can
// never be true -- the failure discriminator is destroyed before the guard.
// ---------------------------------------------------------------------------
function case2_transformBeforeGuard(): void {
  const r2 = create(flag);
  const id2 = Number(r2);
  if (id2 instanceof Error) return;
  authenticate(id2);
}

// ---------------------------------------------------------------------------
// CASE 3 (SAFE): discriminated-union safe case -- guard on the `ok` tag,
// which is a structural discriminator that no numeric coercion can destroy.
// ---------------------------------------------------------------------------
function case3_discriminatedUnionSafe(): void {
  const r3 = createD(flag);
  if (!r3.ok) return;
  const id3 = r3.value;
  authenticate(id3);
}

// ---------------------------------------------------------------------------
// CASE 4 (SAFE / null-sentinel): guard on strict null check before use.
// ---------------------------------------------------------------------------
function case4_nullSentinelSafe(): void {
  const r4 = createN(flag);
  if (r4 === null) return;
  authenticate(r4);
}

// ---------------------------------------------------------------------------
// CASE 4b (CANDIDATE SHAPE / null-sentinel erased by coercion): Number(null)
// is 0, a valid-looking number, so a strict-equality-to-null check on the
// *transformed* value can never fire.
// ---------------------------------------------------------------------------
function case4b_nullSentinelErasedByCoercion(): void {
  const r4b = createN(flag);
  const id4b = Number(r4b);
  if (id4b === null) return; // never true: Number(null) is 0, not null
  authenticate(id4b);
}

// ---------------------------------------------------------------------------
// CASE 5 (transformation that PROVABLY PRESERVES the failure state): identity
// function / pass-through. The guarded value and the original value are the
// same reference, so there is no erasure regardless of check placement.
// ---------------------------------------------------------------------------
function identity<T>(x: T): T {
  return x;
}
function case5_preservingTransform(): void {
  const r5 = create(flag);
  const id5 = identity(r5);
  if (id5 instanceof Error) return;
  authenticate(id5 as number);
}

// ---------------------------------------------------------------------------
// CASE 6 (transformation with UNKNOWN semantics): an external, undefined
// normalizer whose body Fable cannot see. Its effect on the failure
// discriminator is not provable either way, so this must abstain rather than
// assume erasure or preservation.
// ---------------------------------------------------------------------------
declare function externalNormalize(x: unknown): number;
function case6_unknownTransformAbstain(): void {
  const r6 = create(flag);
  const id6 = externalNormalize(r6);
  if (id6 < 0) return; // guard subject is the transformed value; semantics of
                        // externalNormalize's relationship to failure is unknown
  authenticate(id6);
}

// ---------------------------------------------------------------------------
// CASE 7 (transformed error-like value that never reaches a security-
// sensitive sink): erasure happens, but the destination is inert, so this is
// not the target bug shape regardless of the erasure.
// ---------------------------------------------------------------------------
function case7_erasedButNoSensitiveSink(): void {
  const r7 = create(flag);
  const id7 = Number(r7);
  if (id7 instanceof Error) return; // same erasure as case 2
  unrelatedSink(id7); // not a security-sensitive operation
}

// ---------------------------------------------------------------------------
// CASE 8: same shape as case 2 but using a bitwise coercion instead of
// Number(), to characterize whether bitwise operators are represented the
// same way as function-call coercions.
// ---------------------------------------------------------------------------
function case8_bitwiseCoercionBeforeGuard(): void {
  const r8 = create(flag);
  const id8 = (r8 as unknown as number) | 0; // representative of `x | 0`-style coercion
  if (id8 instanceof Error) return;
  authenticate(id8);
}

// ---------------------------------------------------------------------------
// CASE 9: same shape as case 2 but using unary plus, to characterize whether
// unary-operator coercions are represented the same way as Number()/String().
// ---------------------------------------------------------------------------
function case9_unaryPlusBeforeGuard(): void {
  const r9 = create(flag);
  const id9 = +(r9 as unknown as number);
  if (id9 instanceof Error) return;
  authenticate(id9);
}

// ---------------------------------------------------------------------------
// CASE 10/11/12: same shape as case 2 but using String()/Boolean()/parseInt(),
// to empirically verify (not assume-by-analogy) that these coercions are
// represented the same way as Number(). Report flagged this as unverified.
// ---------------------------------------------------------------------------
function case10_stringCoercionBeforeGuard(): void {
  const r10 = create(flag);
  const id10 = String(r10);
  if (id10 instanceof Error) return;
  unrelatedSink(id10);
}

function case11_booleanCoercionBeforeGuard(): void {
  const r11 = create(flag);
  const id11 = Boolean(r11);
  if (id11 instanceof Error) return;
  unrelatedSink(id11);
}

function case12_parseIntCoercionBeforeGuard(): void {
  const r12 = create(flag);
  const id12 = parseInt(r12 as unknown as string, 10);
  if (id12 instanceof Error) return;
  unrelatedSink(id12);
}

// ---------------------------------------------------------------------------
// CASE 13: same erasure shape as case2 (Number() before an instanceof-Error
// check), but the ONLY call reaching the guarded local as an argument is
// INSIDE the guard's own true (early-return) branch, not on the continue
// path. Since Number() applied to an Error-shaped value is never instanceof
// Error, this branch is dead in practice, and authenticate() here is
// unreachable -- not a real bypass. A same-function-only reachability check
// (no branch awareness) would wrongly flag this as SENSITIVE; a
// branch-aware check must not credit it, because there is no call on the
// actual continue path at all.
// ---------------------------------------------------------------------------
function case13_sinkOnlyInGuardTrueBranch(): void {
  const r13 = create(flag);
  const id13 = Number(r13);
  if (id13 instanceof Error) {
    authenticate(id13 as number); // structurally inside the guard's true branch
    return;
  }
  // no sink call on the continue path
}

// ---------------------------------------------------------------------------
// CASE 14: same erasure shape as case2, and the sink call IS on the continue
// path this time -- but the guarded local is reassigned to an unrelated,
// constant value between the guard and the sink call. The value that
// actually reaches authenticate() is 42, not the erased Number(r14) result.
// A reachability check that only tracks LOCAL identity (not intervening
// reassignment) would wrongly credit this as SENSITIVE via the erased value;
// it is not, because the erased value never reaches the sink.
// ---------------------------------------------------------------------------
function case14_reassignedBeforeSink(): void {
  const r14 = create(flag);
  let id14 = Number(r14);
  if (id14 instanceof Error) return;
  id14 = 42; // reassigned to an unrelated safe constant before the sink
  authenticate(id14);
}
