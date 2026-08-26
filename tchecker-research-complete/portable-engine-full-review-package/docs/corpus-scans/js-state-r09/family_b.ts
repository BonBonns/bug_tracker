// JS-STATE-R09 — Family B (IMPLICIT_COMPARISON_COERCION) characterization
// fixture. Characterization only: nothing here is a detector, and no
// implementation follows from this file in R09.
//
// POSITIVE ANCHOR is reduced directly from the source-confirmed historical
// vulnerability replayed in JS-STATE-R08:
//   CVE-2026-21854 / GHSA-r8w6-9xwg-6h73, the-hideout/tarkov-data-manager,
//   src/tarkov-data-manager/index.mjs:192, vulnerable commit 188f7562.
//   Fixed by a single `==` -> `===` change (commit f188f0ab).
//
// The NEGATIVE CONTROLS exist because `==` by itself is emphatically NOT a
// vulnerability. A detector that flags abstract equality generally would be
// unusable. These controls are the discriminating cases any future
// ComparisonCoercionFact would have to survive.

declare function authenticate(user: string): void;
declare function unrelatedSink(x: unknown): void;

// ---------------------------------------------------------------------------
// POSITIVE ANCHOR (B1): the CVE shape.
// `users[username]` returns the admin password string on success, but returns
// Object.prototype (an INHERITED property, truthy) when username="__proto__".
// The `==` operator then coerces Object.prototype to "[object Object]".
// Both operands are in semantically DIFFERENT domains at the comparison:
// an attacker-influenced object-domain value vs. a string-domain value.
// Security decision: session/privilege assignment.
// ---------------------------------------------------------------------------
const users: Record<string, string> = { admin: "secret" };
function b1_positiveAnchor_prototypeCoercion(username: string, password: string): void {
  if (users[username] && users[username] == password) {
    authenticate(username); // full admin session
  }
}

// ---------------------------------------------------------------------------
// NEGATIVE CONTROL (B2): the actual fix. Strict equality performs NO abstract
// coercion. Structurally near-identical to B1 -- same operands, same sink,
// same everything except the operator. Any Family-B detector MUST separate
// B1 from B2, or it has learned nothing.
// ---------------------------------------------------------------------------
function b2_control_strictEquality(username: string, password: string): void {
  if (users[username] && users[username] === password) {
    authenticate(username);
  }
}

// ---------------------------------------------------------------------------
// NEGATIVE CONTROL (B3): `==` between two operands of the SAME proven type
// domain. Abstract equality on two strings performs no cross-domain coercion,
// so the operator's coercion semantics are inert here even though the
// operator is `==` and the sink IS security-relevant.
// ---------------------------------------------------------------------------
function b3_control_sameTypeDomain(a: string, b: string): void {
  if (a == b) {
    authenticate(a);
  }
}

// ---------------------------------------------------------------------------
// NEGATIVE CONTROL (B4): `x == null` -- the deliberate, extremely common
// idiom for matching BOTH null and undefined in one check. Coercion here is
// intentional and correct. Flagging this would make a detector unusable, per
// the explicit warning that drove this fixture.
// ---------------------------------------------------------------------------
declare function lookupToken(id: string): string | null | undefined;
function b4_control_nullIdiom(id: string): void {
  const token = lookupToken(id);
  if (token == null) return; // intentional null|undefined match
  authenticate(token);
}

// ---------------------------------------------------------------------------
// NEGATIVE CONTROL (B5): `x == 0` on a numeric value with no security
// decision downstream. Coercion is possible in principle, but the use is not
// security-relevant. Tests that Family B requires a SECURITY_DECISION_USE
// component and is not merely "coercion happened somewhere."
// ---------------------------------------------------------------------------
function b5_control_nonSecurityUse(count: number): void {
  if (count == 0) {
    unrelatedSink(count);
  }
}

// ---------------------------------------------------------------------------
// PROBE (B6): cross-domain `==` where one operand is a genuinely unknown /
// externally-shaped value and the other is a string, feeding a security
// decision. Structurally the CVE shape but WITHOUT the prototype mechanism --
// used to characterize whether type-domain evidence alone is recoverable,
// separately from the inherited-property mechanism that made B1 exploitable.
// ---------------------------------------------------------------------------
declare function externalLookup(k: string): unknown;
function b6_probe_crossDomainUnknown(k: string, supplied: string): void {
  const stored = externalLookup(k);
  if (stored == supplied) {
    authenticate(supplied);
  }
}
