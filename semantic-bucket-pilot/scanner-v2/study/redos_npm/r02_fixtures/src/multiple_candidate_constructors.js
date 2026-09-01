// Capability 5 abstention: MULTIPLE possible constructors for an exported identifier -- the
// SAME identifier is reassigned to two different (anonymous) class expressions before being
// exported. REAL, confirmed CPG behavior (not the originally-assumed mechanism): unlike a class
// DECLARATION's own self-binding (`class Widget {}` desugars directly to
// `Widget = <MethodRef to init>`), a class EXPRESSION assigned to `Exported` here does NOT
// desugar to `Exported = <MethodRef>` -- it abstains one level earlier, as
// UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT (zero qualifying candidate assignments found,
// same reason a re-export or any other non-MethodRef RHS abstains). This is still a real,
// correct, DISTINCT capability-5 discipline for this exact "multiple possible constructors"
// shape: it never guesses which of the two class expressions is "the real" export -- see
// R02_IMPLEMENTATION.md for the honest account of why the reason label differs from
// AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS. Must abstain either way, so the first
// class's own dangerous+reachable-shaped `run` method must NOT be promoted to a source despite
// being syntactically dangerous.
let Exported = class {
  constructor(x) {
    this.x = x;
  }
  run(y) {
    return /^(a+)+$/.test(y);
  }
};
Exported = class {
  constructor(z) {
    this.z = z;
  }
};
module.exports = Exported;
