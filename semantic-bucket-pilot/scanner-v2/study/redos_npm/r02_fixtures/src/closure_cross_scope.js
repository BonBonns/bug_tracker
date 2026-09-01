// Capability 4 + Regression fixture #1: two DIFFERENT, unrelated closures each declare their
// own same-named `RE` regex variable at their own (different) enclosing scope, each consumed
// by a nested inner closure's own sink call -- must resolve each independently to ITS OWN
// pattern, never cross-contaminate. makeHandlerA's RE is DANGEROUS (reachable via its own
// exported `param`); makeHandlerB's RE is safe (never emitted).
function makeHandlerA(param) {
  const RE = /^(a+)+$/;
  function inner() {
    return RE.test(param);
  }
  return inner();
}
function makeHandlerB(param) {
  const RE = /safe/;
  function inner() {
    return RE.test(param);
  }
  return inner();
}
module.exports = { makeHandlerA, makeHandlerB };
