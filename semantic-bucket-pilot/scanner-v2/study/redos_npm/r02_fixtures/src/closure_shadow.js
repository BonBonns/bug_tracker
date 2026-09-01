// Capability 4 + Regression fixture #2: lexical shadowing. An outer, module-scope
// `const RE = /safe/` and an inner, nested-scope `const RE = /^(a+)+$/` (inside the exported
// `outer` function), with the sink call inside a further-nested closure using the INNER RE --
// must resolve to the inner (nearest-enclosing) declaration, not the outer one. If the bug
// existed (silently picking the outer/safe RE), this sink would classify SAFE and emit
// nothing; the presence of a DANGEROUS, reachable row IS the confirmation of correct
// inner-scope resolution.
const RE = /safe/;
function outer(param) {
  const RE = /^(a+)+$/;
  function inner() {
    return RE.test(param);
  }
  return inner();
}
module.exports = { outer };
