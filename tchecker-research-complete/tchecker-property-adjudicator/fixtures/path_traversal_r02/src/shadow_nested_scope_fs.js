// R02 new fixture: real WITHIN-METHOD shadowing -- the exact bug class R01's own Capability 3 was
// vulnerable to (a name-matched identifier search, `p.method.ast.isIdentifier.name(p.name)`,
// scoped to the exported method's own AST subtree -- which INCLUDES any nested function declared
// inside it). A nested function inside the SAME exported method declares its OWN, differently
// bound local variable of the exact SAME name as the outer exported parameter -- mirroring
// npm_source_identity_r01/src/cap2_shadow_nested_scope.js's own real shape, but with the inner,
// shadowed local now flowing to a REAL fs sink instead of merely being returned. A real
// identity-based resolver (refsTo/closureBindingId) must NEVER conflate the inner, unrelated local
// with the outer parameter, even though both share the exact same textual name and both live
// inside `p.method.ast`'s own AST subtree.
//
// Real, side-by-side comparison (see docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md for the
// full quoted run): R01 WRONGLY credits this sink as reachable from readGamma's own exported
// PACKAGE_API_INPUT parameter -- a real false positive, since the name-matching search cannot tell
// the inner shadowed Local apart from the outer MethodParameterIn -- while R02 correctly emits ZERO
// rows for this sink, since the value that actually reaches it is `helperTrustedPath()`'s own
// return value, assigned to a SHADOWED local of the same name, never the exported parameter.
const fs = require('fs');

function helperTrustedPath() {
  return '/var/app/fixed-trusted-path.txt';
}

function readGamma(userPath) {
  function helper() {
    const userPath = helperTrustedPath(); // SHADOWS the outer parameter -- an unrelated, fixed value
    fs.writeFileSync(userPath, 'x');
  }
  helper();
}

module.exports.readGamma = readGamma;
