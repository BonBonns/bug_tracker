// Regression check: top-level module.exports[computedExpr] = fn (already-supported R01 shape,
// DYNAMIC_COMPUTED_EXPORT_KEY) -- must still abstain identically under R02, zero regression.
function foo(x) {
  return /^(a+)+$/.test(x);
}
const key = "foo";
module.exports[key] = foo;
