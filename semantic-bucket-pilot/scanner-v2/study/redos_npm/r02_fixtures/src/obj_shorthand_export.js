// Capability 2 + Regression fixture #6: module.exports = { foo, bar } object-literal shorthand.
// Both foo and bar must resolve cleanly to real MethodRefs (foo is dangerous+reachable, bar is
// safe -- demonstrating resolution succeeds independent of whether the sink is DANGEROUS).
function foo(x) {
  return /^(a+)+$/.test(x);
}
function bar(y) {
  return /safe/.test(y);
}
module.exports = { foo, bar };
