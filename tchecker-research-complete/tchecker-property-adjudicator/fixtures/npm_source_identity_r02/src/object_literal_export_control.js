// Export-surface capability: object-literal shorthand export, `module.exports = { foo, bar }` --
// each property resolves independently via the same single-prior-MethodRef-assignment rule.
function foo(x) {
  return x;
}

function bar(y) {
  return y;
}

module.exports = { foo, bar };
