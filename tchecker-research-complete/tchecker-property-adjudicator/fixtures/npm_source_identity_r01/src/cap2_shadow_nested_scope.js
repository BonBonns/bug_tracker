// Capability 2 (lexical shadowing, nested-scope variant): a module-scope `const label` and an
// INNER, same-named `const label` declared inside an exported function's own body. A reference
// to `label` inside the inner scope must resolve to the INNER declaration (nearest enclosing),
// never be conflated with (or silently fall back to) the outer, unrelated module-scope one.
const label = "outer-module-scope-label";

function describeOuter() {
  return label;
}

function describeInner() {
  const label = "inner-function-scope-label";
  return function nested() {
    return label;
  };
}

module.exports = { describeOuter, describeInner };
