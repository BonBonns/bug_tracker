// Capability 5 abstention (distinct from the top-level dynamic-export-key shape already
// handled in R01): module.exports = { [computedKey]: fn } -- a computed PROPERTY KEY inside
// the object literal itself -- must abstain (COMPUTED_OBJECT_LITERAL_PROPERTY_KEY), never guess.
function foo(x) {
  return /^(a+)+$/.test(x);
}
const computedKey = "foo";
module.exports = { [computedKey]: foo };
