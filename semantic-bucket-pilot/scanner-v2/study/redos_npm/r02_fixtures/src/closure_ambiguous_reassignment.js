// Capability 5 abstention for capability 4: an AMBIGUOUS closure binding -- `RE` is assigned
// TWICE at the same enclosing scope level (a genuine reassignment) before the nested closure's
// use -- more than one live candidate reaches the use site, so resolution must abstain rather
// than guessing which assignment is "the real one."
function outer(param) {
  let RE = /^(a+)+$/;
  RE = /^(b+)+$/;
  function inner() {
    return RE.test(param);
  }
  return inner();
}
module.exports = { outer };
