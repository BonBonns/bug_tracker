// Capability 1 (closure identity, AMBIGUOUS outcome): `RE` is assigned TWICE at module scope
// before the nested closure that reads it -- two live candidate bindings for the same resolved
// Local, so the closure-identity resolver must ABSTAIN (AMBIGUOUS), never guess which assignment
// is "the real" one (never silently pick the first or the last).
function makeSafe() {
  return /^safe$/;
}

function makeDangerous() {
  return /^(a+)+$/;
}

let RE = makeSafe;
RE = makeDangerous;

function outer() {
  return function inner(s) {
    return RE;
  };
}

module.exports = { outer };
