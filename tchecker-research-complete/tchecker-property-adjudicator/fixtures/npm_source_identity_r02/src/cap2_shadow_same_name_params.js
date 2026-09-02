// Capability 2 (lexical shadowing / same-name parameters kept distinct): TWO different exported
// functions each declare their OWN parameter named `req` -- a naive same-file, name-matching
// resolver could conflate them; a real refsTo-based resolver must keep each `req` reference tied
// to its own function's own MethodParameterIn/Local, never the other function's.
function handleAlpha(req) {
  return req.alphaField;
}

function handleBeta(req) {
  return req.betaField;
}

module.exports = { handleAlpha, handleBeta };
