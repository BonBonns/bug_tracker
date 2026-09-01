// Minimal JS fixture to validate the astgen 3.47.0 + jssrc2cpg 4.0.608 frontend before
// trusting it on real packages. Deterministic, tiny, with one recognizable required
// binding and one call, so the exported/normalized JS facts can be asserted exactly.
const bindings = require('./build/Release/addon.node');

function runIterator() {
  return bindings.iteratorNext(42);
}

module.exports = { runIterator };
