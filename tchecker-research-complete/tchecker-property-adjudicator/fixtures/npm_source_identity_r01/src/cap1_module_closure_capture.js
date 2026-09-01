// Capability 1 (closure capture identity): a module-scope `let` variable, written by one
// top-level function and READ by a different top-level function's own nested body -- a real
// closure capture (the reading function is a distinct lexical scope from the module scope that
// declares the variable), modeled directly on motifer-26.1.1's own `let logger = null;` /
// `LoggerObject` shape (see fixtures/npm_source_identity_r01/dev_packages/motifer-26.1.1.tgz).
let handlerState = null;

function configure(state) {
  handlerState = state;
}

function useState() {
  // `handlerState` here is NOT declared in useState's own scope -- it is captured from the
  // module (:program) scope. A real closure-identity resolver must resolve this to the SAME
  // Local `configure` itself assigns, never a name-matched guess.
  return handlerState;
}

module.exports = { configure, useState };
