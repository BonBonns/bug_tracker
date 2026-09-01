// Export-surface capability (regression parity with export_redos_npm_integ.sc's own frozen
// DYNAMIC_COMPUTED_EXPORT_KEY abstention): `module.exports[key] = fn` where `key` is a variable,
// not a literal -- the export NAME itself is not statically known, so it must be abstained on,
// never guessed.
function handler(x) {
  return x;
}

const key = computeKeyName();
module.exports[key] = handler;

function computeKeyName() {
  return "dynamicName";
}
