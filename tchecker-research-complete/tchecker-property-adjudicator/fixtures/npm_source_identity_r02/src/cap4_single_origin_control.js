// Negative control for capability 4: an exported function's parameter that is PACKAGE_API_INPUT
// only (its own name does not match the APPLICATION_INGRESS_INPUT naming convention at all) --
// must emit exactly ONE origin_family row, multi_origin=false, origin_count=1. Proves the
// MULTIPLE_ORIGINS machinery does not over-fire on an ordinary single-family site.
function handlePayload(payload) {
  return payload;
}

module.exports = { handlePayload };
