// APPLICATION_INGRESS_INPUT source model (property-neutral re-derivation of
// export_redos_npm_integ.sc's own req.*/request.* literal pattern semantics): a plain internal
// function (NOT itself exported) that reads `req.body`/`request.query` -- proves the
// APPLICATION_INGRESS_INPUT family is recognized independent of any package export surface.
function internalOnlyHandler(req, request) {
  const a = req.body;
  const b = request.query;
  return a || b;
}

// Deliberately NOT exported (no module.exports assignment anywhere in this file) -- this
// function's own `req`/`request` parameters must never appear as PACKAGE_API_INPUT candidates,
// only as APPLICATION_INGRESS_INPUT ones, proving the two families are independently derived.
internalOnlyHandler(null, null);
