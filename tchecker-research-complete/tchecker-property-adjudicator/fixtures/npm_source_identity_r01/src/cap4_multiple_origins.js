// Capability 4 (MULTIPLE_ORIGINS): a single candidate source node that is REACHABLE under more
// than one distinct origin_family at once -- must never be collapsed to one row. Here the
// exported function's own parameter is itself named `req` (so its bare identifier reference
// simultaneously (a) IS a PACKAGE_API_INPUT candidate -- a reference to this package's own
// exported-function parameter -- and (b) matches the property-neutral APPLICATION_INGRESS_INPUT
// naming convention re-derived from export_redos_npm_integ.sc's own req/request source model).
function handleRequest(req) {
  return req;
}

module.exports = { handleRequest };
