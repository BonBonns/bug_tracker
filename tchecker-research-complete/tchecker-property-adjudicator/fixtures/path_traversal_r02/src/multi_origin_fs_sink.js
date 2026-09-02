// R02 new fixture: MULTIPLE_ORIGINS, now real for Path Traversal (not merely for the shared
// npm-source-identity module). Mirrors npm_source_identity_r01/src/cap4_multiple_origins.js's own
// real shape -- the exported function's OWN parameter is itself named `req`, so its bare
// identifier reference simultaneously (a) IS a PACKAGE_API_INPUT candidate (a reference to this
// package's own exported-function parameter) and (b) matches the property-neutral
// APPLICATION_INGRESS_INPUT naming convention (bare req/request identifier) -- but here, unlike
// cap4_multiple_origins.js's own plain `return req;`, that SAME identifier is passed DIRECTLY to a
// real filesystem sink, so export_path_traversal_integ_r02.sc must emit TWO rows in
// source_facts.tsv for this one (sink, src) pair -- one per real, distinct family -- never
// collapsed to a single family the way R01's own `familyOfSource` (a single string) would have.
// Uses the SAME named-CommonJS-export shape (`module.exports.NAME = NAME`) as
// package_api_named_exports.js -- a shape BOTH R01's own resolveExportRhs and the shared
// export_npm_source_identity.sc producer resolve identically, so this fixture isolates the
// MULTIPLE_ORIGINS behavior itself, not export-shape support.
const fs = require('fs');

function handleRequest(req) {
  fs.readFileSync(req);
}

module.exports.handleRequest = handleRequest;
