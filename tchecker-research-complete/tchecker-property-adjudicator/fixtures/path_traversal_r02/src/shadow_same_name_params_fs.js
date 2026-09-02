// R02 new fixture: same-name-parameter distinctness, now real for Path Traversal. Mirrors
// npm_source_identity_r01/src/cap2_shadow_same_name_params.js's own real shape -- TWO different
// exported functions each declare their OWN parameter named `userPath`, each reaching its OWN,
// SEPARATE real fs sink. A real, identity-based (refsTo/closureBindingId) source resolver must
// keep each `userPath` reference tied to its own function's own MethodParameterIn, never the
// other function's -- so readAlpha's sink must see ONLY readAlpha's own userPath as a source, and
// readBeta's sink must see ONLY readBeta's own userPath, never cross-contaminated.
// Uses the SAME named-CommonJS-export shape (`module.exports.NAME = NAME`) as
// package_api_named_exports.js -- a shape BOTH R01's own resolveExportRhs and the shared
// export_npm_source_identity.sc producer resolve identically, so this fixture isolates the
// same-name-parameter-distinctness behavior itself, not export-shape support.
const fs = require('fs');

function readAlpha(userPath) {
  fs.readFileSync(userPath);
}

function readBeta(userPath) {
  fs.writeFileSync(userPath, 'x');
}

module.exports.readAlpha = readAlpha;
module.exports.readBeta = readBeta;
