// R02 new fixture: real closure-capture case, now reaching a REAL fs sink. Mirrors
// npm_source_identity_r01/src/cap1_module_closure_capture.js's own real shape -- an exported
// function's OWN parameter (`userPath`) is captured -- by a genuine nested-function closure, using
// the SAME identifier name, not merely a same-named but structurally different module-scope
// reassignment -- by an inner function that itself performs the real fs read. A real
// refsTo/closureBindingId-based resolver must resolve `userPath` inside `readIt` back through the
// closure to `makeReader`'s own parameter as a PACKAGE_API_INPUT source, something R01's own
// simple `p.method.ast.isIdentifier.name(p.name)` search (Capability 3, since replaced) was never
// designed to prove correctly (it is a real CPG identity/closure proof here, not a textual/AST
// coincidence) -- see docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md for the real,
// side-by-side R01-vs-R02 comparison run against this exact fixture.
// Uses the SAME named-CommonJS-export shape (`module.exports.NAME = NAME`) as
// package_api_named_exports.js -- a shape BOTH R01's own resolveExportRhs and the shared
// export_npm_source_identity.sc producer resolve identically, so this fixture isolates the
// closure-capture-resolution behavior itself, not export-shape support.
const fs = require('fs');

function makeReader(userPath) {
  return function readIt() {
    fs.readFileSync(userPath);
  };
}

module.exports.makeReader = makeReader;
