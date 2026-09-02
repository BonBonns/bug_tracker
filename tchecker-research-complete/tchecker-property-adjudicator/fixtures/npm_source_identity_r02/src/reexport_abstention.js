// Export-surface capability: a genuine multi-hop re-export shape (`export * from "./other.js"`,
// modeled on miniml-1.0.19's own real index.js), which js2cpg desugars to
// `var _other = require("./other.js"); exports.other.js = _other;` -- an identifier assigned
// from a require() CALL, never a MethodRef. A real resolver must abstain honestly
// (REEXPORT_UNRESOLVED), never silently guess or silently drop this export entirely.
export * from "./other.js";
