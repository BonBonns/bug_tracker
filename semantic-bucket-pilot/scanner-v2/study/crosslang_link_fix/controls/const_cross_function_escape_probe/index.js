// --- Case A: conditional (ternary) initializer -- const, but ambiguous value ---
let flag = true;
const fake = {};
const nativeA = flag
  ? require('node-gyp-build')(__dirname)
  : fake;
function wrapperA() { return nativeA.Foo(); }

// --- Case B: callback invocation BEFORE initialization (escape via argument-passing) ---
function invokeB(callback) { callback(); }
function wrapperB() { return nativeB.Bar(); }
invokeB(wrapperB);
const nativeB = require('node-gyp-build')(__dirname);

// --- Case C: callback registration AFTER initialization (should be safe/positive) ---
function invokeC(callback) { callback(); }
const nativeC = require('node-gyp-build')(__dirname);
function wrapperC() { return nativeC.Baz(); }
invokeC(wrapperC);

// --- Case D: export/assignment of the wrapper BEFORE initialization ---
function wrapperD() { return nativeD.Qux(); }
module.exports = { wrapperD };
const nativeD = require('node-gyp-build')(__dirname);
