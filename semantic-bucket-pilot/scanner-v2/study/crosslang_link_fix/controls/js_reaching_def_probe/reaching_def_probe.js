// Reaching-definition adversarial probes for resolve_loader_provenance -- real
// programs, run through the real frontend, testing the exact concern that "exactly one
// <operator>.assignment by NAME, anywhere in the file" is a blunt proxy for real
// reaching-definition, not the real thing.

// --- Case 1: overwrite-before-use (two real assignments, the SECOND is what a real
// use after both would see) ---
let native1 = require('node-gyp-build')(__dirname);
native1 = { Foo: function (n) { return n; } };
function callFoo() { return native1.Foo(1); }

// --- Case 2: branch multi-definition (two real assignments, one per branch) ---
let native2;
if (typeof process !== 'undefined') {
  native2 = require('node-gyp-build')(__dirname);
} else {
  native2 = { Bar: function (n) { return n; } };
}
function callBar() { return native2.Bar(2); }

// --- Case 3: parameter shadowing (real risk: the outer const has the SAME name as an
// inner function's own PARAMETER -- the call site inside uses the PARAMETER, not the
// outer native binding, even though there is only ONE <operator>.assignment to this
// name in the whole file) ---
const native3 = require('node-gyp-build')(__dirname);
function makeWrapper(native3) {
  return function callBaz() { return native3.Baz(3); };
}
const wrappedBaz = makeWrapper({ Baz: function (n) { return n; } });

// --- Case 4: assignment-after-use (the function referencing the receiver is DEFINED
// before the assignment executes -- only matters if actually INVOKED before the
// assignment; here we invoke it only afterward, which is the common, valid real
// pattern, but the STRUCTURAL question is whether the resolver accounts for order at
// all) ---
function callQux() { return native4.Qux(4); }
var native4;
native4 = require('node-gyp-build')(__dirname);

// --- Case 5: alias cycle (neither x5 nor y5 ever bottoms out at a real require() --
// must not false-positive, hang, or crash) ---
function someFunction() { return { Corge: function (n) { return n; } }; }
let x5 = someFunction;
let y5 = x5;
x5 = y5;
const native6 = x5(__dirname);
function callCorge() { return native6.Corge(6); }

module.exports = { callFoo, callBar, wrappedBaz, callQux, callCorge };
