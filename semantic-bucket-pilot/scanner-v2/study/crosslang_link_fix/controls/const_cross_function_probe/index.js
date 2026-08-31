// --- Case 1: same-function direct use (no closure needed) -- real dominance ---
const directNative = require('node-gyp-build')(__dirname);
function callDirect() { return directNative.Direct(); }
callDirect();

// --- Case 2: module-level const, cross-function, safe (define+export pattern) ---
const native1 = require('node-gyp-build')(__dirname);
function callFoo() { return native1.Foo(1); }

// --- Case 3: const captured cross-function, but the DEFINING function has a real
// early return BEFORE the const line -- exit-dominance must fail ---
function setupBar() {
  if (Math.random() > 2) {
    return null;
  }
  const native2 = require('node-gyp-build')(__dirname);
  function callBar() { return native2.Bar(2); }
  return callBar;
}

// --- Case 4: const captured cross-function, but the capturing function is invoked
// SYNCHRONOUSLY, in the SAME defining scope, BEFORE the const line executes ---
function setupBaz() {
  function callBaz() { return native3.Baz(3); }
  callBaz();
  const native3 = require('node-gyp-build')(__dirname);
  return callBaz;
}

module.exports = { callDirect, callFoo, setupBar, setupBaz };

// --- Case 5: genuinely same-function direct use (no closure at all) ---
function sameFn() {
  const nativeSame = require('node-gyp-build')(__dirname);
  return nativeSame.SameFn();
}
