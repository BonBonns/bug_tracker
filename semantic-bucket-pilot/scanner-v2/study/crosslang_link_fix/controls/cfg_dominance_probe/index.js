// CFG/reachability adversarial probes: assignment-after-use, one-branch-only,
// loop-only, try/catch-only. Each has EXACTLY ONE real <operator>.assignment to its
// name (so the current "exactly one assignment" rule alone cannot reject them) but the
// SINGLE assignment is not guaranteed to actually execute before the use, or at all.

// --- assignment-after-use: callFoo invoked BEFORE the var assignment executes ---
function callFoo() { return native1.Foo(1); }
callFoo();
var native1 = require('node-gyp-build')(__dirname);

// --- one-branch-only: the sole assignment is inside an if with no else ---
let native2;
if (typeof process !== 'undefined' && process.env.SOME_FLAG) {
  native2 = require('node-gyp-build')(__dirname);
}
function callBar() { return native2.Bar(2); }

// --- loop-only: the sole assignment is inside a loop body ---
let native3;
for (let i = 0; i < 1; i++) {
  native3 = require('node-gyp-build')(__dirname);
}
function callBaz() { return native3.Baz(3); }

// --- try/catch-only: the sole assignment is inside a try block ---
let native4;
try {
  native4 = require('node-gyp-build')(__dirname);
} catch (e) {
  // native4 stays undefined on failure
}
function callQux() { return native4.Qux(4); }

module.exports = { callFoo, callBar, callBaz, callQux };
