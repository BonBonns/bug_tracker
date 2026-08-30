// CROSSLANG-LINK-FIX01 real controls -- three positive native-binding-loading shapes
// (matching real, independently-confirmed corpus conventions: direct build-path require,
// node-gyp-build loader indirection, bindings loader package) and three negative shapes
// (a Node core module, an unrelated real npm package, a lookalike package name that
// merely CONTAINS "bindings" as a substring -- must NOT match the exact-membership check).

const native1 = require('./build/Release/addon1');
function callFoo() { return native1.Foo(1, 2); }

const native2 = require('node-gyp-build')(__dirname);
function callBar() { return native2.Bar(3); }

const native3 = require('bindings')('addon3');
function callBaz() { return native3.Baz(); }

const fs = require('fs');
function readIt() { return fs.readFileSync('/tmp/x'); }

const lodash = require('lodash');
function mapIt(arr) { return lodash.map(arr, function (x) { return x; }); }

const helper = require('some-bindings-helper');
function helpIt() { return helper.Assist(); }

module.exports = { callFoo, callBar, callBaz, readIt, mapIt, helpIt };
