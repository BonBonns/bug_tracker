// CROSSLANG-LINK-FIX01 real controls -- three positive native-binding-loading shapes
// (matching real, independently-confirmed corpus conventions: direct build-path require,
// node-gyp-build loader indirection, bindings loader package), three negative shapes
// (a Node core module, an unrelated real npm package, a lookalike package name that
// merely CONTAINS "bindings" as a substring -- must NOT match the exact-membership check),
// one more negative shape (CROSSLANG-LINK-FIX01B): calling a method DIRECTLY on the
// loader helper itself (require('node-gyp-build') referenced but never INVOKED) must not
// be mistaken for a call on the actual native binding (require('node-gyp-build')(x), the
// loader's return value) -- both share the exact same receiver_type ("node-gyp-build"),
// so this is the one case receiver_type ALONE cannot distinguish; see
// _via_loader_invocation()'s own docstring for the real, structural signal that does.
//
// CROSSLANG-LINK-FIX01D adds a fourth positive shape (the SAME node-gyp-build invocation,
// but double-quoted -- the marker check must not depend on the analyzed package's own
// source-formatting/quote-style convention) and two more negative shapes, structurally
// identical to checkLoaderPath's own case but for the two real packages a prior version of
// this fix incorrectly included in NATIVE_LOADER_PACKAGES: both export a plain HELPER
// OBJECT, not a callable loader function --
//   - require('@mapbox/node-pre-gyp').find(...) (node-pre-gyp@0.17.0's real export shape)
//   - require("prebuild-install").download(...) (prebuild-install@7.1.3's real export
//     shape -- resolved via Node's own root-index.js fallback despite no "main" field;
//     double-quoted here deliberately, exercising FIX01D on a negative control too)

const native1 = require('./build/Release/addon1');
function callFoo() { return native1.Foo(1, 2); }

const native2 = require('node-gyp-build')(__dirname);
function callBar() { return native2.Bar(3); }

const native3 = require('bindings')('addon3');
function callBaz() { return native3.Baz(); }

const native4 = require("node-gyp-build")(__dirname);
function callQux() { return native4.Qux(4); }

const fs = require('fs');
function readIt() { return fs.readFileSync('/tmp/x'); }

const lodash = require('lodash');
function mapIt(arr) { return lodash.map(arr, function (x) { return x; }); }

const helper = require('some-bindings-helper');
function helpIt() { return helper.Assist(); }

const loader = require('node-gyp-build');
function checkLoaderPath() { return loader.path(__dirname); }

const nodePreGyp = require('@mapbox/node-pre-gyp');
function checkNodePreGypFind() { return nodePreGyp.find('/tmp/package.json'); }

const prebuildInstall = require("prebuild-install");
function checkPrebuildInstallDownload() { return prebuildInstall.download({}); }

module.exports = {
  callFoo, callBar, callBaz, callQux, readIt, mapIt, helpIt,
  checkLoaderPath, checkNodePreGypFind, checkPrebuildInstallDownload,
};
