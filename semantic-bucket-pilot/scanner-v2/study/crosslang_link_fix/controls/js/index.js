// CROSSLANG-LINK-FIX01 real controls -- three positive native-binding-loading shapes
// (matching real, independently-confirmed corpus conventions: direct build-path require,
// node-gyp-build loader indirection, bindings loader package), three negative shapes
// (a Node core module, an unrelated real npm package, a lookalike package name that
// merely CONTAINS "bindings" as a substring -- must NOT match the exact-membership check),
// one more negative shape (CROSSLANG-LINK-FIX01B): calling a method DIRECTLY on the
// loader helper itself (require('node-gyp-build') referenced but never INVOKED) must not
// be mistaken for a call on the actual native binding (require('node-gyp-build')(x), the
// loader's return value) -- both share the exact same receiver_type ("node-gyp-build"),
// so this is the one case receiver_type ALONE cannot distinguish.
//
// CROSSLANG-LINK-FIX01D adds a fourth positive shape (the SAME node-gyp-build invocation,
// but double-quoted) and two more negative shapes for the two real packages a prior
// version of this fix incorrectly included in NATIVE_LOADER_PACKAGES -- both export a
// plain HELPER OBJECT, not a callable loader function.
//
// CROSSLANG-LINK-FIX01E: FIX01B/D's own marker-regex approach was ITSELF shown to be
// source-formatting-fragile (see CHARACTERIZATION.md) -- a template literal, internal
// whitespace/a comment, and an ALIASED two-statement loader each produced a DIFFERENT
// decision than the plain chained case the regex was built from. Every one of those
// syntax forms gets its OWN positive (loader properly invoked) AND bare-helper negative
// (loader referenced but never invoked -- same object, same package, called directly)
// pair here, real and regenerated through the real frontend, so the canonical resolver
// (`resolve_loader_provenance`) is proven correct across all of them, not just the one
// shape the original regex happened to be built from.

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

// CROSSLANG-LINK-FIX01E: template-literal chain -- positive + bare-helper negative.
const native5 = require(`node-gyp-build`)(__dirname);
function callQuux() { return native5.Quux(5); }

const loaderTemplate = require(`node-gyp-build`);
function checkLoaderTemplatePath() { return loaderTemplate.path(__dirname); }

// CROSSLANG-LINK-FIX01E: whitespace/comment chain -- positive + bare-helper negative.
const native6 = require( 'node-gyp-build' )( __dirname );
function callCorge() { return native6.Corge(6); }

const loaderWhitespace = require( 'node-gyp-build' );
function checkLoaderWhitespacePath() { return loaderWhitespace.path(__dirname); }

const native7 = require('node-gyp-build') /* load the addon */ (__dirname);
function callGrault() { return native7.Grault(7); }

// CROSSLANG-LINK-FIX01E: aliased two-statement loader -- positive + bare-helper negative.
const loaderFn = require('node-gyp-build');
const native8 = loaderFn(__dirname);
function callGarply() { return native8.Garply(8); }
function checkLoaderFnPath() { return loaderFn.path(__dirname); }

module.exports = {
  callFoo, callBar, callBaz, callQux, readIt, mapIt, helpIt,
  checkLoaderPath, checkNodePreGypFind, checkPrebuildInstallDownload,
  callQuux, checkLoaderTemplatePath,
  callCorge, checkLoaderWhitespacePath, callGrault,
  callGarply, checkLoaderFnPath,
};
