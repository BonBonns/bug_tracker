// PACKAGE_API_INPUT abstentions -- must resolve ZERO exported functions from any of these three
// real shapes: a dynamic/computed export key, a require()-based re-export (identifier resolves to
// a CALL, not a MethodRef), and a class export (resolves to the class's own constructor, not its
// real public methods).
const fs = require('fs');
const key = computeKey();
function dynamicExportTarget(userPath) { fs.readFile(userPath, () => {}); }
module.exports[key] = dynamicExportTarget;

const reexported = require('./other-module');
module.exports.reexported = reexported;

class SomeClass {
  constructor(userPath) { fs.readFile(userPath, () => {}); }
}
module.exports.SomeClass = SomeClass;

function computeKey() { return 'x'; }
