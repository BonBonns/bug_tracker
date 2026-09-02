// PACKAGE_API_INPUT source model: an exported function's own parameter reaches a real fs sink,
// unguarded -- must be reachable via the PACKAGE_API_INPUT source tier (a capability the audited
// producer does not have at all -- confirmed zero rows there for this fixture).
const fs = require('fs');
function readPackageFile(userPath) {
  fs.readFile(userPath, () => {});
}
module.exports = readPackageFile;
