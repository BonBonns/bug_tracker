// PACKAGE_API_INPUT, named CommonJS exports -- module.exports.NAME = <identifier resolving to a
// single prior MethodRef assignment>.
const fs = require('fs');
function writePackageFile(userPath) {
  fs.writeFile(userPath, 'x', () => {});
}
module.exports.writePackageFile = writePackageFile;
