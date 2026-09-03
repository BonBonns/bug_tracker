// CONTROL 5: the structured text is read from a stored file and processed later, in a
// restore routine. Expect: delayed-source evidence recorded.
const fs = require('fs');
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function restore(dumpPath) {
  const dump = fs.readFileSync(dumpPath, 'utf8');
  return dump.replace(BOUNDARY, function (whole, inner) { return inner; });
}
module.exports = { restore };
