// CONTROL 7: decode -> replace -> encode -> structured consumer, from a stored dump.
// Expect: the complete reachable chain.
const fs = require('fs');
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function rewriteValue(whole, inner) { return "'" + inner.toUpperCase() + "'"; }
function importDump(dumpPath) {
  const stored = fs.readFileSync(dumpPath, 'utf8');
  const decoded = Buffer.from(stored, 'base64').toString('utf8');
  const replaced = decoded.replace(BOUNDARY, rewriteValue);
  const reencoded = Buffer.from(replaced, 'utf8').toString('base64');
  return JSON.parse(reencoded);
}
module.exports = { importDump };
