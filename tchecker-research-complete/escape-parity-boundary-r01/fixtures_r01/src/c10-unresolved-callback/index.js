// CONTROL 10: a resolvable boundary rule, but the replacement callback arrives from
// outside and cannot be identified. Expect: abstain on the transformation identity.
const fs = require('fs');
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function transform(dumpPath, handler) {
  const stored = fs.readFileSync(dumpPath, 'utf8');
  return stored.replace(BOUNDARY, handler);
}
module.exports = { transform };
