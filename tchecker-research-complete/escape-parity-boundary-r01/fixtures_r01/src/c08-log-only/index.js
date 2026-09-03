// CONTROL 8: the same transformation, but the result only reaches logging. Expect:
// parser candidate only -- no structured-text consumer.
const fs = require('fs');
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function auditValue(whole, inner) { return "'" + inner.trim() + "'"; }
function audit(dumpPath) {
  const stored = fs.readFileSync(dumpPath, 'utf8');
  const decoded = Buffer.from(stored, 'base64').toString('utf8');
  const replaced = decoded.replace(BOUNDARY, auditValue);
  console.log(replaced);
}
module.exports = { audit };
