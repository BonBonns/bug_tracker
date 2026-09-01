// CONTROL 12: two distinct boundary candidates whose outputs both reach the same
// consumer through a shared variable. Expect: abstain on consumer linkage.
const fs = require('fs');
const RULE_A = /'(.*?)(?<!\\)'/g;
const RULE_B = /"(.*?)(?<!\\)"/g;
function merge(pathA, pathB, flag) {
  const a = fs.readFileSync(pathA, 'utf8');
  const b = fs.readFileSync(pathB, 'utf8');
  let text = a.replace(RULE_A, function (w, inner) { return inner; });
  if (flag) { text = b.replace(RULE_B, function (w, inner) { return inner; }); }
  return JSON.parse(text);
}
module.exports = { merge };
