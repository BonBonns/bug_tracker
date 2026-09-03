// CONTROL 13: the same boundary-rule text at two different program points. Expect:
// two distinct sites retained, never merged.
const fs = require('fs');
function first(p) {
  const t = fs.readFileSync(p, 'utf8');
  return t.replace(/'(.*?)(?<!\\)'/g, function (w, inner) { return inner; });
}
function second(p) {
  const t = fs.readFileSync(p, 'utf8');
  return t.replace(/'(.*?)(?<!\\)'/g, function (w, inner) { return inner; });
}
module.exports = { first, second };
