// CONTROL 6: the same boundary rule applied to a value built in memory in the same
// call. Expect: NOT classified as delayed/second-order.
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function normalize(rows) {
  const text = rows.join(', ');
  return text.replace(BOUNDARY, function (whole, inner) { return inner; });
}
module.exports = { normalize };
