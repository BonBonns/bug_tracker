// CONTROL 9: the boundary regex is built at run time from a value this analysis cannot
// resolve. Expect: abstain -- the pattern's structure is unknown.
function makeParser(escapeChar) {
  const dynamic = new RegExp("'(.*?)(?<!" + escapeChar + ")'", 'g');
  return function (text) { return text.replace(dynamic, function (w, inner) { return inner; }); };
}
module.exports = { makeParser };
