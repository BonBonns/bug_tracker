// CONTROL 1: one-character negative-lookbehind boundary rule; the fixture's own data
// carries an EVEN-length escape run before the quote. Expect: parser candidate.
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function extract(text) {
  return text.replace(BOUNDARY, function (whole, inner) { return inner; });
}
// even-length run (2) directly before the closing quote
const SAMPLE = "'abc\\\\', 'next'";
module.exports = { extract, SAMPLE };
