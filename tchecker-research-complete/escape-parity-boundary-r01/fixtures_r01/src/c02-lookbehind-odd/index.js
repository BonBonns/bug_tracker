// CONTROL 2: the SAME one-character negative-lookbehind rule, exercised with an
// ODD-length escape run. The rule happens to be right on this input; the rule itself
// is structurally unchanged, so it is still a parser candidate.
const BOUNDARY = /'(.*?)(?<!\\)'/g;
function extract(text) {
  return text.replace(BOUNDARY, function (whole, inner) { return inner; });
}
// odd-length run (1) directly before the quote
const SAMPLE = "'abc\\', 'next'";
module.exports = { extract, SAMPLE };
