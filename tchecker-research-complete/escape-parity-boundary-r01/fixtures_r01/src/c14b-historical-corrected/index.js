// CONTROL 14b: the historical CORRECTED parser's boundary rule, carried over verbatim.
// Expect: negative -- escape-run parity established by construction.
const BOUNDARY = /'((?:[^'\\]++|\\.)*+)'/s;
function replaceValues(text, cb) { return text.replace(BOUNDARY, cb); }
module.exports = { replaceValues };
