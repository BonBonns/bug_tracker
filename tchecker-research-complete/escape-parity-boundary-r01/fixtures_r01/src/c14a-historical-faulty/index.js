// CONTROL 14a: the historical FAULTY parser's boundary rule, carried over verbatim as
// a pattern. Parser correctness only. Expect: parser candidate.
const BOUNDARY = /'(.*?)(?<!\\)'/;
function replaceValues(text, cb) { return text.replace(BOUNDARY, cb); }
module.exports = { replaceValues };
