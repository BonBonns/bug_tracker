// CONTROL 11a: RegExp built from a single, uniquely resolved string literal. The pattern
// identity is known, so it is classified rather than abstained.
const BOUNDARY = new RegExp("'(.*?)(?<!\\\\)'", "g");
function extract(t) { return t.replace(BOUNDARY, (w, inner) => inner); }
module.exports = { extract };
