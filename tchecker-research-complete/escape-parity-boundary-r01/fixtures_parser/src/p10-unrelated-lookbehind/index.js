// CONTROL 10: negative lookbehinds that have nothing to do with quote termination.
// Neither may become a candidate.
const NOT_AFTER_DIGIT = /(?<!\d)\w+/g;          // lookbehind, no quoted-string construct
const ESCAPED_X       = /(?<!\\)x/g;            // escape lookbehind, but before 'x', not a quote
const AFTER_DOLLAR    = /(?<=\$)\d+/g;          // positive lookbehind, unrelated
function scan(t) { return [t.match(NOT_AFTER_DIGIT), t.match(ESCAPED_X), t.match(AFTER_DOLLAR)]; }
module.exports = { scan };
