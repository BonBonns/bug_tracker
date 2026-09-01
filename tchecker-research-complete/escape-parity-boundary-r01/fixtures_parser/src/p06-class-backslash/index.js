// CONTROL 6 + 7: backslashes inside character classes, and escaped backslashes inside
// regex literals, must be parsed as escape atoms rather than terminating the class.
const A = /'([^'\\]*(?:\\.[^'\\]*)*)'/g;   // class excludes the escape char
const B = /'((?:\\\\|[^'\\])*)'/g;         // explicit escape-PAIR alternative
const C = /'([^'\\]*)'/g;                  // class cannot contain an escape at all
module.exports = { A, B, C };
