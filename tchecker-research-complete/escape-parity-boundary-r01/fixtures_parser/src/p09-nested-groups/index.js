// CONTROL 9: nested and non-capturing groups around the same boundary rules.
const NESTED_PARITY     = /'(((?:(?:[^'\\])|(?:\\.))*))'/g;
const NESTED_INCOMPLETE = /'((?:(.*?)))(?<!\\)'/g;
module.exports = { NESTED_PARITY, NESTED_INCOMPLETE };
