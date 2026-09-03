// CONTROL 8: alternation where only one branch carries the quote boundary.
const ONE_BRANCH_INCOMPLETE = /(?:\d+|'(.*?)(?<!\\)')/g;   // the quoted branch is incomplete
const BOTH_BRANCHES_PARITY  = /(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g;
module.exports = { ONE_BRANCH_INCOMPLETE, BOTH_BRANCHES_PARITY };
