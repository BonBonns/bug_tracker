// REDOS-SINK-R01: sink-semantics fixtures for ATTACKER_CONTROLLED_REGEX_COMPLEXITY.
// Each function isolates ONE regex-execution call shape. No complexity classification logic here
// -- pure identification of (a) which operand is the attacker-influenceable matched-against
// string, and (b) which operand is the regex pattern itself, matching the discipline used for
// every other Stage 1 in this project.
const Meteor = { methods: (obj) => obj };

// --- .test(): pattern is the receiver, string is the argument ---
async function testCall(userString) {
  const re = /^[a-z]+$/;
  return re.test(userString);
}

// --- .exec(): same receiver/argument shape as .test() ---
async function execCall(userString) {
  const re = /^[a-z]+$/;
  return re.exec(userString);
}

// --- String.prototype.match(): string is the receiver, pattern is the argument ---
async function matchCall(userString) {
  return userString.match(/^[a-z]+$/);
}

// --- String.prototype.matchAll(): same shape as match() ---
async function matchAllCall(userString) {
  return [...userString.matchAll(/[a-z]+/g)];
}

// --- String.prototype.search(): same shape as match() -- matches the REAL parseMessage.js sink shape ---
async function searchCall(userString) {
  return userString.search(/^:|\s+:/);
}

// --- String.prototype.replace(): string is the receiver, pattern is arg0, replacement is arg1 ---
async function replaceCall(userString) {
  return userString.replace(/^\s*<p>|<\/p>\s*$/gm, '');
}

// --- new RegExp(literalString) construction, then .test() -- pattern still statically known ---
async function newRegExpLiteralThenTest(userString) {
  const re = new RegExp('^[a-z]+$');
  return re.test(userString);
}

// --- dynamic pattern: regex text itself is NOT a literal, cannot be statically analyzed ---
async function dynamicPattern(userString, userPattern) {
  const re = new RegExp(userPattern);
  return re.test(userString);
}

// --- the attacker-influenceable operand is the PATTERN, not the matched string -- a different,
// arguably worse shape (attacker controls the regex itself, not just the input) ---
async function attackerControlsPattern(userPattern, fixedString) {
  const re = new RegExp(userPattern);
  return re.test(fixedString);
}

Meteor.methods({
  testCall, execCall, matchCall, matchAllCall, searchCall, replaceCall,
  newRegExpLiteralThenTest, dynamicPattern, attackerControlsPattern,
});
