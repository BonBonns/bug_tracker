// NOSQLI-PROP-R01 (Stage 2): property effects for ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE.
// The defense mechanism here is fundamentally TYPE-based, not content-based -- unlike command
// injection's open-ended shell-metacharacter space, JavaScript's typeof has a CLOSED, finite set
// of outcomes ("undefined","object","boolean","number","bigint","string","symbol","function").
// This means BOTH a positive type check (typeof x === 'string') AND a negative/exclusion check
// (typeof x !== 'object') can be genuinely, structurally COMPLETE guards for this property --
// a real asymmetry-breaker unique to type-based properties, distinct from the "only positive
// allowlists count" rule that applied to content-based properties (SSRF, path traversal, command
// injection). Explicit key/character-based blocklists remain untrustworthy, matching the SAME
// asymmetric discipline as those properties -- and are grounded in a REAL, disclosed RocketChat
// bypass (Sonar's 2021 writeup: a blocklist that checked known query FIELDS but not top-level
// MongoDB OPERATORS, bypassed via $where).
const Meteor = { methods: (obj) => obj, check: (val, pattern) => {} };

// --- no guard at all: UNSAFE ---
async function noGuard(userInput) {
  return Users.findOne({ username: userInput });
}

// --- positive type check, dominates the sink: BREAKS ---
async function typeofStringPositiveDominates(userInput) {
  if (typeof userInput === 'string') {
    return Users.findOne({ username: userInput });
  }
}

// --- positive type check present, but does NOT dominate: PRESERVES ---
async function typeofStringPositiveDoesNotDominate(userInput) {
  const isString = typeof userInput === 'string';
  log(isString);
  return Users.findOne({ username: userInput });
}

// --- negative/exclusion type check, dominates: BREAKS -- testing the closed-type-system
// asymmetry specifically (typeof's enumerable output set makes "not object" as complete as
// "is string" for ruling out operator injection, unlike an open-ended character blocklist) ---
async function typeofObjectNegativeDominates(userInput) {
  if (typeof userInput !== 'object') {
    return Users.findOne({ username: userInput });
  }
}

// --- explicit string coercion: BREAKS (String({$ne:null}) produces the literal string
// "[object Object]", not an interpretable operator) ---
async function stringCoercion(userInput) {
  return Users.findOne({ username: String(userInput) });
}

// --- template literal interpolation: BREAKS (forces string conversion the same way String() does) ---
async function templateLiteralCoercion(userInput) {
  return Users.findOne({ username: `${userInput}` });
}

// --- Meteor's check() with the String pattern: BREAKS (a real, well-known Meteor validation
// primitive that throws synchronously on type mismatch, before the sink is ever reached) ---
async function meteorCheckString(userInput) {
  Meteor.check(userInput, String);
  return Users.findOne({ username: userInput });
}

// --- known-incomplete key/character blocklist: the REAL bypassed pattern from RocketChat's own
// disclosed history -- checks whether specific FIELDS are being queried, never checks whether the
// VALUE itself is an object, so $ne/$regex/$where all sail through untouched: PRESERVES, never
// BREAKS, regardless of how thorough the field list looks ---
async function incompleteFieldBlocklist(userInput) {
  const forbiddenFields = ['$where', 'password', 'services'];
  if (!forbiddenFields.includes(userInput)) {
    return Users.findOne({ username: userInput });
  }
}

// --- an INCOMPLETE type check: verifies the value is not an ARRAY, but never checks for plain
// objects -- {$ne: null} is an object, not an array, so Array.isArray() alone does not exclude
// it: PRESERVES, this is a genuinely incomplete type check, not a complete one ---
async function incompleteArrayOnlyCheck(userInput) {
  if (!Array.isArray(userInput)) {
    return Users.findOne({ username: userInput });
  }
}

Meteor.methods({
  noGuard, typeofStringPositiveDominates, typeofStringPositiveDoesNotDominate,
  typeofObjectNegativeDominates, stringCoercion, templateLiteralCoercion, meteorCheckString,
  incompleteFieldBlocklist, incompleteArrayOnlyCheck,
});
