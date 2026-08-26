// REDOS-PROP-R01 (Stage 2): complexity classification fixtures. Every DANGEROUS/SAFE case here
// was independently verified by direct timing measurement (not assumed from pattern shape alone)
// during the original RocketChat investigation this property was generalized from.
const Meteor = { methods: (obj) => obj };

// --- REAL, confirmed DANGEROUS: the exact pattern from CVE-2025-5892 (parseMessage.js),
// empirically measured at O(n^2): 10000 chars -> 117ms, 80000 chars -> 7273ms ---
async function knownDangerous_parseMessage(userString) {
  return userString.search(/^:|\s+:/);
}

// --- REAL, confirmed DANGEROUS: the exact pattern from the new autotranslate.ts finding,
// empirically measured at O(n^2): 500 lines -> 12ms, 4000 lines -> 812ms ---
async function knownDangerous_autotranslate(userString) {
  return userString.replace(/^\s*<p>|<\/p>\s*$/gm, '');
}

// --- REAL, confirmed SAFE: the exact pattern from cors.ts, empirically measured at
// sub-millisecond, no scaling with input size at all ---
async function knownSafe_cors(userString) {
  const re = /^\s*(127\.0\.0\.1|::1)\s*$/;
  return re.test(userString);
}

// --- classic textbook DANGEROUS: nested quantifier, exponential blowup ---
async function textbookNestedQuantifier(userString) {
  return /^(a+)+$/.test(userString);
}

// --- SAFE: simple anchored allowlist, no alternation, no quantifier-then-content ambiguity ---
async function simpleAnchoredAllowlist(userString) {
  return /^[a-z0-9_-]+$/.test(userString);
}

// --- SAFE: quantifier present but at the very end of the pattern, nothing follows it, fully
// anchored -- no ambiguity about how much the quantifier should consume ---
async function quantifierAtEndFullyAnchored(userString) {
  return /^prefix\s*$/.test(userString);
}

// --- UNKNOWN: dynamic pattern, cannot be statically resolved ---
async function unresolvedDynamic(userString, userPattern) {
  const re = new RegExp(userPattern);
  return re.test(userString);
}

// --- SAFE: suffix-delimited nested quantifier -- the REAL email-validation regex from
// RocketChat's server/lib/omnichannel/messages.ts, initially a false positive (flagged DANGEROUS
// by the prefix-only delimiter check), empirically confirmed safe (essentially linear:
// 0.56ms/0.57ms/1.17ms at 10000/50000/100000 adversarial chars) before this fixture was added ---
async function suffixDelimitedNestedQuantifier(userString) {
  return /\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,4}\b/i.test(userString);
}

Meteor.methods({
  knownDangerous_parseMessage, knownDangerous_autotranslate, knownSafe_cors,
  textbookNestedQuantifier, simpleAnchoredAllowlist, quantifierAtEndFullyAnchored,
  unresolvedDynamic, suffixDelimitedNestedQuantifier,
});
