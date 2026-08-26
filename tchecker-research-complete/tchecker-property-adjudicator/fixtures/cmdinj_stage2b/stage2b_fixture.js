// CMDINJ-STAGE2B: ad-hoc character-filter characterization. Deliberately narrower and lower-trust
// than Stage 2A. The central asymmetric rule, mirroring SSRF and path traversal:
//   demonstrated restrictive allowlist                    -> BREAKS
//   known incomplete blacklist                             -> PRESERVES
//   apparently comprehensive blacklist, completeness NOT
//     structurally established                             -> UNKNOWN, never assumed safe
const Meteor = { methods: (obj) => obj };
const { exec } = require('child_process');

// --- STRONG cases: demonstrated restrictive allowlists ---
async function strongAllowlist_anchoredAlnum(x) {
  if (/^[A-Za-z0-9_-]+$/.test(x)) {
    return exec(`tool ${x}`);
  }
}
async function strongAllowlist_numericOnly(x) {
  if (/^[0-9]+$/.test(x)) {
    return exec(`tool ${x}`);
  }
}
async function strongAllowlist_fixedEnum(x) {
  if (x === 'start' || x === 'stop') {
    return exec(`tool ${x}`);
  }
}

// --- a blacklist that CLAIMS to reject "all known shell metacharacters" -- completeness is not
// structurally provable from the character class alone, must NOT be assumed BREAKS ---
async function claimedComprehensiveBlacklist(x) {
  if (!/[;&|`$(){}\[\]<>\\'"*?~!#^\n\r]/.test(x)) {
    return exec(`tool ${x}`);
  }
}

// --- WEAK / adversarial cases: known-incomplete blacklists ---
async function removeSemicolonOnly(x) {
  const cleaned = x.replace(/;/g, '');
  return exec(`tool ${cleaned}`);
}
async function removeAmpersandOnly(x) {
  const cleaned = x.replace(/&/g, '');
  return exec(`tool ${cleaned}`);
}
async function removeThreeMetachars(x) {
  // removes ; | & but $, `, newline, redirection, subshell syntax, whitespace/globbing all survive
  const cleaned = x.replace(/[;|&]/g, '');
  return exec(`tool ${cleaned}`);
}
async function singleReplaceNonGlobal(x) {
  // especially weak: non-global replace only removes the FIRST occurrence
  const cleaned = x.replace(';', '');
  return exec(`tool ${cleaned}`);
}

// --- format checks that do NOT restrict command syntax at all ---
async function endsWithCheckOnly(x) {
  if (x.endsWith('.txt')) {
    return exec(`tool ${x}`);
  }
}
async function lengthBoundOnly(x) {
  if (x.length <= 10) {
    return exec(`tool ${x}`);
  }
}

// --- normalization only, no restriction ---
async function trimAndLowercase(x) {
  const cleaned = x.trim().toLowerCase();
  return exec(`tool ${cleaned}`);
}

// --- guard-dominance negative control: blacklist check exists but does NOT gate the sink ---
async function blacklistDoesNotDominate(x) {
  const hasSemicolon = x.includes(';');
  log(hasSemicolon);
  return exec(`tool ${x}`);  // unconditional -- the check above has no effect
}

// --- guard-dominance positive control: allowlist check DOES gate the sink (paired with the
// strong cases above, confirming the dominance mechanism still matters here too) ---
async function allowlistDominatesSink(x) {
  const isSafe = /^[A-Za-z0-9_-]+$/.test(x);
  if (isSafe) {
    return exec(`tool ${x}`);
  }
}

Meteor.methods({
  strongAllowlist_anchoredAlnum, strongAllowlist_numericOnly, strongAllowlist_fixedEnum,
  claimedComprehensiveBlacklist, removeSemicolonOnly, removeAmpersandOnly, removeThreeMetachars,
  singleReplaceNonGlobal, endsWithCheckOnly, lengthBoundOnly, trimAndLowercase,
  blacklistDoesNotDominate, allowlistDominatesSink,
});
