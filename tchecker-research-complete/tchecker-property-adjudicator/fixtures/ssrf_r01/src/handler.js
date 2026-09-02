const Meteor = { methods: (obj) => obj, check: (val, pattern) => {} };
const fetch = require('node-fetch');

// no guard at all -- ESTABLISHED (real candidate)
async function noGuard(userHost) {
  return fetch(userHost);
}

// host overwritten by a fixed literal after attacker input -- BROKEN
async function hostOverwritten(userInput) {
  const u = new URL(userInput);
  u.hostname = 'fixed.example';
  return fetch(u);
}

// fixed-origin prefix concatenation -- BROKEN (path only survives)
async function fixedPrefixConcat(attackerPath) {
  return fetch('https://fixed.example/' + attackerPath);
}

// guard dominates the sink call -- OPEN (v1 syntactic approximation, not confirmed safe)
async function guardDominates(userHost) {
  if (userHost === 'allowed.example') {
    return fetch(userHost);
  }
  return null;
}

// unresolved wrapper transform -- OPEN (UNKNOWN)
async function unresolvedWrapper(userInput) {
  const processed = someExternalNormalizer(userInput);
  return fetch(processed);
}

Meteor.methods({
  noGuard, hostOverwritten, fixedPrefixConcat, guardDominates, unresolvedWrapper,
});
