// SSRF-PROP-R01: controlled property-effect fixtures for ATTACKER_CONTROL_OF_REQUEST_HOST.
// Each function isolates ONE transform shape. Comment states the EXPECTED effect per the frozen
// design brief. No corpus scanning -- this file exists purely to validate the classifier.

// --- identity / alias: PRESERVES ---
function identity(userHost) {
  const h = userHost;
  return fetch(h);
}

// --- normalization is not restriction: PRESERVES/TRANSFORMS, host control survives ---
function urlWrap(userInput) {
  return fetch(new URL(userInput));
}
function stringCoerce(userInput) {
  return fetch(String(userInput));
}
function trimmed(userInput) {
  return fetch(userInput.trim());
}
function lowercased(userInput) {
  return fetch(userInput.toLowerCase());
}
function decoded(userInput) {
  return fetch(decodeURIComponent(userInput));
}
function extractedHostname(userInput) {
  const h = new URL(userInput).hostname;
  return fetch(h);
}
function templateLiteralHost(userInput) {
  return fetch(`https://${userInput}`);
}

// --- fixed-prefix concatenation: BREAKS host control (path only survives) ---
function fixedPrefixConcat(attackerPath) {
  return fetch('https://fixed.example/' + attackerPath);
}

// --- host assignment overwritten by a fixed literal AFTER attacker input: BREAKS ---
function hostOverwritten(userInput) {
  const u = new URL(userInput);
  u.hostname = 'fixed.example';
  return fetch(u);
}

// --- two-arg new URL(x, base): UNKNOWN unless x is known path-relative ---
function urlWithBaseAmbiguous(userInput) {
  // userInput could be an absolute URL ("http://evil.example") which OVERRIDES the base entirely,
  // or a path ("/foo") which stays relative to the fixed base. Not statically distinguishable
  // here -- must be UNKNOWN, never assumed BREAKS.
  return fetch(new URL(userInput, 'https://fixed.example'));
}
function urlWithBaseKnownPathRelative(userInput) {
  // the first argument is a LITERAL that is unambiguously path-relative (starts with "/", no
  // scheme) -- this is the one case where the two-arg form CAN be resolved: base wins.
  return fetch(new URL('/attacker/path', 'https://fixed.example'));
}

// --- guard dominance: POSITIVE control, comparison genuinely gates the sink call ---
function guardDominatesSink(userHost) {
  if (userHost === 'allowed.example') {
    return fetch(userHost);
  }
  return null;
}
function allowlistIncludesDominates(userHost) {
  const allowedHosts = ['allowed.example', 'also-allowed.example'];
  if (allowedHosts.includes(userHost)) {
    return fetch(userHost);
  }
  return null;
}
function setHasDominates(userHost) {
  const allowed = new Set(['allowed.example']);
  if (allowed.has(userHost)) {
    return fetch(userHost);
  }
  return null;
}

// --- guard dominance: NEGATIVE control, comparison exists but does NOT gate the sink call ---
function guardDoesNotDominateSink(userHost) {
  const ok = userHost === 'allowed.example';
  log(ok);
  return fetch(userHost);   // unconditional -- the comparison above has no effect on this call
}
function guardOnDifferentBranch(userHost) {
  if (userHost === 'allowed.example') {
    log('matched');
  }
  return fetch(userHost);   // OUTSIDE the if-body -- always reached regardless of the comparison
}

// --- lookup by attacker-controlled key: OPEN (same lesson as the RocketChat findOneById case) ---
function lookupByUserId(userId) {
  const webhookUrl = lookupTenant(userId).webhookUrl;
  return fetch(webhookUrl);
}
function configLookupByKey(userKey) {
  const serviceUrl = config.services[userKey].url;
  return fetch(serviceUrl);
}

// --- unresolved wrapper: UNKNOWN ---
function unresolvedWrapperTransform(userInput) {
  const processed = someExternalNormalizer(userInput);
  return fetch(processed);
}
