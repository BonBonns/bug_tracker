// PATH-TRAV-PROP-R01: controlled property-effect fixtures for ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION.
// Fixtures registered via Meteor.methods so parameters are recognized as ingress sources (reusing
// the same ingress-boundary mechanism SSRF already verified).
const Meteor = { methods: (obj) => obj };
const fs = require('fs');
const path = require('path');

// --- identity / alias: PRESERVES ---
async function identity(userPath) {
  const p = userPath;
  return fs.readFile(p, () => {});
}

// --- normalization is not restriction: PRESERVES ---
async function normalized(userPath) {
  return fs.readFile(path.normalize(userPath), () => {});
}
async function resolvedNoBase(userPath) {
  return fs.readFile(path.resolve(userPath), () => {});
}

// --- THE CRITICAL NEGATIVE CONTROL: a fixed base directory does NOT contain path.join/resolve
// against '../' traversal, unlike SSRF's fixed axios baseURL containing the host. This must NOT
// be classified BREAKS just because a "fixed prefix" is present -- doing so would be silently
// wrong for a well-known, real Node.js vulnerability pattern. ---
async function joinedWithFixedBase(userPath) {
  // path.join('/safe/base', '../../etc/passwd') === '/etc/passwd' -- genuinely escapes.
  return fs.readFile(path.join('/safe/base', userPath), () => {});
}
async function resolvedWithFixedBase(userPath) {
  // path.resolve behaves the same way when given multiple segments -- no containment.
  return fs.readFile(path.resolve('/safe/base', userPath), () => {});
}
async function concatenatedWithFixedPrefix(userPath) {
  // plain string concatenation: even more obviously offers no containment at all.
  return fs.readFile('/safe/base/' + userPath, () => {});
}

// --- genuine restrictions: explicit denylist / allowlist checks that actually dominate the sink ---
async function stripsDotDotLiterally(userPath) {
  const cleaned = userPath.replace(/\.\./g, '');
  return fs.readFile(cleaned, () => {});
}
async function guardDominatesSink(userPath) {
  if (!userPath.includes('..')) {
    return fs.readFile(userPath, () => {});
  }
}
async function guardDoesNotDominateSink(userPath) {
  const ok = !userPath.includes('..');
  log(ok);
  return fs.readFile(userPath, () => {});  // unconditional -- the check above has no effect
}

// --- the REAL, correct containment pattern: resolve THEN verify containment with startsWith ---
async function resolveThenVerifyContainment(userPath) {
  const resolved = path.resolve('/safe/base', userPath);
  if (resolved.startsWith('/safe/base' + path.sep)) {
    return fs.readFile(resolved, () => {});
  }
}
async function resolveThenVerifyContainmentDoesNotDominate(userPath) {
  const resolved = path.resolve('/safe/base', userPath);
  const ok = resolved.startsWith('/safe/base' + path.sep);
  log(ok);
  return fs.readFile(resolved, () => {});  // unconditional -- check above has no effect
}

// --- extension check: validates FORMAT, not LOCATION -- must not count as a location guard ---
async function extensionCheckOnly(userPath) {
  if (userPath.endsWith('.pdf')) {
    return fs.readFile(userPath, () => {});
  }
}

// --- lookup by attacker-controlled key: OPEN, same lesson as SSRF and serialize-dos ---
async function lookupByUserId(userId) {
  const filePath = fileRegistry[userId].path;
  return fs.readFile(filePath, () => {});
}

// --- unresolved wrapper: UNKNOWN ---
async function unresolvedWrapperTransform(userPath) {
  const processed = someExternalPathNormalizer(userPath);
  return fs.readFile(processed, () => {});
}

Meteor.methods({
  identity, normalized, resolvedNoBase, joinedWithFixedBase, resolvedWithFixedBase,
  concatenatedWithFixedPrefix, stripsDotDotLiterally, guardDominatesSink,
  guardDoesNotDominateSink, resolveThenVerifyContainment,
  resolveThenVerifyContainmentDoesNotDominate, extensionCheckOnly, lookupByUserId,
  unresolvedWrapperTransform,
});
