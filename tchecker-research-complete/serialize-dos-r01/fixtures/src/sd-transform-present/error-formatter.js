// Size axis: ABSTAIN (a transform intervenes -- whether it bounds size is unknown
// structurally). Crash axis: candidate (no try/catch, no depth guard, no net).
function errorFormatter(req) {
  const propertyValue = req.body;
  const sanitized = sanitizePayload(propertyValue);
  return JSON.stringify(sanitized);
}
