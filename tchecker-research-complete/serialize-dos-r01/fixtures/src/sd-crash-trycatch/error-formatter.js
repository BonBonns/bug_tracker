// Crash axis: SAFE (try/catch). Size axis: still a candidate (no bounding transform) --
// the case RECONCILIATION.md documents as the two axes genuinely disagreeing.
function errorFormatter(req) {
  const propertyValue = req.body;
  try {
    return JSON.stringify(propertyValue);
  } catch (e) {
    return null;
  }
}
