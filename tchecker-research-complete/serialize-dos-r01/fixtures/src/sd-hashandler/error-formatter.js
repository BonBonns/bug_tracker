// Crash axis: SUSPICIOUS (an uncaughtException net exists package-wide -- de-escalated,
// not a hard crash). Size axis: still a candidate (no bounding transform).
function errorFormatter(req) {
  const propertyValue = req.body;
  return JSON.stringify(propertyValue);
}
