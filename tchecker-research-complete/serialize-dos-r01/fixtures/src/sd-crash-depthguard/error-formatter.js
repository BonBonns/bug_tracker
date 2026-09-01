// Crash axis: SAFE (depth guard present in the same method).
function errorFormatter(req) {
  const propertyValue = req.body;
  const depth = computeDepth(propertyValue);
  if (depth > maxDepth) {
    return "[too deep]";
  }
  return JSON.stringify(propertyValue);
}
