// Positive (both axes): raw req.body serialized directly, no guard, no transform.
function errorFormatter(req) {
  const propertyValue = req.body;
  return JSON.stringify(propertyValue);
}
