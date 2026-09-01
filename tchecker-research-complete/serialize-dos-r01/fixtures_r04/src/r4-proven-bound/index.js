// C9: exported parameter through a proven, package-local size bound (slice with a
// numeric literal arg) -- negative.
function safe(input) {
  const bounded = String(input).slice(0, 32);
  return JSON.stringify(bounded);
}
module.exports = safe;
