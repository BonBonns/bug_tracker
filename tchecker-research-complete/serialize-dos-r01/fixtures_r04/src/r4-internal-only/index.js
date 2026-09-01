// C5: internal-only parameter -- not externally sourced (helper is never exported).
function internal(secret) {
  return JSON.stringify(secret);
}
function process() {
  return internal("literal");
}
module.exports = process;
