// C6: same-name parameter in an unrelated (non-exported) function must not contribute.
function exported(input) {
  return JSON.stringify(input);
}
function other(input) {
  return input.length;
}
module.exports = exported;
