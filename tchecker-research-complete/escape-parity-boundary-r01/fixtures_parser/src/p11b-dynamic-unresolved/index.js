// CONTROL 11b: RegExp built by concatenation from a value this analysis cannot resolve.
// The pattern identity is unknown -> abstain.
function make(esc) {
  const dyn = new RegExp("'(.*?)(?<!" + esc + ")'", "g");
  return (t) => t.replace(dyn, (w, inner) => inner);
}
module.exports = { make };
