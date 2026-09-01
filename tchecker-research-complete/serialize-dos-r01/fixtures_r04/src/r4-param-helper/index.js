// C2: exported parameter passed through a uniquely resolved helper.
function wrap(x) {
  return { wrapped: x };
}
function process(input) {
  const w = wrap(input);
  return JSON.stringify(w);
}
module.exports = process;
