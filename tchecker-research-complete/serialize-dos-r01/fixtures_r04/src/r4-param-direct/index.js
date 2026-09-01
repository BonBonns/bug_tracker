// C1: exported function parameter directly serialized.
function process(input) {
  return JSON.stringify(input);
}
module.exports = process;
