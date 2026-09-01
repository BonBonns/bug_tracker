function dangerousInternal() {
  const literal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";
  return /^(a+)+$/.test(literal);
}
module.exports.passthrough = function passthrough(input) {
  return input.toUpperCase();
};
