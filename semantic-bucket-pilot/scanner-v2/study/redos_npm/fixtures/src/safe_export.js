module.exports.checkSafe = function checkSafe(input) {
  return /^[a-z0-9_-]+$/.test(input);
};
