function checkDyn(input) {
  return /^(a+)+$/.test(input);
}
const key = computeKey();
module.exports[key] = checkDyn;
