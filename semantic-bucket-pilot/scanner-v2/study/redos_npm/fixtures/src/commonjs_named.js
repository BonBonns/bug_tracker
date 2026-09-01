function checkThing(input) {
  return /^(a+)+$/.test(input);
}
module.exports.checkThing = checkThing;
exports.checkOther = function(x) {
  return /^(b+)+$/.exec(x);
};
