class Checker {
  check(input) {
    return /^(a+)+$/.test(input);
  }
}
module.exports = Checker;
