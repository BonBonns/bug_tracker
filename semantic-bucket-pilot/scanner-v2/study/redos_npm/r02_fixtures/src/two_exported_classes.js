// Regression fixture #4: two exported classes from the same file, each with their own
// distinct instance methods and constructor fields -- must resolve both independently and
// correctly, no cross-class field/method confusion.
class Alpha {
  constructor(a) {
    this.a = a;
  }
  run(x) {
    return /^(a+)+$/.test(x);
  }
  useField() {
    return /^(p+)+$/.test(this.a);
  }
}
class Beta {
  constructor(b) {
    this.b = b;
  }
  run(y) {
    return /^(c+)+$/.test(y);
  }
  useField() {
    return /^(q+)+$/.test(this.b);
  }
}
module.exports.Alpha = Alpha;
module.exports.Beta = Beta;
