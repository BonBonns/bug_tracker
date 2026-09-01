// Capability 1 (direct class export) + Regression fixture #7:
// module.exports = SomeClass with 2+ real instance methods. Expect: `process`'s own parameter
// is recognized as a PACKAGE_API_INPUT source and reaches its DANGEROUS sink; the constructor
// itself stays correctly non-public-API (CLASS_CONSTRUCTOR_NOT_PUBLIC_API, unchanged from R01).
class Widget {
  constructor(opts) {
    this.opts = opts;
  }
  process(input) {
    return /^(a+)+$/.test(input);
  }
  safe(input2) {
    return /safe/.test(input2);
  }
}
module.exports = Widget;
