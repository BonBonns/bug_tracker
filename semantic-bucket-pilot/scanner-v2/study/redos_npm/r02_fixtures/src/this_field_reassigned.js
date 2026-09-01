// Capability 3 abstention + Regression fixture #3: this.req is assigned in the constructor
// AND reassigned again elsewhere before any read -- must abstain (never treat the read as
// reaching the original constructor parameter).
class Handler {
  constructor(req) {
    this.req = req;
  }
  reset() {
    this.req = getSafeDefault();
  }
  handle() {
    return /^(a+)+$/.test(this.req.body);
  }
}
function getSafeDefault() {
  return { body: "" };
}
module.exports = Handler;
