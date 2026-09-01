// Capability 3 abstention: this.req is set to a COMPUTED/transformed value (a call), not an
// exact identity of the constructor's own parameter -- must abstain, never guess.
class Handler {
  constructor(req) {
    this.req = transform(req);
  }
  handle() {
    return /^(a+)+$/.test(this.req.body);
  }
}
function transform(r) {
  return r;
}
module.exports = Handler;
