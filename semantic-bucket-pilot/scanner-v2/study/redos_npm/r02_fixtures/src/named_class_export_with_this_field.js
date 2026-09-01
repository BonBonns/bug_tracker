// Capability 1 (named ESM export desugaring to the SAME shape as module.exports = Class) +
// Capability 3 (constructor param -> exact this.field identity -> method-use propagation),
// positive case. Mirrors the real velociradix Context/graphql() shape.
class Context {
  constructor(req) {
    this.req = req;
  }
  graphql() {
    return /^(a+)+$/.test(this.req.body);
  }
  other() {
    return 1;
  }
}
export { Context };
