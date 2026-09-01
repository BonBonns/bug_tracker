// C3: exported class constructor parameter stored in this.field, serialized by a method.
class Handler {
  constructor(req) {
    this.req = req;
  }
  process() {
    return JSON.stringify(this.req);
  }
}
module.exports = Handler;
