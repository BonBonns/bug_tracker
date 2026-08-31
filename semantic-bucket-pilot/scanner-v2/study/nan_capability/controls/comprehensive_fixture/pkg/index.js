var probe = require('./build/Release/probe.node');

// Real end-to-end JS wrapper shape, mirroring node-snap7's own real
// `S7Client.prototype.DBRead = function (dbNumber, start, size, cb) { return
// this.ReadArea(...) }` idiom exactly: a public wrapper method whose own JS-caller-supplied
// argument is forwarded positionally into the native prototype method.

probe.Widget.prototype.dbRead = function (area, dbNumber, start, size, wordLen) {
  return this.readAreaLike(area, dbNumber, start, size, wordLen);
};

probe.Widget.prototype.doUpload = function (blockNum, len, extra) {
  return this.uploadLike(blockNum, len, extra);
};

probe.Widget.prototype.doGuarded = function (len, extra) {
  return this.guardedLike(len, extra);
};

probe.Widget.prototype.doCopyGood = function (len) {
  return this.copyGoodLike(len);
};

probe.Widget.prototype.doCopyMismatch = function (len) {
  return this.copyMismatchLike(len);
};

probe.Widget.prototype.doCopyUnresolved = function (idx, len) {
  return this.copyUnresolvedLike(idx, len);
};

module.exports = probe;
