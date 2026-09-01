// Minimal positive control (mirrors ms-2.1.3's own real shape): `module.exports = <function
// expression>` resolves DIRECTLY to a MethodRef, no identifier indirection at all.
module.exports = function (val, options) {
  return val;
};
