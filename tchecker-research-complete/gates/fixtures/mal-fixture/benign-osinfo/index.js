const os = require("os");
module.exports = function report() {
  return `host=${os.hostname()} platform=${process.platform} node=${process.version}`;
};
