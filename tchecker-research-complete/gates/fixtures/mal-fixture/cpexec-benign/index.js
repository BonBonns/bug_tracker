const { execSync } = require("child_process");
module.exports = function build() {
  return execSync("node-gyp rebuild").toString();   // runtime, not install-hook
};
