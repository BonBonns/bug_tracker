const inner = require("./inner");
function outerShared(a){ return a; }
module.exports = { shared: outerShared, inner };
