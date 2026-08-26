const os = require("os");
function gather() { return { host: os.hostname(), plat: process.platform }; }
module.exports = function show() { console.log(gather()); };   // stays local
