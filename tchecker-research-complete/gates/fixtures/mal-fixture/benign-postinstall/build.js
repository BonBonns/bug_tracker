const fs = require("fs");
fs.writeFileSync("./.built", String(Date.now()));
