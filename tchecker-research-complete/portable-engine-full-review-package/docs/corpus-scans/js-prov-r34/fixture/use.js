const b = require("./barrel");
function use(x){return x;}
use(b.leaf.leafFn);     // P1: must resolve to leaf.js:leafFn, NEVER other.js:leafFn
use(b.sel.otherFn);     // N1: must abstain (selector-bearing)
use(b.plain.leafFn);    // N2: must abstain (not a module)
use(b.localFn);         // N3: resolves as an ordinary member, NOT as a module
