const leaf = require("./leaf");                 // P1 bare require-bound local
const sel  = require("./other").otherFn;        // N1 SELECTOR-bearing (R33) -> abstain
const plain = { leafFn: 1 };                    // N2 not a module at all
function localFn(a){ return a; }
module.exports = { leaf, sel, plain, localFn }; // N3 localFn: plain function, not a module
