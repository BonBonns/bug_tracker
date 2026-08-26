const ctrl = require("./outer").inner;        // T1/T2: must bind to ./inner
const whole = require("./outer");             // T3: bare require unchanged
const missingSel = require("./outer").nope;   // T4: unresolved member -> abstain
function use(x){return x;}
use(ctrl.shared);      // must be innerShared, NEVER outerShared
use(whole.shared);     // must be outerShared
use(missingSel);
