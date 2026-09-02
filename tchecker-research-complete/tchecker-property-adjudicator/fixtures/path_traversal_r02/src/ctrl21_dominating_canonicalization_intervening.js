// Correction round 2, item 6 (positive control): a canonicalizing assignment that TRULY,
// unconditionally dominates the boundary check -- with a real intervening, non-branching statement
// between the assignment and the check -- must still be recognized as genuine containment. This
// confirms the TRUE-dominance proof (real `.dominatedBy`/`.dominates` CfgNode queries) is not
// overly narrow/fragile: dominance is correctly transitive through the intervening statement
// (confirmed via a real probe, see docs section 9), unlike a hypothetical same-CFG-node-only check
// would have been.
const path = require('path');
const fs = require('fs');
Meteor.methods({
  dominatingWithIntervening(userPath) {
    const resolved = path.resolve('/safe/base', userPath);
    const unrelatedStatement = 1;
    if (resolved === '/safe/base' || resolved.startsWith('/safe/base' + path.sep)) {
      fs.readFile(resolved, () => {});
    }
  }
});
