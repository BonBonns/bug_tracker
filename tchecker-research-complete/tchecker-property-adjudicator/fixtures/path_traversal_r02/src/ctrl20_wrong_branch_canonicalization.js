// Correction round 2, item 5: a canonicalizing assignment on ONE if/else branch must NOT be
// credited toward a boundary check that runs regardless of which branch executed -- the OLD
// line-number-order approximation (round 1's FIX02) would have WRONGLY accepted this (the
// assignment's own line precedes the check's own line in straight top-to-bottom reading), because
// it never verified real CFG dominance. The corrected TRUE-dominance check must reject it: neither
// branch's own `resolved = ...` assignment CFG-dominates the check (confirmed via a real
// `.dominatedBy` probe, see docs section 9) -- the check can run against the un-canonicalized
// `else`-branch value, so containment is never proven.
const path = require('path');
const fs = require('fs');
Meteor.methods({
  wrongBranchCanonicalization(userPath) {
    let resolved;
    if (someUnrelatedCondition) {
      resolved = path.resolve('/safe', userPath);
    } else {
      resolved = userPath;
    }
    if (resolved.startsWith('/safe' + path.sep)) {
      fs.readFile(resolved, () => {});
    }
  }
});
