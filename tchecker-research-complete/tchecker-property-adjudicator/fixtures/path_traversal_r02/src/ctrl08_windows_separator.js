// Control 8: Windows/POSIX separator handling -- a bare `.includes('../')` check (raw, no
// canonicalization+boundary proof) is a WEAK diagnostic-only guard under the corrected design; it
// must never mark the sink safe regardless of separator style, so this fixture alone already
// demonstrates the fix (a backslash '..\\' traversal attempt was never going to be caught by this
// forward-slash-specific check, and the corrected design never trusts it either way).
const fs = require('fs');
Meteor.methods({
  weakSeparatorCheck(userPath) {
    if (!userPath.includes('../')) {
      fs.readFile(userPath, () => {});
    }
  }
});
