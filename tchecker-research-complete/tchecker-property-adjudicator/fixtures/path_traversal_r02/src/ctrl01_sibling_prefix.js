// Control 1: sibling-prefix bypass. '/safe-backup/secret' textually starts with '/safe' even
// though it lives in a completely unrelated sibling directory. A bare `.startsWith(base)` (no
// separator boundary) must NOT produce a contained/safe classification, even on a resolved value.
const path = require('path');
const fs = require('fs');

Meteor.methods({
  siblingPrefixBug(userPath) {
    const resolved = path.resolve('/safe', userPath);
    if (resolved.startsWith('/safe')) {
      fs.readFile(resolved, () => {});
    }
  }
});
