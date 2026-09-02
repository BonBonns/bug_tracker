// Companion to control 1: the boundary-AWARE form of the same base check (canonicalized value,
// checked with a proven separator boundary) -- must be recognized as genuinely contained (BROKEN).
const path = require('path');
const fs = require('fs');
Meteor.methods({
  boundaryAware(userPath) {
    const resolved = path.resolve('/safe/base', userPath);
    if (resolved === '/safe/base' || resolved.startsWith('/safe/base' + path.sep)) {
      fs.readFile(resolved, () => {});
    }
  }
});
