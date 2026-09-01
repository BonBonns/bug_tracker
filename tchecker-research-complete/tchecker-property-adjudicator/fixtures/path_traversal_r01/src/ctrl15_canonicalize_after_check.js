// Control 15 (FIX02): a canonicalizing assignment to the SAME variable name that happens AFTER
// the boundary check must not retroactively "prove" that check ran on canonicalized data. Here
// `resolved` is checked while it is still the raw, uncanonicalized parameter; only AFTER the
// (already-passed) check does it get reassigned via path.resolve(). Before FIX02, the mere
// EXISTENCE of a canonicalizing assignment anywhere in the method was enough to credit the
// check, regardless of order -- a real unsoundness this fixture reproduces and closes.
const path = require('path');
const fs = require('fs');

Meteor.methods({
  canonicalizeAfterCheckBug(userPath) {
    let resolved = userPath;
    if (resolved.startsWith('/safe' + path.sep)) {
      fs.readFile(resolved, () => {});
    }
    resolved = path.resolve('/safe', userPath);
  }
});
