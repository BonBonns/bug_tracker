// Control 9: repeated traversal components ('....//' style) defeating a single non-global
// .replace(/\.\./, '') strip. Under the corrected design, NO literal '..' strip (global or
// non-global) is ever treated as containment proof (item 4's exhaustive list of proven idioms
// does not include any regex-strip shape), so this must fall through to ESTABLISHED either way.
const fs = require('fs');
Meteor.methods({
  nonGlobalStrip(userPath) {
    const cleaned = userPath.replace(/\.\./, '');
    fs.readFile(cleaned, () => {});
  }
});
