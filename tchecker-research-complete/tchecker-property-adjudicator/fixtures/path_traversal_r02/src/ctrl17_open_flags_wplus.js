// Correction round 2, item 2: 'w+' (create/truncate for read+write) must also resolve to
// FS_READ_WRITE, confirming the literal-flags resolver recognizes every combined-mode literal in
// Node's own documented set ('r+'/'rs+'/'w+'/'wx+'/'a+'/'ax+'/'as+'), not just 'r+'.
const fs = require('fs');
Meteor.methods({
  openReadWriteWPlus(userPath) {
    fs.openSync(userPath, 'w+');
  }
});
