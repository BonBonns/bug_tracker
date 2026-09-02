// Correction round 2, item 1: fs.open/openSync's flags argument resolving to the combined
// read+write literal 'r+' must produce the NEW FS_READ_WRITE sink family, not FS_READ (the old
// binary logic) and not FS_WRITE. This is a genuinely distinct 6th family, per direct instruction.
const fs = require('fs');
Meteor.methods({
  openReadWriteRPlus(userPath) {
    fs.open(userPath, 'r+', (err, fd) => {});
  }
});
