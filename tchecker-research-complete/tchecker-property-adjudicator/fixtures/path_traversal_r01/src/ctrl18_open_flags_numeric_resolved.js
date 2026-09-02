// Correction round 2, item 3: numeric/constants flags that structurally resolve. Real, confirmed
// CPG shape (see docs section 9): js2cpg's own type recovery does NOT fold `fs.constants.O_WRONLY`
// into a numeric literal -- it stays a real `<operator>.fieldAccess` Call whose own `.code` ends in
// the constant's name, recognized structurally by that name, never guessed. A bitwise-OR chain
// (`<operator>.or`, confirmed real operator name) resolves when EVERY operand is itself one of:
// an access-mode constant (O_RDONLY/O_WRONLY/O_RDWR), another recognized modifier constant
// (O_CREAT/O_TRUNC/O_APPEND/O_EXCL/O_SYNC), or a numeric literal -- base access mode taken from
// whichever access-mode constant (if any) is present: O_WRONLY present -> FS_WRITE.
const fs = require('fs');
Meteor.methods({
  openNumericConstantsWrite(userPath) {
    fs.open(userPath, fs.constants.O_WRONLY | fs.constants.O_CREAT, (err, fd) => {});
  },
  openNumericConstantsReadWrite(userPath) {
    fs.open(userPath, fs.constants.O_RDWR, (err, fd) => {});
  }
});
