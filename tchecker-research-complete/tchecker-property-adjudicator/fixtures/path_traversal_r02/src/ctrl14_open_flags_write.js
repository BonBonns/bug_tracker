// Control 14 (FIX01): fs.open/openSync's own `flags` argument determines read vs. write intent.
// A write-mode flag ('w') must be tagged FS_WRITE, not the disclosed FS_READ default; an
// explicit read-mode flag ('r') and an unresolved (variable) flags argument must both stay
// FS_READ -- the fix only ever narrows the conservative default toward FS_WRITE when it can
// prove write intent from a literal, never widens it by guessing.
const fs = require('fs');
Meteor.methods({
  openWriteFlag(userPath) {
    fs.open(userPath, 'w', (err, fd) => {});
  },
  openReadFlagExplicit(userPath) {
    fs.openSync(userPath, 'r');
  },
  openUnresolvedFlag(userPath, flagsVar) {
    fs.open(userPath, flagsVar, (err, fd) => {});
  }
});
