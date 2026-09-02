// Control 7: read/write/delete family separation on attacker-influenced paths -- confirms each
// operation kind is tagged with its own distinct sink family in the raw output.
const fs = require('fs');
Meteor.methods({
  familyRead(userPath) {
    fs.readFile(userPath, () => {});
  },
  familyWrite(userPath) {
    fs.writeFile(userPath, 'data', () => {});
  },
  familyDelete(userPath) {
    fs.unlink(userPath, () => {});
  }
});
