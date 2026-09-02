// Control 12: an unknown/unresolvable wrapper -- a call to a function whose body can't be
// resolved (never defined anywhere in this file/corpus) -- must abstain, never assume it's safe.
const fs = require('fs');
Meteor.methods({
  wrapperUnresolved(userPath) {
    if (isSafeSomehow(userPath)) {
      fs.readFile(userPath, () => {});
    }
  }
});
