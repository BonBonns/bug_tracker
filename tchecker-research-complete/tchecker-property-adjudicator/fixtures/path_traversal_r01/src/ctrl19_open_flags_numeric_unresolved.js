// Correction round 2, item 4 (broader than ctrl14's own bare-variable case): an OR-chain flags
// expression where ONE operand structurally resolves (fs.constants.O_WRONLY) but ANOTHER does not
// (a bare variable `extraFlags`) must abstain on the WHOLE expression -- never guess a base access
// mode from the one operand that happens to resolve. Zero sink target emitted; an explicit
// abstention logged via the same sinkAbstentions mechanism the RootUnresolvedOptions case already
// uses. This is a real, direct regression fix on top of ctrl14's own openUnresolvedFlag case
// (a bare variable with no OR at all), which this correction round also re-verifies now abstains
// instead of wrongly defaulting to FS_READ under the old logic.
const fs = require('fs');
Meteor.methods({
  openNumericOrUnresolvedFlag(userPath, extraFlags) {
    fs.open(userPath, fs.constants.O_WRONLY | extraFlags, (err, fd) => {});
  }
});
