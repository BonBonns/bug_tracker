// CONTROL 14: the same boundary rule under different flag sets. Flags are evidence;
// they must not move the parity conclusion.
const NO_FLAGS = /'(.*?)(?<!\\)'/;
const G        = /'(.*?)(?<!\\)'/g;
const GS       = /'(.*?)(?<!\\)'/gs;
const GIMSU    = /'(.*?)(?<!\\)'/gimsu;
const PARITY_I = /'((?:[^'\\]|\\.)*)'/i;
module.exports = { NO_FLAGS, G, GS, GIMSU, PARITY_I };
