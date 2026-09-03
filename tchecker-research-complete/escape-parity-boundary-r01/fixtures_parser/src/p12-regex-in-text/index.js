// CONTROL 12: regex-LOOKING text that is not a regex. None of these may be discovered
// as a boundary-rule site.
//
//   a comment containing /'(.*?)(?<!\\)'/g  -- must be ignored
//
const DOC   = "use /'(.*?)(?<!\\\\)'/g to split values";   // a string, not a regex
const NOTE  = 'pattern: /"(.*?)(?<!\\\\)"/g';               // another string
const PATH  = "/usr/local/share";                           // slash-delimited, not a regex
const REAL  = /'((?:[^'\\]|\\.)*)'/g;                       // the only real regex here
function run(t) { return t.replace(REAL, (w, i) => i); }
module.exports = { run, DOC, NOTE, PATH };
