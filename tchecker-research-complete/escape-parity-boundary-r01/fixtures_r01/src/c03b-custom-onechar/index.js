// CONTROL 3b (supporting positive for the custom-parser path): a hand-written parser
// whose boundary rule inspects exactly one preceding position. Contrasted against
// c03 (explicit counting) and c04 (parity state machine), which are the negatives.
const fs = require('fs');
function splitQuoted(s) {
  const out = [];
  let start = -1;
  for (let i = 1; i < s.length; i++) {
    if (s[i] === "'" && s[i - 1] !== '\\') {
      if (start < 0) { start = i; } else { out.push(s.slice(start + 1, i)); start = -1; }
    }
  }
  return out;
}
function restore(p) { return splitQuoted(fs.readFileSync(p, 'utf8')); }
module.exports = { splitQuoted, restore };
