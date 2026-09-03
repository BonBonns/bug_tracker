// D1: delimiters held in variables that resolve to a single literal each.
// The boundary rule inspects one preceding position, so it cannot establish
// escape-run parity -- a candidate, exactly as if the literals were inline.
const QUOTE = '"';
const ESCAPE = '\\';

function splitQuoted(s) {
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === QUOTE && (i === 0 || s[i - 1] !== ESCAPE)) {
      if (start < 0) start = i; else { out.push(s.slice(start + 1, i)); start = -1; }
    }
  }
  return out;
}
module.exports = { splitQuoted };
