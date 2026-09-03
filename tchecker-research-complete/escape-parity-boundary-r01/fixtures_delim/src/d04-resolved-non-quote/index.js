// D4: the variable resolves to a delimiter that is not a quote at all. This is
// field splitting, not quoted-string parsing, and must produce no quote site --
// resolving variables must not invent sites that were never there.
const FIELD = ',';
const ESCAPE = '\\';

function splitFields(s) {
  const out = [];
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === FIELD && (i === 0 || s[i - 1] !== ESCAPE)) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out;
}
module.exports = { splitFields };
