// D9: the same search-established position, but the rule looks FORWARD for a
// doubled delimiter. That consumes the pair and is parity-correct, so it must
// never reach the candidate path -- only a backward one-position look can.
const QUOTE = '"';

function splitQuoted(s) {
  const out = [];
  let cursor = 0;
  let p = s.indexOf(QUOTE, cursor);
  while (p !== -1) {
    if (s[p + 1] === QUOTE) {
      p = s.indexOf(QUOTE, p + 2);
      continue;
    }
    out.push(s.slice(cursor, p));
    cursor = p + 1;
    p = s.indexOf(QUOTE, cursor);
  }
  return out;
}
module.exports = { splitQuoted };
