// D8: the quote position comes from a SEARCH rather than a comparison, with
// delimiters that resolve. The boundary rule still inspects a single preceding
// position, so it cannot establish escape-run parity -- a candidate. Before R06
// the quote half of this rule was never found and the site went unclassified.
const QUOTE = '"';
const ESCAPE = '\\';

function splitQuoted(s) {
  const out = [];
  let cursor = 0;
  let p = s.indexOf(QUOTE, cursor);
  while (p !== -1) {
    if (p !== 0 && s[p - 1] === ESCAPE) {
      p = s.indexOf(QUOTE, p + 1);
      continue;
    }
    out.push(s.slice(cursor, p));
    cursor = p + 1;
    p = s.indexOf(QUOTE, cursor);
  }
  return out;
}
module.exports = { splitQuoted };
