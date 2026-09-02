// D2: same resolvable delimiters, but the rule counts the whole escape run and
// tests its parity. Resolving a delimiter must not turn a correct parser into a
// candidate.
const QUOTE = '"';
const ESCAPE = '\\';

function splitQuoted(s) {
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === QUOTE) {
      let run = 0;
      let j = i - 1;
      while (j >= 0 && s[j] === ESCAPE) { run++; j--; }
      if (run % 2 === 0) {
        if (start < 0) start = i; else { out.push(s.slice(start + 1, i)); start = -1; }
      }
    }
  }
  return out;
}
module.exports = { splitQuoted };
