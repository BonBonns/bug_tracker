// CONTROL 3: a parser that explicitly counts the consecutive escape characters and
// tests the count's parity. Expect: negative.
function splitQuoted(s) {
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "'") continue;
    let run = 0;
    let j = i - 1;
    while (j >= 0 && s[j] === '\\') { run++; j--; }
    if (run % 2 === 1) continue;      // odd run -> the quote is escaped
    if (start < 0) { start = i; } else { out.push(s.slice(start + 1, i)); start = -1; }
  }
  return out;
}
module.exports = { splitQuoted };
