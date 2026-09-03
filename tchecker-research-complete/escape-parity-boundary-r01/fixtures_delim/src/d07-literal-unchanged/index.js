// D7: plain inline literals. The pre-existing behaviour must be untouched by
// delimiter resolution -- this stays a candidate for the same reason as before.
function splitQuoted(s) {
  const out = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"' && (i === 0 || s[i - 1] !== '\\')) {
      if (start < 0) start = i; else { out.push(s.slice(start + 1, i)); start = -1; }
    }
  }
  return out;
}
module.exports = { splitQuoted };
