// Critical edge case: does "gated by a leading literal" stay SAFE when the gating literal
// OVERLAPS the quantified character class (e.g. gating char is itself part of what \d+ or \s+
// would match)? If this is ALSO fast, gating is a safe general signal. If this is slow, the
// "leading literal" rule alone is UNSAFE to generalize -- it needs an additional "gating literal
// is disjoint from the quantified class" condition.

function time(label, regex, input) {
  const t0 = process.hrtime.bigint();
  input.search(regex);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`${label}: len=${input.length} time=${ms.toFixed(3)}ms`);
}

console.log('=== Overlap case: gating literal "a" is a MEMBER of the quantified class [a-z] ===');
console.log('    pattern: a([a-z]+X)   (X = literal not in input, forces backtrack to exhaustion)');
const re1 = /a([a-z]+Q)/;
for (const n of [1000, 5000, 10000, 20000, 40000]) {
  time(`n=${n}`, re1, 'a'.repeat(n));
}

console.log();
console.log('=== Disjoint case (control): gating literal "%" is NOT a member of [0-9] ===');
const re2 = /%(\d+Q)/;
for (const n of [1000, 5000, 10000, 20000, 40000]) {
  time(`n=${n}`, re2, '%' + '1'.repeat(n));
}

console.log();
console.log('=== Overlap, unanchored, MANY starting positions (worst case) ===');
console.log('    pattern: a([a-z]+X), input = all "a" repeated (every position is a valid gate AND fill)');
for (const n of [1000, 2000, 4000, 8000, 16000]) {
  time(`n=${n}`, re1, 'a'.repeat(n));
}
