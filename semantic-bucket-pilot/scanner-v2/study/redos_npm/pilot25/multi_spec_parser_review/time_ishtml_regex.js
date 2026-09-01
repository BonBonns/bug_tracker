'use strict';
const regex = /<!doctype\s+html|<html[\s>]/i;
console.log(`node=${process.version} v8=${process.versions.v8}`);
console.log(`regex=${regex.source} flags=${regex.flags}`);

function timeOnce(input) {
  const t0 = process.hrtime.bigint();
  const m = regex.test(input);
  const t1 = process.hrtime.bigint();
  return { ms: Number(t1 - t0) / 1e6, matched: m };
}

function bench(label, buildInput, sizes) {
  console.log(`--- ${label} ---`);
  for (const n of sizes) {
    const input = buildInput(n);
    const trials = [];
    for (let r = 0; r < 5; r++) trials.push(timeOnce(input));
    const times = trials.map(t => t.ms).sort((a,b) => a-b);
    console.log(`n=${n} len=${input.length} min=${times[0].toFixed(3)}ms median=${times[2].toFixed(3)}ms max=${times[4].toFixed(3)}ms matched=${trials[0].matched}`);
  }
}

// Adversarial: "<!doctype" + long whitespace run, never followed by "html" -- targets \s+
// backtracking against a failing match, at every starting position across a long string.
bench('many "<!doctype" + long whitespace run (no html terminator), single occurrence',
  n => '<!doctype' + ' '.repeat(n),
  [1000, 5000, 10000, 20000, 40000, 80000]);

// Worst case for the "every starting position" concern: REPEAT the "<!doctype"+spaces prefix
// many times across a long string, so the O(whitespace-run-length) backtrack cost is paid at
// MANY starting positions, not just one -- this is the shape that would show real O(n^2) if the
// per-position backtrack cost genuinely scales with a shared long run.
bench('repeated "<!doctype"+50-space blocks (no html terminator), many occurrences',
  n => ('<!doctype' + ' '.repeat(50)).repeat(n),
  [200, 1000, 2000, 4000, 8000, 16000]);

console.log();
console.log('--- REAL bounded size (isHtml only ever sees text.slice(0, 4096)) ---');
bench('capped-at-4096 worst case: "<!doctype" + spaces filling the real 4096-char cap',
  () => '<!doctype' + ' '.repeat(4096 - '<!doctype'.length),
  [4096]);
