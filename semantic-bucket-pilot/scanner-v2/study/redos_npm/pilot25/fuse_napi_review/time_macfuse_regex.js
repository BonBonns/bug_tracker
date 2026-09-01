'use strict';
const regex = /(?:macfuse|libfuse3(?:\.\d+)*\.dylib)/i;
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

// Adversarial: many ".DIGITS" segments, never terminated by ".dylib" -- targets the nested
// quantifier (?:\.\d+)* backtracking against a failing match.
bench('libfuse3 prefix + many .digit segments, no .dylib terminator',
  n => 'libfuse3' + '.1'.repeat(n),
  [1000, 5000, 10000, 20000, 40000, 80000]);

bench('libfuse3 prefix + many .digit segments + X (not .dylib)',
  n => 'libfuse3' + '.1'.repeat(n) + 'X',
  [1000, 5000, 10000, 20000, 40000, 80000]);
