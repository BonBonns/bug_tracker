// Complete, repeatable benchmark for the phplike@2.5.12 sprintf() regex adjudication record.
// Regex is the exact literal at src/js/string.js:86 (canonical path within the tarball), copied
// verbatim -- never retyped from a description.
'use strict';
const regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g;

const REPETITIONS = 5; // per input size, per test family
const SIZES = [1000, 5000, 10000, 20000, 40000, 80000];

function timeOnce(input) {
  const t0 = process.hrtime.bigint();
  const matches = input.match(regex);
  const t1 = process.hrtime.bigint();
  return { ms: Number(t1 - t0) / 1e6, matchCount: matches ? matches.length : 0 };
}

function bench(label, buildInput) {
  console.log(`--- ${label} ---`);
  for (const n of SIZES) {
    const input = buildInput(n);
    const trials = [];
    for (let r = 0; r < REPETITIONS; r++) trials.push(timeOnce(input));
    const times = trials.map(t => t.ms).sort((a, b) => a - b);
    const min = times[0], max = times[times.length - 1];
    const median = times[Math.floor(times.length / 2)];
    console.log(`n=${n} len=${input.length} reps=${REPETITIONS} ` +
      `min=${min.toFixed(3)}ms median=${median.toFixed(3)}ms max=${max.toFixed(3)}ms ` +
      `matches=${trials[0].matchCount}`);
  }
}

console.log(`node=${process.version} v8=${process.versions.v8}`);
console.log(`regex=${regex.source} flags=${regex.flags}`);
console.log();

bench('Test 1: single "%" + N digits, no terminator (targets \\d+\\$ backtrack)',
  n => '%' + '1'.repeat(n));

console.log();
bench('Test 2: many "%"+digit-run pairs spread across string (cumulative-backtrack worst case)',
  n => {
    const segLen = 20;
    const nSegs = Math.floor(n / (segLen + 1));
    return ('%' + '1'.repeat(segLen)).repeat(nSegs);
  });

console.log();
bench('Test 3: digits, dot, more digits (targets the second optional (\\.(\\*\\d+\\$|\\*|\\d+))? group)',
  n => '%' + '1'.repeat(n) + '.' + '1'.repeat(n));
