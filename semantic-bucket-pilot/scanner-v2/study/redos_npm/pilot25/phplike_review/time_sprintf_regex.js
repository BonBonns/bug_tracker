const regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g;

function time(label, input) {
  const t0 = process.hrtime.bigint();
  const matches = input.match(regex);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`${label}: len=${input.length} time=${ms.toFixed(3)}ms matches=${matches ? matches.length : 0}`);
  return ms;
}

console.log('=== Test 1: single "%" + many digits, no terminator (targets \\d+\\$ backtrack) ===');
for (const n of [1000, 5000, 10000, 20000, 40000]) {
  time(`n=${n}`, '%' + '1'.repeat(n));
}

console.log();
console.log('=== Test 2: many "%" + digit-run pairs spread across string (worst case for cumulative backtrack) ===');
for (const n of [1000, 5000, 10000, 20000, 40000]) {
  // n total chars: alternating %1111...1 segments of length ~20 digits each
  const segLen = 20;
  const nSegs = Math.floor(n / (segLen + 1));
  const input = ('%' + '1'.repeat(segLen)).repeat(nSegs);
  time(`n=${input.length} (${nSegs} segments)`, input);
}

console.log();
console.log('=== Test 3: adversarial nested-ish - digits then dot then more digits (targets the (\\.(\\*\\d+\\$|\\*|\\d+))? group too) ===');
for (const n of [1000, 5000, 10000, 20000, 40000]) {
  time(`n=${n}`, '%' + '1'.repeat(n) + '.' + '1'.repeat(n));
}
