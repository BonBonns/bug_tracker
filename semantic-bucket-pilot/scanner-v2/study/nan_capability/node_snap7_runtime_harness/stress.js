'use strict';
// Concurrent-allocation stress test: fires N async ReadArea calls (each with a real
// callback, taking the AsyncQueueWorker path) without waiting between them, to see whether
// allocations pile up simultaneously before any connection-failure frees them.
const snap7 = require('./build/Release/node_snap7.node');
const N = parseInt(process.argv[2] || '20', 10);
const SIZE = parseInt(process.argv[3] || '50000000', 10); // 50MB each by default

console.log(`[stress] N=${N} size=${SIZE} total_if_simultaneous=${(N*SIZE/1e6).toFixed(1)}MB pid=${process.pid}`);
console.log(`[stress] rss before: ${(process.memoryUsage().rss/1e6).toFixed(1)}MB`);

let done = 0;
const client = new snap7.S7Client();
for (let i = 0; i < N; i++) {
  client.ReadArea(client.S7AreaDB, 0, 0, SIZE, client.S7WLByte, (err, data) => {
    done++;
    if (done === N) {
      console.log(`[stress] all ${N} callbacks fired`);
      console.log(`[stress] rss after all complete: ${(process.memoryUsage().rss/1e6).toFixed(1)}MB`);
    }
  });
}
console.log(`[stress] rss right after firing all ${N} calls (before any callback): ${(process.memoryUsage().rss/1e6).toFixed(1)}MB`);
setTimeout(() => {
  console.log(`[stress] rss at +2s: ${(process.memoryUsage().rss/1e6).toFixed(1)}MB, callbacks fired: ${done}/${N}`);
  process.exit(0);
}, 2000);
