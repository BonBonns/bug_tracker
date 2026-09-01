'use strict';
// NODE-SNAP7 RUNTIME VALIDATION HARNESS (Track A). Loads the REAL, locally-built Release
// addon (build/Release/node_snap7.node, produced by a real `node-gyp rebuild` against this
// package's own real, pinned vendored deps/snap7 source and its real npm dependency on nan --
// never a synthetic stand-in). No network / PLC connection is used: ReadArea/Upload/FullUpload
// all perform their own allocation as the FIRST unconditional action, before any connection
// check, confirmed directly by reading src/node_snap7_client.cpp earlier in this review.
//
// Usage: node harness.js <method> <size>
//   method: ReadArea | Upload | FullUpload
//   size:   the JS-controlled length value passed as the real "oversized length" argument
const snap7 = require('./build/Release/node_snap7.node');

const method = process.argv[2];
const size = parseInt(process.argv[3], 10);

const client = new snap7.S7Client();

console.log(`[harness] method=${method} size=${size} pid=${process.pid}`);
console.log(`[harness] resident memory before call: ${process.memoryUsage().rss} bytes`);

let result;
try {
  if (method === 'ReadArea') {
    // DBRead(dbNumber, start, size, cb) -> ReadArea(S7AreaDB, dbNumber, start, size, S7WLByte, cb)
    // amount=size, byteCount=1 (S7WLByte) -> allocation size == size (no multiplication overflow
    // needed to reach this size directly).
    result = client.ReadArea(client.S7AreaDB, 0, 0, size, client.S7WLByte, undefined);
  } else if (method === 'Upload') {
    result = client.Upload(0, 0, size, undefined);
  } else if (method === 'FullUpload') {
    result = client.FullUpload(0, 0, size, undefined);
  } else {
    console.error('unknown method', method);
    process.exit(2);
  }
  console.log(`[harness] call RETURNED (no crash): result=`, result);
  console.log(`[harness] resident memory after call: ${process.memoryUsage().rss} bytes`);
  process.exit(0);
} catch (e) {
  console.log(`[harness] call THREW a catchable JS exception (not a fatal crash): ${e && e.message}`);
  process.exit(3);
}
