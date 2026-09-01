// Real pinned-addon test for the leveldb-zlib NAPI-STATUS finding. Uses the REAL,
// pinned prebuilt native addon (build_test1/Release/node-leveldb.node) through the
// package's real public JS API. napi_create_buffer_copy is interposed (LD_PRELOAD) to
// force failure without writing its output, for the duration of this one bounded run.
// Exercises ONLY the iterator_next path, so the other real napi_create_buffer_copy call
// site (a different worker's HandleOKCallback) is never reached in this run.
"use strict";
const path = require("path");
const os = require("os");
const fs = require("fs");
const { LevelDB } = require(
  "/tmp/claude-0/-home-user-bug-tracker/63b70e5a-75d3-5da2-ae81-e00961287c6e/scratchpad/val10/@8crafter__leveldb-zlib/pkg/package/index.js");

async function main() {
  const dbPath = fs.mkdtempSync(path.join(os.tmpdir(), "napi-status-real-test-"));
  const db = new LevelDB(dbPath, {});
  await db.open();
  await db.put("k1", "v1");

  console.log("[test] db opened, one key put. Creating iterator (keyAsBuffer default true)...");
  const it = db.getIterator();    // default options: keyAsBuffer=true, valueAsBuffer=true
  console.log("[test] calling it.next() -> real iterator_next -> NextWorker -> "
             + "async_work -> HandleOKCallback -> napi_create_buffer_copy x2 (INTERPOSED)");
  const row = await it.next();    // this is the exact real chain under test
  console.log("[test] it.next() RETURNED (no crash, no thrown JS exception):", row);
  await db.close();
  console.log("[test] RESULT: REACHED_NAPI_SET_ELEMENT_WITHOUT_CRASH");
}

main().then(() => process.exit(0)).catch((e) => {
  console.log("[test] RESULT: JS_EXCEPTION_OR_REJECTION:", e && e.stack || e);
  process.exit(3);
});
