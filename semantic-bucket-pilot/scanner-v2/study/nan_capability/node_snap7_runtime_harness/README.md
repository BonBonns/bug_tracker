# node-snap7 runtime validation harness

Real, minimal scripts used for Track A's runtime reproduction of the 3 node-snap7 candidates.
See `../NODE_SNAP7_RUNTIME_VALIDATION.md` for the full account -- this directory preserves the
exact scripts and a real transcript, not just a written summary.

- `harness.js` -- loads the real, locally-built `build/Release/node_snap7.node` (built via
  `npm install` then `npx node-gyp rebuild` inside a fresh `node-snap7@1.0.9` checkout,
  sha1 `9402be15ca318c0bba3267494c3ab8892163fd5b`) and calls `ReadArea`/`Upload`/`FullUpload`
  directly with an oversized length. Usage: `node harness.js <ReadArea|Upload|FullUpload> <size>`.
- `stress.js` -- 20 concurrent oversized `ReadArea` calls, to check for allocation pile-up under
  load. Usage: `node stress.js <N> <size_bytes>`.
- `release_flags.txt` -- the real `DEFS_Release`/`CFLAGS_Release`/`CFLAGS_CC_Release` node-gyp
  emitted for this exact build (`build/node_snap7.target.mk`), confirming `-fno-exceptions` and
  the absence of `-DNDEBUG`.
- `crash_transcripts.log` -- real stdout/stderr + exit code from all three sites, each run under
  `( ulimit -v 1228800; node harness.js <method> 629145600 )`.

Not committed here (regenerate locally if needed, per the commands above): the built
`build/Release/node_snap7.node` binary itself, and `node_modules/` -- both are real build
artifacts, not source, and are cheaply reproducible from the pinned tarball.
