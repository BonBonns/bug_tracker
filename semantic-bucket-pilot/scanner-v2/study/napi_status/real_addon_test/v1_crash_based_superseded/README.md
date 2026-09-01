# v1 (superseded) -- crash-based observation

These files are from the FIRST real-addon test attempt, which used `LD_AUDIT` to force
`napi_create_buffer_copy` to fail and let the real code run to completion -- the real
addon then crashed (SIGSEGV, exit 139) when it dereferenced the unwritten output inside
`napi_set_element`/V8's object model (see `gdb_backtrace.log`).

**Superseded by v2** (`../REAL_ADDON_TEST_RESULT.md`), per review correction: relying on
observing a crash from an unspecified garbage pointer value is unreliable and
unnecessary. v2 uses a SAFE interceptor for `napi_set_element` (records reach, never
dereferences its value, returns cleanly) so the same question -- does the real code
proceed to `napi_set_element` after the injected failure? -- is answered directly and
without needing a crash. v2 also correctly tests the SHIPPED PREBUILT first (this v1 run
used `LD_AUDIT`, which does work against the prebuilt, but the review's protocol calls
for `LD_PRELOAD` first, honestly recording `PREBUILT_INTERPOSITION_UNAVAILABLE` when it
fails, before falling back to a source build).

This directory is kept as real, valid supporting evidence (the crash it captured is
consistent with v2's cleaner result), not deleted -- but v2 is the authoritative record.
