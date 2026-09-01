# Real pinned-addon test — @8crafter/leveldb-zlib@1.6.0 (attempted and completed)

Per review correction: the earlier hand-written stub harness proved only
`MODEL_FAILURE_PATH_CONFIRMED` (see `FAILURE_INJECTION_RESULT.md`). This section is the
separate, harder proof: the REAL pinned addon, test-only N-API interposition, invoked
from real JavaScript through the real exported `iterator_next` path.

## Setup

- **Real pinned addon:** `prebuilds/linux-6-x64/node-leveldb.node` from the verified
  `@8crafter/leveldb-zlib@1.6.0` tarball — the actual binary this package ships to
  `linux-x64` users (not rebuilt from source). Loads under Node v22.22.2 (`node22`) and
  exports exactly `iterator_next` plus the other 20 real exports
  `napi_export_root.py` established.
- **Real JS driver** (`real_addon_test.js`): uses the package's own public API
  (`index.js` → `LevelDB`/`Iterator`) — `db.open()`, `db.put("k1","v1")`,
  `db.getIterator()` (default `keyAsBuffer: true`), `it.next()` — the exact real call
  that reaches `NAPI_METHOD(iterator_next)` → `NextWorker` → `napi_queue_async_work` →
  `HandleOKCallback` → the two flagged `napi_create_buffer_copy` sites.
- **Test-only interposition:** `LD_PRELOAD` was tried first and found NOT to take
  priority for `napi_create_buffer_copy` against this specific `node` binary (verified
  with `LD_DEBUG=bindings`: the symbol bound to `node`, not the preloaded library, even
  though a plain LD_PRELOAD constructor sanity check worked). Fell back to the `LD_AUDIT`
  mechanism (`audit_buffer_copy.c`, `la_symbind64`), which is designed for exactly this
  kind of unconditional symbol-bind interposition and DOES take effect. It forces
  **only** `napi_create_buffer_copy` to return `napi_generic_failure` and leaves its
  output untouched (the real N-API failure contract), applying to every call to that
  symbol process-wide; the driver invokes only the `iterator_next` path, so the third
  real `napi_create_buffer_copy` call site (a different worker) is never reached in
  these runs — in effect, only the two relevant sites fire.
- **Isolation control** (`audit_passthrough.c`): identical `LD_AUDIT` machinery, but
  every symbol resolution passes through unchanged — isolates whether a crash is caused
  by the forced failure itself, or by running under audit at all.

## Runs (all bounded: `timeout 20`, single process, no loop)

| run | condition | exit status |
|---|---|---|
| baseline | no interposition | **0** — `it.next()` returns real buffer values |
| pass-through control | `LD_AUDIT`, no symbol redirected | **0** — identical to baseline |
| forced-failure, run A | `LD_AUDIT`, `napi_create_buffer_copy` forced to fail | **139 (SIGSEGV)** |
| forced-failure, run B | same, repeated | **139 (SIGSEGV)** — reproducible |

`interposed_stderr.log` (run A) shows both real call sites hit the interposer before the
crash:
```
[audit-interpose] napi_create_buffer_copy(length=2) FORCED FAILURE (output left untouched)
[audit-interpose] napi_create_buffer_copy(length=2) FORCED FAILURE (output left untouched)
```
(two calls, matching `key.size()`/`value.size()` for `"k1"`/`"v1"` — the two real sites
at `bindings.cpp:1440` and `:1447`).

## Observation: does the real code proceed to `napi_set_element`? (`gdb_backtrace.log`)

Yes — and it crashes there. A bounded, non-interactive `gdb -batch` session
(`run` + `bt full`, single crash, no further interaction) recorded:

```
Thread 1 "node" received signal SIGSEGV, Segmentation fault.
#0  v8::internal::JSObject::AddDataElement(...)
#1  v8::internal::Object::AddDataProperty(...)
#2  v8::Object::Set(v8::Local<v8::Context>, unsigned int, v8::Local<v8::Value>)
#3  napi_set_element ()
#4  NextWorker::HandleOKCallback ()   <-- from node-leveldb.node
#5  BaseWorker::Complete(napi_env__*, napi_status, void*) ()   <-- from node-leveldb.node
#6  node::ThreadPoolWork::ScheduleWork()::{lambda}::_FUN(uv_work_s*, int) ()
#7  uv__work_done (...)
    ... (libuv event loop) ...
```

This is exactly the chain proved structurally: the real code reaches
`napi_set_element` with the unavailable output, and there hits a real crash inside V8's
own object model — the process receives SIGSEGV rather than surfacing an N-API error or
throwing a catchable JS exception.

## What was recorded (per the review's checklist)

- **Exit status:** 139 (SIGSEGV), reproducible across 2 runs; 0 for both controls.
- **Emitted N-API error:** none — no `napi_throw_error`/rejected promise was observed;
  the crash occurs before any JS-visible error path.
- **Assertion:** none observed (this is a release Node build; no `CHECK`/`assert`
  fired — the crash is a raw SIGSEGV).
- **Backtrace:** captured via `gdb -batch` (above; full log in `gdb_backtrace.log`).
- **Sanitizer/Valgrind:** not run (this Node build is not sanitizer-instrumented; not
  attempted, so no claim is made either way about what a sanitizer would additionally
  report).

## Claims boundary (load-bearing, per direct instruction)

**No security impact, severity, or exploitability is inferred from this outcome.** This
is a bounded reliability/crash observation: forcing the documented N-API failure
behavior at the two flagged call sites reproducibly crashes the real pinned addon when
its real JS-facing path is exercised. Whether this observation has any security
implication, whether it is triggerable by an untrusted caller in any real deployment, and
what its severity would be are separate, unestablished questions this reliability
analysis does not answer and does not attempt to answer. The finding remains a
**confirmed API return-code handling discrepancy with a confirmed, reproducible runtime
crash consequence in the real pinned addon** — not a confirmed vulnerability.
