# Superseded by source_build_wrap_v3/

This v2 `--wrap` interposer (`wrap_interpose.cpp`) armed *unconditionally*:
every call to `napi_create_buffer_copy` and `napi_set_element` reaching the
wrapper was treated as one of the two targeted call sites, with no check
that it actually was. That happened to be correct for this specific test
(the worker under study has exactly two calls to each function, and no
other reachable code path calls either symbol during this run) -- but it
was correct by construction of the test, not verified by the interposer
itself. Per review, "don't select them merely as 'the first two calls'."

`source_build_wrap_v3/` fixes this: it runs a "map" mode pass first that
delegates every call to the real implementation unmodified while logging
each call site's identity (return address, `dladdr`-resolved
addon-relative offset, thread id, sequence number, whether an output
pointer was supplied); the two creation-site offsets and their two
corresponding `napi_set_element` offsets are then frozen from that log,
and only calls at those exact offsets are armed in the subsequent "arm"
mode runs. A call at any other offset -- none exist for this worker, but
the logic does not assume that -- delegates normally in both modes.

The v2 result itself is not contradicted: v3 confirms the identical
outcome (both injected failures followed by a real, reached
`napi_set_element` call, exit 0, reproduced across 2 armed runs) under
the stricter, offset-verified precondition. Kept here as consistent prior
evidence, not deleted.
