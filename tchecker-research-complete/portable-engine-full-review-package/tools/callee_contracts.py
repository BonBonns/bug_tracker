#!/usr/bin/env python3
"""Independently-verified CALLEE CONTRACTS for buffer-write sinks -- pure DATA, no
verdict logic. This is the thing oob_call_sink_verdict.py's generic BufferOperationFact
extraction consumes; it is NOT itself allowed to know about any CVE or contain any
per-bug special case. Each entry says, for a given callee, which positional ARGUMENT
INDEX is the destination pointer and which is the write-width expression (in bytes,
unless noted) -- nothing else. A callee with no entry here is simply never examined:
"unknown contracts remain unresolved" is enforced structurally, by the lookup itself
returning nothing to match against, not by a runtime check anyone could get wrong.

Every entry below is verified against the REAL function signature (cited in a comment,
checked against either the actual mozilla/nss header or the C standard), not inferred
from a single call site's usage or a CVE writeup. A contract describes the CALLEE's
general behavior -- true at every call site to that function, in any codebase -- not
a fact about any specific caller. If a contract turns out to be wrong for some
non-standard build of a function (e.g. a custom memcpy-alike with a different argument
order), that is a data error to fix in THIS file, never a reason to add a special case
to the verdict logic that consumes it.

Fields per entry:
  dest_arg  -- 0-based index of the destination-pointer argument.
  width_arg -- 0-based index of the argument giving the write width IN BYTES. Not
               always the literal number of bytes actually written (see HMAC_Finish
               below) -- it is the CALLER'S OWN DECLARATION of how much space is
               available/being used, which is exactly the quantity a capacity check
               needs to compare against remaining destination capacity, regardless of
               what the callee does internally with it.
"""

CALLEE_CONTRACTS = {
    # void *memcpy(void *dest, const void *src, size_t n);       -- C standard library
    'memcpy':  {'dest_arg': 0, 'width_arg': 2, 'source': 'ISO C standard library'},
    # void *memmove(void *dest, const void *src, size_t n);      -- C standard library
    'memmove': {'dest_arg': 0, 'width_arg': 2, 'source': 'ISO C standard library'},
    # wchar_t *wmemcpy(wchar_t *dest, const wchar_t *src, size_t n); -- C standard library
    # NOTE: width is in wchar_t ELEMENTS, not bytes -- same unit caveat the byte-array
    # capacity resolvers already apply (only byte-sized element types are comparable).
    'wmemcpy': {'dest_arg': 0, 'width_arg': 2, 'source': 'ISO C standard library'},
    # #define PORT_Memcpy memcpy   -- mozilla/nss lib/util/secport.h line 180
    'PORT_Memcpy': {'dest_arg': 0, 'width_arg': 2, 'source': 'mozilla/nss lib/util/secport.h:180 (#define PORT_Memcpy memcpy)'},
    # #define PORT_Memmove memmove -- mozilla/nss lib/util/secport.h line 181
    'PORT_Memmove': {'dest_arg': 0, 'width_arg': 2, 'source': 'mozilla/nss lib/util/secport.h:181 (#define PORT_Memmove memmove)'},
    # #define PORT_Memset memset   -- mozilla/nss lib/util/secport.h line 182
    # void *memset(void *s, int c, size_t n);  -- dest=0, no src (the middle arg is a
    # fill BYTE VALUE, not a source pointer), width=2.
    'PORT_Memset': {'dest_arg': 0, 'width_arg': 2, 'source': 'mozilla/nss lib/util/secport.h:182 (#define PORT_Memset memset)'},
    # extern SECStatus HMAC_Finish(HMACContext *cx, unsigned char *result,
    #     unsigned int *result_len, unsigned int max_result_len);
    #   -- mozilla/nss lib/freebl/alghmac.h:57-59. `result` is the destination
    # (arg 1); `max_result_len` (arg 3) is the CALLER'S declared available space --
    # exactly the "claimed write width" quantity this contract format needs, even
    # though the function may write fewer bytes than that in practice (it's the
    # bound the caller is asserting is safe, which is what a capacity check verifies).
    'HMAC_Finish': {'dest_arg': 1, 'width_arg': 3, 'source': 'mozilla/nss lib/freebl/alghmac.h:57-59'},
}
