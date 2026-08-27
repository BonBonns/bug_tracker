#!/usr/bin/env python3
"""Independently-verified ALLOCATOR CONTRACTS -- pure DATA, no analysis logic, same
posture as callee_contracts.py. Says, for a given allocator/deallocator function,
which argument(s) determine an allocation's size and in what shape (a single byte
count, vs. a count*width product, vs. a resize/free of an existing pointer) --
nothing else. A callee with no entry here is never examined by the capacity-tracking
module that consumes this table: unknown/custom allocators remain UNRESOLVED, not
guessed at, enforced structurally by the lookup returning nothing.

Every entry is verified against the real function signature (cited in a comment),
not inferred from usage at any one call site.
"""

ALLOCATOR_CONTRACTS = {
    # void *malloc(size_t size);  -- C standard library
    'malloc':  {'kind': 'simple', 'size_arg': 0, 'source': 'ISO C standard library'},
    # void *calloc(size_t nmemb, size_t size);  -- C standard library
    'calloc':  {'kind': 'product', 'count_arg': 0, 'width_arg': 1, 'source': 'ISO C standard library'},
    # void *realloc(void *ptr, size_t size);  -- C standard library
    'realloc': {'kind': 'realloc', 'ptr_arg': 0, 'size_arg': 1, 'source': 'ISO C standard library'},
    # extern void *PORT_Alloc(size_t len);  -- mozilla/nss lib/util/secport.h:86
    'PORT_Alloc': {'kind': 'simple', 'size_arg': 0, 'source': 'mozilla/nss lib/util/secport.h:86'},
    # extern void *PORT_ZAlloc(size_t len);  -- mozilla/nss lib/util/secport.h:88
    'PORT_ZAlloc': {'kind': 'simple', 'size_arg': 0, 'source': 'mozilla/nss lib/util/secport.h:88'},
    # extern void *PORT_Realloc(void *old, size_t len);  -- mozilla/nss lib/util/secport.h:87
    'PORT_Realloc': {'kind': 'realloc', 'ptr_arg': 0, 'size_arg': 1, 'source': 'mozilla/nss lib/util/secport.h:87'},
}

# extern void PORT_Free(void *ptr);  -- mozilla/nss lib/util/secport.h:92
FREE_FUNCS = {'free', 'PORT_Free'}
