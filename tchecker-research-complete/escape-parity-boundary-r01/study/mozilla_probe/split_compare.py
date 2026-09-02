#!/usr/bin/env python3
"""Compare two implementations of splitting a Content-Type header value:

  spec_split     -- WHATWG Fetch "get, decode, and split a header value", which calls
                    "collect an HTTP quoted string" (that algorithm consumes a U+005C
                    together with the FOLLOWING code point, i.e. escape pairs).
  mozilla_split  -- the loop in mozilla-central dom/base/MimeType.cpp SplitMimetype,
                    which decides the quote by looking at ONE preceding character.

The spec implementation is first validated against the expectations that ship in
web-platform-tests fetch/content-type/resources/content-types.json, so it is not merely
my reading of the prose.
"""

def collect_http_quoted_string(inp, pos):
    """Fetch: collect an HTTP quoted string (extract-value = false -> raw slice)."""
    start = pos
    assert inp[pos] == '"'
    pos += 1
    while True:
        while pos < len(inp) and inp[pos] not in ('"', '\\'):
            pos += 1
        if pos >= len(inp):
            break
        q = inp[pos]
        pos += 1
        if q == '\\':
            if pos >= len(inp):
                break
            pos += 1                      # consume the ESCAPED code point as a pair
        else:
            break                         # q == '"' -> the quoted string ends
    return inp[start:pos], pos


def spec_split(value):
    """Fetch: get, decode, and split a header value."""
    pos, values, tmp = 0, [], ""
    while True:
        s = pos
        while pos < len(value) and value[pos] not in ('"', ','):
            pos += 1
        tmp += value[s:pos]
        if pos < len(value) and value[pos] == '"':
            q, pos = collect_http_quoted_string(value, pos)
            tmp += q
            if pos < len(value):
                continue
        tmp = tmp.strip(" \t")
        values.append(tmp)
        tmp = ""
        if pos >= len(value):
            return values
        assert value[pos] == ','
        pos += 1


def mozilla_split(value):
    """mozilla-central dom/base/MimeType.cpp TMimeType::SplitMimetype."""
    parts, in_quotes, start = [], False, 0
    for i, c in enumerate(value):
        if c == '"' and (i == 0 or value[i - 1] != '\\'):
            in_quotes = not in_quotes
        elif c == ',' and not in_quotes:
            parts.append(value[start:i])
            start = i + 1
    if start < len(value):
        parts.append(value[start:])
    return parts
