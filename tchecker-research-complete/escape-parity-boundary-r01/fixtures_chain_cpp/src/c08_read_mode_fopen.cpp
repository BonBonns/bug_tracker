// C++ CHAIN CONTROL: fopen("rb") IS a read-mode open and MUST be recorded as a
// delayed source. This control verifies that mode filtering does not accidentally
// exclude read-mode fopen calls. The c01_full_chain fixture also covers this (fopen
// "rb" in a full chain); this fixture isolates the mode-argument check alone.
//
// Expected: delayed_sources.tsv has 1 row for this unit (fopen RESOLVED_EXTERNAL).
//           chain search_space.resolved_sources_in_unit == 1.
#include <cstdio>
#include <cstring>

static bool parse_quoted(const char* s) {
  bool in_quote = false;
  for (const char* p = s; *p; ++p)
    if (*p == '"' && (p == s || *(p - 1) != '\\'))
      in_quote = !in_quote;
  return in_quote;
}

void load_record(const char* path) {
  FILE* fp = fopen(path, "rb");  // read-only: "rb" -- MUST be a delayed source
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  buf[n] = '\0';
  bool ok = parse_quoted(buf);  // buf is read from the file
  fclose(fp);
  (void)ok;
}
