// C++ CHAIN CONTROL: fopen("wb") is a write-only open and is NOT a delayed source.
// A write-mode fopen cannot supply stored data to a text parser: data flows from the
// caller's arguments into the file, not from the file into the parser. Counting it
// as a source would inflate resolved_sources_in_unit and make a vacuous negative look
// like a traced one. The producer must exclude it.
//
// Expected: delayed_sources.tsv has 0 rows for this unit.
//           chain search_space.resolved_sources_in_unit == 0.
#include <cstdio>
#include <cstring>

static bool parse_quoted(const char* s) {
  bool in_quote = false;
  for (const char* p = s; *p; ++p)
    if (*p == '"' && (p == s || *(p - 1) != '\\'))
      in_quote = !in_quote;
  return in_quote;
}

void dump_record(const char* path, const char* data) {
  FILE* fp = fopen(path, "wb");  // write-only: "wb" -- must NOT be a delayed source
  fwrite(data, 1, strlen(data), fp);
  bool ok = parse_quoted(data);  // data is the caller's argument, not read from file
  fclose(fp);
  (void)ok;
}
