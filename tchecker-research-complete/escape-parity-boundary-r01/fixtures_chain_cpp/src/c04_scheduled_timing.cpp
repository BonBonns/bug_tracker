// C++ CHAIN CONTROL: the full chain, reached from a scheduled/administrative entry
// point. Execution timing is recorded as EVIDENCE ONLY and must not change the verdict.
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sqlite3.h>

static std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) start = (long)i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  return out;
}

void nightly_restore(const char* path, sqlite3* db) {
  sleep(3600);                                  // scheduled: evidence only, not a guard
  FILE* fp = fopen(path, "rb");
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf), fp);
  std::string stored(buf, n);
  std::vector<std::string> values = split_quoted(stored);
  sqlite3_exec(db, values.empty() ? "" : values[0].c_str(), nullptr, nullptr, nullptr);
  fclose(fp);
}
