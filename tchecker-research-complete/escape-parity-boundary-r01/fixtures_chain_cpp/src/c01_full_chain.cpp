// C++ CHAIN CONTROL: stored dump -> one-position parser -> decode/re-encode ->
// database import routine. The complete reachable chain.
#include <cstdio>
#include <string>
#include <vector>
#include <sqlite3.h>

extern std::string base64_decode(const std::string&);
extern std::string base64_encode(const std::string&);

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

void import_dump(const char* path, sqlite3* db) {
  FILE* fp = fopen(path, "rb");
  char buf[65536];
  size_t n = fread(buf, 1, sizeof(buf), fp);
  std::string stored(buf, n);
  std::string decoded = base64_decode(stored);
  std::vector<std::string> values = split_quoted(decoded);
  std::string sql = base64_encode(values.empty() ? std::string() : values[0]);
  sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
  fclose(fp);
}
