// C++ CHAIN CONTROL: the same complete chain, but the parser returns a plain
// std::string rather than a container. This isolates the chain layer from the
// engine's container-element modelling.
#include <cstdio>
#include <string>
#include <sqlite3.h>

extern std::string base64_decode(const std::string&);
extern std::string base64_encode(const std::string&);

static std::string first_quoted(const std::string& s) {
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) start = (long)i;
      else return s.substr(start + 1, i - start - 1);
    }
  return std::string();
}

void import_one(const char* path, sqlite3* db) {
  FILE* fp = fopen(path, "rb");
  char buf[65536];
  size_t n = fread(buf, 1, sizeof(buf), fp);
  std::string stored(buf, n);
  std::string decoded = base64_decode(stored);
  std::string value = first_quoted(decoded);
  std::string sql = base64_encode(value);
  sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
  fclose(fp);
}
