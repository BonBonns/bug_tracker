// C++ CHAIN CONTROL: string-returning parser whose result only reaches logging.
#include <cstdio>
#include <string>

static std::string first_quoted(const std::string& s) {
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) start = (long)i;
      else return s.substr(start + 1, i - start - 1);
    }
  return std::string();
}

void audit_one(const char* path) {
  FILE* fp = fopen(path, "rb");
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf), fp);
  std::string stored(buf, n);
  std::string value = first_quoted(stored);
  fprintf(stderr, "%s\n", value.c_str());
  fclose(fp);
}
