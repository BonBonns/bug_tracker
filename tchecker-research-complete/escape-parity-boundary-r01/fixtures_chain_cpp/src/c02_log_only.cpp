// C++ CHAIN CONTROL: same stored source and same parser, but the result only reaches
// logging. Parser candidate only -- no structured-text consumer.
#include <cstdio>
#include <string>
#include <vector>

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

void audit_dump(const char* path) {
  FILE* fp = fopen(path, "rb");
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf), fp);
  std::string stored(buf, n);
  std::vector<std::string> values = split_quoted(stored);
  for (const auto& v : values) fprintf(stderr, "%s\n", v.c_str());
  fclose(fp);
}
