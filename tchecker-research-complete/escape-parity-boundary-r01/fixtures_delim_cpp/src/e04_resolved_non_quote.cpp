// E4: the variable resolves to a non-quote delimiter. Field splitting is not
// quoted-string parsing and must produce no quote site.
#include <string>
#include <vector>

std::vector<std::string> split_fields(const std::string& s) {
  const char FIELD = ',';
  const char ESCAPE = '\\';
  std::vector<std::string> out;
  size_t start = 0;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == FIELD && (i == 0 || s[i - 1] != ESCAPE)) {
      out.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  out.push_back(s.substr(start));
  return out;
}
