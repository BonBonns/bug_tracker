// C++ NEGATIVE: counts the consecutive escape run and tests its parity.
#include <string>
#include <vector>

std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '\'') continue;
    int run = 0;
    long j = (long)i - 1;
    while (j >= 0 && s[j] == '\\') { run++; j--; }
    if (run % 2 == 1) continue;                  // odd run -> the quote is escaped
    if (start < 0) { start = (long)i; }
    else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
  }
  return out;
}
