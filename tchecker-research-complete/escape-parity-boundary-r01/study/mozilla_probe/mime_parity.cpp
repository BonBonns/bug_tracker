// Faithful reimplementation of the quote-toggle loop in mozilla-central
// dom/base/MimeType.cpp TMimeType<char_type>::SplitMimetype, applied to inputs whose
// closing quote follows an escape run of length 0..6. Parser behaviour only: nothing
// else from that file, and no other Mozilla code, is executed or reproduced.
#include <cstdio>
#include <string>
#include <vector>

static std::vector<std::string> split_mozilla(const std::string& s) {
  std::vector<std::string> parts;
  bool inQuotes = false;
  size_t start = 0;
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (c == '"' && (i == 0 || s[i - 1] != '\\')) {      // the one-position rule
      inQuotes = !inQuotes;
    } else if (c == ',' && !inQuotes) {
      parts.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  if (start < s.size()) parts.push_back(s.substr(start));
  return parts;
}

// The same loop with escape-run parity established, for comparison.
static std::vector<std::string> split_parity(const std::string& s) {
  std::vector<std::string> parts;
  bool inQuotes = false;
  size_t start = 0;
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    size_t run = 0, j = i;
    while (j > 0 && s[j - 1] == '\\') { run++; j--; }   // full consecutive escape run
    if (c == '"' && run % 2 == 0) {                      // even run -> the quote counts
      inQuotes = !inQuotes;
    } else if (c == ',' && !inQuotes) {
      parts.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  if (start < s.size()) parts.push_back(s.substr(start));
  return parts;
}

int main() {
  printf("%-4s %-30s %-9s %-9s %s\n", "run", "input", "mozilla", "parity", "agree");
  for (int n = 0; n <= 6; n++) {
    std::string esc(n, '\\');
    std::string in = "text/plain;p=\"v" + esc + "\",text/html";
    auto a = split_mozilla(in);
    auto b = split_parity(in);
    printf("%-4d %-30s %-9zu %-9zu %s\n", n, in.c_str(), a.size(), b.size(),
           a == b ? "yes" : "NO");
  }
  printf("\nworked example, escape run = 2 (an escaped backslash, so the quote closes):\n");
  std::string in = "text/plain;p=\"v\\\\\",text/html";
  printf("  input           %s\n", in.c_str());
  for (auto& p : split_mozilla(in)) printf("  mozilla part    [%s]\n", p.c_str());
  for (auto& p : split_parity(in))  printf("  parity  part    [%s]\n", p.c_str());
  return 0;
}
