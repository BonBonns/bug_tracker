// C++ engine harness for the escape-run parity matrix.
// Runs the SAME parser shapes as the C++ fixtures against quoted text whose closing
// quote is preceded by an escape run of length 0..6, and reports the values recovered.
// Parser behaviour only.
#include <cstdio>
#include <string>
#include <vector>

// one-position boundary rule, subscript form (the defect shape)
static std::vector<std::string> split_onechar(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  // the one-position rule written faithfully: position 0 has no preceding character,
  // so it is guarded rather than skipped. Skipping index 0 would be a SECOND, unrelated
  // defect and would mask the parity signature this matrix is measuring.
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) start = (long)i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  return out;
}
// explicit escape-run counting (parity established)
static std::vector<std::string> split_counting(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '\'') continue;
    int run = 0; long j = (long)i - 1;
    while (j >= 0 && s[j] == '\\') { run++; j--; }
    if (run % 2 == 1) continue;
    if (start < 0) start = (long)i;
    else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
  }
  return out;
}
// parity-aware state machine (parity established)
static std::vector<std::string> split_toggle(const std::string& s) {
  std::vector<std::string> out; std::string buf;
  bool escaped = false, in_str = false;
  for (size_t i = 0; i < s.size(); ++i) {
    char ch = s[i];
    if (escaped) { escaped = !escaped; buf += ch; continue; }
    if (ch == '\\') { escaped = !escaped; buf += ch; continue; }
    if (ch == '\'') {
      if (in_str) { out.push_back(buf); buf.clear(); in_str = false; } else in_str = true;
      continue;
    }
    if (in_str) buf += ch;
  }
  return out;
}
// no escape awareness at all (a different correctness shape)
static std::vector<std::string> split_noescape(const std::string& s) {
  std::vector<std::string> out; long start = -1;
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'') {
      if (start < 0) start = (long)i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  return out;
}

static void emit(const char* rule, int n, const std::vector<std::string>& got,
                 const std::vector<std::string>& want) {
  bool ok = (got == want);
  printf("{\"rule_id\":\"%s\",\"language\":\"C_CPP\",\"engine\":\"g++\",\"run_length\":%d,"
         "\"parity\":\"%s\",\"matches_parity_rule\":%s,\"recovered\":[",
         rule, n, (n % 2 == 0 ? "even" : "odd"), ok ? "true" : "false");
  for (size_t i = 0; i < got.size(); ++i) {
    printf("%s\"", i ? "," : "");
    for (char c : got[i]) { if (c == '\\' || c == '"') putchar('\\'); putchar(c); }
    printf("\"");
  }
  printf("]}\n");
}

int main() {
  for (int n = 0; n <= 6; ++n) {
    std::string run(n, '\\');
    std::string subject = "'abc" + run + "', 'next'";
    std::vector<std::string> want;
    if (n % 2 == 0) { want.push_back("abc" + run); want.push_back("next"); }
    else            { want.push_back("abc" + run + "', "); }
    emit("cpp_onechar_subscript", n, split_onechar(subject), want);
    emit("cpp_explicit_counting", n, split_counting(subject), want);
    emit("cpp_parity_toggle",     n, split_toggle(subject),   want);
    emit("cpp_no_escape_aware",   n, split_noescape(subject), want);
  }
  return 0;
}
