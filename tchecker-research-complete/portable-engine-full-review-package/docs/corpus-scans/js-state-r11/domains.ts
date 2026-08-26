// JS-STATE-R11 — Family-B operand-domain semantics characterization fixture.
// Characterization only. No detector, no verdict.
// Question: which operand DOMAINS can be proven POSITIVELY from current facts?
declare function sensitive(x: unknown): void;
declare function authenticate(u: string): void;

// A — both domains explicit and DIFFERENT (number vs string literal)
function caseA_explicitDifferent() {
  const a = 1;
  const b = "1";
  if (a == b) sensitive(a);
}

// B — same explicit domain (string vs string)
function caseB_sameDomain() {
  const c = "x";
  const d = "x";
  if (c == d) sensitive(c);
}

// C — nullish idiom (must be a hard negative tooth)
declare const value: string | null | undefined;
function caseC_nullishIdiom() {
  if (value == null) return;
  sensitive(value);
}

// D — ANY vs explicit string
declare const unknownValue: any;
function caseD_anyVsExplicit() {
  if (unknownValue == "secret") sensitive(unknownValue);
}

// E — both ANY
declare const x: any; declare const y: any;
function caseE_bothAny() {
  if (x == y) sensitive(x);
}

// F — the historical CVE shape: index-access base is an object literal whose
// values are all strings. Can LEFT_DOMAIN be recovered from producer history?
const users: Record<string, string> = { admin: "secret" };
declare const request: any;
function caseF_cveShape(name: string) {
  const password = request.body.password;
  if (users[name] == password) authenticate(name);
}

// G — explicit conversion before STRICT equality (non-coercive by construction)
function caseG_explicitConvStrict(a: number, b: string) {
  if (String(a) === b) sensitive(b);
}
