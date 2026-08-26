// JS-STATE-R12 — Prototype-Reachable Property Read Characterization.
// Characterization only. No detector, no verdict.
// Question: when can base[key] resolve to an INHERITED property rather than an
// own property, and can Fable prove when attacker-controlled key makes that
// runtime alternative relevant?
declare function sink(x: unknown): void;
declare const input: string;
declare const request: any;

const users: Record<string, string> = { alice: "secret" };

// T1 — ordinary own property, constant known-own key
function t1_constantOwnKey() { const a = users["alice"]; sink(a); }

// T2 — inherited built-in property, constant key
function t2_constantProtoKey() { const b = users["__proto__"]; sink(b); }

// T3 — attacker-selected key (the CVE's shape)
function t3_attackerKey() { const c = users[input]; sink(c); }

// T4 — null-prototype base: prototype lookup structurally impossible
function t4_nullPrototypeBase() {
  const safe: any = Object.create(null);
  safe["alice"] = "secret";
  const d = safe[input];
  sink(d);
}

// T5 — legacy own-property gate
function t5_hasOwnPropertyGate() {
  if (!Object.prototype.hasOwnProperty.call(users, input)) return;
  const e = users[input];
  sink(e);
}

// T6 — modern own-property gate
function t6_objectHasOwnGate() {
  if (!Object.hasOwn(users, input)) return;
  const f = users[input];
  sink(f);
}

// T7 — Map.get: NOT prototype property lookup. Negative control so a
// syntactic "dynamic keyed lookup" abstraction cannot absorb an unrelated
// storage model.
function t7_mapGetControl() {
  const m = new Map<string, string>();
  m.set("alice", "secret");
  const g = m.get(input);
  sink(g);
}

// T8 — uncontrolled unknown key: prototype possible structurally, but no
// attacker-control claim is available.
function t8_uncontrolledUnknownKey(k: string) {
  const h = users[k];
  sink(h);
}

// T9 — the CVE replay itself
function t9_cveReplay(username: string) {
  const password = request.body.password;
  if (users[username] && users[username] == password) {
    sink(username);
  }
}
