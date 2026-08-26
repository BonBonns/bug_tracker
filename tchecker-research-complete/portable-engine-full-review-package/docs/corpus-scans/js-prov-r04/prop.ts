// JS-PROV-R04 teeth. Characterization only. No propagation implemented.
declare function use(x: any): any;
class Router { r=1 } class Db { d=1 } class Base { b=1 } class Derived extends Base { e=1 }
declare function makeRouter(): Router;
declare function makeDb(): Db;
declare const anyVal: any;
declare const unk: unknown;

// R04-1 one callsite, one concrete type
function r1_register(router) { use(router); }
const r1 = makeRouter(); r1_register(r1);

// R04-2 many callsites, SAME concrete type
function r2_register(router) { use(router); }
const r2a = makeRouter(); const r2b = makeRouter(); const r2c = makeRouter();
r2_register(r2a); r2_register(r2b); r2_register(r2c);

// R04-3 CONFLICTING concrete types  <-- load-bearing tooth
function r3_register(x) { use(x); }
const r3a = makeRouter(); const r3b = makeDb();
r3_register(r3a); r3_register(r3b);

// R04-4 concrete + ANY  (and concrete + unknown, concrete + null)
function r4_register(x) { use(x); }
const r4a = makeRouter();
r4_register(r4a); r4_register(anyVal); r4_register(unk); r4_register(null);

// R04-5 two parameters, NO crossover
function r5_two(a, b) { use(a); use(b); }
const r5r = makeRouter(); const r5d = makeDb();
r5_two(r5r, r5d);

// R04-6 exact call vs UNRESOLVED call
function r6_exact(x) { use(x); }
r6_exact(makeRouter());
declare const dynTarget: any;
dynTarget(makeRouter());          // unresolved callee -> must stay UNKNOWN

// R04-7 transitive two-hop
function r7_c(z) { use(z); }
function r7_b(y) { r7_c(y); }
function r7_a(x) { r7_b(x); }
r7_a(makeRouter());

// R04-8 recursion termination
function r8_self(x) { if (anyVal) r8_self(x); use(x); }
r8_self(makeRouter());
function r8_m1(x) { r8_m2(x); }
function r8_m2(x) { r8_m1(x); }
r8_m1(makeRouter());

// R04-9 stronger DECLARED type preserved
function r9_declared(x: Base) { use(x); }
const r9d = new Derived(); r9_declared(r9d);

// R04-5b default / rest / optional params
function r5c_default(a = 1) { use(a); }
function r5c_rest(...args) { use(args); }
function r5c_mixed(a, b = 2) { use(a); use(b); }
r5c_default(makeRouter() as any); r5c_rest(makeRouter()); r5c_mixed(makeRouter(), makeDb());

// R04-6b higher-order: callback arg vs function-valued arg
function r6b_reg(cb) { use(cb); }
r6b_reg((ctx) => use(ctx));
function r6b_handler(ctx) { use(ctx); }
r6b_reg(r6b_handler);
