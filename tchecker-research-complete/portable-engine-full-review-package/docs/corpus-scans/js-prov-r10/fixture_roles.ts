const Router = require('@koa/router');
const realRouter = new Router();
declare function use(x:any):any;
function install(router){
  router.get("/n1", (ctx, next) => use(ctx));
  router.get("/n2", (context, continuation) => use(context));
  router.get("/n3", (banana, orange) => use(banana));
  router.get("/p1", (a, b) => use(a));      // a = CONTEXT
  router.get("/p2", (a, b) => use(b));      // b must NOT be CONTEXT
  router.get("/p3", (only) => use(only));   // 1-param
  router.get("/p4", () => use(1));          // 0-param
  router.get("/p5", (x, y, z) => use(x));   // 3-param lookalike
  router.get("/n6", namedHandler);
  router.post("/m1", mwA, mwB, namedHandler);
  router.get("/nc", 42 as any);                      // non-callable arg after path
}
install(realRouter);
function namedHandler(a, b) { use(a); }
function mwA(a, b){ return b(); } function mwB(a, b){ return b(); }
function notRegistered(a, b) { use(a); }          // same shape, never registered
const fake = { get(p, cb){} };
fake.get("/x", namedHandler);                      // callback-shaped, no registration
