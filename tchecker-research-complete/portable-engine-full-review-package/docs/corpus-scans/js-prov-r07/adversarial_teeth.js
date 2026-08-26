const Router = require('@koa/router');
function realHandler(ctx){return ctx;} function fakeHandler(ctx){return ctx;}
// R07-1 typed real router, direct
const direct = new Router();
direct.get("/t1", realHandler);
// R07-2 ANY receiver, REAL router passed interprocedurally
function installReal(router){ router.get("/t2", realHandler); }
installReal(new Router());
// R07-3 ANY receiver, FAKE router passed interprocedurally
class FakeRouter { get(p,cb){} post(p,cb){} }
function installFake(router){ router.get("/t3", fakeHandler); }
installFake(new FakeRouter());
// R07-4 concrete FakeRouter, direct
const fr = new FakeRouter(); fr.get("/t4", fakeHandler);
// R07-5 object-literal lookalike
const objLit = { get(p,cb){}, post(p,cb){} }; objLit.get("/t5", fakeHandler);
// R07-7/8 anonymous handler + middleware chain on a REAL router
direct.post("/t7", (ctx)=>ctx);
function mw(ctx,next){return next();}
direct.post("/t8", mw, realHandler);
// R07-9 unresolved dynamic receiver
const dyn = globalThis.whatever; dyn.get("/t9", fakeHandler);
