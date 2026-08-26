const Router = require('@koa/router');
function realHandler(ctx){return ctx;} function fakeHandler(ctx){return ctx;}
class FakeRouter { get(p,cb){} post(p,cb){} }
const real = new Router();      real.get("/ok", realHandler);      // profiled -> ESTABLISH
const fr = new FakeRouter();    fr.get("/no", fakeHandler);        // K3 non-profiled -> 0
const objLit = { get(p,cb){} }; objLit.get("/no2", fakeHandler);   // K3 object literal -> 0
const opaque = globalThis.whatever; opaque.get("/no3", fakeHandler); // K4 ANY-ish -> 0
