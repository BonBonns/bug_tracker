const Router = require('@koa/router');
function realHandler(ctx){return ctx;} function fakeHandler(ctx){return ctx;}
class FakeRouter { get(p,cb){} post(p,cb){} }

const realRouter = new Router();
function installReal(router){ router.get("/t2", realHandler); }   // must GAIN @koa/router
installReal(realRouter);

const fakeRouter = new FakeRouter();
function installFake(router){ router.get("/t3", fakeHandler); }   // must NOT gain it
installFake(fakeRouter);

// conflicting callsites -> SET, never last-wins
function installBoth(router){ router.get("/t4", realHandler); }
installBoth(realRouter); installBoth(fakeRouter);

// genuine ANY contamination -> unconstrained_callsite must be TRUE
function installAny(router){ router.get("/t5", realHandler); }
function outer(untyped){ installAny(untyped); }   // `untyped` is ANY
installAny(realRouter); outer(realRouter);

// genuine cast erasure -> must ABSTAIN via G3
function installCast(router){ router.get("/t6", realHandler); }
installCast(realRouter as any);

// stronger declared param type -> must ABSTAIN via G4
function installDeclared(router: FakeRouter){ router.get("/t7", realHandler); }
installDeclared(fakeRouter);

// rest parameter -> must ABSTAIN via G5
function installRest(...routers){ }
installRest(realRouter);
