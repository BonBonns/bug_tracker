// Two routers in ONE file; only routerA is exported. A mount of this module
// must join routerA's registrations ONLY -- the guard default_export_identifier
// exists for exactly this shape.
const Router = require("koa-router");
const routerA = new Router();
const routerB = new Router();

async function exportedHandler(ctx) {
  const u = ctx.state.user;    // joins (routerA is the exported router)
  const a = ctx.state.audit;   // joins, MUST
  ctx.body = { u, a };
}
async function unexportedHandler(ctx) {
  const u = ctx.state.user;    // must NOT join: routerB is never mounted
  ctx.body = { u };
}
routerA.get("/multi-a", exportedHandler);
routerB.get("/multi-b", unexportedHandler);
module.exports = routerA;
