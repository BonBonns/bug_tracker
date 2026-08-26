const Router = require("koa-router");
const router = new Router();

async function tagWriter(ctx, next) {
  ctx.state.tag = ctx.request.body.tag;
  await next();
}
async function tagHandler(ctx) {
  const u = ctx.state.user;
  const t = ctx.state.tag;
  ctx.body = { u, t };
}
router.post("/tags", tagWriter, tagHandler);
module.exports = router;
