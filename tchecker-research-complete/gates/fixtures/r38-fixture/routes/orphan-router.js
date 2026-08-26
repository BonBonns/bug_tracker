const Router = require("koa-router");
const router = new Router();
async function orphanHandler(ctx) {
  const u = ctx.state.user;
  ctx.body = { u };
}
router.get("/orphan", orphanHandler);
module.exports = router;
