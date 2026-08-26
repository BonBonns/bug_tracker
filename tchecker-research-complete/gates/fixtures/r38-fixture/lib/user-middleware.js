function has(o, p) {
  return p.split(".").every(k => (o = o && o[k]) !== undefined);
}
module.exports = async function userMiddleware(ctx, next) {
  if (has(ctx, "state.jwt.sub.id")) {
    ctx.state.user = ctx.state.jwt.sub;
  }
  await next();
};
