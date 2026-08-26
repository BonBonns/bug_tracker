module.exports = async function lateMiddleware(ctx, next) {
  ctx.state.late = "registered-after-mount";
  await next();
};
