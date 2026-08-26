module.exports = async function auditMiddleware(ctx, next) {
  ctx.state.audit = "on";          // UNCONDITIONAL, before next: MUST across the mount
  await next();
};
