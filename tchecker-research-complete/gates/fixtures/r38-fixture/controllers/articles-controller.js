exports.get = async function getArticle(ctx) {
  const u = ctx.state.user;      // must join userMiddleware's write (MAY)
  const l = ctx.state.late;      // must NOT join lateMiddleware (registered after mount)
  const t = ctx.state.tag;       // must NOT join tags-router's writer (NEG-2)
  ctx.body = { u, l, t };
};
