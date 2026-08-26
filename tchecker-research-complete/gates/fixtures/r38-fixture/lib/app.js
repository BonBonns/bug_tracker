const Koa = require("koa");
const userMiddleware = require("./user-middleware");
const lateMiddleware = require("./late-middleware");
const auditMiddleware = require("./audit-middleware");
const articlesRouter = require("../routes/articles-router");
const tagsRouter = require("../routes/tags-router");
const orphanRouter = require("../routes/orphan-router"); // required but NEVER mounted
const multiRouter = require("../routes/multi-router");

const app = new Koa();

app.use(userMiddleware);                 // BEFORE mounts: must flow into mounted routers
app.use(auditMiddleware);                // unconditional write: MUST across the mount
app.use(articlesRouter.routes());        // mount 1
app.use(tagsRouter.routes());            // mount 2
app.use(multiRouter.routes());           // mount 3: two-routers-one-file guard
app.use(lateMiddleware);                 // AFTER mounts: must NOT flow (ordering tooth)

module.exports = app;
