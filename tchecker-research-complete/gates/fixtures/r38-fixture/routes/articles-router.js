const Router = require("koa-router");
const ctrl = require("../controllers/articles-controller");
const router = new Router();
router.get("/articles/:id", ctrl.get);
module.exports = router;
