const m1 = require('./m1');            // module.exports = other
const m2 = require('./m2');            // exports.validate = validate
const m3 = require('./m3');            // module.exports = { validate, other }
const m4 = require('./m4');            // module.exports.validate = validate
function use(x){return x;}
function h1(c){ use(c.vA); } function h2(c){ use(c.v2); }
function h3(c){ use(c.v3); } function h4(c){ use(c.v4); }
function install(router){
  router.post("/e1", m1(1), h1);
  router.post("/e2", m2.validate(1), h2);
  router.post("/e3", m3.validate(1), h3);
  router.post("/e4", m4.validate(1), h4);
}
const Router = require('@koa/router'); const r = new Router(); install(r);
