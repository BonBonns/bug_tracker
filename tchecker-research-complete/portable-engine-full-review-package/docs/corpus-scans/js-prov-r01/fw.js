// JS-PROV-R01 framework coverage matrix. Characterization only.
// Names are NEVER evidence. Every framework has a lookalike negative control.
function use(x){return x;}
function helper(x){return use(x);}

// ---------- EXPRESS ----------
const express = require('express');
const app = express();
app.post("/e1", (req, res) => { use(req.body.username); use(req.query.q); use(req.params.id); use(req.headers.h); use(req.cookies.c); });

// ---------- EXPRESS ROUTER ----------
const router = express.Router();
router.get("/e2", (req, res) => { use(req.query.id); });

// ---------- FASTIFY ----------
const fastify = require('fastify')();
fastify.post("/f1", (request, reply) => { use(request.body.username); use(request.query.q); use(request.params.id); use(request.headers.h); });

// ---------- KOA ----------
const Koa = require('koa');
const koaApp = new Koa();
koaApp.use(async (ctx, next) => { use(ctx.request.body.username); use(ctx.query.q); use(ctx.params.id); use(ctx.headers.h); use(ctx.cookies.get("c")); });

// ---------- HAPI ----------
const Hapi = require('@hapi/hapi');
const hapiServer = Hapi.server({ port: 3000 });
hapiServer.route({ method: 'POST', path: '/h1', handler: (request, h) => { use(request.payload.username); use(request.query.q); use(request.params.id); use(request.headers.h); use(request.state.c); } });

// ---------- SERVERLESS (AWS Lambda shape) ----------
exports.handler = async (event, context) => { use(event.body); use(event.queryStringParameters.q); use(event.pathParameters.id); use(event.headers.h); };

// ---------- NEGATIVE CONTROLS ----------
function fake(req, res) { use(req.body.username); }            // lookalike, unregistered
function fakeFastify(request, reply) { use(request.body.x); }  // lookalike
const notFramework = { post: (p, cb) => cb };                   // same method name, non-framework
notFramework.post("/n1", (req, res) => { use(req.body.username); });
const plain = { body: { username: "x" } };
use(plain.body.username);                                       // unrelated object with .body
function ordinaryHelper(obj) { use(obj.body.username); }        // helper receiving ordinary object
app.post("/wrongparam", (req, res) => { use(res.locals.x); });  // wrong callback parameter

// ---------- WRAPPER / FORWARDING / MIDDLEWARE ----------
function namedHandler(req, res) { helper(req.body.username); }
router.post("/w1", namedHandler);                               // named callback reference
function mw(req, res, next) { return next(); }
router.post("/w2", mw, namedHandler);                           // middleware chain
const reexported = namedHandler;
router.post("/w3", reexported);                                 // re-exported handler

// ---------- DESTRUCTURING / ALIASES ----------
app.post("/d1", (req, res) => {
  const { body } = req;                 // destructure req
  const { username } = req.body;        // destructure req.body
  const b2 = req.body;                  // alias
  const x2 = b2.username;               // alias -> property
  use(body.username); use(username); use(x2);
});

// ---------- NON-HTTP FAMILIES (no route registration anchor) ----------
function nonHttp() { use(process.env.SECRET); use(process.argv[2]); }
