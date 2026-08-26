// JS-STATE-R13 — JS/TS Source Provenance Characterization.
// Characterization only. No detector. Names are NOT evidence.
const express = require('express');
const app = express();
const router = express.Router();
function use(x) { return x; }
function helper(x) { return use(x); }
const attackerLookingName = { username: "x" };

// T1 — real request source via framework registration
app.post("/x", (req, res) => {
  use(req.body.username);
});

// T2 — CRITICAL NEGATIVE CONTROL: same spelling, same shape, NO registration
function fake(req, res) {
  use(req.body.username);
}

// T3 — destructuring in callback parameter position
app.post("/t3", ({ body }, res) => {
  use(body.username);
});

// T4 — local alias
app.post("/t4", (req, res) => {
  const body = req.body;
  use(body.username);
});

// T5 — wrong callback parameter (res, not req)
app.post("/t5", (req, res) => {
  use(res.someProperty);
});

// T6 — unrelated object's body field
const x = { body: attackerLookingName };
use(x.body.username);

// T7 — wrapper/middleware forwarding, handler registered by reference
function handler(req, res) {
  helper(req.body.username);
}
app.post("/t7", handler);

// T8 — anonymous callback on router, query family
router.get("/t8", function (request, response) {
  use(request.query.id);
});

// T9 — other source families (kept separate, not collapsed)
function otherFamilies(req) {
  use(req.params.id);      // route/path params
  use(req.headers.cookie); // headers
  use(req.cookies.sid);    // cookies
  use(process.env.SECRET); // environment
  use(process.argv[2]);    // CLI
}
