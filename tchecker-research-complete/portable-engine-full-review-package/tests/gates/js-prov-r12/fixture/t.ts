const Router = require('@koa/router');
const realRouter = new Router();
declare function use(x:any):any; declare function sink(x:any):any;
declare const condition:boolean; declare const source:any; declare const schema:any;
declare function lookup(x:any):any;

function validate(sch) {
  return async function (c, n) {
    c.validatedData = c.request.body;
    await n();
  };
}

function install(router){
  router.post("/p1", wholeWriter, readsEmail);        // POSITIVE: whole-object write -> .email read
  router.post("/p2", siblingWriter, readsEmail2);     // NEG 7: .user written, .email read -> INCOMPATIBLE
  router.post("/p3", siblingWriter2, readsUserId);    // POSITIVE: .user written, .user.id read -> ancestor
  router.post("/p4", afterNextWriter, readsAfter);    // NEG 3: AFTER_NEXT
  router.post("/p5", condWriter, readsCond);          // NEG 4: conditional -> MAY
  router.post("/p6", validate(schema), readsEmail3);  // NEG 6: wrapper-returned
  router.post("/p7", 42 as any, readsEmail4);         // NEG 5: stub callback
  router.post("/p8", readsEmail5, wholeWriter2);      // NEG: reader BEFORE writer
  router.post("/ov", ovBroad, ovNarrow, ovReadUser, ovReadEmail);  // R19 overwrite tooth
  router.post("/r1", routeAWriter, routeAReader);     // NEG 2 pair A
  router.post("/r2", routeBWriter, routeBReader);     // NEG 2 pair B
}
install(realRouter);

async function wholeWriter(a, b){  a.validatedData = a.request.body;  await b(); }
async function readsEmail(a){      use(a.validatedData.email); }
async function siblingWriter(a, b){ a.validatedData.user = lookup(1);  await b(); }
async function readsEmail2(a){     use(a.validatedData.email); }
async function siblingWriter2(a, b){ a.validatedData.user = lookup(1); await b(); }
async function readsUserId(a){     use(a.validatedData.user.id); }
async function afterNextWriter(a, b){ await b();  a.lateData = a.request.body; }
async function readsAfter(a){      use(a.lateData); }
async function condWriter(a, b){   if (condition) { a.condData = a.request.body; }  await b(); }
async function readsCond(a){       use(a.condData); }
async function readsEmail3(a){     use(a.validatedData.email); }
async function readsEmail4(a){     use(a.validatedData.email); }
async function wholeWriter2(a, b){ a.validatedData = a.request.body;  await b(); }
async function readsEmail5(a){     use(a.validatedData.email); }
async function ovBroad(a, b){
  const merged = { ...a.request.body, ...a.query };
  const out = opaqueX(merged);
  a.validatedData = out;
  await b();
}
async function ovNarrow(a, b){ a.validatedData.user = a.query; await b(); }
async function ovReadUser(a, b){  use(a.validatedData.user);  await b(); }
async function ovReadEmail(a){    use(a.validatedData.email); }
declare function opaqueX(x:any):any;
async function routeAWriter(a, b){ a.shared = a.request.body; await b(); }
async function routeAReader(a){    use(a.shared); }
async function routeBWriter(a, b){ a.shared = a.query;        await b(); }
async function routeBReader(a){    use(a.shared); }

// NEG 1: different object entirely, no registration
function other(z){ z.validatedData = source; }
function otherReader(w){ sink(w.validatedData.email); }
