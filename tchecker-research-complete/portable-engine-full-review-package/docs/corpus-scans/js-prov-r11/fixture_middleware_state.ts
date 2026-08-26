const Router = require('@koa/router');
const realRouter = new Router();
declare function use(x:any):any; declare function sink(x:any):any;
declare const condition:boolean; declare const source:any; declare const schema:any;
declare function normalize(x:any):any;

// R11-12 wrapper-returned middleware
function validate(sch) { return async function (ctx, next) {
  ctx.validatedData = ctx.request.body;
  await next();
}; }

function install(router){
  // R11-1 direct producer -> consumer ; R11-6 write BEFORE next
  router.post("/r1", producer, consumer);
  // R11-5 producer AFTER consumer (order tooth)
  router.post("/r5", consumer, producer);
  // R11-7 write AFTER next()  (critical Koa tooth)
  router.post("/r7", afterWriter, consumer2);
  // R11-8 conditional write
  router.post("/r8", condWriter, consumer3);
  // R11-9/10/11 origin families
  router.post("/r9",  bodyWriter,  consumer4);
  router.post("/r10", queryWriter, consumer5);
  router.post("/r11", constWriter, consumer6);
  // R11-10b derived
  router.post("/r10b", derivedWriter, consumer7);
  // R11-12 wrapper-returned
  router.post("/r12", validate(schema), consumer8);
  // R11-13 non-callable
  router.post("/r13", 42 as any, consumer9);
  // R11-3 separate route must not satisfy
  router.post("/r3", producerB, consumerB);
}
install(realRouter);

async function producer(ctx, next){
  ctx.validatedData = ctx.request.body;
  await next();
}
async function consumer(ctx){ use(ctx.validatedData.username); }
async function afterWriter(ctx, next){
  await next();
  ctx.afterData = ctx.request.body;
}
async function consumer2(ctx){ use(ctx.afterData); }
async function condWriter(ctx, next){
  if (condition) { ctx.condData = ctx.request.body; }
  await next();
}
async function consumer3(ctx){ use(ctx.condData); }
async function bodyWriter(ctx, next){
  ctx.vBody = ctx.request.body;
  await next();
}
async function consumer4(ctx){ use(ctx.vBody); }
async function queryWriter(ctx, next){
  ctx.vQuery = ctx.query;
  await next();
}
async function consumer5(ctx){ use(ctx.vQuery); }
async function constWriter(ctx, next){
  ctx.vConst = "literal";
  await next();
}
async function consumer6(ctx){ use(ctx.vConst); }
async function derivedWriter(ctx, next){
  ctx.vDerived = normalize(ctx.request.body);
  await next();
}
async function consumer7(ctx){ use(ctx.vDerived); }
async function consumer8(ctx){ use(ctx.validatedData.username); }
async function consumer9(ctx){ use(ctx.validatedData); }
async function producerB(ctx, next){
  ctx.routeBData = ctx.request.body;
  await next();
}
async function consumerB(ctx){ use(ctx.routeBData); }

// R11-2 same property, unrelated objects, NO registration
function a(x){ x.validatedData = source; }
function b(y){ sink(y.validatedData); }
