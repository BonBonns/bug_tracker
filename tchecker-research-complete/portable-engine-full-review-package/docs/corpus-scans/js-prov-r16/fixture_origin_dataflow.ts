declare function use(x:any):any; declare const schema:any; declare const other:any;
declare function preserve(x:any):any;   // known value-preserving wrapper
async function mw(ctx, next){
  const a1 = { ...ctx.request.body };                 // T1 BODY
  const a2 = { ...ctx.query };                        // T2 QUERY
  const a3 = { ...ctx.request.body, ...ctx.query };   // T3 {BODY,QUERY}
  const a4 = { k: 1, ...ctx.request.body };           // T4 BODY only
  const a5 = { ...other };                            // T5 no HTTP origin
  const r  = await schema.validate(a3);               // T8 opaque third-party
  const { value } = r;                                // T6 destructure member
  const { error } = r;                                // T7 sibling
  const p  = preserve(ctx.request.body);              // T9 value-preserving wrapper
  ctx.w1=a1; ctx.w2=a2; ctx.w3=a3; ctx.w4=a4; ctx.w5=a5;
  ctx.w6=value; ctx.w7=error; ctx.w9=p;
  await next();
}
