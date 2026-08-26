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
// JS-PROV-R18 teeth: inline expression arguments
declare function opaque(x:any):any;
async function mw18(ctx, next){
  const i1 = opaque({ ...ctx.request.body, ...ctx.query });  // inline both
  const i2 = opaque({ k: 1 });                               // literal-only
  const i3 = opaque({ ...other });                           // unrelated spread
  const i4 = opaque({ ...ctx.request.body });                // callsite A
  const i5 = opaque({ ...ctx.request.body });                // callsite B (identical text)
  const i6 = opaque(inner(({ ...ctx.request.body })));       // spread inside NESTED call
  ctx.a=i1; ctx.b=i2; ctx.c=i3; ctx.d=i4; ctx.e=i5; ctx.f=i6;
  await next();
}
declare function inner(x:any):any;
