const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2]; const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const funcs=new Map(); for(const st of sf.statements) if(ts.isFunctionDeclaration(st)&&st.name) funcs.set(st.name.text,st);
const arr=s=>[...s].sort(); const union=(...ss)=>new Set(ss.flatMap(s=>[...(s||[])]));
const litKey=e=>ts.isStringLiteral(e)||ts.isNoSubstitutionTemplateLiteral(e)?`S:${e.text}`:ts.isNumericLiteral(e)?`N:${e.text}`:null;
function evalFn(fn){
 const name=fn.name.text, envV=new Map(), envO=new Map(), writes=new Map(); let seq=0; const trace=[];
 fn.parameters.forEach((p,i)=>{if(!ts.isIdentifier(p.name))return; const n=p.name.text; const t=p.type;
   const container=!!t&&(ts.isArrayTypeNode(t)||(ts.isTypeReferenceNode(t)&&t.typeName.getText(sf)==='Record'));
   if(container) envO.set(n,`PARAMOBJ:${name}.${n}`); else envV.set(n,new Set([`PARAM:${name}.${n}`]));});
 const objOf=e=>ts.isIdentifier(e)?envO.get(e.text)||null:null; const ws=o=>{if(!writes.has(o))writes.set(o,[]); return writes.get(o)};
 function val(e){if(!e)return new Set(['CONST:undefined']); if(ts.isStringLiteral(e)||ts.isNumericLiteral(e))return new Set([`CONST:${e.getText(sf)}`]); if(ts.isIdentifier(e))return new Set(envV.get(e.text)||[`UNKNOWN:VAR:${e.text}`]); if(ts.isElementAccessExpression(e))return read(e).values; return new Set([`UNKNOWN:EXPR:${e.kind}`]);}
 function write(lhs,rhs){const o=objOf(lhs.expression), key=litKey(lhs.argumentExpression), v=val(rhs); seq++; if(!o)return; ws(o).push({seq,key,value:new Set(v),dynamic:key===null});}
 function exact(o,key){let last=-1, base=new Set([`STATE_UNKNOWN:${o}[${key}]`]); for(const w of ws(o))if(!w.dynamic&&w.key===key&&w.seq>=last){last=w.seq;base=new Set(w.value)} const dyn=ws(o).filter(w=>w.dynamic&&w.seq>last).map(w=>w.value); const values=union(base,...dyn); return {values,resolution:dyn.length?'AMBIGUOUS':([...values].some(x=>x.startsWith('STATE_UNKNOWN:'))?'UNKNOWN':'EXACT')}}
 function read(e){const o=objOf(e.expression); if(!o)return {values:new Set([`STATE_UNKNOWN:${e.getText(sf)}`]),resolution:'UNKNOWN'}; const key=litKey(e.argumentExpression); if(key)return exact(o,key); let values=new Set([`STATE_UNKNOWN:${o}[*]`]); for(const k of [...new Set(ws(o).filter(w=>!w.dynamic).map(w=>w.key))]) values=union(values,exact(o,k).values); return {values,resolution:'AMBIGUOUS'};}
 function bind(nameNode, initializer){
   if(ts.isIdentifier(nameNode)){envV.set(nameNode.text,val(initializer)); return {resolution:'EXACT'};}
   if(ts.isObjectBindingPattern(nameNode)){
     const base=objOf(initializer); let res='EXACT';
     for(const el of nameNode.elements){
       if(el.dotDotDotToken){ if(ts.isIdentifier(el.name)){let vals=new Set([`STATE_UNKNOWN:REST:${initializer.getText(sf)}`]); if(base) for(const k of [...new Set(ws(base).filter(w=>!w.dynamic).map(w=>w.key))]) vals=union(vals,exact(base,k).values); envV.set(el.name.text,vals); res='AMBIGUOUS'; trace.push({kind:'OBJECT_REST',resolution:'AMBIGUOUS'});} continue; }
       const prop=el.propertyName||el.name; const key=ts.isComputedPropertyName(prop)?null:(ts.isIdentifier(prop)?`S:${prop.text}`:ts.isStringLiteral(prop)?`S:${prop.text}`:null);
       let r; if(!base) r={values:new Set([`STATE_UNKNOWN:${initializer.getText(sf)}`]),resolution:'UNKNOWN'}; else if(key) r=exact(base,key); else {let values=new Set([`STATE_UNKNOWN:${base}[*]`]); for(const k of [...new Set(ws(base).filter(w=>!w.dynamic).map(w=>w.key))]) values=union(values,exact(base,k).values); r={values,resolution:'AMBIGUOUS'};}
       if(ts.isIdentifier(el.name)) envV.set(el.name.text,r.values); if(r.resolution!=='EXACT')res=r.resolution;
     } return {resolution:res};
   }
   if(ts.isArrayBindingPattern(nameNode)){
     const base=objOf(initializer); let res='EXACT'; nameNode.elements.forEach((el,i)=>{if(ts.isOmittedExpression(el))return; if(!ts.isBindingElement(el))return; if(el.dotDotDotToken){if(ts.isIdentifier(el.name)){let vals=new Set([`STATE_UNKNOWN:REST:${initializer.getText(sf)}`]); if(base) for(const k of [...new Set(ws(base).filter(w=>!w.dynamic).map(w=>w.key))].filter(k=>k.startsWith('N:')&&Number(k.slice(2))>=i)) vals=union(vals,exact(base,k).values); envV.set(el.name.text,vals); res='AMBIGUOUS'; trace.push({kind:'ARRAY_REST',resolution:'AMBIGUOUS'});} return;} const r=base?exact(base,`N:${i}`):{values:new Set([`STATE_UNKNOWN:${initializer.getText(sf)}`]),resolution:'UNKNOWN'}; if(ts.isIdentifier(el.name))envV.set(el.name.text,r.values); if(r.resolution!=='EXACT')res=r.resolution;}); return {resolution:res};
   }
 }
 let returnResolution='EXACT', ret=new Set(['CONST:undefined']);
 for(const st of fn.body.statements){
   if(ts.isExpressionStatement(st)&&ts.isBinaryExpression(st.expression)&&st.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isElementAccessExpression(st.expression.left)) write(st.expression.left,st.expression.right);
   else if(ts.isVariableStatement(st)) { for(const d of st.declarationList.declarations) if(d.initializer){const b=bind(d.name,d.initializer); if(b&&b.resolution!=='EXACT')returnResolution=b.resolution;} }
   else if(ts.isReturnStatement(st)){ret=val(st.expression); break;}
 }
 const origins=arr(ret); let res=returnResolution; if(origins.some(x=>x.startsWith('STATE_UNKNOWN:'))&&res==='EXACT')res='UNKNOWN'; if(origins.length>1&&res==='EXACT')res='AMBIGUOUS';
 const positions=[]; fn.parameters.forEach((p,i)=>{if(ts.isIdentifier(p.name)&&origins.includes(`PARAM:${name}.${p.name.text}`))positions.push(i)});
 return {resolution:res,origins,paramPositions:positions,trace};
}
const results={}; for(const [n,f] of funcs)results[n]=evalFn(f); console.log(JSON.stringify(results,null,2));
