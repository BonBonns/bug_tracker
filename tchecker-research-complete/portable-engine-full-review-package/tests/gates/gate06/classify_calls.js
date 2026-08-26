// Gate 5: TypeScript property-type narrowing sidecar.
const ts = require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2], src=fs.readFileSync(file,'utf8');
const kind=file.endsWith('.ts')||file.endsWith('.tsx')?ts.ScriptKind.TS:ts.ScriptKind.JS;
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,kind);
const classes=new Map(), methods=new Map(), classProps=new Map();
const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
function typeNames(type){
  if(!type) return [];
  if(ts.isTypeReferenceNode(type)&&ts.isIdentifier(type.typeName)) return [type.typeName.text];
  if(ts.isUnionTypeNode(type)) return type.types.flatMap(typeNames);
  return [];
}
for(const st of sf.statements){
  if(ts.isClassDeclaration(st)&&st.name){
    const cn=st.name.text, ms=new Set(), props=new Map();
    for(const m of st.members){
      if(ts.isMethodDeclaration(m)&&m.name&&ts.isIdentifier(m.name)){
        ms.add(m.name.text); if(!methods.has(m.name.text))methods.set(m.name.text,[]); methods.get(m.name.text).push(cn);
      } else if(ts.isPropertyDeclaration(m)&&m.name&&ts.isIdentifier(m.name)) {
        props.set(m.name.text,typeNames(m.type));
      }
    }
    classes.set(cn,ms); classProps.set(cn,props);
  }
}
function resolveExprTypes(expr, locals, declared){
  if(ts.isNewExpression(expr)&&ts.isIdentifier(expr.expression)) return {types:[expr.expression.text],basis:'direct new-expression receiver'};
  if(ts.isIdentifier(expr)){
    if(locals.has(expr.text)) return {types:locals.get(expr.text),basis:`local ${expr.text} has known type`};
    if(declared.has(expr.text)&&declared.get(expr.text).length) return {types:declared.get(expr.text),basis:`TypeScript parameter annotation on ${expr.text}`};
    return {types:[],basis:`receiver ${expr.text} type not known`};
  }
  if(ts.isPropertyAccessExpression(expr)){
    const base=resolveExprTypes(expr.expression,locals,declared);
    if(!base.types.length) return {types:[],basis:`${base.basis}; property ${expr.name.text} type not known`};
    const out=[];
    for(const t of base.types){
      for(const pt of (classProps.get(t)?.get(expr.name.text)||[])) out.push(pt);
    }
    return {types:[...new Set(out)],basis:`${base.basis}; property ${expr.name.text} annotation on ${base.types.join('|')}`};
  }
  return {types:[],basis:'receiver expression type not modeled'};
}
const out=[];
function scanFunction(fn){
  if(!fn.body)return;
  const locals=new Map(), declared=new Map();
  for(const p of fn.parameters) if(ts.isIdentifier(p.name)) declared.set(p.name.text,typeNames(p.type));
  function walk(n){
    if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)){
      if(n.initializer&&ts.isNewExpression(n.initializer)&&ts.isIdentifier(n.initializer.expression)) locals.set(n.name.text,[n.initializer.expression.text]);
      else { const t=typeNames(n.type); if(t.length) locals.set(n.name.text,t); }
    }
    if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)){
      const recv=n.expression.expression, meth=n.expression.name.text;
      let {types,basis}=resolveExprTypes(recv,locals,declared);
      let resolution='UNRESOLVED', targets=[];
      if(types.length){
        targets=types.filter(c=>classes.get(c)?.has(meth)).map(c=>`${c}.${meth}`);
        if(targets.length===1 && types.length===1) resolution='EXACT';
        else if(targets.length>1) resolution='AMBIGUOUS';
        else resolution='UNRESOLVED';
      } else {
        const cs=methods.get(meth)||[];
        if(cs.length>1){resolution='AMBIGUOUS';targets=cs.map(c=>`${c}.${meth}`);basis += '; multiple in-scope implementations';}
        else if(cs.length===1){resolution='HEURISTIC';targets=[`${cs[0]}.${meth}`];basis += '; only one in-scope implementation';}
      }
      out.push({line:line(n),method:meth,resolution,targets,basis,receiverTypes:types});
    }
    ts.forEachChild(n,walk);
  }
  walk(fn.body);
}
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)) scanFunction(st);
console.log(JSON.stringify(out,null,2));
