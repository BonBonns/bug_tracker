// Gate 4: TypeScript receiver-type narrowing sidecar.
const ts = require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2], src=fs.readFileSync(file,'utf8');
const kind=file.endsWith('.ts')||file.endsWith('.tsx')?ts.ScriptKind.TS:ts.ScriptKind.JS;
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,kind);
const classes=new Map(), methods=new Map();
for(const st of sf.statements){
  if(ts.isClassDeclaration(st)&&st.name){
    const cn=st.name.text, ms=new Set();
    for(const m of st.members) if(ts.isMethodDeclaration(m)&&m.name&&ts.isIdentifier(m.name)){
      ms.add(m.name.text); if(!methods.has(m.name.text))methods.set(m.name.text,[]); methods.get(m.name.text).push(cn);
    }
    classes.set(cn,ms);
  }
}
const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
const out=[];
function typeNames(type){
  if(!type) return [];
  if(ts.isTypeReferenceNode(type)&&ts.isIdentifier(type.typeName)) return [type.typeName.text];
  if(ts.isUnionTypeNode(type)) return type.types.flatMap(typeNames);
  return [];
}
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
      let resolution='UNRESOLVED', targets=[], basis='receiver type not known';
      let types=[];
      if(ts.isNewExpression(recv)&&ts.isIdentifier(recv.expression)){ types=[recv.expression.text]; basis='direct new-expression receiver'; }
      else if(ts.isIdentifier(recv)&&locals.has(recv.text)){ types=locals.get(recv.text); basis=`local ${recv.text} has known type`; }
      else if(ts.isIdentifier(recv)&&declared.has(recv.text)&&declared.get(recv.text).length){ types=declared.get(recv.text); basis=`TypeScript parameter annotation on ${recv.text}`; }
      if(types.length){
        targets=types.filter(c=>classes.get(c)?.has(meth)).map(c=>`${c}.${meth}`);
        if(targets.length===1 && types.length===1) resolution='EXACT';
        else if(targets.length>1) resolution='AMBIGUOUS';
        else resolution='UNRESOLVED';
      } else {
        const cs=methods.get(meth)||[];
        if(cs.length>1){resolution='AMBIGUOUS';targets=cs.map(c=>`${c}.${meth}`);basis='untyped/dynamic receiver with multiple in-scope implementations';}
        else if(cs.length===1){resolution='HEURISTIC';targets=[`${cs[0]}.${meth}`];basis='untyped/dynamic receiver; only one in-scope implementation';}
      }
      out.push({line:line(n),method:meth,resolution,targets,basis});
    }
    ts.forEachChild(n,walk);
  }
  walk(fn.body);
}
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)) scanFunction(st);
console.log(JSON.stringify(out,null,2));
