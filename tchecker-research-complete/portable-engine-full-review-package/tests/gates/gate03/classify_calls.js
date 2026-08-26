// classify_calls.js — language-front-end resolution-quality sidecar for Gate 3.
// Does not change engine behavior. It records what the JS frontend actually knows.
const ts = require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2], src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.JS);
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
function scanFunction(fn){
  if(!fn.body)return;
  const locals=new Map();
  function walk(n){
    if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.initializer&&ts.isNewExpression(n.initializer)&&ts.isIdentifier(n.initializer.expression)) locals.set(n.name.text,n.initializer.expression.text);
    if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)){
      const recv=n.expression.expression, meth=n.expression.name.text;
      let resolution='UNRESOLVED', targets=[], basis='receiver type not known';
      if(ts.isNewExpression(recv)&&ts.isIdentifier(recv.expression)){
        const cls=recv.expression.text; if(classes.get(cls)?.has(meth)){resolution='EXACT'; targets=[`${cls}.${meth}`]; basis='direct new-expression receiver';}
      } else if(ts.isIdentifier(recv)&&locals.has(recv.text)){
        const cls=locals.get(recv.text); if(classes.get(cls)?.has(meth)){resolution='EXACT'; targets=[`${cls}.${meth}`]; basis=`local ${recv.text} assigned new ${cls}`;}
      } else {
        const cs=methods.get(meth)||[];
        if(cs.length>1){resolution='AMBIGUOUS'; targets=cs.map(c=>`${c}.${meth}`); basis='untyped/dynamic receiver with multiple in-scope implementations';}
        else if(cs.length===1){resolution='HEURISTIC'; targets=[`${cs[0]}.${meth}`]; basis='untyped/dynamic receiver; only one in-scope implementation';}
      }
      out.push({line:line(n),method:meth,resolution,targets,basis});
    }
    ts.forEachChild(n,walk);
  }
  walk(fn.body);
}
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)) scanFunction(st);
console.log(JSON.stringify(out,null,2));
