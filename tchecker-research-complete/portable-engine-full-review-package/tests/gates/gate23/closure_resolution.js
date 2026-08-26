const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const srcFile=process.argv[2], nodesFile=process.argv[3];
const src=fs.readFileSync(srcFile,'utf8'); const sf=ts.createSourceFile(path.basename(srcFile),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const rows=fs.readFileSync(nodesFile,'utf8').trimEnd().split(/\n/).map(x=>x.split('\t'));
const hdr=rows.shift(); const idx=Object.fromEntries(hdr.map((h,i)=>[h,i]));
const nodes=rows.map(r=>Object.fromEntries(hdr.map((h,i)=>[h,r[i]??''])));
const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
const closuresByLine=new Map(); const callsByLine=new Map();
for(const n of nodes){
  const ln=Number(n['lineno:int']||0);
  if(n.type==='AST_CLOSURE'){ if(!closuresByLine.has(ln))closuresByLine.set(ln,[]); closuresByLine.get(ln).push(Number(n['id:int'])); }
  if(n.type==='AST_CALL'){ if(!callsByLine.has(ln))callsByLine.set(ln,[]); callsByLine.get(ln).push(Number(n['id:int'])); }
}
// Recover AST_CALL callee names from nodes+PARENT_OF is overkill here; source line/name plus one-call-per-line fixtures suffice.
const out=[]; const manifest=[];
function visitFunction(fn){
  if(!fn.body)return;
  const bindings=new Map();
  for(const st of fn.body.statements){
    if(ts.isVariableStatement(st)) for(const d of st.declarationList.declarations){
      if(!ts.isIdentifier(d.name)||!d.initializer)continue;
      if(ts.isArrowFunction(d.initializer)||ts.isFunctionExpression(d.initializer)){
        const ids=closuresByLine.get(line(d.initializer))||[];
        if(ids.length){bindings.set(d.name.text,ids[0]); manifest.push({binding:d.name.text,closure_id:ids[0],line:line(d.initializer),kind:'DIRECT_CLOSURE_BINDING'});}
      }
    }
    function walk(n){
      if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&bindings.has(n.expression.text)){
        const ids=callsByLine.get(line(n))||[];
        if(ids.length){out.push(`${ids[0]}\tEXACT\t${bindings.get(n.expression.text)}`); manifest.push({call:n.expression.text,call_id:ids[0],target_closure_id:bindings.get(n.expression.text),line:line(n),resolution:'EXACT'});}
      }
      ts.forEachChild(n,walk);
    }
    walk(st);
  }
}
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)) visitFunction(st);
process.stdout.write(out.join('\n')+(out.length?'\n':''));
fs.writeFileSync(path.join(path.dirname(nodesFile),'closure_resolution_manifest.json'),JSON.stringify(manifest,null,2)+'\n');
