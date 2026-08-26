// Gate 10: narrow, language-frontend state-summary model.
// No security semantics. Models exact receiver+property state only.
const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2];
if(!file) throw new Error('usage: node state_model.js fixture.ts');
const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
const classes=new Map(), functions=new Map(), classProps=new Map();
for(const st of sf.statements){
  if(ts.isClassDeclaration(st)&&st.name){
    const cn=st.name.text, methods=new Map(), props=new Map();
    for(const m of st.members){
      if(ts.isMethodDeclaration(m)&&m.name&&ts.isIdentifier(m.name)) methods.set(m.name.text,m);
      if(ts.isPropertyDeclaration(m)&&m.name&&ts.isIdentifier(m.name)){
        let t='UNKNOWN'; if(m.type&&ts.isTypeReferenceNode(m.type)&&ts.isIdentifier(m.type.typeName)) t=m.type.typeName.text;
        props.set(m.name.text,t);
      }
    }
    classes.set(cn,methods); classProps.set(cn,props);
  } else if(ts.isFunctionDeclaration(st)&&st.name) functions.set(st.name.text,st);
}
function typeName(t){ if(t&&ts.isTypeReferenceNode(t)&&ts.isIdentifier(t.typeName))return t.typeName.text; if(t&&t.kind===ts.SyntaxKind.StringKeyword)return 'string'; return 'UNKNOWN'; }
function cloneHeap(h){ return new Map([...h].map(([k,v])=>[k,new Set(v)])); }
function union(a,b){ return new Set([...(a||[]),...(b||[])]); }
function arr(s){return [...s].sort();}
function isObjType(t){return classes.has(t);}

function methodClassFor(receiverType, method){
  if(receiverType && classes.get(receiverType)?.has(method)) return receiverType;
  return null;
}

function runFunction(fn, actuals, heap, depth=0, trace=[]){
  if(depth>12) return {value:new Set(['UNKNOWN:DEPTH']),heap};
  const envV=new Map(), envO=new Map(), envT=new Map();
  fn.parameters.forEach((p,i)=>{
    if(!ts.isIdentifier(p.name))return;
    const n=p.name.text, a=actuals[i]||{}; const t=typeName(p.type); envT.set(n,t);
    if(a.obj) envO.set(n,a.obj); else if(isObjType(t)) envO.set(n,`PARAMOBJ:${fn.name?.text||'<anon>'}.${n}`);
    if(a.value) envV.set(n,new Set(a.value)); else if(!isObjType(t)) envV.set(n,new Set([`PARAM:${fn.name?.text||'<anon>'}.${n}`]));
  });
  function objOf(e){
    if(ts.isIdentifier(e)) return envO.get(e.text)||null;
    if(ts.isPropertyAccessExpression(e)) { const b=objOf(e.expression); return b?`${b}.${e.name.text}`:null; }
    if(ts.isNewExpression(e)&&ts.isIdentifier(e.expression)) return `ALLOC:${fn.name?.text||'<anon>'}:${line(e)}:${e.expression.text}`;
    return null;
  }
  function typeOfObjExpr(e){
    if(ts.isIdentifier(e)) return envT.get(e.text)||null;
    if(ts.isNewExpression(e)&&ts.isIdentifier(e.expression)) return e.expression.text;
    if(ts.isPropertyAccessExpression(e)) { const bt=typeOfObjExpr(e.expression); return bt?classProps.get(bt)?.get(e.name.text)||null:null; }
    return null;
  }
  function valOf(e){
    if(!e) return new Set(['CONST:undefined']);
    if(ts.isStringLiteral(e)||ts.isNumericLiteral(e)||e.kind===ts.SyntaxKind.TrueKeyword||e.kind===ts.SyntaxKind.FalseKeyword) return new Set([`CONST:${e.getText(sf)}`]);
    if(ts.isIdentifier(e)) return new Set(envV.get(e.text)||[`UNKNOWN:VAR:${e.text}`]);
    if(ts.isPropertyAccessExpression(e)) {
      const o=objOf(e.expression); if(!o)return new Set([`UNKNOWN:PROP:${e.getText(sf)}`]);
      return new Set(heap.get(`${o}.${e.name.text}`)||[`STATE_UNKNOWN:${o}.${e.name.text}`]);
    }
    if(ts.isCallExpression(e)) return callExpr(e).value;
    if(ts.isNewExpression(e)) return new Set([`OBJECT:${objOf(e)}`]);
    return new Set([`UNKNOWN:EXPR:${e.kind}`]);
  }
  function actualOf(e){
    const o=objOf(e); if(o) return {obj:o,type:typeOfObjExpr(e)};
    return {value:valOf(e)};
  }
  function callExpr(e){
    if(ts.isIdentifier(e.expression)){
      const callee=functions.get(e.expression.text);
      if(!callee)return {value:new Set([`UNKNOWN:CALL:${e.expression.text}`])};
      const acts=e.arguments.map(actualOf);
      trace.push({kind:'CALL',line:line(e),target:e.expression.text});
      return runFunction(callee,acts,heap,depth+1,trace);
    }
    if(ts.isPropertyAccessExpression(e.expression)){
      const recv=e.expression.expression, meth=e.expression.name.text, recvObj=objOf(recv), recvType=typeOfObjExpr(recv);
      const cls=methodClassFor(recvType,meth);
      if(!recvObj||!cls){ return {value:new Set([`UNKNOWN:DISPATCH:${meth}`])}; }
      const md=classes.get(cls).get(meth); const pnames=md.parameters.map(p=>ts.isIdentifier(p.name)?p.name.text:'?');
      const pvals=new Map(); md.parameters.forEach((p,i)=>{if(ts.isIdentifier(p.name))pvals.set(p.name.text,valOf(e.arguments[i]));});
      let rv=new Set(['CONST:undefined']);
      trace.push({kind:'METHOD',line:line(e),target:`${cls}.${meth}`,receiver:recvObj});
      if(md.body) for(const st of md.body.statements){
        if(ts.isExpressionStatement(st)&&ts.isBinaryExpression(st.expression)&&st.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken){
          const lhs=st.expression.left;
          if(ts.isPropertyAccessExpression(lhs)&&lhs.expression.kind===ts.SyntaxKind.ThisKeyword){
            const prop=lhs.name.text, rhs=st.expression.right;
            let vv;
            if(ts.isIdentifier(rhs)&&pvals.has(rhs.text)) vv=new Set(pvals.get(rhs.text));
            else if(ts.isStringLiteral(rhs)||ts.isNumericLiteral(rhs)) vv=new Set([`CONST:${rhs.getText(sf)}`]);
            else vv=new Set([`UNKNOWN:METHOD_WRITE:${rhs.getText(sf)}`]);
            heap.set(`${recvObj}.${prop}`,vv);
            trace.push({kind:'WRITE',target:`${cls}.${meth}`,state:`${recvObj}.${prop}`,value:arr(vv)});
          }
        }
        if(ts.isReturnStatement(st)){
          const re=st.expression;
          if(ts.isPropertyAccessExpression(re)&&re.expression.kind===ts.SyntaxKind.ThisKeyword){
            const key=`${recvObj}.${re.name.text}`; rv=new Set(heap.get(key)||[`STATE_UNKNOWN:${key}`]);
            trace.push({kind:'READ_RETURN',target:`${cls}.${meth}`,state:key,value:arr(rv)});
          } else if(ts.isIdentifier(re)&&pvals.has(re.text)) rv=new Set(pvals.get(re.text));
          else rv=valOf(re);
        }
      }
      return {value:rv,heap};
    }
    return {value:new Set(['UNKNOWN:CALL_EXPR'])};
  }
  let ret=new Set(['CONST:undefined']);
  if(fn.body) for(const st of fn.body.statements){
    if(ts.isVariableStatement(st)) for(const d of st.declarationList.declarations){
      if(!ts.isIdentifier(d.name))continue; const n=d.name.text;
      if(d.initializer){ const o=objOf(d.initializer); if(o){envO.set(n,o); envT.set(n,typeOfObjExpr(d.initializer)||typeName(d.type));} else envV.set(n,valOf(d.initializer)); }
    } else if(ts.isExpressionStatement(st)){
      const e=st.expression;
      if(ts.isCallExpression(e)) callExpr(e);
      else if(ts.isBinaryExpression(e)&&e.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isIdentifier(e.left)) envV.set(e.left.text,valOf(e.right));
    } else if(ts.isReturnStatement(st)){ ret=valOf(st.expression); break; }
  }
  return {value:ret,heap};
}

const targets=['aliasSame','aliasAllocation','aliasOverwrite','aliasDistinct','aliasDifferentField','aliasDifferentParams'];
const results={};
for(const name of targets){
  const fn=functions.get(name); if(!fn)continue; const heap=new Map(), trace=[];
  const actuals=fn.parameters.map(p=>{const t=typeName(p.type); const n=ts.isIdentifier(p.name)?p.name.text:'?'; return isObjType(t)?{obj:`PARAMOBJ:${name}.${n}`,type:t}:{value:new Set([`PARAM:${name}.${n}`])};});
  const r=runFunction(fn,actuals,heap,0,trace);
  results[name]={origins:arr(r.value),trace,finalState:Object.fromEntries([...r.heap].map(([k,v])=>[k,arr(v)]))};
}
console.log(JSON.stringify(results,null,2));
