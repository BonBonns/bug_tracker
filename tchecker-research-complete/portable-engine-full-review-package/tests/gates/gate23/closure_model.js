const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2]; const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);

const union=(...sets)=>new Set(sets.flatMap(s=>[...(s||[])]));
const arr=s=>[...s].sort();
class Cell { constructor(values){this.values=new Set(values||[]);} }
class ClosureValue { constructor(node,captured){this.node=node;this.captured=captured;} }
const funcs=new Map();
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)&&st.name) funcs.set(st.name.text,st);

function makeEnv(parent=null){ return {parent, bindings:new Map()}; }
function lookupCell(env,name){ for(let e=env;e;e=e.parent) if(e.bindings.has(name)) return e.bindings.get(name); return null; }
function declare(env,name,values){ const c=values instanceof Cell?values:new Cell(values); env.bindings.set(name,c); return c; }
function assign(env,name,values){ const c=lookupCell(env,name); if(c){ c.values=new Set(values); return c; } return declare(env,name,values); }

function freeVars(node,paramNames,localNames){
  const free=new Set();
  function walk(n, parent){
    if(ts.isIdentifier(n)){
      // Ignore declaration names, property names, and direct callee names for globally declared functions.
      if(parent){
        if((ts.isVariableDeclaration(parent)&&parent.name===n) ||
           ((ts.isArrowFunction(parent)||ts.isFunctionExpression(parent))&&parent.parameters.some(p=>p.name===n)) ||
           (ts.isPropertyAccessExpression(parent)&&parent.name===n) ||
           (ts.isPropertyAssignment(parent)&&parent.name===n) ||
           (ts.isFunctionDeclaration(parent)&&parent.name===n)) return;
        if(ts.isCallExpression(parent)&&parent.expression===n&&funcs.has(n.text)) return;
      }
      if(!paramNames.has(n.text)&&!localNames.has(n.text)) free.add(n.text);
      return;
    }
    ts.forEachChild(n,c=>walk(c,n));
  }
  walk(node,null); return free;
}
function localDecls(fn){ const s=new Set(); if(ts.isBlock(fn.body)) for(const st of fn.body.statements) if(ts.isVariableStatement(st)) for(const d of st.declarationList.declarations) if(ts.isIdentifier(d.name))s.add(d.name.text); return s; }
function makeClosure(node,env){
  const params=new Set(node.parameters.filter(p=>ts.isIdentifier(p.name)).map(p=>p.name.text));
  const locals=localDecls(node);
  const captured=new Map();
  for(const name of freeVars(node.body,params,locals)){
    const c=lookupCell(env,name); if(c) captured.set(name,c);
  }
  return new ClosureValue(node,captured);
}

function evalExpr(e,env){
  if(!e) return {origins:new Set(['CONST:undefined']), closure:null};
  if(ts.isParenthesizedExpression(e)) return evalExpr(e.expression,env);
  if(ts.isStringLiteral(e)||ts.isNumericLiteral(e)||ts.isNoSubstitutionTemplateLiteral(e)||e.kind===ts.SyntaxKind.TrueKeyword||e.kind===ts.SyntaxKind.FalseKeyword)
    return {origins:new Set([`CONST:${e.getText(sf)}`]),closure:null};
  if(ts.isIdentifier(e)){
    const c=lookupCell(env,e.text); return c?{origins:new Set(c.values),closure:c.closure||null}:{origins:new Set([`UNKNOWN:${e.text}`]),closure:null};
  }
  if(ts.isArrowFunction(e)||ts.isFunctionExpression(e)) return {origins:new Set([`CLOSURE@${sf.getLineAndCharacterOfPosition(e.getStart(sf)).line+1}`]),closure:makeClosure(e,env)};
  if(ts.isBinaryExpression(e)){
    if(e.operatorToken.kind===ts.SyntaxKind.EqualsToken && ts.isIdentifier(e.left)){
      const r=evalExpr(e.right,env); const c=assign(env,e.left.text,r.origins); c.closure=r.closure; return r;
    }
    const a=evalExpr(e.left,env), b=evalExpr(e.right,env); return {origins:union(a.origins,b.origins),closure:null};
  }
  if(ts.isConditionalExpression(e)){
    const a=evalExpr(e.whenTrue,env),b=evalExpr(e.whenFalse,env); return {origins:union(a.origins,b.origins),closure:null};
  }
  if(ts.isCallExpression(e)){
    const args=e.arguments.map(a=>evalExpr(a,env));
    if(ts.isIdentifier(e.expression)){
      const c=lookupCell(env,e.expression.text);
      if(c&&c.closure) return callClosure(c.closure,args);
      if(funcs.has(e.expression.text)) return callFunction(funcs.get(e.expression.text),args);
    }
    const cal=evalExpr(e.expression,env); if(cal.closure) return callClosure(cal.closure,args);
    return {origins:new Set([`UNKNOWN:CALL:${e.expression.getText(sf)}`]),closure:null};
  }
  return {origins:new Set([`UNKNOWN:EXPR:${ts.SyntaxKind[e.kind]}`]),closure:null};
}
function execBody(body,env){
  const stmts=ts.isBlock(body)?body.statements:null;
  if(!stmts) return evalExpr(body,env);
  for(const st of stmts){
    if(ts.isVariableStatement(st)){
      for(const d of st.declarationList.declarations){ if(!ts.isIdentifier(d.name)) continue; const r=evalExpr(d.initializer,env); const c=declare(env,d.name.text,r.origins); c.closure=r.closure; }
    } else if(ts.isExpressionStatement(st)) evalExpr(st.expression,env);
    else if(ts.isReturnStatement(st)) return evalExpr(st.expression,env);
  }
  return {origins:new Set(['CONST:undefined']),closure:null};
}
function callClosure(cl,args){
  // Captures point at the original Cells: JS lexical closures capture bindings, not value snapshots.
  const env=makeEnv(null); for(const [n,c] of cl.captured) env.bindings.set(n,c);
  cl.node.parameters.forEach((p,i)=>{ if(!ts.isIdentifier(p.name))return; const r=args[i]||{origins:new Set(['CONST:undefined']),closure:null}; const c=declare(env,p.name.text,r.origins); c.closure=r.closure; });
  return execBody(cl.node.body,env);
}
function callFunction(fn,args){
  const env=makeEnv(null); fn.parameters.forEach((p,i)=>{if(!ts.isIdentifier(p.name))return; const r=args[i]||{origins:new Set(['CONST:undefined']),closure:null}; const c=declare(env,p.name.text,r.origins); c.closure=r.closure;});
  return execBody(fn.body,env);
}
function analyze(fn){
  const args=fn.parameters.map((p,i)=>({origins:new Set([`PARAM:${fn.name.text}.${ts.isIdentifier(p.name)?p.name.text:i}`]),closure:null}));
  const r=callFunction(fn,args); const origins=arr(r.origins); const positions=[];
  fn.parameters.forEach((p,i)=>{if(ts.isIdentifier(p.name)&&origins.includes(`PARAM:${fn.name.text}.${p.name.text}`))positions.push(i)});
  return {origins,paramPositions:positions};
}
const out={}; for(const [n,f] of funcs)out[n]=analyze(f); console.log(JSON.stringify(out,null,2));
