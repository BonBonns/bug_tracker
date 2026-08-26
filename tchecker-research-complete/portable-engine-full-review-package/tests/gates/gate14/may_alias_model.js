const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2]; if(!file) throw new Error('usage: node may_alias_model.js fixture.ts');
const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
const funcs=new Map();
for(const st of sf.statements) if(ts.isFunctionDeclaration(st)&&st.name) funcs.set(st.name.text,st);
const union=(a,b)=>new Set([...(a||[]),...(b||[])]);
const arr=s=>[...s].sort();
const cloneEnv=e=>new Map([...e].map(([k,v])=>[k,new Set(v)]));
const cloneHeap=h=>new Map([...h].map(([k,v])=>[k,new Set(v)]));
function mergeMap(a,b){const o=new Map(); for(const k of new Set([...a.keys(),...b.keys()])) o.set(k,union(a.get(k),b.get(k))); return o;}
function alloc(fn,e){return `ALLOC:${fn}:${line(e)}`;}
function stateKey(obj,prop){return `${obj}.${prop}`;}
function evalFunction(fn){
  const name=fn.name.text; let envO=new Map(), envV=new Map(), heap=new Map(); const trace=[];
  fn.parameters.forEach((p,i)=>{ if(!ts.isIdentifier(p.name)) return; const n=p.name.text; if(p.type&&p.type.kind===ts.SyntaxKind.StringKeyword) envV.set(n,new Set([`PARAM:${name}.${n}`])); else if(p.type&&p.type.kind===ts.SyntaxKind.BooleanKeyword) envV.set(n,new Set([`PARAM:${name}.${n}`])); });
  function objs(e,EO=envO){
    if(ts.isIdentifier(e)) return new Set(EO.get(e.text)||[]);
    if(ts.isNewExpression(e)) return new Set([alloc(name,e)]);
    return new Set();
  }
  function vals(e,EO=envO,EV=envV,H=heap){
    if(!e) return new Set(['CONST:undefined']);
    if(ts.isStringLiteral(e)||ts.isNumericLiteral(e)) return new Set([`CONST:${e.getText(sf)}`]);
    if(ts.isIdentifier(e)) return new Set(EV.get(e.text)||[`UNKNOWN:VAR:${e.text}`]);
    if(ts.isPropertyAccessExpression(e)){
      let out=new Set(); const os=objs(e.expression,EO); if(!os.size) return new Set([`STATE_UNKNOWN:${e.getText(sf)}`]);
      for(const o of os) out=union(out,H.get(stateKey(o,e.name.text))||new Set([`STATE_UNKNOWN:${stateKey(o,e.name.text)}`]));
      return out;
    }
    return new Set([`UNKNOWN:EXPR:${e.kind}`]);
  }
  function methodCall(e,EO=envO,EV=envV,H=heap){
    if(!ts.isCallExpression(e)||!ts.isPropertyAccessExpression(e.expression)) return {value:new Set(['UNKNOWN:CALL']),heap:H};
    const recv=e.expression.expression, method=e.expression.name.text, os=objs(recv,EO);
    const ambiguous=os.size>1;
    trace.push({kind:'METHOD',line:line(e),method,receivers:arr(os),resolution:ambiguous?'AMBIGUOUS':(os.size===1?'EXACT':'UNRESOLVED')});
    if(method==='setValue'||method==='setOther'){
      const prop=method==='setValue'?'value':'other'; const vv=vals(e.arguments[0],EO,EV,H);
      for(const o of os){ const k=stateKey(o,prop); if(ambiguous){ const old=H.get(k)||new Set([`STATE_UNKNOWN:${k}`]); H.set(k,union(old,vv)); } else H.set(k,new Set(vv)); }
      trace.push({kind:'WRITE',property:prop,receivers:arr(os),value:arr(vv),resolution:ambiguous?'AMBIGUOUS':'EXACT'});
      return {value:new Set(['CONST:undefined']),heap:H};
    }
    if(method==='readValue'){
      let out=new Set(); for(const o of os) out=union(out,H.get(stateKey(o,'value'))||new Set([`STATE_UNKNOWN:${stateKey(o,'value')}`]));
      trace.push({kind:'READ',property:'value',receivers:arr(os),value:arr(out),resolution:ambiguous?'AMBIGUOUS':(os.size===1?'EXACT':'UNRESOLVED')});
      return {value:out,heap:H};
    }
    return {value:new Set([`UNKNOWN:METHOD:${method}`]),heap:H};
  }
  function execList(stmts,EO,EV,H){
    let ret=null;
    for(const st of stmts){
      if(ts.isVariableStatement(st)){
        for(const d of st.declarationList.declarations){ if(!ts.isIdentifier(d.name))continue; const n=d.name.text;
          if(d.initializer&&ts.isNewExpression(d.initializer)) EO.set(n,new Set([alloc(name,d.initializer)]));
          else if(d.initializer&&ts.isIdentifier(d.initializer)&&EO.has(d.initializer.text)) EO.set(n,new Set(EO.get(d.initializer.text)));
          else if(d.initializer) EV.set(n,vals(d.initializer,EO,EV,H));
          else EO.set(n,new Set());
        }
      } else if(ts.isIfStatement(st)){
        const thenEO=cloneEnv(EO), thenEV=cloneEnv(EV), thenH=cloneHeap(H);
        const elseEO=cloneEnv(EO), elseEV=cloneEnv(EV), elseH=cloneHeap(H);
        const runBranch=(s,eO,eV,h)=>{ if(ts.isBlock(s)) return execList(s.statements,eO,eV,h); return execList([s],eO,eV,h); };
        runBranch(st.thenStatement,thenEO,thenEV,thenH); if(st.elseStatement) runBranch(st.elseStatement,elseEO,elseEV,elseH);
        EO=mergeMap(thenEO,elseEO); EV=mergeMap(thenEV,elseEV); H=mergeMap(thenH,elseH);
        trace.push({kind:'JOIN',line:line(st),aliases:Object.fromEntries([...EO].map(([k,v])=>[k,arr(v)]))});
      } else if(ts.isExpressionStatement(st)){
        const e=st.expression;
        if(ts.isBinaryExpression(e)&&e.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isIdentifier(e.left)){
          const rhsO=objs(e.right,EO); if(rhsO.size) EO.set(e.left.text,rhsO); else EV.set(e.left.text,vals(e.right,EO,EV,H));
        } else if(ts.isCallExpression(e)) methodCall(e,EO,EV,H);
      } else if(ts.isReturnStatement(st)){
        if(ts.isCallExpression(st.expression)) ret=methodCall(st.expression,EO,EV,H).value; else ret=vals(st.expression,EO,EV,H); break;
      }
    }
    return {envO:EO,envV:EV,heap:H,ret};
  }
  const r=execList(fn.body.statements,envO,envV,heap); const origins=r.ret||new Set(['CONST:undefined']);
  const oa=arr(origins);
  let status='UNKNOWN';
  if(oa.length>1) status='AMBIGUOUS';
  else if(oa.length===1 && (oa[0].startsWith('PARAM:')||oa[0].startsWith('CONST:'))) status='EXACT';
  return {origins:arr(origins),resolution:status,trace};
}
const targets=['mayAliasWrite','sameAliasBothBranches','mayAliasDifferentField','mayAliasOverwrite','mayAliasRead'];
const out={}; for(const n of targets) out[n]=evalFunction(funcs.get(n));
console.log(JSON.stringify(out,null,2));
