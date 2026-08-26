const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2]; if(!file) throw new Error('usage: node indexed_state_model.js gate20.ts');
const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const funcs=new Map(); for(const st of sf.statements) if(ts.isFunctionDeclaration(st)&&st.name) funcs.set(st.name.text,st);
const pos=(fn,n)=>fn.parameters.findIndex(p=>ts.isIdentifier(p.name)&&p.name.text===n);
const isPrimitive=t=>!t || t.kind===ts.SyntaxKind.StringKeyword || t.kind===ts.SyntaxKind.NumberKeyword || t.kind===ts.SyntaxKind.BooleanKeyword;
const isContainerType=t=>!!t && (ts.isArrayTypeNode(t) || ts.isTypeReferenceNode(t));
const litKey=e=>{
  if(ts.isStringLiteral(e)||ts.isNoSubstitutionTemplateLiteral(e)) return `S:${e.text}`;
  if(ts.isNumericLiteral(e)) return `N:${e.text}`;
  return null;
};
const union=(...sets)=>new Set(sets.flatMap(s=>[...(s||[])]));
const arr=s=>[...s].sort();

function evalFn(fn){
  const name=fn.name.text;
  const envVal=new Map(), envObj=new Map();
  fn.parameters.forEach((p,i)=>{ if(!ts.isIdentifier(p.name))return; const n=p.name.text;
    if(isContainerType(p.type) && !isPrimitive(p.type)) envObj.set(n,`PARAMOBJ:${name}.${n}`);
    else envVal.set(n,new Set([`PARAM:${name}.${n}`]));
  });
  let seq=0; const writes=new Map(); const trace=[];
  const objOf=e=>ts.isIdentifier(e)?envObj.get(e.text)||null:null;
  const valueOf=e=>{
    if(!e) return new Set(['CONST:undefined']);
    if(ts.isStringLiteral(e)||ts.isNumericLiteral(e)||e.kind===ts.SyntaxKind.TrueKeyword||e.kind===ts.SyntaxKind.FalseKeyword) return new Set([`CONST:${e.getText(sf)}`]);
    if(ts.isIdentifier(e)) return new Set(envVal.get(e.text)||[`UNKNOWN:VAR:${e.text}`]);
    if(ts.isElementAccessExpression(e)) return readElement(e).values;
    return new Set([`UNKNOWN:EXPR:${e.kind}`]);
  };
  const listFor=o=>{if(!writes.has(o))writes.set(o,[]);return writes.get(o);};
  function writeElement(lhs,rhs){
    const o=objOf(lhs.expression); const key=litKey(lhs.argumentExpression); const vv=valueOf(rhs); seq++;
    if(!o){trace.push({kind:'WRITE',resolution:'UNKNOWN',target:lhs.getText(sf),value:arr(vv)}); return;}
    listFor(o).push({seq,key,value:new Set(vv),dynamic:key===null,keyText:lhs.argumentExpression.getText(sf)});
    trace.push({kind:'WRITE',receiver:o,key:key||`DYNAMIC:${lhs.argumentExpression.getText(sf)}`,resolution:key?'EXACT':'AMBIGUOUS',value:arr(vv)});
  }
  function readExact(o,key){
    const ws=listFor(o); let lastExact=-1, base=new Set([`STATE_UNKNOWN:${o}[${key}]`]);
    for(const w of ws) if(!w.dynamic&&w.key===key&&w.seq>=lastExact){lastExact=w.seq;base=new Set(w.value);}
    let dyn=[]; for(const w of ws) if(w.dynamic&&w.seq>lastExact) dyn.push(w.value);
    const vals=union(base,...dyn); const res=dyn.length?'AMBIGUOUS':(base.size===1&&[...base][0].startsWith('STATE_UNKNOWN:')?'UNKNOWN':'EXACT');
    return {values:vals,resolution:res};
  }
  function readElement(e){
    const o=objOf(e.expression); if(!o)return {values:new Set([`STATE_UNKNOWN:${e.getText(sf)}`]),resolution:'UNKNOWN'};
    const key=litKey(e.argumentExpression);
    if(key){const r=readExact(o,key); trace.push({kind:'READ',receiver:o,key,resolution:r.resolution,value:arr(r.values)}); return r;}
    // Dynamic read may name any known exact slot or a slot not yet seen.
    const exactKeys=[...new Set(listFor(o).filter(w=>!w.dynamic).map(w=>w.key))];
    let vals=new Set([`STATE_UNKNOWN:${o}[*]`]);
    for(const k of exactKeys) vals=union(vals,readExact(o,k).values);
    for(const w of listFor(o).filter(w=>w.dynamic)) vals=union(vals,w.value);
    trace.push({kind:'READ',receiver:o,key:`DYNAMIC:${e.argumentExpression.getText(sf)}`,resolution:'AMBIGUOUS',value:arr(vals)});
    return {values:vals,resolution:'AMBIGUOUS'};
  }
  let ret={values:new Set(['CONST:undefined']),resolution:'EXACT'};
  for(const st of fn.body?.statements||[]){
    if(ts.isExpressionStatement(st)&&ts.isBinaryExpression(st.expression)&&st.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken){
      const l=st.expression.left,r=st.expression.right;
      if(ts.isElementAccessExpression(l)) writeElement(l,r);
      else if(ts.isIdentifier(l)) envVal.set(l.text,valueOf(r));
    } else if(ts.isReturnStatement(st)){
      if(ts.isElementAccessExpression(st.expression)) ret=readElement(st.expression);
      else ret={values:valueOf(st.expression),resolution:'EXACT'};
      break;
    }
  }
  const origins=arr(ret.values);
  const paramPositions=[];
  for(const v of origins){const m=v.match(new RegExp(`^PARAM:${name}\\.([A-Za-z_$][\\w$]*)$`)); if(m){const i=pos(fn,m[1]);if(i>=0)paramPositions.push(i);}}
  let resolution=ret.resolution;
  if(origins.some(x=>x.startsWith('STATE_UNKNOWN:')) && resolution==='EXACT') resolution='UNKNOWN';
  if(origins.length>1 && resolution==='EXACT') resolution='AMBIGUOUS';
  return {resolution,origins,paramPositions:[...new Set(paramPositions)].sort((a,b)=>a-b),trace};
}
const results={}; for(const [n,f] of funcs) results[n]=evalFn(f);
console.log(JSON.stringify(results,null,2));
