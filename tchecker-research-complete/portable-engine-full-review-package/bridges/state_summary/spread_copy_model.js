const ts=require('/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js');
const fs=require('fs'), path=require('path');
const file=process.argv[2]; const src=fs.readFileSync(file,'utf8');
const sf=ts.createSourceFile(path.basename(file),src,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
const funcs=new Map(); for(const st of sf.statements) if(ts.isFunctionDeclaration(st)&&st.name) funcs.set(st.name.text,st);
const arr=s=>[...s].sort();
const union=(...ss)=>new Set(ss.flatMap(s=>[...(s||[])]));
const litKey=e=>ts.isStringLiteral(e)||ts.isNoSubstitutionTemplateLiteral(e)?`S:${e.text}`:ts.isNumericLiteral(e)?`N:${e.text}`:null;
const worst=(a,b)=>{const rank={EXACT:0,AMBIGUOUS:1,UNKNOWN:2}; return rank[a]>=rank[b]?a:b;};

function evalFn(fn){
  const name=fn.name.text, envV=new Map(), envO=new Map(), heaps=new Map(); let seq=0;
  fn.parameters.forEach((p,i)=>{ if(!ts.isIdentifier(p.name)) return; const n=p.name.text,t=p.type;
    const container=!!t&&(ts.isArrayTypeNode(t)||(ts.isTypeReferenceNode(t)&&t.typeName.getText(sf)==='Record'));
    if(container){ const oid=`PARAMOBJ:${name}.${n}`; envO.set(n,oid); heaps.set(oid,[]); }
    else envV.set(n,new Set([`PARAM:${name}.${n}`]));
  });
  const ws=o=>{if(!heaps.has(o))heaps.set(o,[]); return heaps.get(o)};
  const objOf=e=>ts.isIdentifier(e)?envO.get(e.text)||null:null;
  function val(e){
    if(!e)return new Set(['CONST:undefined']);
    if(ts.isStringLiteral(e)||ts.isNumericLiteral(e))return new Set([`CONST:${e.getText(sf)}`]);
    if(ts.isIdentifier(e))return new Set(envV.get(e.text)||[`UNKNOWN:VAR:${e.text}`]);
    if(ts.isElementAccessExpression(e))return read(e).values;
    return new Set([`UNKNOWN:EXPR:${e.kind}`]);
  }
  function writeSlot(o,key,values,dynamic=false){seq++; ws(o).push({seq,key,value:new Set(values),dynamic});}
  function write(lhs,rhs){const o=objOf(lhs.expression), key=litKey(lhs.argumentExpression), v=val(rhs); if(o)writeSlot(o,key,v,key===null);}
  function exact(o,key){
    let last=-1, base=new Set([`STATE_UNKNOWN:${o}[${key}]`]);
    for(const w of ws(o)) if(!w.dynamic&&w.key===key&&w.seq>=last){last=w.seq;base=new Set(w.value)}
    const dyn=ws(o).filter(w=>w.dynamic&&w.seq>last).map(w=>w.value);
    const values=union(base,...dyn);
    return {values,resolution:dyn.length?'AMBIGUOUS':([...values].some(x=>x.startsWith('STATE_UNKNOWN:'))?'UNKNOWN':'EXACT')};
  }
  function read(e){const o=objOf(e.expression); if(!o)return {values:new Set([`STATE_UNKNOWN:${e.getText(sf)}`]),resolution:'UNKNOWN'}; const key=litKey(e.argumentExpression); if(key)return exact(o,key); let values=new Set([`STATE_UNKNOWN:${o}[*]`]); for(const k of [...new Set(ws(o).filter(w=>!w.dynamic).map(w=>w.key))])values=union(values,exact(o,k).values); return {values,resolution:'AMBIGUOUS'};}
  function copyObjectLiteral(expr,target){
    let res='EXACT';
    for(const p of expr.properties){
      if(ts.isSpreadAssignment(p)){
        const srcObj=objOf(p.expression);
        if(!srcObj){res=worst(res,'UNKNOWN'); continue;}
        // Snapshot-copy all known exact slots at this point. Dynamic writes make copied slots MAY.
        const keys=[...new Set(ws(srcObj).filter(w=>!w.dynamic).map(w=>w.key))];
        for(const k of keys){const r=exact(srcObj,k); writeSlot(target,k,r.values,false); res=worst(res,r.resolution);}
        if(ws(srcObj).some(w=>w.dynamic)){ writeSlot(target,null,new Set([`STATE_UNKNOWN:SPREAD:${srcObj}[*]`]),true); res=worst(res,'AMBIGUOUS'); }
      } else if(ts.isPropertyAssignment(p)){
        const key=ts.isIdentifier(p.name)?`S:${p.name.text}`:ts.isStringLiteral(p.name)?`S:${p.name.text}`:ts.isNumericLiteral(p.name)?`N:${p.name.text}`:null;
        writeSlot(target,key,val(p.initializer),key===null); if(key===null)res=worst(res,'AMBIGUOUS');
      } else if(ts.isShorthandPropertyAssignment(p)){
        writeSlot(target,`S:${p.name.text}`,val(p.name),false);
      }
    }
    return res;
  }
  function knownArrayLength(o){const ks=ws(o).filter(w=>!w.dynamic&&w.key&&w.key.startsWith('N:')).map(w=>Number(w.key.slice(2))); return ks.length?Math.max(...ks)+1:0;}
  function copyArrayLiteral(expr,target){
    let res='EXACT', outIdx=0;
    for(const el of expr.elements){
      if(ts.isSpreadElement(el)){
        const srcObj=objOf(el.expression); if(!srcObj){res=worst(res,'UNKNOWN'); continue;}
        const len=knownArrayLength(srcObj);
        for(let i=0;i<len;i++){const r=exact(srcObj,`N:${i}`); writeSlot(target,`N:${outIdx++}`,r.values,false); res=worst(res,r.resolution);}
        if(ws(srcObj).some(w=>w.dynamic)){writeSlot(target,null,new Set([`STATE_UNKNOWN:SPREAD:${srcObj}[*]`]),true);res=worst(res,'AMBIGUOUS');}
      } else {writeSlot(target,`N:${outIdx++}`,val(el),false);}
    }
    return res;
  }
  let returnResolution='EXACT', ret=new Set(['CONST:undefined']);
  for(const st of fn.body.statements){
    if(ts.isExpressionStatement(st)&&ts.isBinaryExpression(st.expression)&&st.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isElementAccessExpression(st.expression.left)) write(st.expression.left,st.expression.right);
    else if(ts.isVariableStatement(st)) for(const d of st.declarationList.declarations){if(!d.initializer||!ts.isIdentifier(d.name))continue; const n=d.name.text;
      if(ts.isObjectLiteralExpression(d.initializer)){const oid=`ALLOC:${name}.${n}`; envO.set(n,oid); heaps.set(oid,[]); returnResolution=worst(returnResolution,copyObjectLiteral(d.initializer,oid));}
      else if(ts.isArrayLiteralExpression(d.initializer)){const oid=`ALLOC:${name}.${n}`; envO.set(n,oid); heaps.set(oid,[]); returnResolution=worst(returnResolution,copyArrayLiteral(d.initializer,oid));}
      else if(objOf(d.initializer)) envO.set(n,objOf(d.initializer)); else envV.set(n,val(d.initializer));
    }
    else if(ts.isReturnStatement(st)){ret=val(st.expression); if(ts.isElementAccessExpression(st.expression))returnResolution=worst(returnResolution,read(st.expression).resolution); break;}
  }
  const origins=arr(ret); let res=returnResolution; if(origins.some(x=>x.startsWith('STATE_UNKNOWN:'))&&res==='EXACT')res='UNKNOWN'; if(origins.length>1&&res==='EXACT')res='AMBIGUOUS';
  const positions=[]; fn.parameters.forEach((p,i)=>{if(ts.isIdentifier(p.name)&&origins.includes(`PARAM:${name}.${p.name.text}`))positions.push(i)});
  return {resolution:res,origins,paramPositions:positions};
}
const results={}; for(const [n,f] of funcs)results[n]=evalFn(f); console.log(JSON.stringify(results,null,2));
