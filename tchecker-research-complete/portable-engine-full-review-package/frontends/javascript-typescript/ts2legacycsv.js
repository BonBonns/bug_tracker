// tsclass2csv.js — Gate 3 prototype: JS/TS class+method adapter into joern-php CSV contract.
// Uses the TypeScript compiler API already present globally in this environment.
const ts = (() => {
  const candidates = [process.env.TYPESCRIPT_LIB, 'typescript', '/opt/nvm/versions/node/v22.16.0/lib/node_modules/typescript/lib/typescript.js'];
  for (const c of candidates) { if (!c) continue; try { return require(c); } catch (_) {} }
  throw new Error('TypeScript compiler API not found. Install typescript or set TYPESCRIPT_LIB.');
})();
const fs = require('fs'), path = require('path');

function toCsv(source, file='gate3.js') {
  let id = 0;
  const nodes=[], rels=[], closureCaptures=[];
  const mkNode=(type,o={})=>{ const n={
    id:id++, label:o.label??'AST', flags:o.flags??'', type,
    lineno:o.lineno??0, code:o.code??'', childnum:o.childnum??0,
    funcid:o.funcid??0, classname:o.classname??'', namespace:o.namespace??'',
    endlineno:o.endlineno??'', name:o.name??'', doccomment:''
  }; nodes.push(n); return n.id; };
  const parent=(p,c)=>rels.push({start:p,end:c,type:'PARENT_OF'});
  const scriptKind = file.endsWith('.ts') || file.endsWith('.tsx') ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sf=ts.createSourceFile(file,source,ts.ScriptTarget.ES2022,true,scriptKind);
  const line=n=>{ try { return sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1; } catch(_) { return 0; } };
  const endline=n=>sf.getLineAndCharacterOfPosition(n.getEnd()).line+1;

  function allocScope(type,o={}) {
    const fid=mkNode(type,o);
    const entry=mkNode('CFG_FUNC_ENTRY',{label:'Artificial',funcid:fid,lineno:o.lineno??0,name:o.name??''});
    const exit =mkNode('CFG_FUNC_EXIT',{label:'Artificial',funcid:fid,lineno:o.lineno??0,name:o.name??''});
    rels.push({start:fid,end:entry,type:'ENTRY'});
    rels.push({start:fid,end:exit,type:'EXIT'});
    return {fid,entry,exit};
  }

  const dir=mkNode('Directory',{label:'Filesystem',name:'"."'});
  const fnode=mkNode('File',{label:'Filesystem',name:`"${file}"`});
  rels.push({start:dir,end:fnode,type:'DIRECTORY_OF'});
  const T=allocScope('AST_TOPLEVEL',{flags:'TOPLEVEL_FILE',lineno:1,endlineno:endline(sf),name:`"./${file}"`});
  const topList=mkNode('AST_STMT_LIST',{childnum:0,funcid:T.fid,lineno:1}); parent(T.fid,topList);

  let topChild=0;
  for(const st of sf.statements) {
    if(ts.isClassDeclaration(st) && st.name) emitClass(st,topList,T.fid,topChild++);
    else if(ts.isFunctionDeclaration(st) && st.name) emitFunction(st,topList,T.fid,topChild++,'');
  }

  function emitClass(cls,parentList,enclosingFid,childnum) {
    const className=cls.name.text;
    const cid=mkNode('AST_CLASS',{funcid:enclosingFid,childnum,lineno:line(cls),endlineno:endline(cls),name:className});
    parent(parentList,cid);
    parent(cid,mkNode('NULL',{childnum:0,funcid:enclosingFid,lineno:line(cls)})); // extends
    parent(cid,mkNode('NULL',{childnum:1,funcid:enclosingFid,lineno:line(cls)})); // implements
    const CT=allocScope('AST_TOPLEVEL',{flags:'TOPLEVEL_CLASS',funcid:enclosingFid,childnum:2,lineno:line(cls),endlineno:endline(cls),name:`"${className}"`});
    parent(cid,CT.fid);
    const body=mkNode('AST_STMT_LIST',{childnum:0,funcid:CT.fid,lineno:line(cls)}); parent(CT.fid,body);
    let cn=0;
    for(const m of cls.members) {
      if(ts.isMethodDeclaration(m) && m.name && ts.isIdentifier(m.name)) emitMethod(m,body,CT.fid,cn++,className);
      else if(ts.isPropertyDeclaration(m) && m.name && ts.isIdentifier(m.name)) emitPropertyDecl(m,body,CT.fid,cn++,className);
      // Constructors can be added in a later gate; NEW still models object identity without one.
    }
  }

  function emitPropertyDecl(prop,parentList,enclosingFid,childnum,classname) {
    // Legacy php-ast CSV has a property-declaration shape but no dedicated property-type slot.
    // Preserve the declaration/name faithfully; TS type information remains in the frontend sidecar.
    const pd=mkNode('AST_PROP_DECL',{flags:'MODIFIER_PUBLIC',funcid:enclosingFid,childnum,lineno:line(prop),classname});
    parent(parentList,pd);
    const pe=mkNode('AST_PROP_ELEM',{childnum:0,funcid:enclosingFid,lineno:line(prop),classname});
    parent(pd,pe);
    parent(pe,mkNode('string',{code:`"${prop.name.text}"`,childnum:0,funcid:enclosingFid,lineno:line(prop),classname}));
    if(prop.initializer) emitExpr(prop.initializer,pe,enclosingFid,1,new Map(),classname);
    else parent(pe,mkNode('NULL',{childnum:1,funcid:enclosingFid,lineno:line(prop),classname}));
    return pd;
  }

  function emitFunction(fn,parentList,enclosingFid,childnum,classname) {
    const name=fn.name.text;
    const F=allocScope('AST_FUNC_DECL',{funcid:enclosingFid,childnum,lineno:line(fn),endlineno:endline(fn),name,classname});
    parent(parentList,F.fid);
    emitFunctionBody(fn,F,classname);
  }
  function emitMethod(fn,parentList,enclosingFid,childnum,classname) {
    const name=fn.name.text;
    const F=allocScope('AST_METHOD',{funcid:enclosingFid,childnum,lineno:line(fn),endlineno:endline(fn),name,classname});
    parent(parentList,F.fid);
    emitFunctionBody(fn,F,classname);
  }

  function emitFunctionBody(fn,F,classname) {
    const paramList=mkNode('AST_PARAM_LIST',{childnum:0,funcid:F.fid,lineno:line(fn),classname}); parent(F.fid,paramList);
    const defs=new Map();
    fn.parameters.forEach((p,i)=>{
      if(!ts.isIdentifier(p.name)) return;
      const nm=p.name.text;
      const par=mkNode('AST_PARAM',{childnum:i,funcid:F.fid,lineno:line(p),name:nm,classname}); parent(paramList,par);
      // Preserve a simple TypeScript class annotation in the PHP-compatible AST_PARAM type slot.
      // Union/complex types deliberately stay NULL so the legacy engine cannot flatten ambiguity.
      if (p.type && ts.isTypeReferenceNode(p.type) && ts.isIdentifier(p.type.typeName)) {
        emitName(p.type.typeName.text,par,F.fid,0,line(p.type),classname);
      } else {
        parent(par,mkNode('NULL',{childnum:0,funcid:F.fid,lineno:line(p),classname}));
      }
      parent(par,mkNode('string',{code:`"${nm}"`,childnum:1,funcid:F.fid,lineno:line(p),classname}));
      parent(par,mkNode('NULL',{childnum:2,funcid:F.fid,lineno:line(p),classname}));
      defs.set(nm,par);
    });
    parent(F.fid,mkNode('NULL',{childnum:1,funcid:F.fid,lineno:line(fn),classname}));
    const body=mkNode('AST_STMT_LIST',{childnum:2,funcid:F.fid,lineno:line(fn),classname}); parent(F.fid,body);
    parent(F.fid,mkNode('NULL',{childnum:3,funcid:F.fid,lineno:line(fn),classname}));
    if(fn.body) { let cn=0; for(const st of fn.body.statements) emitStmt(st,body,F.fid,cn++,defs,classname); }
  }

  function emitStmt(st,parentList,funcid,childnum,defs,classname) {
    if(ts.isVariableStatement(st)) {
      let last=null;
      for(const d of st.declarationList.declarations) {
        const bindAssign=(nm,rhsExpr,cn)=>{ const a=mkNode('AST_ASSIGN',{childnum:cn,funcid,lineno:line(st),classname}); parent(parentList,a); const v=emitVar(nm,a,funcid,0,line(d),classname); defs.set(nm,v); emitExpr(rhsExpr,a,funcid,1,defs,classname); last=a; };
        if(ts.isIdentifier(d.name)) { bindAssign(d.name.text,d.initializer,childnum); continue; }
        if(ts.isObjectBindingPattern(d.name) && d.initializer) {
          let off=0;
          for(const el of d.name.elements) {
            if(el.dotDotDotToken || !ts.isIdentifier(el.name)) continue;
            const prop=el.propertyName||el.name;
            let arg;
            if(ts.isComputedPropertyName(prop)) arg=prop.expression;
            else if(ts.isIdentifier(prop)) arg=ts.factory.createStringLiteral(prop.text);
            else if(ts.isStringLiteral(prop)||ts.isNumericLiteral(prop)) arg=prop;
            else continue;
            const rhs=ts.factory.createElementAccessExpression(d.initializer,arg);
            bindAssign(el.name.text,rhs,childnum+(off++));
          }
          continue;
        }
        if(ts.isArrayBindingPattern(d.name) && d.initializer) {
          let off=0;
          d.name.elements.forEach((el,i)=>{ if(ts.isOmittedExpression(el)||!ts.isBindingElement(el)||el.dotDotDotToken||!ts.isIdentifier(el.name))return; const rhs=ts.factory.createElementAccessExpression(d.initializer,ts.factory.createNumericLiteral(i)); bindAssign(el.name.text,rhs,childnum+(off++)); });
          continue;
        }
      }
      return last;
    }
    if(ts.isReturnStatement(st)) {
      const r=mkNode('AST_RETURN',{childnum,funcid,lineno:line(st),classname}); parent(parentList,r);
      emitExpr(st.expression,r,funcid,0,defs,classname); return r;
    }
    if(ts.isExpressionStatement(st)) return emitExpr(st.expression,parentList,funcid,childnum,defs,classname);
    return null;
  }
  function emitVar(name,p,funcid,childnum,lineno,classname) {
    const v=mkNode('AST_VAR',{childnum,funcid,lineno,name,classname}); parent(p,v);
    parent(v,mkNode('string',{code:`"${name}"`,childnum:0,funcid,lineno,classname})); return v;
  }
  function emitName(name,p,funcid,childnum,lineno,classname) {
    const n=mkNode('AST_NAME',{childnum,funcid,lineno,name,classname}); parent(p,n);
    parent(n,mkNode('string',{code:`"${name}"`,childnum:0,funcid,lineno,classname})); return n;
  }
  function emitArgs(args,p,funcid,childnum,defs,classname) {
    const al=mkNode('AST_ARG_LIST',{childnum,funcid,lineno:args.length?line(args[0]):0,classname}); parent(p,al);
    args.forEach((a,i)=>emitExpr(a,al,funcid,i,defs,classname)); return al;
  }

  function closureCaptureNames(fn, outerDefs) {
    const params=new Set(fn.parameters.filter(p=>ts.isIdentifier(p.name)).map(p=>p.name.text));
    const locals=new Set();
    if(ts.isBlock(fn.body)) for(const st of fn.body.statements) {
      if(ts.isVariableStatement(st)) for(const d of st.declarationList.declarations) if(ts.isIdentifier(d.name)) locals.add(d.name.text);
    }
    const free=new Set();
    function walk(n,parentNode) {
      if(ts.isIdentifier(n)) {
        if(parentNode) {
          if((ts.isVariableDeclaration(parentNode)&&parentNode.name===n) ||
             ((ts.isArrowFunction(parentNode)||ts.isFunctionExpression(parentNode))&&parentNode.parameters.some(p=>p.name===n)) ||
             (ts.isPropertyAccessExpression(parentNode)&&parentNode.name===n) ||
             (ts.isFunctionDeclaration(parentNode)&&parentNode.name===n)) return;
          if(ts.isCallExpression(parentNode)&&parentNode.expression===n) return; // named/global or local callable, not lexical data capture here
        }
        if(!params.has(n.text)&&!locals.has(n.text)&&outerDefs.has(n.text)) free.add(n.text);
        return;
      }
      ts.forEachChild(n,c=>walk(c,n));
    }
    walk(fn.body,null);
    return [...free].sort();
  }

  function emitClosure(fn,parentNode,outerFuncid,childnum,outerDefs,classname) {
    const cname=`{closure@${line(fn)}}`;
    const C=allocScope('AST_CLOSURE',{funcid:outerFuncid,childnum,lineno:line(fn),endlineno:endline(fn),name:cname,classname});
    parent(parentNode,C.fid);
    const defs=new Map();
    const pl=mkNode('AST_PARAM_LIST',{childnum:0,funcid:C.fid,lineno:line(fn),classname}); parent(C.fid,pl);
    fn.parameters.forEach((p,i)=>{
      if(!ts.isIdentifier(p.name)) return;
      const nm=p.name.text; const par=mkNode('AST_PARAM',{childnum:i,funcid:C.fid,lineno:line(p),name:nm,classname}); parent(pl,par);
      if (p.type && ts.isTypeReferenceNode(p.type) && ts.isIdentifier(p.type.typeName)) emitName(p.type.typeName.text,par,C.fid,0,line(p.type),classname);
      else parent(par,mkNode('NULL',{childnum:0,funcid:C.fid,lineno:line(p),classname}));
      parent(par,mkNode('string',{code:`"${nm}"`,childnum:1,funcid:C.fid,lineno:line(p),classname}));
      parent(par,mkNode('NULL',{childnum:2,funcid:C.fid,lineno:line(p),classname})); defs.set(nm,par);
    });
    const captures=closureCaptureNames(fn,outerDefs);
    if(captures.length) {
      const uses=mkNode('AST_CLOSURE_USES',{childnum:1,funcid:C.fid,lineno:line(fn),classname}); parent(C.fid,uses);
      captures.forEach((nm,i)=>{
        const cv=mkNode('AST_CLOSURE_VAR',{childnum:i,funcid:C.fid,lineno:line(fn),classname}); parent(uses,cv);
        parent(cv,mkNode('string',{code:`"${nm}"`,childnum:0,funcid:C.fid,lineno:line(fn),classname}));
        defs.set(nm,cv);
      });
    } else parent(C.fid,mkNode('NULL',{childnum:1,funcid:C.fid,lineno:line(fn),classname}));
    const body=mkNode('AST_STMT_LIST',{childnum:2,funcid:C.fid,lineno:line(fn),classname}); parent(C.fid,body);
    if(ts.isBlock(fn.body)) { let cn=0; for(const st of fn.body.statements) emitStmt(st,body,C.fid,cn++,defs,classname); }
    else { const r=mkNode('AST_RETURN',{childnum:0,funcid:C.fid,lineno:line(fn.body),classname}); parent(body,r); emitExpr(fn.body,r,C.fid,0,defs,classname); }
    parent(C.fid,mkNode('NULL',{childnum:3,funcid:C.fid,lineno:line(fn),classname}));
    closureCaptures.push({closure_id:C.fid,name:cname,enclosing_funcid:outerFuncid,captures});
    return C.fid;
  }

  function emitExpr(expr,parentNode,funcid,childnum,defs,classname) {
    if(!expr) { const n=mkNode('NULL',{funcid,childnum,classname}); parent(parentNode,n); return n; }
    if(ts.isIdentifier(expr)) return emitVar(expr.text,parentNode,funcid,childnum,line(expr),classname);
    if(ts.isArrowFunction(expr)||ts.isFunctionExpression(expr)) return emitClosure(expr,parentNode,funcid,childnum,defs,classname);
    if(expr.kind===ts.SyntaxKind.ThisKeyword) return emitVar('this',parentNode,funcid,childnum,line(expr),classname);
    if(ts.isBinaryExpression(expr) && expr.operatorToken.kind===ts.SyntaxKind.EqualsToken) {
      const a=mkNode('AST_ASSIGN',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,a);
      emitExpr(expr.left,a,funcid,0,defs,classname);
      emitExpr(expr.right,a,funcid,1,defs,classname);
      return a;
    }
    if(ts.isStringLiteral(expr)||ts.isNumericLiteral(expr)||ts.isNoSubstitutionTemplateLiteral(expr)) { const s=mkNode('string',{code:JSON.stringify(expr.text),childnum,funcid,lineno:line(expr),classname}); parent(parentNode,s); return s; }
    if(ts.isBinaryExpression(expr)) {
      const opMap = new Map([
        [ts.SyntaxKind.PlusToken,'BINARY_ADD'], [ts.SyntaxKind.MinusToken,'BINARY_SUB'],
        [ts.SyntaxKind.AsteriskToken,'BINARY_MUL'], [ts.SyntaxKind.SlashToken,'BINARY_DIV'],
        [ts.SyntaxKind.PercentToken,'BINARY_MOD'], [ts.SyntaxKind.EqualsEqualsEqualsToken,'BINARY_IS_IDENTICAL'],
        [ts.SyntaxKind.ExclamationEqualsEqualsToken,'BINARY_IS_NOT_IDENTICAL'],
        [ts.SyntaxKind.AmpersandAmpersandToken,'BINARY_BOOL_AND'], [ts.SyntaxKind.BarBarToken,'BINARY_BOOL_OR']
      ]);
      const flag=opMap.get(expr.operatorToken.kind) || 'BINARY_ADD';
      const b=mkNode('AST_BINARY_OP',{flags:flag,childnum,funcid,lineno:line(expr),classname}); parent(parentNode,b);
      emitExpr(expr.left,b,funcid,0,defs,classname);
      emitExpr(expr.right,b,funcid,1,defs,classname);
      return b;
    }
    if(ts.isTemplateExpression(expr)) {
      const pieces=[{kind:'text',text:expr.head.text,node:expr.head}];
      for(const sp of expr.templateSpans) { pieces.push({kind:'expr',node:sp.expression}); pieces.push({kind:'text',text:sp.literal.text,node:sp.literal}); }
      function emitPiece(piece,p,cn) {
        if(piece.kind==='expr') return emitExpr(piece.node,p,funcid,cn,defs,classname);
        const q=mkNode('string',{code:JSON.stringify(piece.text),childnum:cn,funcid,lineno:line(piece.node),classname}); parent(p,q); return q;
      }
      function emitConcat(lo,hi,p,cn) {
        if(lo===hi) return emitPiece(pieces[lo],p,cn);
        const b=mkNode('AST_BINARY_OP',{flags:'BINARY_CONCAT',childnum:cn,funcid,lineno:line(expr),classname}); parent(p,b);
        emitConcat(lo,hi-1,b,0); emitPiece(pieces[hi],b,1); return b;
      }
      return emitConcat(0,pieces.length-1,parentNode,childnum);
    }
    if(ts.isConditionalExpression(expr)) {
      const c=mkNode('AST_CONDITIONAL',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,c);
      emitExpr(expr.condition,c,funcid,0,defs,classname);
      emitExpr(expr.whenTrue,c,funcid,1,defs,classname);
      emitExpr(expr.whenFalse,c,funcid,2,defs,classname);
      return c;
    }
    if(ts.isPropertyAccessExpression(expr)) {
      const p=mkNode('AST_PROP',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,p);
      emitExpr(expr.expression,p,funcid,0,defs,classname);
      parent(p,mkNode('string',{code:`"${expr.name.text}"`,childnum:1,funcid,lineno:line(expr.name),classname}));
      return p;
    }
    if(ts.isElementAccessExpression(expr)) {
      const d=mkNode('AST_DIM',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,d);
      emitExpr(expr.expression,d,funcid,0,defs,classname);
      emitExpr(expr.argumentExpression,d,funcid,1,defs,classname);
      return d;
    }
    if(ts.isNewExpression(expr)) {
      const n=mkNode('AST_NEW',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,n);
      if(ts.isIdentifier(expr.expression)) emitName(expr.expression.text,n,funcid,0,line(expr.expression),classname); else parent(n,mkNode('NULL',{childnum:0,funcid,lineno:line(expr),classname}));
      emitArgs(expr.arguments?Array.from(expr.arguments):[],n,funcid,1,defs,classname); return n;
    }
    if(ts.isCallExpression(expr)) {
      if(ts.isPropertyAccessExpression(expr.expression)) {
        const mc=mkNode('AST_METHOD_CALL',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,mc);
        emitExpr(expr.expression.expression,mc,funcid,0,defs,classname);
        const mn=mkNode('string',{code:`"${expr.expression.name.text}"`,childnum:1,funcid,lineno:line(expr.expression.name),classname}); parent(mc,mn);
        emitArgs(Array.from(expr.arguments),mc,funcid,2,defs,classname); return mc;
      }
      if(ts.isIdentifier(expr.expression)) {
        const call=mkNode('AST_CALL',{childnum,funcid,lineno:line(expr),classname}); parent(parentNode,call);
        emitName(expr.expression.text,call,funcid,0,line(expr.expression),classname);
        emitArgs(Array.from(expr.arguments),call,funcid,1,defs,classname); return call;
      }
    }
    const n=mkNode('NULL',{funcid,childnum,lineno:line(expr),classname}); parent(parentNode,n); return n;
  }

  // Same input-contract rules established in Gate 2.
  const structural=rels.filter(r=>r.type!=='PARENT_OF'&&r.type!=='FILE_OF');
  // The legacy CSV interpreter requires a child's subtree to be wired before the
  // parent->child relation is consumed. A global reverse achieves child-first but
  // also reverses siblings, corrupting parameter/argument positions. Emit AST
  // relations in post-order while preserving childnum order instead.
  const rawAst=rels.filter(r=>r.type==='PARENT_OF');
  const byParent=new Map(), childIds=new Set();
  for(const e of rawAst){ if(!byParent.has(e.start)) byParent.set(e.start,[]); byParent.get(e.start).push(e); childIds.add(e.end); }
  const astEdges=[];
  function emitPost(parentId){
    const es=(byParent.get(parentId)||[]).slice().sort((a,b)=>(nodes[a.end]?.childnum??0)-(nodes[b.end]?.childnum??0));
    for(const e of es){ emitPost(e.end); astEdges.push(e); }
  }
  const roots=[...byParent.keys()].filter(x=>!childIds.has(x)).sort((a,b)=>a-b);
  for(const r of roots) emitPost(r);
  rels.length=0; rels.push(...structural,...astEdges,{start:fnode,end:T.fid,type:'FILE_OF'});
  return {nodes,rels,closureCaptures};
}

function writeCsv({nodes,rels}) {
  const NH='id:int\tlabels:label\ttype\tflags:string_array\tlineno:int\tcode\tchildnum:int\tfuncid:int\tclassname\tnamespace\tendlineno:int\tname\tdoccomment';
  const nrows=nodes.map(n=>[n.id,n.label,n.type,n.flags,n.lineno,n.code,n.childnum,n.funcid,n.classname,n.namespace,n.endlineno,n.name,n.doccomment].join('\t'));
  return {
    'nodes.csv':[NH,...nrows].join('\n')+'\n',
    'rels.csv':['start\tend\ttype',...rels.map(r=>[r.start,r.end,r.type].join('\t'))].join('\n')+'\n'
  };
}
if(require.main===module) {
  const src=fs.readFileSync(process.argv[2],'utf8'), outdir=process.argv[3]||'.';
  const parsed=toCsv(src,path.basename(process.argv[2])); const out=writeCsv(parsed); fs.mkdirSync(outdir,{recursive:true});
  for(const [f,c] of Object.entries(out)) fs.writeFileSync(path.join(outdir,f),c);
  fs.writeFileSync(path.join(outdir,'closure_captures.json'),JSON.stringify(parsed.closureCaptures,null,2)+'\n');
  console.error(`wrote ${outdir}`);
}
module.exports={toCsv,writeCsv};
