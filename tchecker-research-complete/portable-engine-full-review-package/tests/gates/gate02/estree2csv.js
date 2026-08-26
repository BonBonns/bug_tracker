// estree2csv.js — Gate 2 (v2): joern-php CSV with required funcid+1/+2 id discipline.
const acorn = require("acorn");

function toCsv(source, file = "input.js") {
  let id = 0;
  const nodes = [], rels = [], cpg = [];
  const mkNode = (type, o = {}) => { const n = {
    id: id++, label: o.label ?? "AST", flags: o.flags ?? "", type,
    lineno: o.lineno ?? 0, code: o.code ?? "", childnum: o.childnum ?? 0,
    funcid: o.funcid ?? 0, name: o.name ?? "", endlineno: o.endlineno ?? "" };
    nodes.push(n); return n.id; };
  const parent = (p, c) => rels.push({ start: p, end: c, type: "PARENT_OF" });
  const reaches = (a, b, v) => cpg.push({ start: a, end: b, type: "REACHES", var: v });
  const flows = (a, b) => cpg.push({ start: a, end: b, type: "FLOWS_TO", var: "" });
  const ast = acorn.parse(source, { ecmaVersion: 2022, locations: true });
  const ln = n => (n.loc ? n.loc.start.line : 0);
  const funcDeclId = new Map();   // function name -> AST_FUNC_DECL node id (for CALLS edges)
  const callEdges = [];           // {callNode, calleeName}  -> resolved to CALLS after all decls known

  function allocFuncScope(type, o) {
    const fid = mkNode(type, o);
    const entry = mkNode("CFG_FUNC_ENTRY", { label: "Artificial", funcid: fid, lineno: o.lineno ?? 0 });
    const exit  = mkNode("CFG_FUNC_EXIT",  { label: "Artificial", funcid: fid, lineno: o.lineno ?? 0 });
    rels.push({ start: fid, end: entry, type: "ENTRY" });
    rels.push({ start: fid, end: exit,  type: "EXIT" });
    return { fid, entry, exit };
  }

  const dir = mkNode("Directory", { label: "Filesystem", name: `"."` });
  const fnode = mkNode("File", { label: "Filesystem", name: `"${file}"` });
  rels.push({ start: dir, end: fnode, type: "DIRECTORY_OF" });

  const T = allocFuncScope("AST_TOPLEVEL", { flags: "TOPLEVEL_FILE", lineno: 1, endlineno: (ast.loc?ast.loc.end.line:1), name: `"./${file}"` });
  rels.push({ start: fnode, end: T.fid, type: "FILE_OF" });
  const topStmts = mkNode("AST_STMT_LIST", { childnum: 0, funcid: T.fid, lineno: 1 });
  parent(T.fid, topStmts);

  let topChild = 0;
  for (const s of ast.body) if (s.type === "FunctionDeclaration") emitFunc(s, topStmts, T.fid, topChild++);

  function emitFunc(fn, parentList, enclosingFid, childnum) {
    const F = allocFuncScope("AST_FUNC_DECL", { funcid: enclosingFid, childnum, lineno: ln(fn), endlineno: (fn.loc?fn.loc.end.line:ln(fn)), name: fn.id.name });
    funcDeclId.set(fn.id.name, F.fid);
    parent(parentList, F.fid);
    const paramList = mkNode("AST_PARAM_LIST", { childnum: 0, funcid: F.fid, lineno: ln(fn) });
    parent(F.fid, paramList);
    const paramNodes = [];
    fn.params.forEach((p, i) => {
      if (p.type !== "Identifier") return;
      const par = mkNode("AST_PARAM", { childnum: i, funcid: F.fid, lineno: ln(fn), name: p.name });
      parent(paramList, par);
      parent(par, mkNode("string", { code: `"${p.name}"`, childnum: 1, funcid: F.fid, lineno: ln(fn) }));
      paramNodes.push({ node: par, name: p.name });
    });
    const bodyList = mkNode("AST_STMT_LIST", { childnum: 2, funcid: F.fid, lineno: ln(fn) });
    parent(F.fid, bodyList);
    const defs = new Map();
    paramNodes.forEach(p => defs.set(p.name, p.node));
    let prevCfg = F.entry, cn = 0;
    for (const st of fn.body.body) {
      const cfg = emitStmt(st, bodyList, F.fid, cn++, defs);
      if (cfg != null) { flows(prevCfg, cfg); prevCfg = cfg; }
    }
    flows(prevCfg, F.exit);
  }

  function emitStmt(st, parentList, funcid, childnum, defs) {
    if (st.type === "VariableDeclaration") {
      let last = null;
      for (const d of st.declarations) {
        if (d.id.type !== "Identifier") continue;
        const assign = mkNode("AST_ASSIGN", { childnum, funcid, lineno: ln(st) });
        parent(parentList, assign);
        const v = mkNode("AST_VAR", { childnum: 0, funcid, lineno: ln(st), name: d.id.name });
        parent(assign, v);
        parent(v, mkNode("string", { code: `"${d.id.name}"`, childnum: 0, funcid, lineno: ln(st) }));
        const rhs = emitExpr(d.init, assign, funcid, 1, defs);
        if (rhs != null) reaches(rhs, v, d.id.name);
        defs.set(d.id.name, v);
        last = assign;
      }
      return last;
    }
    if (st.type === "ReturnStatement") {
      const ret = mkNode("AST_RETURN", { childnum, funcid, lineno: ln(st) });
      parent(parentList, ret);
      emitExpr(st.argument, ret, funcid, 0, defs);
      return ret;
    }
    if (st.type === "ExpressionStatement") return emitExpr(st.expression, parentList, funcid, childnum, defs);
    return null;
  }

  function emitExpr(expr, parentNode, funcid, childnum, defs) {
    if (!expr) return mkNode("NULL", { funcid, childnum });
    switch (expr.type) {
      case "Identifier": {
        const v = mkNode("AST_VAR", { childnum, funcid, lineno: ln(expr), name: expr.name });
        parent(parentNode, v);
        parent(v, mkNode("string", { code: `"${expr.name}"`, childnum: 0, funcid, lineno: ln(expr) }));
        const def = defs.get(expr.name);
        if (def != null) reaches(def, v, expr.name);
        return v;
      }
      case "Literal": {
        const s = mkNode("string", { code: JSON.stringify(String(expr.value)), childnum, funcid, lineno: ln(expr) });
        parent(parentNode, s); return s;
      }
      case "CallExpression": {
        const call = mkNode("AST_CALL", { childnum, funcid, lineno: ln(expr) });
        parent(parentNode, call);
        if (expr.callee.type === "Identifier") {
          const nm = mkNode("AST_NAME", { childnum: 0, funcid, lineno: ln(expr), name: expr.callee.name });
          parent(call, nm);
          parent(nm, mkNode("string", { code: `"${expr.callee.name}"`, childnum: 0, funcid, lineno: ln(expr) }));
          callEdges.push({ callNode: call, calleeName: expr.callee.name });   // resolve to CALLS after pass
        }
        const argList = mkNode("AST_ARG_LIST", { childnum: 1, funcid, lineno: ln(expr) });
        parent(call, argList);
        expr.arguments.forEach((a, i) => emitExpr(a, argList, funcid, i, defs));
        return call;
      }
      default: { const nul = mkNode("NULL", { funcid, childnum }); parent(parentNode, nul); return nul; }
    }
  }
  // resolve CALLS edges now that all function declarations are known
  for (const ce of callEdges) {
    const target = funcDeclId.get(ce.calleeName);
    if (target != null) cpg.push({ start: ce.callNode, end: target, type: "CALLS", var: "" });
    // unresolved callee -> no CALLS edge (correct UNKNOWN behavior)
  }

  return { nodes, rels, cpg };
}

function writeCsv({ nodes, rels, cpg }) {
  const NH = "id:int\tlabels:label\ttype\tflags:string_array\tlineno:int\tcode\tchildnum:int\tfuncid:int\tclassname\tnamespace\tendlineno:int\tname\tdoccomment";
  const nrows = nodes.map(n => [n.id, n.label, n.type, n.flags, n.lineno, n.code, n.childnum, n.funcid, "", "", n.endlineno, n.name, ""].join("\t"));
  return {
    "nodes.csv": [NH, ...nrows].join("\n") + "\n",
    "rels.csv": ["start\tend\ttype", ...rels.map(r => [r.start, r.end, r.type].join("\t"))].join("\n") + "\n",
    "cpg_edges.csv": ["start\tend\ttype\tvar", ...cpg.map(c => [c.start, c.end, c.type, c.var].join("\t"))].join("\n") + "\n",
  };
}
module.exports = { toCsv, writeCsv };
if (require.main === module) {
  const fs = require("fs"), path = require("path");
  const out = writeCsv(toCsv(fs.readFileSync(process.argv[2], "utf8"), path.basename(process.argv[2])));
  const dir = process.argv[3] || "."; fs.mkdirSync(dir, { recursive: true });
  for (const [f, c] of Object.entries(out)) fs.writeFileSync(`${dir}/${f}`, c);
  console.error(`wrote to ${dir}`);
}
