package tools.php.ast2cpg;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import ast.php.declarations.ClassDef;
import ast.php.statements.blockstarters.IfStatement;
import ast.php.statements.blockstarters.IfElement;
import ast.php.statements.blockstarters.SwitchCase;

import ast.ASTNode;
import ast.expressions.ArgumentList;
import ast.expressions.ArrayIndexing;
import ast.expressions.AssignmentExpression;
import ast.expressions.CallExpressionBase;
import ast.expressions.CastExpression;
import ast.expressions.Expression;
import ast.expressions.Identifier;
import ast.expressions.StringExpression;
import ast.expressions.NewExpression;
import ast.expressions.PropertyExpression;
import ast.expressions.Variable;
import ast.php.statements.GlobalStatement;
import ast.functionDef.ParameterBase;
import ast.functionDef.ParameterList;
import ast.php.expressions.ExitExpression;
import ast.php.expressions.IncludeOrEvalExpression;
import ast.php.expressions.MethodCallExpression;
import ast.php.expressions.StaticCallExpression;
import ast.php.functionDef.FunctionDef;
import ast.php.functionDef.Method;
import ast.php.functionDef.Parameter;
import ast.php.functionDef.TopLevelFunctionDef;
import ast.php.statements.EchoStatement;
import ast.statements.jump.ReturnStatement;
import cg.PHPCGFactory;
import cg.ParseVar;
import cg.toTopLevelFile;
import ddg.DataDependenceGraph.DDG;
import inputModules.csv.csv2ast.ASTUnderConstruction;
import misc.MultiHashMap;
import misc.Pair;
import outputModules.csv.exporters.CSVCFGExporter;

public class StaticAnalysis  {
	public static Set<Long> sources = PHPCSVEdgeInterpreter.sources;
	public static Set<Long> sinks = new HashSet<Long>();
	public static Set<Long> sqlSanitizers = new HashSet<Long>();

	// ITEM18 coverage reporting: a single shared counter for every "Vul: " line emitted, from
	// whichever of the several emission mechanisms in this file produced it. Exists so the final,
	// human-facing summary (printed from Main.java, alongside the CTRLREACH coverage/truncation
	// data and dynamic-dispatch resolution counts) can state the total finding count plainly next
	// to the coverage caveats -- the exact pairing the Smush crash showed was missing: "0 Vul:
	// lines" and "the analysis pass never completed" were indistinguishable without this.
	public static int totalVulCount = 0;

	// Parallel to vulStmts: records the specific source node ID that caused each sink to fire.
	// Used to emit "Vul Source: <nodeId> file=<path> line=<n> code=[<text>]" alongside "Vul: <sinkId>",
	// giving the LLM adjudicator the exact taint origin rather than requiring it to re-derive which
	// $_GET/$_POST in the handler body is the relevant one.
	public static MultiHashMap<Long, Long> vulSources = new MultiHashMap<Long, Long>();

	/** A tainted value reached a sink but no ultimate origin was resolved. This is a FLOW-STATE
	 *  marker, not source evidence: the TAINTVAR stream contributed `sink == node`, i.e. the sink
	 *  statement reported as its own source. Kept OUT of the source union so it can never be
	 *  serialized as an origin, and kept ROUTE-SPECIFIC so two call contexts reaching one sink
	 *  remain two records rather than one sink-keyed entry with two stacks. */
	public static final class UnresolvedValueFlow {
		public final Long sinkNode, unresolvedValueNode;
		public final java.util.List<Long> taintStateNodes, routeContext;
		public final String unresolvedReason;
		public String relationKind = "UNKNOWN", identityPrecision = "UNKNOWN";
		public Integer sinkArgumentIndex = null;
		UnresolvedValueFlow(Long sink, Long unresolvedValue, java.util.Collection<Long> taint,
		                    java.util.Collection<Long> route, String reason) {
			sinkNode=sink; unresolvedValueNode=unresolvedValue; unresolvedReason=reason;
			taintStateNodes=java.util.Collections.unmodifiableList(new java.util.ArrayList<Long>(taint));
			routeContext=java.util.Collections.unmodifiableList(new java.util.ArrayList<Long>(route));
		}
		// VALUE-SPECIFIC identity: sink + route + the actual unresolved value node, so
		// sink($a, $b) with both unresolved yields TWO records, not one collapsed by sink+route.
		// key includes relation_kind + argument index so a route-level fallback and a
		// value-specific argument match at the same node can never collapse into one record.
		String key() { return sinkNode+"|"+routeContext+"|"+unresolvedValueNode+"|"+relationKind+"|"+sinkArgumentIndex; }
	}
	public static final java.util.LinkedHashMap<String,UnresolvedValueFlow> unresolvedFlows =
		new java.util.LinkedHashMap<String,UnresolvedValueFlow>();

	// Built-in functions that PRESERVE attacker control over the string content (i.e. an
	// injection payload survives them intact), so taint must propagate through them. Limiting
	// pass-through to this allowlist keeps precision: functions that reduce/transform input to
	// a non-injectable form (count/strlen/json_encode/base64_encode/dechex/...) or that escape
	// quotes (esc_html/esc_attr/htmlspecialchars) are deliberately excluded, as is anything in
	// the sanitizer set (absint/intval/esc_sql/... are handled at the sink check instead).
	// sanitize_text_field / wp_unslash / strip_tags / esc_like all leave quotes intact and ARE
	// included -- this is exactly the wrapping real WordPress request data passes through.
	public static final Set<String> taintPreserving = new HashSet<String>(Arrays.asList(
		// PHP string manipulation that preserves substrings of the input
		"trim", "ltrim", "rtrim", "strtolower", "strtoupper", "ucfirst", "ucwords", "lcfirst",
		"str_replace", "str_ireplace", "preg_replace", "preg_replace_callback", "substr",
		"mb_substr", "substr_replace", "sprintf", "vsprintf", "implode", "join", "strtr",
		"strrev", "str_repeat", "str_pad", "nl2br", "wordwrap", "chunk_split", "stripslashes",
		"stripcslashes", "html_entity_decode", "htmlspecialchars_decode", "urldecode",
		"rawurldecode", "mb_strtolower", "mb_strtoupper", "mb_convert_case", "mb_convert_encoding",
		"iconv", "utf8_decode", "utf8_encode", "strip_tags",
		// WordPress wrappers that leave SQL metacharacters (quotes) intact
		"wp_unslash", "stripslashes_deep", "sanitize_text_field", "sanitize_textarea_field",
		"wp_strip_all_tags", "wp_check_invalid_utf8", "wptexturize", "convert_chars",
		"convert_smilies", "force_balance_tags", "remove_accents", "wp_kses", "wp_kses_post",
		"wp_kses_data", "seems_utf8", "esc_like", "stripslashes_from_strings_only",
		// shortcode_atts($defaults, $atts) returns the merged attribute array, which still holds the
		// attacker-supplied attribute values, so taint must flow through it (the dominant shortcode idiom).
		"shortcode_atts",
		// array_map($cb, $arr) applies $cb to each element of $arr and returns the array — attacker
		// control survives unless $cb neutralizes it. Taint must flow from the array argument; whether
		// the CALLBACK sanitizes is decided per-class at the sink (sanitizedOnPath special-cases
		// array_map to test its callback, so array_map('intval',$x) clears but
		// array_map('sanitize_text_field',$x) stays a SQLi candidate — the ubiquitous WP idiom that
		// caused the survey-maker CVE-2023-23490 to be missed). array_filter/array_values/array_unique
		// likewise preserve element content.
		"array_map", "array_filter", "array_values", "array_unique", "array_reverse", "array_merge"
	));

	public static Set<Long> cfgNode = new HashSet<Long>();
	public static MultiHashMap<Long, Long> srcDim = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> srcProp = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> srcGlobal = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> dstGlobal = new MultiHashMap<Long, Long>();
	// cross-function taint for variables imported via `global $g;` (distinct from the $GLOBALS[...]
	// form tracked by src/dstGlobal). Keyed stmt -> Variable node id; matched under a "GVAR::name"
	// identity in the inter-procedural taint set.
	public static MultiHashMap<Long, Long> srcGlobalVar = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> dstGlobalVar = new MultiHashMap<Long, Long>();
	public static HashMap<Long, Node> ID2Node = new HashMap<Long, Node>();
	public static int nodeDiagSeq = 0;
	public static MultiHashMap<Long, Long> dstProp = new MultiHashMap<Long, Long>();
	public static Node root = new Node((long) 0, new Node.TracingInterMap(), new HashSet<Long>(), new Stack<Long>());
	public static MultiHashMap<Long, Stack<Long>> vulStmts = new MultiHashMap<Long, Stack<Long>>();
	public static Set<Stack<Long>> vulPaths = new HashSet<Stack<Long>>();
	public static Long ID = null;
	public static MultiHashMap<String, Long> name2Stmt = new MultiHashMap<String, Long>();
	//we only step into the function 
	public static MultiHashMap<String, Long> name2Func = new MultiHashMap<String, Long>();
	public static MultiHashMap<Long, Long> caller2callee = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> callee2caller = new MultiHashMap<Long, Long>();
	public static HashSet<Long> validFunc = new HashSet<Long>();
	public static HashSet<Long> unused = new HashSet<Long>();
	public static HashMap<Long, Integer> Edgetimes = new HashMap<Long, Integer>();
	public static HashMap<Long, Integer> Edgesize = new HashMap<Long, Integer>();
	// FIX (2026-08-08): sinkClass (in PHPCGFactory) is keyed by the SINK's own AST node id, but
	// both the SINK_CLASS_PURITY report and traverse()'s xssClassSink computation look up class
	// by the ENCLOSING STATEMENT id (from getStatement(sink)), which is frequently a DIFFERENT
	// id -- confirmed live: a sink node id 21 nested inside statement 18 caused sinkClass.get(18)
	// to miss (return null) even though the sink at 21 was genuinely tagged "xss". This silently
	// downgraded xssClassSink to false, which routes hasUnsanitizedInlineSource()/inlineSanitized()
	// into checking sqlSanitizers instead of xssSanitizers/htmlEscapers for a real XSS sink.
	// stmtSinkClass is populated once, at the same point the sink node -> statement conversion
	// already happens (see the "get the sink statement" loop below), so the class survives the
	// conversion instead of being silently dropped. "xss" wins if a statement ever contains
	// more than one differently-classed sink (rare; conservative toward NOT missing xss credit).
	// FIX (2026-08-08): sinkClass (in PHPCGFactory) is keyed by the SINK's own AST node id, but
	// both the SINK_CLASS_PURITY report and traverse()'s xssClassSink computation look up class
	// by the ENCLOSING STATEMENT id (from getStatement(sink)), which is frequently a DIFFERENT
	// id -- confirmed live: a sink node id 21 nested inside statement 18 caused sinkClass.get(18)
	// to miss (return null) even though the sink at 21 was genuinely tagged "xss". This silently
	// downgraded xssClassSink to false, which routes hasUnsanitizedInlineSource()/inlineSanitized()
	// into checking sqlSanitizers instead of xssSanitizers/htmlEscapers for a real XSS sink.
	//
	// REVISION (2026-08-08, same day): the first version of this fix used Map<Long,String> (one
	// class per statement), which reintroduces the identical ID-domain-collapse failure mode one
	// level later -- CONFIRMED live via an order-reversal test: a statement containing both a
	// file-delete sink and a priv_esc sink resolved to "file-delete" or "priv_esc" depending
	// SOLELY on which sink was iterated first (no receiver-identity or evidentiary tiebreak,
	// pure iteration-order accident). A same-class-family tiebreak (xss preferred) happened to
	// mask this for xss-vs-other pairs but did nothing for other-vs-other pairs. Fixed properly
	// by recording the FULL SET of sink classes present in each statement, not a single winner --
	// this makes "does this statement contain class X" (the actual question every consumer asks)
	// order-independent by construction, since set membership doesn't depend on insertion order.
	// NOTE (residual, documented not fixed): this is still coarser than per-sink identity -- a
	// sanitizer decision that needs to know WHICH of two co-located sinks a given source reaches
	// still can't get that from this structure. Preserving full sink-node identity through the
	// decision path (Map<Long,Map<Long,String>>, statementId -> sinkNodeId -> class, as the
	// review suggested) is the principled fix if a future consumer needs that; not built here
	// because no current consumer (xssClassSink boolean check; the purity report's per-statement
	// class-set display) needs finer granularity than "which classes are present."
	public static HashMap<Long, java.util.Set<String>> stmtSinkClass = new HashMap<Long, java.util.Set<String>>();
	public static HashMap<Long, Integer> savesize = new HashMap<Long, Integer>();

	/** Null-safe Edgesize accessor. traverse()'s convergence checks compare
	 *  Edgetimes.get(next) (always non-null once mergeNode() has run) against Edgesize.get(next)
	 *  via auto-unboxing '>' / '==' -- a CFG target that a later, additive dispatch-resolution
	 *  feature (hook-registration edges, sink-funcid nodes, forwarded call edges) can introduce
	 *  WITHOUT ever registering it in Edgesize throws a NullPointerException at that unboxing.
	 *  es(id) returns the stored size if present, else defensively seeds Edgesize.put(id, 1) and
	 *  returns 1 -- the SAME conservative default (a single predecessor edge) this file already
	 *  used ad hoc elsewhere for other dynamically-discovered nodes (see the ctor/backing-field
	 *  `Edgesize.put(id, Math.max(1, inDegree))` pattern below). Only call sites that were
	 *  genuinely unguarded were converted to es(); sites already behind an explicit containsKey
	 *  guard, an explicit ==null check, or used only as a boxed .equals()/println argument
	 *  (never unboxed, so they cannot NPE this way) were left as raw Edgesize.get() calls. */
	private static int es(Long id) {
		Integer v = Edgesize.get(id);
		if (v == null) { v = 1; Edgesize.put(id, v); }
		return v;
	}
	public static HashMap<Long, Boolean> active = new HashMap<Long, Boolean>();
	public static MultiHashMap<Long, Long> sourceFunc = new MultiHashMap<Long, Long>(); 
	public static MultiHashMap<Long, Long> clean = new MultiHashMap<Long, Long>();
	public static HashSet<Long> loop = new HashSet<Long>();
	public static HashSet<Long> forloop = new HashSet<Long>();
	public static MultiHashMap<Long, Long> srcStmt = new MultiHashMap<Long, Long>();
	public static HashMap<Long, Integer> loopsize = new HashMap<Long, Integer>(); 
	public static HashSet<Long> allTargets = new HashSet<Long>();
	public static HashMap<Long, HashMap<String, Long>> addInter = new HashMap<Long, HashMap<String, Long>>(); 
	public static HashMap<Long, HashMap<String, Long>> removeInter = new HashMap<Long, HashMap<String, Long>>();
	public static HashMap<Long, Boolean> addIntro = new HashMap<Long, Boolean>();
	public static HashMap<Long, Stack<Long>> sum = new HashMap<Long, Stack<Long>>();
	public static HashSet<Long> expList = new HashSet<Long>();
	public static HashMap<Long, String> dstDim = new HashMap<Long, String>();
	
	public StaticAnalysis() {
		init();
		// Scalability guard for very large plugins (>750k AST nodes): the taint analysis
		// is O(entries × reachable_statements). With 1000+ entry points (wp_loaded, init,
		// plugins_loaded, …) and hundreds of thousands of nodes each analysis times out.
		// For large plugins, restrict topFunIds to UNAUTH and LOW-PRIV handlers only —
		// these are the ones that produce bounty-relevant findings (an authenticated-admin
		// path is almost never actionable at Standard tier). Structural hooks (wp_loaded,
		// plugins_loaded, wp_enqueue_scripts) don't carry request taint and are dropped too.
		final int TAINT_NODE_LIMIT = 750_000;
		System.err.println("IDTONODE_SIZE="+ASTUnderConstruction.idToNode.size()+" LIMIT="+TAINT_NODE_LIMIT);
		if( ASTUnderConstruction.idToNode.size() > TAINT_NODE_LIMIT ) {
			Set<Long> trimmed = new HashSet<Long>();
			for( Long fid : PHPCGFactory.topFunIds ) {
				String priv = PHPCGFactory.entryPriv.get(fid);
				// Keep only handlers that actually carry user request data (AJAX, REST, self-contained).
				// Structural hooks (wp_loaded, plugins_loaded, wp_enqueue_scripts, wp_head, etc.)
				// are called on every request but do not carry user-controlled input as taint sources —
				// they produce zero bounty-relevant findings while dominating entry-point count.
				boolean keepEntry = false;
				if( priv != null ) {
					keepEntry = priv.contains("nopriv") || priv.contains("wp_ajax")
						|| priv.startsWith("rest:") || priv.contains("self-contained")
						|| priv.startsWith("parse_request") || priv.startsWith("template_redirect")
						|| priv.startsWith("wp_loaded:") && priv.contains("nopriv");
				}
				if( keepEntry ) {
					trimmed.add(fid);
				}
			}
			int dropped = PHPCGFactory.topFunIds.size() - trimmed.size();
			System.err.println("TAINT_ENTRY_CAP large plugin ("+ASTUnderConstruction.idToNode.size()
				+" nodes): "+PHPCGFactory.topFunIds.size()+" → "+trimmed.size()
				+" entries (dropped "+dropped+" auth/structural hooks)");
			PHPCGFactory.topFunIds = trimmed;
		}
		for(Long entry: PHPCGFactory.topFunIds) {
			ID2Node = new HashMap<Long, Node>();
			//the source can only be in the main application
			if(isVendoredDir(PHPCGFactory.getDir(entry))) {
				continue;
			}
			//the file is included/required, so it is not the entry
			ASTNode filename = ASTUnderConstruction.idToNode.get(entry);
			//System.out.println("filename: "+filename.getEscapedCodeStr());
			if(!PHPCGFactory.entrypoint.contains(filename.getEscapedCodeStr())) {
				//continue;
			}
			if(CSVCFGExporter.cfgSave.get(entry+1)==null) {
				continue;
			}
			Long stmt = CSVCFGExporter.cfgSave.get(entry+1).get(0);
			Set<Long> intro = new HashSet<Long>();
			ID = (long) 0;
			HashMap<String, Long> inter = new Node.TracingInterMap();
			Stack<Long> callStack = new Stack<Long>();
			Node node = new Node(stmt, inter, intro, callStack);
			constructTaintTree(node);
		}
		emitAllFindings();   // all roots processed -> emit each finding once
		detectInlineSourceTaint();
		System.out.println("Summary: "+sum);
		// Emit ESCAPED lines for sinks tagged by filterProvablySafeXssSinks as escaper-matched-by-name.
		// These are sinks the engine previously deleted silently; they now survive for downstream review.
		// Emit regardless of whether a taint path was found (the name-match alone is the signal).
		for( java.util.Map.Entry<Long, String> e : cg.PHPCGFactory.xssEscaperMatched.entrySet() ) {
			Long s = e.getKey();
			String escaper = e.getValue();
			ASTNode sn = ASTUnderConstruction.idToNode.get(s);
			if( sn == null ) continue;
			String dir = PHPCGFactory.getDir(s);
			int line = (sn.getLocation() != null) ? sn.getLocation().startLine : -1;
			System.out.println("ESCAPED node="+s+" escaper="+escaper+" file="+dir+" line="+line);
		}
		if( System.getenv("WP_SINK_LOC") != null ) {
			for( Long s : sum.keySet() ) {
				ASTNode sn = ASTUnderConstruction.idToNode.get(s);
				if( sn == null ) continue;
				String dir = PHPCGFactory.getDir(s);
				String code = sn.getEscapedCodeStr();
				if( code != null && code.length() > 80 ) code = code.substring(0,80)+"...";
				boolean hasPath = sum.get(s) != null && !sum.get(s).isEmpty();
				System.out.println("SINKLOC node="+s+" path="+(hasPath?"yes":"no")
					+" file="+dir+" line="+sn.getLocation().startLine+" code=["+code+"]");
				// Also flag if this finding's sink was escaper-tagged (may be a false-safe case).
				if( cg.PHPCGFactory.xssEscaperMatched.containsKey(s) )
					System.out.println("ESCAPED node="+s+" escaper="
						+cg.PHPCGFactory.xssEscaperMatched.get(s)+" file="+dir+" line="+sn.getLocation().startLine);
			}
		}
	}
	
	void init() {
		System.out.println("Entry point: "+PHPCGFactory.entrypoint);
		//System.out.println("Call Graph "+PHPCGFactory.call2mtd);
		// integrity check: call2mtd duplicates inflate Edgesize and deadlock merges (WP_DUP_AUDIT=1)
		if("1".equals(System.getenv("WP_DUP_AUDIT_SELFTEST"))) {   // inject one dup to prove the audit fires
			for(Long cs : PHPCGFactory.call2mtd.keySet()) {
				java.util.List<Long> cl = PHPCGFactory.call2mtd.get(cs);
				if(cl != null && !cl.isEmpty()) { PHPCGFactory.call2mtd.add(cs, cl.get(0)); break; }
			}
		}
		cg.CallGraphDupAudit.run();
		
		//collect cfg node
		cfgNode.addAll(CSVCFGExporter.cfgSave.keySet());
		//set the sanitizer statement
		for(Long astID: PHPCSVEdgeInterpreter.sqlSanitizers) {
			Long stmt = getStatement(astID);
			sqlSanitizers.add(stmt);
		}
		//statement -> source dim
		Set<Long> srcGlobalSet = new HashSet<Long>();
		for(Long dim: PHPCSVEdgeInterpreter.dimVar) {
			Long tmp=null, tmp1=null;
			if(System.getenv("SG_PIPELINE_DIAG")!=null) {
				ASTNode _arrName = ASTUnderConstruction.idToNode.get(dim+2);
				boolean _isGlobals = _arrName != null && "string".equals(_arrName.getProperty("type"))
					&& "GLOBALS".equals(_arrName.getEscapedCodeStr());
				if(_isGlobals) {
					Long _stmt0 = getStatement(dim);
					ASTNode _stmtNode0 = ASTUnderConstruction.idToNode.get(_stmt0);
					System.err.println("DIMVAR_GLOBAL_CANDIDATE dim="+dim+" stmt="+_stmt0
						+" stmt_type="+(_stmtNode0==null?"null":_stmtNode0.getClass().getSimpleName()));
				}
			}
			//get the statement of expression
			ASTNode DIMNode = ASTUnderConstruction.idToNode.get(dim);
			Long stmt = getStatement(dim);
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
			//it is in assignment
			if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight()!=null) {
				Long rightHandId = ((AssignmentExpression) stmtNode).getRight().getNodeId();
				Long leftHandId = ((AssignmentExpression) stmtNode).getLeft().getNodeId();
				//the dim is in the right hand
				if(rightHandId<=dim) {
					tmp=dim;
				}
				//the dim is assigned
				else if(leftHandId.equals(dim)){
					tmp1=dim;
					String iden = getDIMIdentity(DIMNode);
					dstDim.put(stmt, iden);
				}
			}
			//it is a function call
			else if(stmtNode instanceof CallExpressionBase) {
				tmp=dim;
			}
			//it is a return statement — a superglobal in a `return` is an inline source for
			//the P13 SQL-filter return-sink (posts_where/join callbacks whose return value is
			//spliced into WP core's query). Only consulted when the return is also a sink, so
			//this does not affect any non-filter return.
			else if(stmtNode instanceof ReturnStatement) {
				tmp=dim;
			}
			//the dim is used as source variable
			if(tmp!=null) {
				//the dim is $GLOABLS[] variable
				ASTNode arrayName = ASTUnderConstruction.idToNode.get(dim+2);
				if(arrayName.getProperty("type").equals("string") && arrayName.getEscapedCodeStr().equals("GLOBALS")) {
					if(System.getenv("SG_PIPELINE_DIAG")!=null) {
						String _iden0 = getDIMIdentity(ASTUnderConstruction.idToNode.get(dim));
						System.err.println("SRC_GLOBAL_WRITE stmt="+stmt+" dim="+dim+" tmp="+tmp
							+" identity="+_iden0+" func="+stmtNode.getFuncId()
							+" already_in_sources="+PHPCSVEdgeInterpreter.sources.contains(dim));
					}
					srcGlobal.add(stmt, tmp);
					srcGlobalSet.add(tmp);
					Long funcID = stmtNode.getFuncId();
					String iden = getDIMIdentity(ASTUnderConstruction.idToNode.get(dim));
					name2Func(iden, funcID);
				}
				else {
					// A request source inside the CONDITION of a ternary whose value-arms are
					// constant literals (e.g. cond($_GET) ? 'DESC' : 'ASC') only selects which
					// literal is produced — control-dependence, never data flow — so it cannot
					// carry injection. Do not seed it as a source. FN-free: skipped only when both
					// arms are provably literal-only (no variable/dim/prop/call in either arm).
					if(!inLiteralTernaryCondition(tmp) && !isBenignFilesSubfield(DIMNode)) {
						srcDim.add(stmt, tmp);
					}
				}
			}
			if(tmp1!=null) {
				//the dim is $GLOABLS[] variable
				ASTNode arrayName = ASTUnderConstruction.idToNode.get(dim+2);
				if(arrayName.getProperty("type").equals("string") && arrayName.getEscapedCodeStr().equals("GLOBALS")) {
					dstGlobal.add(stmt, tmp1);
					Long funcID = stmtNode.getFuncId();
					String iden = getDIMIdentity(ASTUnderConstruction.idToNode.get(dim));
					name2Func(iden, funcID);
				}
			}
		}
		// --- cross-function taint for `global $g;` variables ---
		// Build, per function, the set of variable names imported via `global $g;`. Globals are a
		// flat namespace, so a write to $g in one function and a read of $g in another (each having
		// declared it global) refer to the same storage. We register writes into dstGlobalVar and
		// reads into srcGlobalVar under a "GVAR::name" identity, and let the existing inter-procedural
		// propagation match them -- mirroring the property (src/dstProp) mechanism.
		// Skip on very large plugins: the two full-AST passes below are O(n²) at scale
		// (scan all nodes for GlobalStatement, then scan ALL variables for matches).
		// Large plugins rarely use PHP `global` keyword in AJAX handlers; the taint analysis
		// still catches superglobal $_POST/$_GET reads via the standard source-seeding path.
		HashMap<Long, Set<String>> funcGlobals = new HashMap<Long, Set<String>>();
		if( ASTUnderConstruction.idToNode.size() <= 750_000 ) {
		cg.PHPCGFactory.recordScanSite("SA_437", ASTUnderConstruction.idToNode.size());
		for(ASTNode gn: ASTUnderConstruction.idToNode.values()) {
			if(!(gn instanceof GlobalStatement)) continue;
			Variable gv = ((GlobalStatement) gn).getVariable();
			if(gv == null || gv.getNameExpression() == null) continue;
			String gname = gv.getNameExpression().getEscapedCodeStr();
			if(gname == null || gname.isEmpty()) continue;
			Long fid = gn.getFuncId();
			if(!funcGlobals.containsKey(fid)) funcGlobals.put(fid, new HashSet<String>());
			funcGlobals.get(fid).add(gname);
		}
		} else { System.err.println("GLOBAL_TRACK_SKIP large AST ("+ASTUnderConstruction.idToNode.size()+" nodes)"); }
		if(!funcGlobals.isEmpty()) {
			cg.PHPCGFactory.recordScanSite("SA_449", ASTUnderConstruction.idToNode.size());
			for(ASTNode vn: ASTUnderConstruction.idToNode.values()) {
				if(!(vn instanceof Variable)) continue;
				Variable v = (Variable) vn;
				Long fid = v.getFuncId();
				Set<String> names = funcGlobals.get(fid);
				if(names == null) continue;
				if(v.getNameExpression() == null) continue;
				String vname = v.getNameExpression().getEscapedCodeStr();
				if(vname == null || !names.contains(vname)) continue;
				// skip the `global $g;` declaration's own Variable child
				Long parentId = PHPCSVEdgeInterpreter.child2parent.get(v.getNodeId());
				if(parentId != null && ASTUnderConstruction.idToNode.get(parentId) instanceof GlobalStatement) continue;
				Long stmt = getStatement(v.getNodeId());
				ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
				boolean isWrite = false;
				if(stmtNode instanceof AssignmentExpression
						&& ((AssignmentExpression) stmtNode).getLeft() != null
						&& ((AssignmentExpression) stmtNode).getLeft().getNodeId().equals(v.getNodeId())) {
					isWrite = true;
				}
				// Mirror the $GLOBALS[...] pattern exactly (both read and write sides call
				// name2Func there, lines ~331/357): the zero-argument call-descent gate
				// (~line 3102) only steps into a callee if name2Func says the callee USES the
				// caller's current inter identity. Without this, GVAR::-prefixed identities were
				// NEVER registered, so descent could never trigger for declared-global state --
				// confirmed via CALL_RELEVANCE_CHECK: inter_identity=GVAR::g name2Func_targets=null.
				// Registered at the ADMITTED producer statement (this `stmt`), never at the bare
				// `global $g;` declaration itself -- that Variable child is already excluded above.
				if(isWrite) {
					dstGlobalVar.add(stmt, v.getNodeId());
					name2Func(getGlobalVarIdentity(v), fid);
				}
				else {
					srcGlobalVar.add(stmt, v.getNodeId());
					name2Func(getGlobalVarIdentity(v), fid);
				}
			}
		}
		//statement -> source property
		Set<Long> srcPropSet = new HashSet<Long>();
		// Scalability: for large plugins skip the expensive getPropIdentity (getClassId) calls.
		// Property classification (srcProp/dstProp) still runs — only the name2Func/iden lookup
		// that powers stored-taint interprocedural matching is skipped. Stored-taint findings
		// on large plugins are infrequent and still caught via the inline-source path.
		final boolean skipPropIden = ASTUnderConstruction.idToNode.size() > 750_000;
		if( skipPropIden ) System.err.println("PROP_IDEN_SKIP large AST ("+ASTUnderConstruction.idToNode.size()+" nodes) - name2Func/iden disabled");
		for(Long prop: PHPCSVEdgeInterpreter.property) {
			Long stmt = getStatement(prop);
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
			try {
				//it is in assignment
				if(stmtNode instanceof AssignmentExpression) {
					Long rightHandId = ((AssignmentExpression) stmtNode).getRight().getNodeId();
					Long leftHandId = ((AssignmentExpression) stmtNode).getLeft().getNodeId();
					//it is in the right hand
					if(rightHandId<=prop) {
						srcProp.add(stmt, prop);
						srcPropSet.add(prop);
					}
					//it is in the left hand
					else if(leftHandId.equals(prop)){
						dstProp.add(stmt, prop);
					}
					//get the function of prop
					if( !skipPropIden ) {
						Long funcID = stmtNode.getFuncId();
						String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
						name2Func(iden, funcID);
					}
				}
				//it is a function call
				else if(stmtNode instanceof CallExpressionBase) {
					srcProp.add(stmt, prop);
					srcPropSet.add(prop);
					if( !skipPropIden ) {
						Long funcID = stmtNode.getFuncId();
						String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
						name2Func(iden, funcID);
					}
				}
				//it is a return node
				else if(stmtNode instanceof ReturnStatement) {
					srcProp.add(stmt, prop);
					srcPropSet.add(prop);
					if( !skipPropIden ) {
						Long funcID = stmtNode.getFuncId();
						String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
						name2Func(iden, funcID);
					}
				}
				//it is an echo/exit sink: a tainted property output directly (e.g. echo $this->data)
				//must be matched against the symbolic property-taint set, same as the cases above.
				//Without this, property taint that reaches an output sink without first passing through a
				//local is silently dropped (object-field-sensitivity recall gap).
				else if(stmtNode instanceof EchoStatement || stmtNode instanceof ExitExpression) {
					srcProp.add(stmt, prop);
					srcPropSet.add(prop);
					if( !skipPropIden ) {
						Long funcID = stmtNode.getFuncId();
						String iden = getPropIdentity(ASTUnderConstruction.idToNode.get(prop), (long) 0);
						name2Func(iden, funcID);
					}
				}
			} catch(Exception e){
				//System.err.println("Unknown assignment: "+stmt);
			}
			
		}
		
		// Defect 3: build the property-to-request-origin map now that dstProp is populated.
		// This pre-computes which property identities can be reached from $_POST/$_GET/...
		// through local variable chains, so vulSources.add can emit the superglobal origin
		// alongside the bare property read node.
		cg.PHPCGFactory.buildPropRequestOrigins();
		// Defect 2: remove from srcPropSet any property that is ONLY ever written from
		// $wpdb->prepare() return values. Those properties carry parameterized/escaped SQL
		// and should not be seeded as stored-taint sources — doing so creates false positives
		// (the value stored is safe, but taint flows through it to a real query and fires).
		// Skip the per-property safePrepare check for large plugins — it calls getClassId()
		// per srcPropSet entry (potentially 10k+ calls), timing out on 800k+ node plugins.
		// The Defect 2 inline-source guard in the taint analysis handles these regardless.
		if( !cg.PHPCGFactory.safePrepareProps.isEmpty() && ASTUnderConstruction.idToNode.size() <= 750_000 ) {
			java.util.Iterator<Long> it = srcPropSet.iterator();
			while( it.hasNext() ) {
				Long propNode = it.next();
				ASTNode pn = ASTUnderConstruction.idToNode.get(propNode);
				if( pn == null ) continue;
				String iden = getPropIdentity(pn, 0L);
				if( iden != null && cg.PHPCGFactory.safePrepareProps.contains(iden) ) {
					it.remove();
					System.err.println("SAFE_PREPARE_EXCLUDE "+iden+" node="+propNode);
				}
			}
		}

		// XSS-only: the HTML-allowlist wrappers (wp_kses/wp_kses_post/wp_kses_data) neutralize
		// markup-based XSS, so taint must STOP at them. They are kept taint-preserving for SQL
		// (they leave quotes intact) but treated as sanitizers for an XSS scan.
		if( cg.PHPCGFactory.XSS_ONLY ) {
			taintPreserving.remove("wp_kses");
			taintPreserving.remove("wp_kses_post");
			taintPreserving.remove("wp_kses_data");
		}

		//get the sink statement
		for(Long sink: PHPCGFactory.sinks) {
			// XSS-only: keep only output sinks (tagged "xss"); drop SQL ($wpdb, untagged) and
			// extended (ssrf/lfi/object-injection, tagged otherwise) sinks.
			if( cg.PHPCGFactory.XSS_ONLY && !"xss".equals(cg.PHPCGFactory.sinkClass.get(sink)) ) continue;
			// PRIV_ESC-only / FILE_READ-only: keep just that class so the emitted stream is
			// single-class and the adjudicator's --vul-class label is accurate.
			if( cg.PHPCGFactory.PRIV_ESC_ONLY ) {
				String sc = cg.PHPCGFactory.sinkClass.get(sink);
				if( sc == null || !sc.startsWith("priv_esc") ) continue;
			}
			if( cg.PHPCGFactory.FILE_READ_ONLY
			    && !"file-read".equals(cg.PHPCGFactory.sinkClass.get(sink)) ) continue;
			if( cg.PHPCGFactory.FILE_DELETE_ONLY
			    && !"file-delete".equals(cg.PHPCGFactory.sinkClass.get(sink)) ) continue;
			Long stmt = getStatement(sink);
			// Record EVERY class present in this statement (a Set, not a single winner -- see
			// the stmtSinkClass field comment). Order-independent by construction.
			{
				String sinkCls = cg.PHPCGFactory.sinkClass.get(sink);
				if( sinkCls != null ) {
					stmtSinkClass.computeIfAbsent(stmt, k -> new java.util.HashSet<String>()).add(sinkCls);
				}
			}
			sinks.add(stmt);
		}
		// CLASS-PURITY EVIDENCE. The harness must be able to ASSERT that an isolated profile really
		// produced a single-class sink set, rather than trusting that an env flag was passed. Emits
		// the kept/dropped counts and the surviving class set.
		{
			java.util.Map<String,Integer> kept = new java.util.TreeMap<String,Integer>();
			int multiClassStmts = 0;
			for( Long st : sinks ) {
				java.util.Set<String> classes = stmtSinkClass.get(st);
				if( classes == null || classes.isEmpty() ) {
					String k = "untagged(sql-default)";
					kept.put(k, kept.containsKey(k) ? kept.get(k)+1 : 1);
				} else {
					// A statement can genuinely contain sinks of more than one class (e.g.
					// array($wpdb_call, printf($x))) -- count it toward EVERY class present
					// rather than picking one, so the report can't silently hide a co-located
					// sink the way the single-value map did.
					if( classes.size() > 1 ) multiClassStmts++;
					for( String c : classes ) kept.put(c, kept.containsKey(c) ? kept.get(c)+1 : 1);
				}
			}
			System.err.println("SINK_CLASS_PURITY kept_sink_stmts=" + sinks.size()
				+ " classes=" + kept
				+ (multiClassStmts > 0 ? " multi_class_statements=" + multiClassStmts : "")
				+ " isolation=" + (cg.PHPCGFactory.PRIV_ESC_ONLY ? "PRIV_ESC_ONLY"
					: cg.PHPCGFactory.FILE_DELETE_ONLY ? "FILE_DELETE_ONLY"
					: cg.PHPCGFactory.FILE_READ_ONLY ? "FILE_READ_ONLY"
					: cg.PHPCGFactory.XSS_ONLY ? "XSS_ONLY"
					: cg.PHPCGFactory.SQLI_ONLY ? "SQLI_ONLY" : "NONE")
				+ " env_WP_SQLI_ONLY=" + ("1".equals(System.getenv("WP_SQLI_ONLY"))));
		}
		//echo/print output sinks (XSS-class) unless in SQLi-only / priv-esc-only / file-read-only mode
		if( !cg.PHPCGFactory.SQLI_ONLY && !cg.PHPCGFactory.PRIV_ESC_ONLY
		    && !cg.PHPCGFactory.FILE_READ_ONLY && !cg.PHPCGFactory.FILE_DELETE_ONLY ) {
		for(Long sink: PHPCSVNodeInterpreter.xsssinks) {
			Long stmt = getStatement(sink);
			sinks.add(stmt);
		}
		}
		
		System.out.println(sinks);
		
		//get the identity of the source class property and global variables
		for(Long src: srcPropSet) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String iden = getPropIdentity(srcNode, (long) 0);
			name2Stmt.add(iden, src);
		}
		for(Long src: srcGlobalSet) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String iden = getDIMIdentity(srcNode);
			name2Stmt.add(iden, src);
		}
		
		//get all destination stmts
		Set<Long> value = new HashSet<Long>();
		for(Long key: CSVCFGExporter.cfgSave.keySet()) {
			List<Long> vals = CSVCFGExporter.cfgSave.get(key);
			for(Long val: vals) {
				value.add(val);
			}
		}
		
		for(Long key: CSVCFGExporter.cfgSave.keySet()) {
			//catch stmt: the stmt is never reached and it is not the entry point stmt
			if(!value.contains(key) && ASTUnderConstruction.idToNode.containsKey(key)) {
				System.out.println("catch: "+key);
				continue;
			}
			
			
			List<Long> vals = CSVCFGExporter.cfgSave.get(key);
			int w = 1;
			ASTNode stmtNode = ASTUnderConstruction.idToNode.get(key);
			if(PHPCGFactory.call2mtd.containsKey(key)) {
				w = PHPCGFactory.call2mtd.get(key).size();
			}
			else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
				CallExpressionBase callsite = (CallExpressionBase) ((AssignmentExpression) stmtNode).getRight();
				if(PHPCGFactory.call2mtd.containsKey(callsite.getNodeId())) {
					w = PHPCGFactory.call2mtd.get(callsite.getNodeId()).size();
				}
				
			}
			for(Long val: vals) {
				//expList
				if(ASTUnderConstruction.idToNode.containsKey(key) && ASTUnderConstruction.idToNode.get(key).getProperty("type").equals("AST_EXPR_LIST")) {
					expList.add(val);
				}
				
				//loop back
				if(val<key && ASTUnderConstruction.idToNode.containsKey(val) && CSVCFGExporter.cfgSave.containsKey(val)) {
					//the third element of for loop
					if(CSVCFGExporter.cfgSave.get(val).size()<2) {
						if(CSVCFGExporter.cfgSave.get(val).size()==1) {
							forloop.add(val);
							Long next = CSVCFGExporter.cfgSave.get(val).get(0);
							if(CSVCFGExporter.cfgSave.get(next).size()<2) {
								continue;
							}
							else {
								next = CSVCFGExporter.cfgSave.get(next).get(1);
								if(!Edgesize.containsKey(next)) {
									Edgesize.put(next, w);
								}
								else {
									int number = Edgesize.get(next)+w;
									Edgesize.put(next, number);
								}
							}
						}
						continue;
					}
					//System.err.println("val: "+val);
					loop.add(val);
					Long next = CSVCFGExporter.cfgSave.get(val).get(1);
					while(loop.contains(next)) {
						next = CSVCFGExporter.cfgSave.get(next).get(1);
					}
					if(!Edgesize.containsKey(next)) {
						//System.out.println("edgesize: "+next+" "+w+" "+key);
						Edgesize.put(next, w);
					}
					else {
						int number = Edgesize.get(next)+w;
						//System.out.println("edgesize: "+next+" "+number+" "+key);
						Edgesize.put(next, number);
					}
				}
				else {
					if(!Edgesize.containsKey(val)) {
						Edgesize.put(val, w);
					}
					else {
						int number = Edgesize.get(val)+w;
						Edgesize.put(val, number);
					}
				}
			}
		}
		
		for(Long third: forloop) {
			Edgesize.put(third, 0);
		}
		
		for(Long exp: expList) {
			Edgesize.put(exp, 1);
		}
		
		savesize = (HashMap<Long, Integer>) Edgesize.clone();
		
		// Cross-method object-property taint (isolated branch): must run BEFORE the sources-processing loop
		// below, since it adds newly-promoted property-read nodes to `sources`/`propertyTaintSourceNodes`,
		// and this loop is what turns membership in `sources` into srcStmt/sourceFunc facts.
		seedPropertyTaintSources();
		
		for(Long src: sources) {
			ASTNode srcNode = ASTUnderConstruction.idToNode.get(src);
			String dir = PHPCGFactory.getDir(srcNode.getNodeId());
			if("1".equals(System.getenv("WP_PROP_DEBUG")) && propertyTaintSourceNodes.contains(src)) {
				System.out.println("PROP_DEBUG sourcesLoop src=" + src + " dir=" + dir
					+ " isVendored=" + isVendoredDir(dir) + " isSource=" + isSource(src)
					+ " inTernary=" + inLiteralTernaryCondition(src) + " inMatch=" + inLiteralMatchControl(src)
					+ " stmt=" + getStatement(src) + " funcId=" + srcNode.getFuncId());
			}
			if(isVendoredDir(dir)) {
				continue;
			}
			if(isSource(src) && !inLiteralTernaryCondition(src) && !inLiteralMatchControl(src)) {
				srcStmt.add(getStatement(src), src);
				sourceFunc(src, srcNode.getFuncId());
			}
		}
		
		//get all target functions
		for(Long key: PHPCGFactory.call2mtd.keySet()) {
			allTargets.addAll(PHPCGFactory.call2mtd.get(key));
		}
	}
	
	private void sourceFunc(Long src, Long funcId) {
		//the statement of source
		Long stmtID = getStatement(src);
		//the functions define source
		HashSet<Long> related = getAllcaller(funcId);
		for(Long relate: related) {
			//function => source stmt
			sourceFunc.add(relate, stmtID);
		}
	}

	private void name2Func(String inter, Long func) {
		if(!inter.contains("::")) {
			return;
		}
		HashSet<Long> related = getAllcaller(func);
		for(Long relate: related) {
			//prop identity => function
			name2Func.add(inter, relate);
		}
	}
	
	//get all function called the input function
	private HashSet<Long> getAllcaller(Long func) {
		if(callee2caller.containsKey(func)) {
			HashSet<Long> ret=new HashSet<Long>(callee2caller.get(func));
			return ret;
		}
		else {
			HashSet<Long> ret=new HashSet<Long>();
			Queue<Long> que = new LinkedList<Long>();
			que.add(func);
			while(!que.isEmpty()) {
				Long node = que.poll();
				ret.add(node);
				if(PHPCGFactory.callee2caller.containsKey(node)) {
					List<Long> callers = PHPCGFactory.callee2caller.get(node);
					for(Long caller: callers) {
						ASTNode callerNode = ASTUnderConstruction.idToNode.get(caller);
						//valid call site
						if(callerNode instanceof CallExpressionBase || callerNode instanceof IncludeOrEvalExpression ||
								(callerNode instanceof AssignmentExpression && ((AssignmentExpression) callerNode).getRight() instanceof CallExpressionBase) ||
								(callerNode instanceof ReturnStatement && ((ReturnStatement) callerNode).getReturnExpression() instanceof CallExpressionBase)) {
							Long funcID = callerNode.getFuncId();
							if(!ret.contains(funcID)) {
								//System.out.println("add caller: "+funcID);
								ret.add(funcID);
								que.add(funcID);
							}
						}
					}
				}
			}
			for(Long node: ret) {
				callee2caller.add(func, node);
			}
			return ret;
		}
	}

	//get all callees of the input function
	private HashSet<Long> getAllcallee(Long func) {
		if(caller2callee.containsKey(func)) {
			HashSet<Long> ret=new HashSet<Long>(caller2callee.get(func));
			return ret;
		}
		else {
			HashSet<Long> ret=new HashSet<Long>();
			Queue<Long> que = new LinkedList<Long>();
			que.add(func);
			while(!que.isEmpty()) {
				Long node = que.poll();
				ret.add(node);
				if(PHPCGFactory.mtd2mtd.containsKey(node)) {
					List<Long> callees = PHPCGFactory.mtd2mtd.get(node);
					for(Long callee: callees) {
						ASTNode target = ASTUnderConstruction.idToNode.get(callee);
						if(!ret.contains(callee)) {
							if(isVendoredDir(PHPCGFactory.getDir(callee)) ||
									target.getEnclosingClass()!=null && (target.getEnclosingClass().contains("test") || target.getEnclosingClass().contains("Test")) ||
									target.getEscapedCodeStr()!=null && (target.getEscapedCodeStr().contains("test") || target.getEscapedCodeStr().contains("Test"))) {
								continue;
							}
							que.add(callee);
						}
					}
				}
			}
			for(Long node: ret) {
				caller2callee.add(func, node);
			}
			return ret;
		}
	}

	// Inline source->sink: a request/stored source used directly inside a sink statement with no
	// intermediate variable (echo $_GET['x']; $wpdb->query("..".$_POST['y']); print get_post_meta(..)).
	// The variable-dataflow misses these because there is no def-use edge to follow — the source IS
	// the sink's argument. This pass flags such a sink when an unsanitized source sits in its subtree.
	// Sanitizer-aware: a source wrapped in esc_html(...) (XSS) or esc_sql/intval(...) (SQL) on the path
	// up to the sink is clean, matching the variable-mediated behaviour.
	private void detectInlineSourceTaint() {
		HashMap<Long,String> sinkStmtClass = new HashMap<Long,String>();
		for(Long sn: cg.PHPCGFactory.sinks) {
			Long st = getStatement(sn);
			if(st != null && !sinkStmtClass.containsKey(st)) sinkStmtClass.put(st, cg.PHPCGFactory.sinkClass.get(sn));
		}
		for(Long sn: PHPCSVNodeInterpreter.xsssinks) {
			Long st = getStatement(sn);
			if(st != null) sinkStmtClass.put(st, "xss");
		}
		for(Long src: PHPCSVEdgeInterpreter.sources) {
			Long stmt = getStatement(src);
			if(stmt == null || !sinks.contains(stmt)) continue;          // source sits inside a sink statement
			if(sum.containsKey(stmt)) continue;                          // already reported by the dataflow
			// Scope to output (XSS-class) sinks: echo/print are not call-arguments, so isSource misses
			// them. SQL sinks are method-call args already covered by isSource — leave that mature path
			// untouched (its quote/placeholder reasoning is finer than a flat sanitizer-on-path check).
			if(!"xss".equals(sinkStmtClass.get(stmt))) continue;
			ASTNode sNode = ASTUnderConstruction.idToNode.get(src);
			if(sNode == null) continue;
			String dir = cg.PHPCGFactory.getDir(src);
			if(isVendoredDir(dir)) continue;
			if(inTernaryCondition(src)) continue;   // source only in a ternary condition -> never output
			if(sanitizedOnPath(src, stmt, sinkStmtClass.get(stmt))) continue;   // wrapped in a sanitizer
			Stack<Long> path = new Stack<Long>(); path.push(stmt);
			if(isVendoredDir(PHPCGFactory.getDir(stmt))) continue;   // skip bundled/vendored code
			sum.put(stmt, path);
			// Emit Vul + Vul Source here (same format as getVulnerablePath) so all finding paths
			// produce parseable output regardless of which detection mechanism fired.
			if(System.getenv("WP_SITE_DIAG")!=null) System.err.println("SITE_DIAG site=INLINE_SOURCE_TAINT stmt="+stmt);
			totalVulCount++;
			System.out.println("Vul: "+stmt);
			emitVulSinkIdentity(stmt);
			vulSources.add(stmt, src);
			emitVulSource(stmt);
		}
	}

	// True if a sanitizer call for the sink's class wraps `src` on the path up to the sink statement.
	private boolean sanitizedOnPath(Long src, Long sinkStmt, String cls) {
		boolean xss = "xss".equals(cls) || (cls == null && cg.PHPCGFactory.XSS_ONLY);
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(src);
		int guard = 0;
		while(cur != null && !cur.equals(sinkStmt) && guard++ < 300) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			if( System.getenv("WP_CAST_DIAG") != null ) {
				System.err.println("CAST_DIAG walk cur=" + cur + " class=" + (n==null?"null":n.getClass().getSimpleName()));
			}
			// Numeric CAST expressions: (int)/(float) coerce their operand to a number, so the
			// result cannot contain HTML/JS metacharacters regardless of what the operand was --
			// safe for XSS-context output specifically (SQL-context is NOT covered here: numeric
			// substitution safety for SQL depends on whether the surrounding query actually uses
			// the value as a bare numeric literal, a different and stricter question this cast
			// check doesn't attempt to answer, so it stays scoped to xss==true only). Deliberately
			// narrow: (string)/(array)/(object) casts do NOT neutralize anything and are not
			// included -- this is not a general "any cast sanitizes" rule.
			if(xss && n instanceof CastExpression) {
				String flags = n.getFlags();
				if( System.getenv("WP_CAST_DIAG") != null ) {
					System.err.println("CAST_DIAG cur=" + cur + " flags=" + flags);
				}
				if("TYPE_LONG".equals(flags) || "TYPE_DOUBLE".equals(flags)) return true;
			}
			if(n instanceof CallExpressionBase) {
				String nm = inlineCallName((CallExpressionBase)n);
				// array_map($cb, $arr): the per-element transform is the callback, so judge the
				// sink-class safety by $cb (array_map('intval',$x) sanitizes for SQL; 'sanitize_text_field'
				// sanitizes for XSS but NOT SQL) rather than by the literal name "array_map".
				if("array_map".equals(nm)) {
					String cb = firstStringArgName((CallExpressionBase)n);
					if(cb != null) nm = cb;
				}
				if(nm != null) {
					// Align the inline-source path with the main XSS suppressor: credit the WP esc_*
					// family (htmlEscapers: esc_html/esc_attr/esc_url/wp_kses*/...) in addition to the
					// numeric xssSanitizers list. Without this, `echo esc_html($_GET[...])` (and any
					// inline-forwarded param use wrapped in an escaper) was a false positive — the inline
					// path only checked xssSanitizers while the reaching-def path credited htmlEscapers.
					if(xss && cg.PHPCGFactory.isXssOutputEscaper(nm)) return true;
					if(xss && PHPCSVEdgeInterpreter.xssSanitizers.contains(nm)) return true;
					if(xss && PHPCSVEdgeInterpreter.xssInputSanitizers.contains(nm)) return true;
					// preg_replace with a character-stripping pattern that removes < and >
					if(xss && "preg_replace".equals(nm)
						&& cg.PHPCGFactory.isPregReplaceXssSanitizerPublic((CallExpressionBase)n)) return true;
					if(!xss && PHPCSVEdgeInterpreter.repairs.contains(nm)) return true;
					if(!xss && cg.PHPCGFactory.EXTENDED && PHPCSVEdgeInterpreter.pathSanitizers.contains(nm)) return true;
				}
				// INTERPROCEDURAL RETURN-SUMMARY CHECK (separate from the by-name checks above --
				// those stay exactly as they were, for the same-statement case they're good at, e.g.
				// echo esc_html($_GET['x']); Deliberately NOT "does this callee contain an escaper
				// anywhere" -- that would be unsound (a discarded esc_html($x) call whose result is
				// never returned must NOT suppress the finding; see the "escaper exists but is
				// irrelevant" regression fixture). Instead: does the RESOLVED callee's own
				// already-computed return-taint summary say THIS SPECIFIC CALLEE PARAMETER actually
				// contributes to what it returns? If every resolved target is analyzed and NONE of
				// them says this parameter is return-relevant, the source does not reach the sink
				// through this call -- equivalent, for this purpose, to being sanitized on this path.
				// Unresolved call or any unanalyzed target: fall through, unchanged conservative
				// behavior (same fail-closed rule used throughout today's other fixes).
				//
				// Uses mapSourceToResolvedCalleeParam(), NOT the raw call-site argument index --
				// for call_user_func/call_user_func_array the call-site argument index and the
				// callee's own parameter index are NOT the same thing (the args array at call_user_
				// func_array's own argument 1 unpacks element-by-element into the callee's
				// parameters). Using the raw call-site index here was a real, confirmed bug: a
				// resolved, genuinely-unsafe call_user_func_array target incorrectly cleared because
				// $_GET at args-array position 1 was compared against returnTaintPositions (keyed by
				// the callee's OWN parameter positions, where that same value lands at parameter 0
				// after unpacking) and never matched. See mapSourceToResolvedCalleeParam()'s own
				// docstring for the full mapping and its conservative-unless-provable fallbacks.
				Integer argPos = mapSourceToResolvedCalleeParam((CallExpressionBase)n, src);
				if(argPos != null) {
					List<Long> targets = cg.PHPCGFactory.call2mtd.get(n.getNodeId());
					if(targets != null && !targets.isEmpty()) {
						boolean allAnalyzed = true;
						boolean anyRelevant = false;
						for(Long t : targets) {
							if(!cg.PHPCGFactory.returnTaintAnalyzed.contains(t)) { allAnalyzed = false; break; }
							Set<Integer> pos = cg.PHPCGFactory.returnTaintPositions.get(t);
							if(pos != null && pos.contains(argPos)) { anyRelevant = true; break; }
						}
						if(allAnalyzed && !anyRelevant) return true;
					}
				}
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	// Maps `srcNodeId`'s position to a CALLEE PARAMETER index for call `call`, accounting for
	// call_user_func()/call_user_func_array()'s argument-unpacking semantics -- the raw call-site
	// argument index is NOT the callee's parameter index for either of these two functions:
	//
	//   ordinary resolved call:  call-site argument N        -> callee parameter N   (unchanged)
	//   call_user_func:          call-site argument N (>= 1) -> callee parameter N-1 (arg 0 is
	//                             the callable itself, not data)
	//   call_user_func_array:    args-array ELEMENT N        -> callee parameter N   (the entire
	//                             args array sits at the call's own argument 1, which by itself
	//                             says nothing about which callee parameter a value inside it
	//                             reaches -- only the element's position within that array does)
	//
	// Returns null (UNKNOWN) whenever the mapping can't be established with confidence -- callers
	// MUST treat null as "stay conservative" (the existing fallback), never as "position 0" or
	// "no relevant position". In particular, for call_user_func_array: null if the args argument
	// isn't a literal, statically-inspectable array expression (e.g. a variable, a function call
	// result, or built via array_merge/spread) or if any element has an explicit/associative key
	// (not a plain positional args list) -- both cases make "element N -> parameter N" unsafe to
	// assume, so this deliberately gives up rather than guess.
	private Integer mapSourceToResolvedCalleeParam(CallExpressionBase call, Long srcNodeId) {
		String cn = inlineCallName(call);
		ArgumentList al = call.getArgumentList();
		if( al == null ) return null;
		if( "call_user_func_array".equals(cn) ) {
			if( al.size() < 2 ) return null;
			Expression argsExpr = al.getArgument(1);
			if( argsExpr == null || !localSubtreeContains(argsExpr.getNodeId(), srcNodeId) ) return null;
			if( !(argsExpr instanceof ast.php.expressions.ArrayExpression) ) return null;
			ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression) argsExpr;
			for( int i = 0; i < arr.size(); i++ ) {
				ast.php.expressions.ArrayElement el = arr.getArrayElement(i);
				if( el == null ) return null;
				if( el.getKey() != null ) return null;   // associative/explicit key -- not a plain
					// positional args list; element-index-to-parameter mapping isn't safe here.
				if( el.getValue() != null && localSubtreeContains(el.getValue().getNodeId(), srcNodeId) ) {
					return i;
				}
			}
			return null;   // src is inside the array node itself but not cleanly inside one
				// element's value subtree (shouldn't normally happen for a literal array) -- give up
		}
		if( "call_user_func".equals(cn) ) {
			Integer callSitePos = argumentPositionContaining(call, srcNodeId);
			if( callSitePos == null || callSitePos < 1 ) return null;   // position 0 is the
				// callable itself, not a data argument this data-taint check is answering about
			return callSitePos - 1;
		}
		return argumentPositionContaining(call, srcNodeId);   // ordinary call: unchanged
	}

	// Returns the index of call c's argument whose subtree contains `node`, or null if `node`
	// isn't within any argument of c (e.g. it's the call's own receiver/target-function position,
	// or c is unrelated). Local to this file -- PHPCGFactory's subtreeIds() is private there and
	// this check is specific to sanitizedOnPath()'s ancestor walk, not worth exposing more broadly.
	private Integer argumentPositionContaining(CallExpressionBase c, Long node) {
		if(node == null) return null;
		ArgumentList al = c.getArgumentList();
		if(al == null) return null;
		for(int i = 0; i < al.size(); i++) {
			ASTNode a = al.getArgument(i);
			if(a == null) continue;
			if(a.getNodeId().equals(node)) return i;
			if(localSubtreeContains(a.getNodeId(), node)) return i;
		}
		return null;
	}

	private boolean localSubtreeContains(Long root, Long target) {
		if(root == null || target == null) return false;
		if(root.equals(target)) return true;
		java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
		java.util.Set<Long> seen = new java.util.HashSet<Long>();
		work.add(root);
		while(!work.isEmpty()) {
			Long id = work.poll();
			if(id == null || !seen.add(id)) continue;
			if(id.equals(target)) return true;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
			if(kids != null) work.addAll(kids.values());
		}
		return false;
	}

	private String inlineCallName(CallExpressionBase c) {
		Expression t = c.getTargetFunc();
		if(t instanceof Identifier && ((Identifier)t).getNameChild() != null)
			return ((Identifier)t).getNameChild().getEscapedCodeStr();
		if(t instanceof StringExpression) return ((StringExpression)t).getEscapedCodeStr();
		return null;
	}

	// True if argument at position argPos of call c is an empty array literal (array() or []).
	// Used to detect wp_kses($x, array()) which is unconditionally safe (strips all HTML).
	private boolean isEmptyArrayArg(CallExpressionBase c, int argPos) {
		ArgumentList args = c.getArgumentList();
		if(args == null || args.size() <= argPos) {
			// Fallback: parent2child may lack entries if childnum parsing failed.
			// Directly scan the children of this call's arg-list node for an AST_ARRAY with
			// no children of its own (= empty array literal).
			HashMap<Integer,Long> callKids = PHPCSVEdgeInterpreter.parent2child.get(c.getNodeId());
			if(callKids == null) return false;
			// Find the arg-list child (type AST_ARG_LIST)
			for(Long kid : callKids.values()) {
				ASTNode kn = ASTUnderConstruction.idToNode.get(kid);
				if(kn == null || !"AST_ARG_LIST".equals(kn.getProperty("type"))) continue;
				// Scan children of arg list for an AST_ARRAY
				HashMap<Integer,Long> argKids = PHPCSVEdgeInterpreter.parent2child.get(kid);
				if(argKids == null) {
					// Try rels.csv-backed child set (child2parent inverse) — count any AST_ARRAY children
					// by scanning all known nodes for parent=kid with type AST_ARRAY
					for(java.util.Map.Entry<Long,Long> e : PHPCSVEdgeInterpreter.child2parent.entrySet()) {
						if(!e.getValue().equals(kid)) continue;
						ASTNode maybe = ASTUnderConstruction.idToNode.get(e.getKey());
						if(maybe != null && "AST_ARRAY".equals(maybe.getProperty("type"))) {
							// Found an AST_ARRAY child of the arg list — check it's empty
							HashMap<Integer,Long> arrKids = PHPCSVEdgeInterpreter.parent2child.get(e.getKey());
							if(arrKids == null || arrKids.isEmpty()) return true;
						}
					}
					return false;
				}
				// Normal path: argKids is populated
				int idx = 0;
				for(Long argKid : argKids.values()) {
					if(idx++ == argPos) {
						ASTNode an = ASTUnderConstruction.idToNode.get(argKid);
						if(an != null && "AST_ARRAY".equals(an.getProperty("type"))) {
							HashMap<Integer,Long> arrKids = PHPCSVEdgeInterpreter.parent2child.get(argKid);
							return (arrKids == null || arrKids.isEmpty());
						}
						return false;
					}
				}
				return false;
			}
			return false;
		}
		Expression arg = args.getArgument(argPos);
		if(arg == null) return false;
		if("AST_ARRAY".equals(arg.getProperty("type"))) {
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(arg.getNodeId());
			return (kids == null || kids.isEmpty());
		}
		return false;
	}

	// First argument of a call, if it is a plain string literal, returned unquoted. Used to read the
	// callback name of array_map('callback', $arr) so its per-element sanitizer effect is evaluated.
	private String firstStringArgName(CallExpressionBase c) {
		ArgumentList a = c.getArgumentList();
		if(a == null || a.size() < 1) return null;
		Expression arg0 = a.getArgument(0);
		if(arg0 instanceof StringExpression) {
			String s = ((StringExpression)arg0).getEscapedCodeStr();
			if(s != null && s.length() >= 2) {
				char f = s.charAt(0), l = s.charAt(s.length()-1);
				if((f=='"'||f=='\'') && f==l) s = s.substring(1, s.length()-1);
			}
			return s;
		}
		return null;
	}

	//check if the source is a taint variable
	private boolean isSource(Long astId) {
		// Seeded hook-parameter sources are tainted by fiat and may appear inline (inside a concat/
		// sink argument) rather than as an assignment right-value, so accept them directly.
		if(cg.PHPCGFactory.hookParamSourceNodes.contains(astId)) return true;
		if(propertyTaintSourceNodes.contains(astId)) return true;   // cross-method object-property taint (isolated branch)
		while(PHPCSVEdgeInterpreter.child2parent.containsKey(astId)) {
			Long save = astId;
			astId = PHPCSVEdgeInterpreter.child2parent.get(astId);
			String rootType = ASTUnderConstruction.idToNode.get(astId).getProperty("type");
			// A request source that flows into a return statement (return $_GET[...], return "x".$_POST[...])
			// makes the enclosing function taint-producing, exactly like an assignment RHS — so its callers
			// get traversed. (Infrastructure correctness fix; not a corpus-recall change.)
			if( rootType.equals("AST_RETURN") ) return true;
			//the source is used in assignment
			if(rootType.equals("AST_ASSIGN") ||
					rootType.equals("AST_ASSIGN_OP") ||
					rootType.equals("AST_ASSIGN_REF") ||
					ASTUnderConstruction.idToNode.get(astId) instanceof CallExpressionBase) {
				// the source is the right value
				if(PHPCSVEdgeInterpreter.parent2child.get(astId).get(1).equals(save)) {
					return true;
				}
				else {
					return false;
				}
			}
		}
		return false;
	}

	//Does a subtree (an argument list / expression) contain a request source node?
	//Used so that a value wrapped in a built-in call (e.g. trim($_POST['x'])) is still
	//recognized as carrying taint into the call result.
	private boolean argsContainSource(Long nodeId, int depth) {
		if(nodeId == null || depth > 60) return false;
		if(PHPCSVEdgeInterpreter.sources.contains(nodeId)) return true;
		HashMap<Integer, Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nodeId);
		if(kids != null) {
			for(Long c: kids.values()) {
				if(argsContainSource(c, depth+1)) return true;
			}
		}
		return false;
	}

	// P15: true if the subtree rooted at n contains a call to a content-preserving built-in
	// (taintPreserving — NOT esc_sql/intval/absint) whose arguments contain a source. Used to
	// see through `$v = "...".sanitize_text_field($_POST['x'])."..."` where the taint-preserving
	// wrapper is nested inside a string concatenation rather than being the assignment RHS.
	private boolean nestedTaintPreservingSource(ASTNode n) {
		if(n == null) return false;
		if(n instanceof CallExpressionBase) {
			CallExpressionBase c = (CallExpressionBase) n;
			List<Long> tf = PHPCGFactory.call2mtd.get(c.getNodeId());
			if(tf == null || tf.isEmpty()) {           // built-ins only, like the direct pass-through
				String nm = null;
				Expression t = c.getTargetFunc();
				if(t instanceof Identifier && ((Identifier) t).getNameChild() != null)
					nm = ((Identifier) t).getNameChild().getEscapedCodeStr();
				else if(t instanceof StringExpression)
					nm = ((StringExpression) t).getEscapedCodeStr();
				if(nm != null && taintPreserving.contains(nm)) {
					ArgumentList a = c.getArgumentList();
					if(argsContainSource(a==null?null:a.getNodeId(), 0)) return true;
				}
			}
		}
		for(int i=0; i<n.getChildCount(); i++) {
			if(nestedTaintPreservingSource(n.getChild(i))) return true;
		}
		return false;
	}

	private void constructTaintTree(Node node) {
		if(ASTUnderConstruction.idToNode.containsKey(node.astId)) {
			Long funcID = ASTUnderConstruction.idToNode.get(node.astId).getFuncId();
			active.put(funcID, true);
			traverse(node);
			// ACCUMULATE ONLY. getVulnerablePath() ran here once per taint-tree root, and each run
			// re-printed EVERY key accumulated in vulStmts (never cleared between roots) — so one
			// finding produced an extra output line for every subsequent root. Emission is deferred
			// to emitAllFindings(), called once after the root loop completes.
			if(System.getenv("VF_DIAG")!=null)
				System.err.println("VFDIAG root_done vulStmts_keys="+vulStmts.keySet().size());
		}
		
	}

	// Emit "Vul Source: ..." lines for the given sink node ID using vulSources entries.
	// Called from both getVulnerablePath() and detectInlineSourceTaint().
	/** AUTHORITATIVE machine-readable evidence record. The human-readable "Vul ..." lines are
	 *  diagnostics/compatibility only. Regex parsing of increasingly structured text failed three
	 *  times in one session — on bracketed lists, embedded spaces and new record types — so
	 *  consumers should ingest EVJSON and never re-derive fields from prose. */
	/** TYPED serializer. No "does this look like an array" sniffing (that produced invalid JSON
	 *  for "[id]" earlier) — callers pass real Long/List/null and this renders by TYPE. */
	private static String jsonVal(Object v) {
		if(v == null) return "null";
		if(v instanceof Number) return String.valueOf(v);
		if(v instanceof java.util.List) {
			StringBuilder b = new StringBuilder("[");
			java.util.List<?> l = (java.util.List<?>)v;
			for(int i=0;i<l.size();i++) { if(i>0) b.append(","); b.append(jsonVal(l.get(i))); }
			return b.append("]").toString();
		}
		String s2 = String.valueOf(v);
		return "\"" + s2.replace("\\","\\\\").replace("\"","\\\"") + "\"";
	}
	private static void evjson(String kind, Object... kv) {
		StringBuilder b = new StringBuilder("EVJSON {\"schema_version\":\"value-flow-evidence-v1\"")
			.append(",\"record_kind\":").append(jsonVal(kind));
		for(int i=0; i+1<kv.length; i+=2)
			b.append(",").append(jsonVal(kv[i])).append(":").append(jsonVal(kv[i+1]));
		System.out.println(b.append("}").toString());
	}

	/** REQUIRED GATES for isrelatedEvidence(), run via RE_GATE_DIAG=1. Order independence and
	 *  same-argument multiplicity, verified directly against the method rather than inferred. */
	private void runRelatedEvidenceGates(Long stmt, Set<Long> intro, Long caller) {
		if(System.getenv("RE_GATE_DIAG")==null) return;
		java.util.LinkedHashMap<String,RelatedEvidence> ev = isrelatedEvidence(stmt, intro, caller);
		System.err.println("REGATE stmt="+stmt+" intro="+intro+" evidence_count="+ev.size());
		for(RelatedEvidence e : ev.values())
			System.err.println("  REGATE_ENTRY relatedNode="+e.relatedNode+" introNode="+e.introNode
				+" kind="+e.relationKind+" argIdx="+e.sinkArgumentIndex+" precision="+e.identityPrecision);
	}

	private void emitUnresolvedFlows(Long nodeID) {
		for(UnresolvedValueFlow u : unresolvedFlows.values()) {
			if(!u.sinkNode.equals(nodeID)) continue;
			evjson("UNRESOLVED_VALUE_FLOW",
				"sink_node", u.sinkNode,
				"related_node", u.unresolvedValueNode,
				"relation_kind", u.relationKind,
				"sink_argument_index", u.sinkArgumentIndex,
				"identity_precision", u.identityPrecision,
				"unresolved_relation_coverage", "ARGUMENT_MATCH_AND_FALLBACK_ONLY",
				"taint_state", u.taintStateNodes,
				// taint_state is STRUCTURAL METADATA (formal-parameter node ids of the function
				// containing the sink), proven by /tmp/introfix constant across every caller.
				// Must NOT be used for finding identity, supersession, or route discrimination.
				"taint_state_semantics", "ENCLOSING_FUNCTION_PARAMETERS",
				"taint_state_role", "NON_DISCRIMINATING_METADATA",
				"route_context", u.routeContext,
				"ultimate_origin", null,
				"unresolved_reason", u.unresolvedReason,
				"record_role", "PRIMARY");
			System.out.println("Vul UnresolvedFlow: sink_node="+u.sinkNode
				+" taint_state="+u.taintStateNodes
				+" route_context="+u.routeContext
				+" evidence_class=UNRESOLVED_VALUE_FLOW"
				+" ultimate_origin=NOT_ESTABLISHED"
				+" unresolved_reason="+u.unresolvedReason
				+" record_role=PRIMARY");
		}
	}

	private void emitVulSource(Long nodeID) {
		emitUnresolvedFlows(nodeID);
		if(!vulSources.containsKey(nodeID)) return;
		java.util.Set<Long> seen = new java.util.HashSet<>();
		// BASE-FIRST NORMALIZATION. vulSources is fed by several independent streams at different
		// granularities: a producer-tagged AST_VAR base ($_POST) and the AST_DIM access wrapping it
		// ($_POST['id']) arrive from DIFFERENT streams and were emitted as two contradictory records
		// for ONE semantic access. Start from the TAGGED BASE (which alone proves the external-source
		// classification), walk its contiguous AST_DIM chain, and absorb the matching access entry.
		// Unpaired AST_DIM entries are NEVER absorbed — being an AST_DIM does not confer provenance.
		java.util.Set<Long> absorbed = new java.util.HashSet<Long>();
		java.util.HashMap<Long,Long> accessOfBase = new java.util.HashMap<Long,Long>();
		for(Long cand : vulSources.get(nodeID)) {
			if(!PHPCSVEdgeInterpreter.RULE_REQUEST_SUPERGLOBAL.equals(
					PHPCSVEdgeInterpreter.sourceProducerRule.get(cand))) continue;
			Long cur = cand;
			for(int d=0; d<8; d++) {
				Long par = PHPCSVEdgeInterpreter.child2parent.get(cur);
				if(par == null) break;
				ASTNode pn = ASTUnderConstruction.idToNode.get(par);
				if(!(pn instanceof ArrayIndexing)) break;
				ast.expressions.Expression ae = ((ArrayIndexing)pn).getArrayExpression();
				if(ae == null || !cur.equals(ae.getNodeId())) break;
				cur = par;
			}
			if(!cur.equals(cand) && vulSources.get(nodeID).contains(cur)) {
				absorbed.add(cur); accessOfBase.put(cand, cur);
			}
		}
		for(Long srcId : vulSources.get(nodeID)) {
			if(absorbed.contains(srcId)) continue;   // normalized into its tagged base record
			if(!seen.add(srcId)) continue;
			ASTNode sn = ASTUnderConstruction.idToNode.get(srcId);
			if(sn == null) continue;
			String code;
			if(sn instanceof Variable) {
				ast.expressions.Expression ne = ((Variable)sn).getNameExpression();
				code = "$" + (ne != null ? ne.getEscapedCodeStr() : "?");
			} else if(sn instanceof ArrayIndexing) {
				ArrayIndexing dim = (ArrayIndexing)sn;
				String base = "$?", key = "?";
				if(dim.getArrayExpression() instanceof Variable) {
					ast.expressions.Expression ne = ((Variable)dim.getArrayExpression()).getNameExpression();
					if(ne != null) base = "$"+ne.getEscapedCodeStr();
				}
				if(dim.getIndexExpression() != null && dim.getIndexExpression().getEscapedCodeStr() != null)
					key = dim.getIndexExpression().getEscapedCodeStr();
				code = base+"['"+key+"']";
			} else {
				String raw = sn.getEscapedCodeStr();
				code = (raw != null) ? raw : "("+sn.getProperty("type")+")";
			}
			String file = cg.PHPCGFactory.getDir(srcId);
			int line = (sn.getLocation() != null) ? sn.getLocation().startLine : -1;
			// ONE-WAY classification only. Membership in hookParamSourceNodes proves the node is a
			// PROMOTED CALLEE PARAMETER (seeded by forwardInlineSourceArgs because a caller passed a
			// tainted argument) — it is a local frontier, not a proven origin. The COMPLEMENT is NOT
			// asserted: `sources` has many producers (synthetic stored reads, normalised and wrapper
			// sources), so a non-promoted node is UNCLASSIFIED here rather than assumed exact.
			// ONE normalized evidence decision; every field below is rendered FROM it. Querying
			// `promoted`, producerRule and SRCDIM membership independently in the output block let
			// evidence_class and provenance precision disagree (UNCLASSIFIED + EXACT).
			boolean promoted = cg.PHPCGFactory.hookParamSourceNodes.contains(srcId);
			String rule = PHPCSVEdgeInterpreter.sourceProducerRule.get(srcId);
			boolean tagged = PHPCSVEdgeInterpreter.RULE_REQUEST_SUPERGLOBAL.equals(rule);
			if(System.getenv("FALLBACK_DIAG")!=null && tagged && promoted)
				System.err.println("TAGGED_AND_PROMOTED_EXCLUSION srcId="+srcId
					+" -- canonical request source ALSO in hookParamSourceNodes, acc forced to null,"
					+" REQUEST_SOURCE_EVIDENCE will NOT be emitted for this node");
			String[] acc = (tagged && !promoted) ? cg.PHPCGFactory.resolveRequestAccess(srcId) : null;
			Long accNode = accessOfBase.get(srcId);

			String evClass, provClass, precision, origin, frontier;
			if(tagged && !promoted) {
				evClass="REQUEST_SOURCE_EVIDENCE"; provClass="EXACT_EXTERNAL_ORIGIN";
				precision="EXACT"; origin=(acc==null?"UNKNOWN":acc[0]+":"+acc[1]); frontier="null";
			} else if(promoted) {
				evClass="LOCAL_SINK_FRONTIER"; provClass="UNRESOLVED_PROVENANCE_FRONTIER";
				precision="UNRESOLVED"; origin="UNKNOWN"; frontier=code;
			} else {
				evClass="UNCLASSIFIED"; provClass="NOT_ESTABLISHED";
				precision="NOT_ESTABLISHED"; origin="NOT_ESTABLISHED"; frontier="null";
			}
			// serializer invariant — impossible combinations must never be emitted
			if("REQUEST_SOURCE_EVIDENCE".equals(evClass) && (rule==null || acc==null || "UNRESOLVED".equals(precision)))
				throw new IllegalStateException("REQUEST_SOURCE_EVIDENCE without producer_rule/channel: "+srcId);
			if("UNCLASSIFIED".equals(evClass) && "EXACT".equals(precision))
				throw new IllegalStateException("UNCLASSIFIED cannot be EXACT: "+srcId);

			// legacy line, explicitly a compatibility projection — NOT a second semantic record
			System.out.println("Vul Source: "+srcId
				+" file="+file+" line="+line+" code=["+code+"]"
				+" evidence_class="+evClass
				+" provenance_class="+provClass
				+" ultimate_origin="+origin
				+" local_frontier="+frontier
				+" source_provenance_precision="+precision
				+" record_role="+(tagged && !promoted ? "COMPATIBILITY_PROJECTION" : "PRIMARY"));
			if("UNCLASSIFIED".equals(evClass))
				evjson("UNCLASSIFIED_SOURCE_EVIDENCE",
					"sink_node", nodeID, "source_node", srcId,
					"evidence_class", "UNCLASSIFIED", "ultimate_origin", null,
					"record_role", "PRIMARY");
			if("LOCAL_SINK_FRONTIER".equals(evClass))
				evjson("LOCAL_SINK_FRONTIER_EVIDENCE",
					"sink_node", nodeID, "frontier_node", srcId, "local_frontier", code,
					"provenance_class", "UNRESOLVED_PROVENANCE_FRONTIER", "ultimate_origin", null,
					"record_role", "PRIMARY");

			if(tagged && !promoted) {
				java.util.List<String> _kp = new java.util.ArrayList<String>();
				if(!"[]".equals(acc[1]))
					for(String _k : acc[1].replaceAll("[\\[\\]]","").split(",\\s*")) if(!_k.isEmpty()) _kp.add(_k);
				java.util.List<Long> _contrib = new java.util.ArrayList<Long>();
				_contrib.add(srcId); if(accNode!=null) _contrib.add(accNode);
				evjson("REQUEST_SOURCE_EVIDENCE",
					"base_node", srcId,
					"expression_node", accNode==null ? srcId : accNode,
					"channel", acc[0], "key_path", _kp, "key_precision", acc[2],
					"provenance_class", "EXACT_EXTERNAL_ORIGIN",
					"contributing_nodes", _contrib,
					"record_role", "PRIMARY");
				System.out.println("Vul RequestAccess: base_node="+srcId
					+" expression_node="+(accNode==null ? srcId : accNode)
					+" channel="+acc[0]+" key_path="+acc[1]+" key_precision="+acc[2]
					+" provenance_class=EXACT_EXTERNAL_ORIGIN"
					+" contributing_nodes=["+srcId+(accNode!=null?","+accNode:"")+"]"
					+" contributing_streams=[TAGGED_BASE"+(accNode!=null?",SRCDIM":"")+"]"
					+" record_role=PRIMARY");
			}
		}
	}

	private static boolean isVendoredDir(String dir) {
		if(dir == null) return false;
		// Segment-aware (not substring): match whole path components so 'latest/' or 'contest/' are
		// NOT wrongly excluded by a 'test' substring. Bundled third-party / non-plugin code only.
		for(String seg : dir.replace('\\','/').split("/")) {
			String s = seg.toLowerCase();
			if(s.equals("vendor") || s.equals("freemius") || s.equals("node_modules")
				|| s.equals("test") || s.equals("tests") || s.equals("phpunit")) return true;
		}
		return false;
	}

	// Emit each accumulated finding EXACTLY ONCE, after every taint-tree root is processed.
	// Instance-scoped flag: a static one would persist across StaticAnalysis instances and let an
	// earlier empty invocation permanently suppress emission. NOT deduplicated on sink alone —
	// several legitimate routes/sources may reach one sink.
	private boolean findingsEmitted = false;
	public void emitAllFindings() {
		if(findingsEmitted) return;
		findingsEmitted = true;
		getVulnerablePath();
		if(System.getenv("VFF_DIAG")!=null) {
			java.util.Set<String> seen = new java.util.HashSet<String>();
			for(ValueFlowFinding v : valueFlowFindings) {
				if(!seen.add(v.eventKey())) continue;
				ASTNode sn = ASTUnderConstruction.idToNode.get(v.source);
				String code = (sn==null) ? "?" : (sn.getEscapedCodeStr()!=null ? sn.getEscapedCodeStr()
					: "("+sn.getProperty("type")+")");
				int sl = (sn!=null && sn.getLocation()!=null) ? sn.getLocation().startLine : -1;
				System.err.println("VFF sink="+v.sink+" source="+v.source+" src_line="+sl
					+" src_code=["+code+"] callstack="+v.callstack
					+" producer="+v.producer+" pairing="+v.pairingStatus);
			}
		}
	}


	/** FIRST-CLASS VALUE-FLOW FINDING. Created at the analysis point where a particular source and
	 *  its propagation route coexist — BEFORE they are written into the sink-keyed maps that erase
	 *  their relationship. All mutable state is snapshotted, never referenced.
	 *  Sites without an individuated source at the add point stay on the legacy path and are
	 *  labelled so consumers do not assume equal evidence quality. */
	public static final class ValueFlowFinding {
		public final Long sink, source, taintRoot;
		public final java.util.List<Long> callstack;   // immutable snapshot
		public final String producer, pairingStatus;
		ValueFlowFinding(Long sink, Long source, java.util.Collection<Long> stack,
		                 Long taintRoot, String producer, String pairingStatus) {
			this.sink=sink; this.source=source; this.taintRoot=taintRoot;
			this.callstack=java.util.Collections.unmodifiableList(new java.util.ArrayList<Long>(stack));
			this.producer=producer; this.pairingStatus=pairingStatus;
		}
		/** Equality on the COMPLETE event tuple — never sink+source alone, or the same source via
		 *  guarded and unguarded routes would collapse. */
		String eventKey() { return sink+"|"+source+"|"+callstack+"|"+producer; }
	}
	public static final java.util.List<ValueFlowFinding> valueFlowFindings =
		new java.util.ArrayList<ValueFlowFinding>();

	private void getVulnerablePath() {
		System.out.println("Completed!");
		for(Long nodeID: vulStmts.keySet()) {
			if(isVendoredDir(PHPCGFactory.getDir(nodeID))) continue;   // skip bundled/vendored code
			totalVulCount++;
			System.out.println("Vul: "+nodeID);
			emitVulSinkIdentity(nodeID);
			emitVulSource(nodeID);
			for(Stack<Long> callstack: vulStmts.get(nodeID)) {
				emitVulPath(nodeID, callstack);
				sum.put(nodeID, callstack);
			}
		}
	}

	// Emit a human-readable source→sink trace.
	// The callstack is a Stack<Long> of call-site AST node IDs accumulated as the taint engine
	// crossed function boundaries. Bottom of stack = first call crossing (closest to source);
	// top = last crossing (closest to sink). Each node is a CallExpressionBase at the call site.
	//
	// Output format (one line per hop, then the sink):
	//   Vul Path Step 0 [source]:  file.php:LINE  ($var)
	//   Vul Path Step 1 [call]:    file.php:LINE  in enclosing_function()  → callee()
	//   Vul Path Step 2 [call]:    file.php:LINE  in enclosing_function()  → callee()
	//   Vul Path Step N [sink]:    file.php:LINE  in enclosing_function()  (echo/print/...)
	private void emitVulPath(Long sinkId, Stack<Long> callstack) {
		// Step 0: source (already emitted by emitVulSource, repeat here for path coherence)
		int step = 0;
		java.util.TreeSet<Integer> plines = new java.util.TreeSet<Integer>();  // taint-path line numbers
		if(vulSources.containsKey(sinkId)) {
			java.util.Set<Long> seen = new java.util.HashSet<>();
			for(Long srcId : vulSources.get(sinkId)) {
				if(!seen.add(srcId)) continue;
				ASTNode sn = ASTUnderConstruction.idToNode.get(srcId);
				if(sn == null) continue;
				String srcFile = shortFile(cg.PHPCGFactory.getDir(srcId));
				int srcLine = (sn.getLocation() != null) ? sn.getLocation().startLine : -1;
				if(srcLine>0) plines.add(srcLine);
				String srcCode = vulSourceCode(sn);
				System.out.printf("Vul Path Step %d [source]:  %s:%d  %s%n",
					step++, srcFile, srcLine, srcCode);
				break; // one source per path
			}
		}

		// Steps 1..N-1: call-site hops in callstack (bottom-first = call order)
		// callstack is a Stack — iterate bottom-to-top via index 0..size-1
		for(int i = 0; i < callstack.size(); i++) {
			Long csId = callstack.get(i);
			ASTNode csNode = ASTUnderConstruction.idToNode.get(csId);
			if(csNode == null) continue;
			String csFile = shortFile(cg.PHPCGFactory.getDir(csId));
			int csLine = (csNode.getLocation() != null) ? csNode.getLocation().startLine : -1;
			if(csLine>0) plines.add(csLine);
			// Enclosing function of this call site
			String enclosing = enclosingFuncName(csNode);
			// The callee being invoked
			String callee = (csNode instanceof CallExpressionBase)
				? callTargetNamePublic((CallExpressionBase)csNode) : null;
			String calleeStr = (callee != null) ? "→ " + callee + "()" : "";
			System.out.printf("Vul Path Step %d [call]:    %s:%d  in %s()  %s%n",
				step++, csFile, csLine, enclosing, calleeStr);
		}

		// Final step: sink itself
		ASTNode sinkNode = ASTUnderConstruction.idToNode.get(sinkId);
		if(sinkNode != null) {
			String sinkFile = shortFile(cg.PHPCGFactory.getDir(sinkId));
			int sinkLine = (sinkNode.getLocation() != null) ? sinkNode.getLocation().startLine : -1;
			String sinkEnclosing = enclosingFuncName(sinkNode);
			String sinkType = sinkNode.getProperty("type");
			if(sinkLine>0) plines.add(sinkLine);
			System.out.printf("Vul Path Step %d [sink]:    %s:%d  in %s()  (%s)%n",
				step, sinkFile, sinkLine, sinkEnclosing, sinkType != null ? sinkType : "sink");
		}
		if(System.getenv("WP_DUMP_CALLGRAPH") != null && !plines.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			for(Integer l : plines) { if(sb.length()>0) sb.append(","); sb.append(l); }
			System.out.println("Vul Lines: "+sinkId+" "+sb.toString());
		}
	}

	// Return just the filename (no path) for compact display. Falls back to full path if needed.
	private static String shortFile(String path) {
		if(path == null) return "?";
		int slash = path.lastIndexOf('/');
		return (slash >= 0 && slash < path.length()-1) ? path.substring(slash+1) : path;
	}

	// Return the name of the function/method enclosing a given AST node.
	private static String enclosingFuncName(ASTNode node) {
		Long fid = node.getFuncId();
		if(fid == null) return "(global)";
		ASTNode funcNode = ASTUnderConstruction.idToNode.get(fid);
		if(funcNode == null) return "(global)";
		String name = funcNode.getProperty("name");
		if(name == null || name.isEmpty()) {
			// AST_TOPLEVEL: use just the bare filename, stripping any trailing > or whitespace
			String code = funcNode.getEscapedCodeStr();
			if(code == null) return "(toplevel)";
			String base = shortFile(code);
			// phpjoern encodes toplevel names as "filename>" — strip trailing non-alphanumeric
			return base.replaceAll("[^A-Za-z0-9_\\-\\.]+$", "");
		}
		return name.replaceAll("\"", "");
	}

	// ADDITIVE identity line for a Vul finding's SINK node. Emitted alongside (never replacing) the existing
	// "Vul: <id>" / "Vul Source: ..." / "Vul Path Step ..." lines, so old consumers are unaffected. Reuses the
	// SAME node.getFuncId() that enclosingFuncName() already relies on for display — this is the identical
	// value phpjoern's nodes.csv calls "funcid" for this node (both are read from the same parsed CSV), so a
	// downstream consumer can cross-reference it directly. classname/namespace come from the enclosing
	// function's own FunctionDef/Method accessors (the same ones PHPCSVNodeInterpreter populates from the
	// nodes.csv classname/namespace columns) rather than being re-derived by a second, possibly-divergent path.
	// funcid is non-null even for file-top-level code — phpjoern wraps each file's top-level statements in an
	// implicit AST_TOPLEVEL pseudo-function with its own funcid (see enclosingFuncName's "(toplevel)"/"(global)"
	// handling above), so two files' top-level sinks still get DISTINCT identities. classname/namespace are null
	// in that case since a file-scope sink belongs to no class and (absent an explicit `namespace` statement) no
	// namespace. fid can still be null in principle (enclosingFuncName defends against it); this is reported
	// honestly as classname=null/namespace=null rather than guessed.
	// ===================== Cross-method object-property taint (isolated branch, LearnPress oracle) =====================
	// GOAL: carry taint across a property WRITE in one method and a property READ in another method/class, when
	// the receiver's class can be resolved (directly, or via a superclass/subclass relationship) — NOT a
	// receiver-insensitive "any $obj->prop taints any $obj->prop" rule (same property name on two UNRELATED
	// classes must never cross-contaminate).
	// EXPLICITLY OUT OF SCOPE (do not fold in): static-call argument->parameter chaining, helper/wrapper
	// return-value summaries, apply_filters()/WordPress filter semantics.
	private static Set<Long> propertyTaintSourceNodes = new HashSet<Long>();
	private Map<Long, Long> classParentId = new HashMap<Long, Long>();

	private void buildClassHierarchy() {
		for(Map.Entry<String, Long> e : PHPCGFactory.classDef.entrySet()) {
			Long classId = e.getValue();
			ASTNode cn = ASTUnderConstruction.idToNode.get(classId);
			if(!(cn instanceof ClassDef)) continue;
			Identifier ext = ((ClassDef) cn).getExtends();
			if(ext == null || ext.getNameChild() == null) continue;
			String parentName = ext.getNameChild().getEscapedCodeStr();
			if(parentName == null || parentName.isEmpty()) continue;
			Long parentId = PHPCGFactory.getClassId(parentName, classId, cn.getEnclosingNamespace());
			if(parentId != null && parentId != -1 && !parentId.equals(classId)) classParentId.put(classId, parentId);
		}
	}

	// true if a==b, or a is an ancestor of b, or b is an ancestor of a (single-parent PHP `extends` chain).
	private boolean classesCompatible(Long a, Long b) {
		if(a == null || b == null) return false;
		if(a.equals(b)) return true;
		Long cur = a;
		for(int i = 0; i < 20 && cur != null; i++) {
			cur = classParentId.get(cur);
			if(cur != null && cur.equals(b)) return true;
		}
		cur = b;
		for(int i = 0; i < 20 && cur != null; i++) {
			cur = classParentId.get(cur);
			if(cur != null && cur.equals(a)) return true;
		}
		return false;
	}

	// $var's class when $var is a PARAMETER with an explicit type hint. getPropIdentity() does not resolve
	// this case (it only handles $this, call-return classes, and same-function `$var = new X()`), and this is
	// exactly LearnPress's read-side shape: `function execute( LP_Filter $filter, ... ) { ... $filter->order_by`.
	private Long resolveParamTypeHintClassId(Variable objNode) {
		Long fid = objNode.getFuncId();
		if(fid == null) return null;
		ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
		if(!(fn instanceof FunctionDef)) return null;
		ParameterList pl = ((FunctionDef) fn).getParameterList();
		if(pl == null) return null;
		String varName = objNode.getNameExpression() != null ? objNode.getNameExpression().getEscapedCodeStr() : null;
		if(varName == null) return null;
		for(int i = 0; i < pl.size(); i++) {
			Parameter p = (Parameter) pl.getParameter(i);
			if(p.getName() != null && p.getName().equals(varName) && p.getType() != null
					&& p.getType().getNameChild() != null) {
				String typeName = p.getType().getNameChild().getEscapedCodeStr();
				if(typeName == null) continue;
				Long cid = PHPCGFactory.getClassId(typeName, fn.getNodeId(), fn.getEnclosingNamespace());
				if(cid != null && cid != -1) return cid;
			}
		}
		return null;
	}

	// Resolve a property access's receiver classId, reusing getPropIdentity's proven resolution ($this,
	// call-return class, same-function `new` tracing) and adding parameter-type-hint resolution on top.
	// Returns null if unresolved — callers MUST fail closed, never guess (this is the single choke point that
	// keeps the whole pass receiver-class-sensitive rather than name-only).
	private Long resolvePropertyReceiverClassId(PropertyExpression node) {
		String identity = getPropIdentity(node, 0L);
		if(identity != null && !identity.equals("-2")) {
			int sep = identity.indexOf("::");
			if(sep > 0) {
				String cidStr = identity.substring(0, sep);
				if(!cidStr.equals("-1")) {
					try { return Long.parseLong(cidStr); } catch(NumberFormatException e) { /* fall through */ }
				}
			}
		}
		Expression objNode = node.getObjectExpression();
		if(objNode instanceof Variable) return resolveParamTypeHintClassId((Variable) objNode);
		return null;
	}

	// literal (non-dynamic) property name, or null. $obj->$dynamicName is not handled — fail closed.
	private String propertyLiteralName(PropertyExpression node) {
		Expression propNode = node.getPropertyExpression();
		if(propNode != null && "string".equals(propNode.getProperty("type"))) return propNode.getEscapedCodeStr();
		return null;
	}

	private IfElement enclosingIfElement(ASTNode node) {
		Long id = node.getNodeId();
		int hops = 0;
		while(PHPCSVEdgeInterpreter.child2parent.containsKey(id) && hops++ < 300) {
			id = PHPCSVEdgeInterpreter.child2parent.get(id);
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if(n == null) return null;
			if(n instanceof IfElement) return (IfElement) n;
			if(n instanceof FunctionDef) return null;   // do not cross the enclosing function's boundary
		}
		return null;
	}

	// True if `node` sits inside ANY construct that is not guaranteed to execute exactly once on every pass
	// through its enclosing function — an if/elseif/else branch, a loop body (for/while/do-while/foreach,
	// which may execute zero times), or a switch case. Used for CONTROL-FLOW DOMINANCE (see
	// _writeDominanceValue below): a write inside such a construct cannot be assumed to have executed, so it
	// must never be treated as unconditionally overwriting ("clearing") an earlier write's taint.
	//
	// SCOPE LIMITATION (documented, not fixed here — fail-closed by construction, not by an explicit check):
	// "unconditional" here is scoped to the AST parent chain WITHIN ONE FUNCTION ONLY. It says nothing about
	// whether that write executes before or after a write in a DIFFERENT function — calls across separate
	// methods, early returns, exceptions, and alternate call orders can all make cross-method execution order
	// unresolved, even when one method is textually called before another in an obviously-visible sequence
	// (see fixture f10). This is NOT handled by attempting cross-method ordering (which would require real
	// call-graph sequencing this pass does not have) — instead, seedPropertyTaintSources() NEVER compares or
	// orders writes from different functions against each other at all: each (funcId, receiverSymbol,
	// propName) key is resolved entirely independently, and the whole-program result is the UNION of all
	// per-function verdicts. A safe write resolved in one function can therefore never suppress a tainted
	// write resolved in a different function, regardless of apparent call order — this is fail-closed by
	// construction (the absence of cross-method ordering, not a rule that examines and rejects it).
	private boolean isConditionallyReached(ASTNode node) {
		Long id = node.getNodeId();
		int hops = 0;
		while(PHPCSVEdgeInterpreter.child2parent.containsKey(id) && hops++ < 300) {
			id = PHPCSVEdgeInterpreter.child2parent.get(id);
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if(n == null) return false;
			if(n instanceof FunctionDef) return false;   // reached the function boundary unconditionally
			if(n instanceof IfElement || n instanceof SwitchCase) return true;
			String t = n.getProperty("type");
			if(t != null && (t.equals("AST_WHILE") || t.equals("AST_DO_WHILE")
					|| t.equals("AST_FOR") || t.equals("AST_FOREACH"))) {
				return true;
			}
		}
		return false;
	}

	// does `branch` (an IfElement's subtree) contain another write to the SAME receiver-symbol + property name?
	// Used for BRANCH AMBIGUITY: if a sibling if/elseif/else branch ALSO writes this (symbol,prop), which value
	// actually reaches a later read depends on a runtime condition this static analysis does not resolve —
	// the write must NOT be counted as an unconditional taint fact (fail closed, matching the project's
	// established "multiple reaching definitions -> ambiguous, not asserted" philosophy applied here at the
	// property-summary level).
	private boolean siblingWritesSameProp(ASTNode node, String recvSymbol, String propName, int depth) {
		if(node == null || depth > 300) return false;
		if(node instanceof AssignmentExpression) {
			Expression lhs = ((AssignmentExpression) node).getLeft();
			if(lhs instanceof PropertyExpression) {
				String pn = propertyLiteralName((PropertyExpression) lhs);
				Expression objNode = ((PropertyExpression) lhs).getObjectExpression();
				String sym = (objNode instanceof Variable && ((Variable) objNode).getNameExpression() != null)
					? ((Variable) objNode).getNameExpression().getEscapedCodeStr() : null;
				if(propName.equals(pn) && recvSymbol.equals(sym)) return true;
			}
		}
		for(int i = 0; i < node.getChildCount(); i++) {
			ASTNode child = (ASTNode) node.getChild(i);
			if(siblingWritesSameProp(child, recvSymbol, propName, depth + 1)) return true;
		}
		return false;
	}

	// The literal type-hint text of the parameter $var is bound to in its OWN enclosing function, or null.
	// Deliberately independent of resolveParamTypeHintClassId (which resolves to a PHPCGFactory classId for
	// user-defined classes) — WP_REST_Request is a WordPress CORE class with no ClassDef node in the plugin's
	// own CPG, so there is no classId to resolve; a direct type-hint TEXT match is the correct, simpler check.
	private String paramTypeHintText(Variable objNode) {
		Long fid = objNode.getFuncId();
		if(fid == null) return null;
		ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
		if(!(fn instanceof FunctionDef)) return null;
		ParameterList pl = ((FunctionDef) fn).getParameterList();
		if(pl == null) return null;
		String varName = objNode.getNameExpression() != null ? objNode.getNameExpression().getEscapedCodeStr() : null;
		if(varName == null) return null;
		for(int i = 0; i < pl.size(); i++) {
			Parameter p = (Parameter) pl.getParameter(i);
			if(p.getName() != null && p.getName().equals(varName) && p.getType() != null
					&& p.getType().getNameChild() != null) {
				return p.getType().getNameChild().getEscapedCodeStr();
			}
		}
		return null;
	}

	// PRECISE request-derived check for property-write RHS values — deliberately NOT the general isSource()/
	// argsContainSource(), which under WP_SEED_MODE=all is intentionally broad for RECALL (it means "worth
	// tracing under permissive seeding", not "confirmed request-derived") and was found, by direct debug
	// testing, to report plain string literals as "tainted" in that mode. A property write feeding a whole-
	// program summary needs the narrower, unambiguous signal: does this subtree contain an actual
	// $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES superglobal access, or a read of a WP_REST_Request-typed
	// parameter (array access $request['key'] or ->get_param('key') — the dominant modern WP request-input
	// idiom; recognizing it is answering "is this write's RHS request-derived", the same question this check
	// already asks of superglobals, NOT a new argument/return/filter propagation mechanism), or a
	// taint-preserving wrapper call around any of the above.
	private boolean containsRequestSuperglobal(ASTNode n, int depth) {
		if(n == null || depth > 60) return false;
		if(n instanceof ArrayIndexing) {
			Expression base = ((ArrayIndexing) n).getArrayExpression();
			if(base instanceof Variable && ((Variable) base).getNameExpression() instanceof StringExpression) {
				String vn = ((StringExpression) ((Variable) base).getNameExpression()).getEscapedCodeStr();
				if("_GET".equals(vn) || "_POST".equals(vn) || "_REQUEST".equals(vn)
						|| "_COOKIE".equals(vn) || "_FILES".equals(vn)) {
					return !isBenignFilesSubfield(n);
				}
				String hint = paramTypeHintText((Variable) base);
				if("WP_REST_Request".equals(hint)) return true;
			}
		}
		if(n instanceof MethodCallExpression) {
			Expression recv = ((MethodCallExpression) n).getTargetObject();
			Expression methodNameExpr = ((MethodCallExpression) n).getTargetFunc();
			String mn = (methodNameExpr instanceof Identifier && ((Identifier) methodNameExpr).getNameChild() != null)
				? ((Identifier) methodNameExpr).getNameChild().getEscapedCodeStr() : null;
			if(recv instanceof Variable && ("get_param".equals(mn) || "get_params".equals(mn)
					|| "get_json_params".equals(mn) || "get_body_params".equals(mn))) {
				String hint = paramTypeHintText((Variable) recv);
				if("WP_REST_Request".equals(hint)) return true;
			}
		}
		if(n instanceof CallExpressionBase) {
			CallExpressionBase c = (CallExpressionBase) n;
			List<Long> tf = PHPCGFactory.call2mtd.get(c.getNodeId());
			if(tf == null || tf.isEmpty()) {
				String nm = null;
				Expression t = c.getTargetFunc();
				if(t instanceof Identifier && ((Identifier) t).getNameChild() != null)
					nm = ((Identifier) t).getNameChild().getEscapedCodeStr();
				if(nm != null && !taintPreserving.contains(nm)) return false;   // a non-preserving call breaks taint
			}
		}
		for(int i = 0; i < n.getChildCount(); i++) {
			if(containsRequestSuperglobal((ASTNode) n.getChild(i), depth + 1)) return true;
		}
		return false;
	}

	private void seedPropertyTaintSources() {
		boolean dbg = "1".equals(System.getenv("WP_PROP_DEBUG"));
		buildClassHierarchy();
		if(dbg) System.out.println("PROP_DEBUG classParentId size=" + classParentId.size());

		// ---- pass 1: collect WRITES. Per (funcId, receiverSymbol, propName), taintedness is computed with
		// CONTROL-FLOW DOMINANCE, not naive last-write-wins (source order alone is unsound — a write nested in
		// a conditional/loop/switch is NOT guaranteed to execute, so it must never be treated as unconditionally
		// clearing an earlier write's taint). Processing writes in program order (node-id order, a sound proxy
		// within one function's straight-line parse order) with an accumulator:
		//   unconditional write  -> DETERMINES the state outright (it always executes, overwriting whatever came
		//                           before it — this is the only kind of write that can clear an earlier taint)
		//   conditional write, tainted -> can only ADD risk (its branch/loop MIGHT execute) — accumulator becomes
		//                           possibly-tainted and STAYS that way regardless of what follows conditionally
		//   conditional write, safe    -> CANNOT clear an existing possibly-tainted state (its branch might not
		//                           run, leaving the prior — possibly tainted — value in place)
		// A write inside a branch with a competing SIBLING branch write (if/elseif/else alternatives, mutually
		// exclusive) is excluded entirely as ambiguous, regardless of order — kept from the prior design, this
		// is a distinct case from the sequential-dominance question above (alternatives vs. a later write that
		// may-or-may-not additionally execute). Writes in SEPARATE FUNCTIONS never interact here at all — each
		// (funcId,...) key is independent, and a safe write in one method can never suppress a tainted write
		// registered by a different method (the whole-program union below preserves that). ----
		List<ASTNode> propWrites = new ArrayList<ASTNode>();
		cg.PHPCGFactory.recordScanSite("SA_1927", ASTUnderConstruction.idToNode.size());
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof AssignmentExpression)) continue;
			Expression lhs = ((AssignmentExpression) n).getLeft();
			if(lhs instanceof PropertyExpression) propWrites.add(n);
		}
		propWrites.sort(new Comparator<ASTNode>() {
			public int compare(ASTNode a, ASTNode b) { return a.getNodeId().compareTo(b.getNodeId()); }
		});
		if(dbg) System.out.println("PROP_DEBUG propWrites total=" + propWrites.size());

		Map<String, Boolean> possibleTaint = new HashMap<String, Boolean>();   // funcKey -> accumulator state
		Map<String, String> keyClassProp = new HashMap<String, String>();      // funcKey -> "classId::propName"
		Set<String> ambiguousKeys = new HashSet<String>();
		for(ASTNode n : propWrites) {
			AssignmentExpression assign = (AssignmentExpression) n;
			PropertyExpression lhs = (PropertyExpression) assign.getLeft();
			Expression rhs = assign.getRight();
			if(rhs == null) continue;
			String propName = propertyLiteralName(lhs);
			if(dbg) System.out.println("PROP_DEBUG write node=" + n.getNodeId() + " propName=" + propName);
			if(propName == null) continue;
			Long classId = resolvePropertyReceiverClassId(lhs);
			if(dbg) System.out.println("PROP_DEBUG write node=" + n.getNodeId() + " classId=" + classId
				+ " getPropIdentity=" + getPropIdentity(lhs, 0L));
			if(classId == null) continue;

			Expression objNode = lhs.getObjectExpression();
			String recvSymbol = (objNode instanceof Variable && ((Variable) objNode).getNameExpression() != null)
				? ((Variable) objNode).getNameExpression().getEscapedCodeStr() : ("#" + objNode.getNodeId());
			Long fid = n.getFuncId();
			String funcKey = (fid == null ? "0" : fid.toString()) + "|" + recvSymbol + "|" + propName;

			IfElement branch = enclosingIfElement(n);
			if(branch != null) {
				Long parentId = PHPCSVEdgeInterpreter.child2parent.get(branch.getNodeId());
				ASTNode parent = parentId == null ? null : ASTUnderConstruction.idToNode.get(parentId);
				if(parent instanceof IfStatement) {
					for(IfElement sib : (IfStatement) parent) {
						if(sib == branch) continue;
						if(siblingWritesSameProp(sib, recvSymbol, propName, 0)) { ambiguousKeys.add(funcKey); break; }
					}
				}
			}
			if(ambiguousKeys.contains(funcKey)) { possibleTaint.remove(funcKey); continue; }

			boolean tainted = containsRequestSuperglobal(rhs, 0);
			boolean conditional = isConditionallyReached(n);
			if(dbg) System.out.println("PROP_DEBUG write node=" + n.getNodeId() + " tainted=" + tainted
				+ " conditional=" + conditional);
			if(!conditional) {
				possibleTaint.put(funcKey, tainted);              // unconditional write DETERMINES the state
			} else if(tainted) {
				possibleTaint.put(funcKey, true);                 // conditional-tainted can only ADD risk
			}
			// conditional-and-safe: leave whatever was already accumulated untouched (cannot clear)
			keyClassProp.put(funcKey, classId + "::" + propName);
		}

		Set<String> taintedWriteKeys = new HashSet<String>();
		for(Map.Entry<String, Boolean> e : possibleTaint.entrySet()) {
			if(ambiguousKeys.contains(e.getKey())) continue;
			if(dbg) System.out.println("PROP_DEBUG resolved key=" + e.getKey() + " possibleTaint=" + e.getValue());
			if(Boolean.TRUE.equals(e.getValue())) {
				String cp = keyClassProp.get(e.getKey());
				if(cp != null) taintedWriteKeys.add(cp);
			}
		}
		if(dbg) System.out.println("PROP_DEBUG taintedWriteKeys=" + taintedWriteKeys);

		// ---- pass 2: collect READS; promote to a taint source when a class-compatible tainted write exists ----
		int dbgReadCount = 0, dbgPropCount = 0;
		cg.PHPCGFactory.recordScanSite("SA_1998", ASTUnderConstruction.idToNode.size());
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof PropertyExpression)) continue;
			dbgPropCount++;
			Long parentId = PHPCSVEdgeInterpreter.child2parent.get(n.getNodeId());
			ASTNode parent = parentId == null ? null : ASTUnderConstruction.idToNode.get(parentId);
			if(parent instanceof AssignmentExpression && ((AssignmentExpression) parent).getLeft() == n) continue;
			dbgReadCount++;

			PropertyExpression prop = (PropertyExpression) n;
			String propName = propertyLiteralName(prop);
			Long classId = resolvePropertyReceiverClassId(prop);
			if(dbg) System.out.println("PROP_DEBUG read node=" + n.getNodeId() + " propName=" + propName
				+ " classId=" + classId + " getPropIdentity=" + getPropIdentity(prop, 0L));
			if(propName == null) continue;
			if(classId == null) continue;

			for(String key : taintedWriteKeys) {
				int sep = key.indexOf("::");
				if(sep <= 0 || !key.substring(sep + 2).equals(propName)) continue;
				Long writeClassId;
				try { writeClassId = Long.parseLong(key.substring(0, sep)); } catch(NumberFormatException ex) { continue; }
				if(classesCompatible(classId, writeClassId)) {
					propertyTaintSourceNodes.add(n.getNodeId());
					PHPCSVEdgeInterpreter.sources.add(n.getNodeId());
					if(dbg) System.out.println("PROP_DEBUG PROMOTED read node=" + n.getNodeId());
					break;
				}
			}
		}
		if(dbg) System.out.println("PROP_DEBUG propCount=" + dbgPropCount + " readCount=" + dbgReadCount
			+ " promoted=" + propertyTaintSourceNodes.size());
	}

	private void emitVulSinkIdentity(Long sinkId) {
		// Per-FINDING class, so the harness can assert every emitted finding references a sink of
		// the profile class -- stronger than asserting only that the retained sink SET is pure.
		{ String _sc = cg.PHPCGFactory.sinkClass.get(sinkId);
		  System.out.println("Vul Sink Class: "+sinkId+" class="+(_sc==null?"untagged(sql-default)":_sc)); }
		ASTNode sinkNode = ASTUnderConstruction.idToNode.get(sinkId);
		if(sinkNode == null) return;
		Long fid = sinkNode.getFuncId();
		String classname = null, namespace = null;
		if(fid != null) {
			ASTNode funcNode = ASTUnderConstruction.idToNode.get(fid);
			if(funcNode instanceof Method) {
				classname = ((Method)funcNode).getEnclosingClass();
				namespace = ((Method)funcNode).getEnclosingNamespace();
			} else if(funcNode instanceof FunctionDef) {
				namespace = ((FunctionDef)funcNode).getEnclosingNamespace();
			}
		}
		System.out.println("Vul Sink Identity: "+sinkId
			+" funcid="+(fid != null ? fid : "null")
			+" classname="+(classname != null && !classname.isEmpty() ? classname : "null")
			+" namespace="+(namespace != null && !namespace.isEmpty() ? namespace : "null"));
	}

	// Public-visibility wrapper for callTargetName (which is private in PHPCGFactory).
	// Duplicates the minimal logic needed here rather than changing CG visibility.
	private static String callTargetNamePublic(CallExpressionBase c) {
		ast.expressions.Expression tf = c.getTargetFunc();
		if(tf instanceof ast.expressions.Identifier) {
			ast.ASTNode nc = ((ast.expressions.Identifier)tf).getNameChild();
			if(nc != null) return nc.getEscapedCodeStr();
		}
		if(tf instanceof ast.expressions.StringExpression)
			return ((ast.expressions.StringExpression)tf).getEscapedCodeStr();
		if(tf instanceof ast.expressions.Variable) {
			ast.expressions.Expression ne = ((ast.expressions.Variable)tf).getNameExpression();
			return (ne != null) ? "$"+ne.getEscapedCodeStr() : "$?";
		}
		return null;
	}

	// Format a source node for the path trace (compact version of emitVulSource logic).
	private static String vulSourceCode(ASTNode sn) {
		if(sn instanceof ast.expressions.Variable) {
			ast.expressions.Expression ne = ((ast.expressions.Variable)sn).getNameExpression();
			return "$" + (ne != null ? ne.getEscapedCodeStr() : "?");
		}
		if(sn instanceof ast.expressions.ArrayIndexing) {
			ast.expressions.ArrayIndexing dim = (ast.expressions.ArrayIndexing)sn;
			String base = "$?", key = "?";
			if(dim.getArrayExpression() instanceof ast.expressions.Variable) {
				ast.expressions.Expression ne = ((ast.expressions.Variable)dim.getArrayExpression()).getNameExpression();
				if(ne != null) base = "$"+ne.getEscapedCodeStr();
			}
			if(dim.getIndexExpression() != null && dim.getIndexExpression().getEscapedCodeStr() != null)
				key = dim.getIndexExpression().getEscapedCodeStr();
			return base+"['"+key+"']";
		}
		String raw = sn.getEscapedCodeStr();
		return (raw != null) ? raw : "("+sn.getProperty("type")+")";
	}
	

	private void DFS(Long nodeID, Stack<Long> vulPath) {
		Node node = ID2Node.get(nodeID);
		if(node.parent==null) {
			Stack<Long> tmp = new Stack<Long>();
			while(vulPath.isEmpty()) {
				tmp.push(vulPath.pop());
			}
			vulPaths.add(tmp);
			return;
		}
		Long prt = node.parent;
		vulPath.add(ID2Node.get(prt).astId);
		DFS(prt, vulPath);
		vulPath.pop();
	}

	private Node mergeNode(Long stmt, Set<Long> intra, HashMap<String, Long> inter, Stack<Long> stack) {
		
		if(ASTUnderConstruction.idToNode.containsKey(stmt)) {
            Long func = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
            //the function has exited
            if(!active.containsKey(func) || active.get(func)==false) {
                    Node node = ID2Node.get(stmt);
                    if(System.getenv("MN_DIAG")!=null) {
                        System.err.println("MNDIAG REUSE stmt=" + stmt
                            + " requested_caller=" + stack
                            + " requested_caller_id=" + System.identityHashCode(stack)
                            + " requested_intro=" + intra
                            + " returned_node_id=" + System.identityHashCode(node)
                            + " returned_caller=" + (node==null?"null":String.valueOf(node.caller))
                            + " returned_caller_id=" + (node==null?0:System.identityHashCode(node.caller))
                            + " returned_intro=" + (node==null?"null":String.valueOf(node.intro))
                            + " returned_inter=" + (node==null?"null":String.valueOf(node.inter)));
                    }
                    Edgetimes.put(stmt, 0);
                    return node;
            }
		}
		
		
		Node node = null;
		if(ID2Node.containsKey(stmt)) {
			//merge the intra- and inter- tainted variables
			node = ID2Node.get(stmt);
			node.intro.addAll(intra);
			for(String key: inter.keySet()) {
				if(System.getenv("CFG_JOIN_DIAG")!=null)
					System.err.println("CFG_JOIN_MERGE stmt="+stmt
						+" existing_node_map="+System.identityHashCode(node.inter)
						+" existing_value_before="+node.inter.get(key)
						+" incoming_map="+System.identityHashCode(inter)
						+" incoming_value="+inter.get(key)
						+" key="+key);
				// SITE 1 of 6 (§82/83): the CFG-join reuse-overwrite, wired to mergeOverwrite (§83)
				// instead of a raw put() -- this was the confirmed §80 desynchronization site.
				if(node.inter instanceof Node.TracingInterMap) {
					long srcState = (inter instanceof Node.TracingInterMap)
						? ((Node.TracingInterMap) inter).currentStateEventId : -1;
					((Node.TracingInterMap) node.inter).mergeOverwrite(key, inter.get(key),
						((Node.TracingInterMap) node.inter).currentStateEventId, srcState);
				} else {
					if(System.getenv("MUTATION_DAG_DIAG")!=null)
						System.err.println("DIAGNOSTIC_INVARIANT_VIOLATION site1 fallback hit -- node.inter not traced");
					node.inter.put(key, inter.get(key));
				}
			}
			node.caller = stack;
		}
		else {
			if(System.getenv("CFG_JOIN_DIAG")!=null)
				System.err.println("CFG_JOIN_NEW stmt="+stmt+" incoming_map="+System.identityHashCode(inter)
					+" incoming_keys="+inter.keySet());
			node = new Node(stmt, inter, intra, stack);
		}
		
		if(!Edgetimes.containsKey(stmt)) {
			Edgetimes.put(stmt, 1);
		}
		else {
			int number = Edgetimes.get(stmt)+1;
			Edgetimes.put(stmt, number);
		}
		
		if(ASTUnderConstruction.idToNode.containsKey(stmt)) {
			Long funcID = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
			Long exit = funcID+2;
			clean.add(exit, stmt);
		}
		//it is file-exit node
		else {
			clean.add(stmt, stmt);
		}
		
		System.out.println(stmt+": times: "+Edgetimes.get(stmt)+"size: "+Edgesize.get(stmt));
		
		return node;
	}
	
	private void clean(Node node) {
		// DIRECT RESET INVARIANT (reviewer's follow-up): tests the STATE_RESET claim at the point
		// of action, not through isrelated() (which only runs when state is already tracked, so
		// "live=null, reconstructed=null" is often unobservable downstream by design -- absence of
		// a consumer call is itself consistent with a correct reset, not evidence either way).
		if(System.getenv("MUTATION_DAG_DIAG")!=null && node.inter instanceof Node.TracingInterMap) {
			Node.TracingInterMap before = (Node.TracingInterMap) node.inter;
			for(String key : before.keySet())
				System.err.println("RESET_INVARIANT_BEFORE stmt="+node.astId+" key="+key
					+" live="+before.get(key)+" map="+System.identityHashCode(before));
		}
		if(node.inter instanceof Node.TracingInterMap)
			((Node.TracingInterMap) node.inter).recordReset(node.astId);
		node.inter = new Node.TracingInterMap();
		node.intro = new HashSet<Long>();
		node.caller = new Stack<Long>();
		if(System.getenv("MUTATION_DAG_DIAG")!=null) {
			Node.TracingInterMap after = (Node.TracingInterMap) node.inter;
			System.err.println("RESET_INVARIANT_AFTER stmt="+node.astId+" size="+after.size()
				+" currentStateEventId="+after.currentStateEventId
				+" new_map="+System.identityHashCode(after)+" -- expect size=0, currentStateEventId=-1");
		}
		
		Edgetimes.put(node.astId, 0);
	}
	
	//traverse the node's statement
	//@param: one taint node, a boolean value indicating if the current statement is initial source
	//@output: get taint status of this statement, add it to taint tree is it is tainted, and find the next statement ID 
	private static Long lastTraverseFuncid = null;
	private boolean traverse(Node node) {
		if(node == null) return false;
		if(System.getenv("SG_PIPELINE_DIAG")!=null && node.astId != null) {
			ASTNode _n = ASTUnderConstruction.idToNode.get(node.astId);
			Long _toFunc = (_n==null) ? null : _n.getFuncId();
			if(_toFunc != null && !_toFunc.equals(lastTraverseFuncid)) {
				System.err.println("ISRELATED_RECURSE from_funcid="+lastTraverseFuncid
					+" to_funcid="+_toFunc+" to_stmt="+node.astId
					+" caller_stack="+node.caller);
			}
			lastTraverseFuncid = _toFunc;
		}
		System.out.println("parse stmt: "+" "+node.astId+" "+node.inter+" "+node.intro+" "+node.caller);
		//System.out.println("parse stmt: "+node.nodeId+" "+node.astId);
		Long stmt = node.astId;
		if(stmt==null) {
			System.err.println("Fail to get statement location: "+stmt);
			return false;
		}
		
		boolean taintFunc = false;
		Node nextNode = null;
		
		//iterate the next statement
		if(CSVCFGExporter.cfgSave.containsKey(stmt)) {
			//the function exits here
			//check if the statement has been sanitized
			boolean valid = isvalid(stmt);
			Long topCaller;
			if(node.caller==null || node.caller.isEmpty()) {
				topCaller = (long) 0;
			}
			else {
				topCaller = node.caller.peek();
			}
			
			//check if the statement has data flow relationship with taint variables
			HashMap<Long, Long> related = isrelated(stmt, node.intro, node.inter, topCaller);
			runRelatedEvidenceGates(stmt, node.intro, topCaller);
			// INLINE-SOURCE check: a superglobal source used directly inside a sink statement
			// (co-located, never an incoming reaching def, so the `related` test misses it).
			// Originally written for SQL sinks (CVE-2021-24340 class: $wpdb->get_var with
			// esc_sql($_GET[...]) inline). Shortcode/block-callback return sinks now also live
			// in `sinks` (tagged "xss"), so the sanitizer check is class-aware: SQL sinks check
			// sqlSanitizers (esc_sql etc); XSS sinks check xssSanitizers (esc_html/esc_attr/
			// sanitize_text_field etc). This means sanitize_text_field($_GET[...]) correctly
			// suppresses a finding in an XSS return-sink, while an unescaped $atts['x']
			// returned from a shortcode callback is correctly flagged.
			java.util.Set<String> stmtClasses = stmtSinkClass.get(stmt);
			boolean xssClassSink = stmtClasses != null && stmtClasses.contains("xss");
			if ("1".equals(System.getenv("WP_XSSCLASS_DEBUG")) && sinks.contains(stmt)) {
				System.err.println("XSSCLASS_DEBUG stmt=" + stmt
					+ " classesByStmtId=" + stmtClasses
					+ " xssClassSink=" + xssClassSink);
			}
			// Defect 2 fix: if the sink stmt is an assignment whose RHS is $wpdb->prepare(),
			// AND the source reaches only the %s/%d ARGUMENT positions (not the format string),
			// then prepare() parameterizes the value and it's safe — suppress the finding.
			// The format-string check (sqlSinkProvablySafe) already runs separately; this guard
			// prevents the inline-source path from double-reporting when the source is a bound arg.
			boolean skipDueToPrepare = false;
			{
				ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
				if( stmtNode instanceof AssignmentExpression ) {
					Expression stmtRhs = ((AssignmentExpression)stmtNode).getRight();
					if( stmtRhs instanceof MethodCallExpression ) {
						Expression tf = ((MethodCallExpression)stmtRhs).getTargetFunc();
						if( tf instanceof StringExpression && "prepare".equals(((StringExpression)tf).getEscapedCodeStr()) ) {
							// Correct check: does any srcDim/srcGlobal source for this stmt appear
							// INSIDE arg[0] (the format string)? If all sources are in arg[1+]
							// (the bound params), prepare() parameterizes them → suppress.
							// Build the set of all node IDs under arg[0] (the format string subtree).
							ArgumentList pArgs = ((MethodCallExpression)stmtRhs).getArgumentList();
							if( pArgs != null && pArgs.size() >= 1 ) {
								Set<Long> fmtSubtree = new HashSet<Long>();
								java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<>();
								ASTNode fmtArg = pArgs.getArgument(0);
								if( fmtArg != null ) { q.add(fmtArg.getNodeId()); }
								while( !q.isEmpty() ) {
									Long nid = q.poll();
									if( nid == null || !fmtSubtree.add(nid) ) continue;
									HashMap<Integer,Long> ch = PHPCSVEdgeInterpreter.parent2child.get(nid);
									if( ch != null ) q.addAll(ch.values());
								}
								// Check if any dim/global source for this stmt is in the format subtree
								boolean sourceInFmt = false;
								if( srcDim.containsKey(stmt) )
									for( Long s : srcDim.get(stmt) ) if( fmtSubtree.contains(s) ) { sourceInFmt=true; break; }
								if( !sourceInFmt && srcGlobal.containsKey(stmt) )
									for( Long s : srcGlobal.get(stmt) ) if( fmtSubtree.contains(s) ) { sourceInFmt=true; break; }
								if( !sourceInFmt ) skipDueToPrepare = true;
							}
						}
					}
				}
			}
			if(!skipDueToPrepare && sinks.contains(stmt) && hasUnsanitizedInlineSource(stmt, xssClassSink)) {
				Stack<Long> tmp = (Stack<Long>) node.caller.clone();
				if(System.getenv("PROD_DIAG")!=null) System.err.println("PRODUCER site=1 java_line=1814 sink="+node.astId+" node_id="+System.identityHashCode(node)+" caller="+tmp+" intro="+node.intro+" inter="+node.inter);
				if(System.getenv("WP_SITE_DIAG")!=null) System.err.println("SITE_DIAG site=1 stmt="+node.astId);
				vulStmts.add(node.astId, tmp);
				// Record any srcDim sources for this statement so the output can show source location.
				if(srcDim.containsKey(stmt))
					for(Long dimSrc : srcDim.get(stmt)) vulSources.add(node.astId, dimSrc);
				System.out.println("inline-source sink: "+node.astId);
			}
			//TAINT PASS-THROUGH: `$v = builtin($source)`. The engine's assignment-with-call
			//dispatch is buried under the call-statement branch and is unreachable for an
			//assignment statement, so a source wrapped in a built-in (sanitize_text_field /
			//wp_unslash / trim / ...) otherwise loses its taint here, leaving $v "clean".
			//Mark the assignment target tainted and propagate to successors. Genuine SQL
			//sanitizers are still neutralized at the sink check via sqlSanitizers, so it is
			//sound to propagate through ALL built-ins (absint/intval/esc_sql stay safe).
			if( System.getenv("WP_INTRO_DIAG") != null ) {
				ASTNode diagN = ASTUnderConstruction.idToNode.get(stmt);
				System.err.println("INTRO_DIAG[PRE] stmt=" + stmt + " valid=" + valid
					+ " related=" + related + " intro_before=" + node.intro
					+ " isAssignment=" + (diagN instanceof AssignmentExpression));
			}
			{
				ASTNode ptN = ASTUnderConstruction.idToNode.get(stmt);
				if(valid && related.keySet().isEmpty()
						&& ptN instanceof AssignmentExpression) {
					Expression ptRhs = ((AssignmentExpression) ptN).getRight();
					boolean ptPassThrough = false;
					if(ptRhs instanceof CallExpressionBase) {
						CallExpressionBase ptCall = (CallExpressionBase) ptRhs;
						List<Long> ptTf = PHPCGFactory.call2mtd.get(ptCall.getNodeId());
						if( System.getenv("WP_INTRO_DIAG") != null ) {
							System.err.println("INTRO_DIAG[TAINT_PASSTHROUGH] stmt=" + stmt + " related_empty=" + related.keySet().isEmpty()
								+ " ptTf=" + ptTf + " intro_before=" + node.intro);
						}
						if(ptTf == null || ptTf.isEmpty()) {
							// resolve the built-in's name and only pass taint through known
							// content-preserving functions (keeps precision; see taintPreserving).
							String ptName = null;
							Expression ptTarget = ptCall.getTargetFunc();
							if(ptTarget instanceof Identifier && ((Identifier) ptTarget).getNameChild()!=null) {
								ptName = ((Identifier) ptTarget).getNameChild().getEscapedCodeStr();
							}
							else if(ptTarget instanceof StringExpression) {
								ptName = ((StringExpression) ptTarget).getEscapedCodeStr();
							}
							ArgumentList ptArgs = ptCall.getArgumentList();
							boolean ptArgHasSource = argsContainSource(ptArgs==null?null:ptArgs.getNodeId(), 0);
							if(ptName != null && taintPreserving.contains(ptName)
									&& ptArgHasSource) {
								// Exception: preg_replace that strips < and > is an XSS sanitizer —
								// do NOT propagate taint through it (the output is XSS-safe).
								if("preg_replace".equals(ptName)
									&& cg.PHPCGFactory.isPregReplaceXssSanitizerPublic(ptCall)) {
									// Sanitizer: don't pass taint, don't set ptPassThrough
								} else {
									ptPassThrough = true;
								}
							}
							// FIXTURE F FIX: genuinely unresolved callee (call2mtd empty, so not a
							// user-defined function this engine could find a body for) whose name is
							// ALSO not any recognized safe/preserving/sanitizing name at all -- not in
							// taintPreserving, not a recognized SQL/XSS sanitizer or escaper.
							// Previously $v stayed "clean" here unconditionally, a real
							// false-negative: confirmed identical to `$v = unknown_helper($_GET['x']);
							// echo $v;` clearing when it should conservatively fire, and structurally
							// the same shape AIOWM's resolved dispatch chain hit before today's
							// callback-resolution fix. Deliberately conservative -- fires whenever the
							// name isn't recognized as safe, erring toward false positives over
							// silently dropping taint, matching the fail-closed rule used throughout
							// this engine's other fixes. Does NOT touch the resolved-callee branch
							// below (retArbitraryFids) or the ternary/property-write branch after it.
							else if(!ptPassThrough && ptName != null && ptArgHasSource
									&& !taintPreserving.contains(ptName)
									&& !PHPCSVEdgeInterpreter.sqlSanitizers.contains(ptName)
									&& !PHPCSVEdgeInterpreter.xssSanitizers.contains(ptName)
									&& !PHPCSVEdgeInterpreter.xssInputSanitizers.contains(ptName)
									&& !PHPCSVEdgeInterpreter.repairs.contains(ptName)
									&& !cg.PHPCGFactory.isXssOutputEscaper(ptName)) {
								ptPassThrough = true;
							}
						} else {
							// User-defined function: check if it reads a request source internally
							// and returns it (retArbitraryFids), e.g.:
							//   function get_name() { return $_GET['name']; }
							//   $x = get_name();   // <- this statement, $x gets tainted
							for(Long ptt : ptTf) {
								if(cg.PHPCGFactory.retArbitraryFids.contains(ptt)) {
									ptPassThrough = true;
									break;
								}
							}
						}
					}
					// PROPERTY/GLOBAL write whose RHS is a ternary nesting a taint-preserving wrapper of a
					// source, e.g. $this->data = isset($_POST['x']) ? stripslashes_deep($_POST['x']) : null
					// (wp-optimize's set_data shape). The selected value still carries taint. Gated to
					// property/global writes (dstProp/dstGlobal) so local-taint behavior — already handled
					// by detectInlineSourceTaint — is left untouched and oracle counts don't shift.
					else if(ptRhs instanceof ast.expressions.ConditionalExpression
							&& (dstProp.containsKey(stmt) || dstGlobal.containsKey(stmt))
							&& nestedTaintPreservingSource(ptRhs)) {
						ptPassThrough = true;
					}
					if(ptPassThrough) {
						Set<Long> ptSave = new HashSet<Long>(node.intro);
						ptSave.add(node.astId);
						// Register any property/global written here into the symbolic inter set so the
						// taint propagates CROSS-METHOD (node-based intro only reaches in-function successors;
						// a later method reading $this->data would otherwise see it clean). No-op for locals.
						if(System.getenv("SG_PIPELINE_DIAG")!=null) System.err.println("ADDINTER_CALL_SITE_1 astId="+node.astId+" func="+ASTUnderConstruction.idToNode.get(node.astId).getFuncId());
						HashMap<String, Long> ptInter = addInter(node).inter;
						for(int pi=0; pi<CSVCFGExporter.cfgSave.get(stmt).size(); pi++) {
							Long pnext = CSVCFGExporter.cfgSave.get(stmt).get(pi);
							Stack<Long> pstack = (Stack<Long>) node.caller.clone();
							Node pNode = mergeNode(pnext, ptSave, ptInter, pstack);
							if(Edgetimes.get(pnext)==es(pnext)) {
								traverse(pNode);
							}
							else if(Edgetimes.get(pnext)>es(pnext) && loop.contains(pnext)) {
								if(CSVCFGExporter.cfgSave.get(pnext).size()>1) {
									Long pnn = CSVCFGExporter.cfgSave.get(pnext).get(1);
									while(loop.contains(pnn)) { pnn = CSVCFGExporter.cfgSave.get(pnn).get(1); }
									Node pNode2 = mergeNode(pnn, ID2Node.get(pnext).intro, ID2Node.get(pnext).inter, ID2Node.get(pnext).caller);
									if(Edgetimes.get(pnn)==es(pnn)) { traverse(pNode2); }
								}
							}
						}
						return false;
					}
				}
			}
			// Return-taint interproc: $v = f($_GET['x']) where user function f returns a value
			// derived from a param (PHPCGFactory.returnTaintPositions). Propagate taint to $v so a
			// later sink using $v is reported. Mirrors the built-in pass-through; f's own internal
			// sinks are handled by wrapper modeling at the call site, so short-circuiting is sound.
			// Only direct sources in the return-relevant arg position qualify, and only when the
			// statement carries no other taint relation (related empty). NOTE: extending this to a
			// tainted *local* argument by relaxing the related-empty guard was tried and reverted —
			// short-circuiting when `related` is non-empty pre-empts the normal reaching-taint
			// propagation and dropped real true positives (rsvpmaker 8->4). That increment needs the
			// interprocedural return->caller-LHS binding fixed in the traversal, not a pass-through.
			{
				ASTNode rtN = ASTUnderConstruction.idToNode.get(stmt);
				if(valid
						&& rtN instanceof AssignmentExpression
						&& ((AssignmentExpression) rtN).getRight() instanceof CallExpressionBase) {
					CallExpressionBase rtCall = (CallExpressionBase) ((AssignmentExpression) rtN).getRight();
					List<Long> rtTgts = PHPCGFactory.call2mtd.get(rtCall.getNodeId());
					if( System.getenv("WP_INTRO_DIAG") != null ) {
						System.err.println("INTRO_DIAG[RT_INTERPROC] stmt=" + stmt + " rtTgts=" + rtTgts
							+ " related=" + related + " intro_before=" + node.intro);
						if(rtTgts != null) for(Long t : rtTgts) {
							System.err.println("INTRO_DIAG[RT_INTERPROC]   tgt=" + t
								+ " returnTaintPositions=" + PHPCGFactory.returnTaintPositions.get(t)
								+ " returnTaintAnalyzed=" + PHPCGFactory.returnTaintAnalyzed.contains(t));
						}
					}
					if(rtTgts != null && !rtTgts.isEmpty()) {
						ArgumentList rtArgs = rtCall.getArgumentList();
						boolean rtDirect = false;   // a direct source sits at a return-relevant position
						boolean rtLocal  = false;   // a tainted LOCAL reaches a return-relevant position
						for(Long tgt : rtTgts) {
							Set<Integer> rtPos = PHPCGFactory.returnTaintPositions.get(tgt);
							if(rtPos == null) continue;
							for(Integer p : rtPos) {
								if(rtArgs == null || p >= rtArgs.size()) continue;
								Long aNode = rtArgs.getArgument(p).getNodeId();
								if(argsContainSource(aNode, 0)) rtDirect = true;
								if(argNodeTainted(aNode, related)) rtLocal = true;
							}
						}
						// (A) Direct source, no other taint relation: original pass-through. The source
						// is inline (never a reaching def), so short-circuiting is sound here.
						if(rtDirect && related.keySet().isEmpty()) {
							Set<Long> ptSave = new HashSet<Long>(node.intro);
							ptSave.add(node.astId);
							for(int pi=0; pi<CSVCFGExporter.cfgSave.get(stmt).size(); pi++) {
								Long pnext = CSVCFGExporter.cfgSave.get(stmt).get(pi);
								Stack<Long> pstack = (Stack<Long>) node.caller.clone();
								Node pNode = mergeNode(pnext, ptSave, node.inter, pstack);
								if(Edgetimes.get(pnext)==es(pnext)) {
									traverse(pNode);
								}
								else if(Edgetimes.get(pnext)>es(pnext) && loop.contains(pnext)) {
									if(CSVCFGExporter.cfgSave.get(pnext).size()>1) {
										Long pnn = CSVCFGExporter.cfgSave.get(pnext).get(1);
										while(loop.contains(pnn)) { pnn = CSVCFGExporter.cfgSave.get(pnn).get(1); }
										Node pNode2 = mergeNode(pnn, ID2Node.get(pnext).intro, ID2Node.get(pnext).inter, ID2Node.get(pnext).caller);
										if(Edgetimes.get(pnn)==es(pnn)) { traverse(pNode2); }
									}
								}
							}
							return false;
						}
						// (B) A tainted LOCAL (or a direct source alongside other reaching taint) lands
						// on a return-relevant position: f returns a value derived from it, so the
						// assignment's LHS ($v) is tainted. Bind that by adding the assignment node to
						// the propagated taint set, then fall through to NORMAL propagation. Unlike the
						// reverted attempt this does NOT short-circuit (return false), so the ordinary
						// reaching-taint flow that carries real true positives is preserved.
						else if(rtLocal) {
							node.intro.add(node.astId);
							if( System.getenv("WP_INTRO_DIAG") != null ) {
								System.err.println("INTRO_DIAG[RT_INTERPROC] rtLocal=true -> intro.add(" + node.astId + ") intro_after=" + node.intro);
							}
						}
						else if( System.getenv("WP_INTRO_DIAG") != null ) {
							System.err.println("INTRO_DIAG[RT_INTERPROC] neither rtDirect nor rtLocal -- block declines, falling through. intro_unchanged=" + node.intro);
						}
					}
				}
			}
			// P15: taint-preserving builtin nested in a concatenation RHS, e.g.
			//   $q = "... '" . sanitize_text_field($_POST['x']) . "'";
			// The direct-call pass-through above only fires when the RHS *is* the call; a
			// wrapper buried inside a BinaryExpression concat otherwise launders the taint.
			// Only content-preserving builtins qualify (taintPreserving excludes
			// esc_sql/intval/absint), so genuine sanitizers stay safe at the sink check.
			{
				ASTNode ptN2 = ASTUnderConstruction.idToNode.get(stmt);
				if(valid && related.keySet().isEmpty()
						&& ptN2 instanceof AssignmentExpression
						&& !(((AssignmentExpression) ptN2).getRight() instanceof CallExpressionBase)
						&& ((AssignmentExpression) ptN2).getRight() != null
						&& nestedTaintPreservingSource(((AssignmentExpression) ptN2).getRight())) {
					Set<Long> ptSave = new HashSet<Long>(node.intro);
					ptSave.add(node.astId);
					for(int pi=0; pi<CSVCFGExporter.cfgSave.get(stmt).size(); pi++) {
						Long pnext = CSVCFGExporter.cfgSave.get(stmt).get(pi);
						Stack<Long> pstack = (Stack<Long>) node.caller.clone();
						Node pNode = mergeNode(pnext, ptSave, node.inter, pstack);
						if(Edgetimes.get(pnext)==es(pnext)) {
							traverse(pNode);
						}
						else if(Edgetimes.get(pnext)>es(pnext) && loop.contains(pnext)) {
							if(CSVCFGExporter.cfgSave.get(pnext).size()>1) {
								Long pnn = CSVCFGExporter.cfgSave.get(pnext).get(1);
								while(loop.contains(pnn)) { pnn = CSVCFGExporter.cfgSave.get(pnn).get(1); }
								Node pNode2 = mergeNode(pnn, ID2Node.get(pnext).intro, ID2Node.get(pnext).inter, ID2Node.get(pnext).caller);
								if(Edgetimes.get(pnn)==es(pnn)) { traverse(pNode2); }
							}
						}
					}
					return false;
				}
			}
			//this statement has been sanitized
			if(!valid) {
				HashMap<String, Long> newInter = null;
				//check weather the node needs to be changed
				Set<String> unrelated = RemoveInterTaint(stmt, topCaller, node.inter);
				//remove unrelated global variables and properties
				if(!unrelated.isEmpty()) {
					newInter = new Node.TracingInterMap();
					// SITE 2/3/4 of 6 (§82/83): selective copy-forward, wired to copySelectedFrom -- the
					// excluded-key set (unrelated) IS the semantics here, unlike a plain copyFrom().
					java.util.Set<String> _transferKeys = new java.util.HashSet<String>(node.inter.keySet());
					_transferKeys.removeAll(unrelated);
					((Node.TracingInterMap) newInter).copySelectedFrom(node.inter, _transferKeys);
				}
				//the taint status is not changed
				else {
					newInter = node.inter;
				}
				//iterate the next statement
				//only one subsequent node, just traverse
				Set<Long> intra=node.intro;
				for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
					Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
					Stack<Long> stack =(Stack<Long>) node.caller.clone();
					//update context
					nextNode = mergeNode(next, intra, newInter, stack);
					//merge completed and traverse the next statement
					if(Edgetimes.get(next)==es(next)) {
						//clean(node);
						traverse(nextNode);
					}
					//loop back
					else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
						if(CSVCFGExporter.cfgSave.get(next).size()>1) {
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
						else if(forloop.contains(next)){
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
						else {
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
					}
					else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
						Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
						nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
						if(Edgetimes.get(nextnext)==es(nextnext)) {
							traverse(nextNode);
						}
					}
				}
			}
			//the statement is not sanitized
			else{
				//this stmt is source statement, we add taint variables
				if(srcStmt.containsKey(stmt)) {
					System.out.println("source stmt: "+stmt);
					//the source is used in call expression
					List<Long> srcs = srcStmt.get(stmt);
					boolean isarg = true;
					for(Long src: srcs) {
						Long argList = isArg(src, stmt);
						//source is used as argument
						if(argList!=-1) {
							Long func = PHPCSVEdgeInterpreter.child2parent.get(argList);
							String funName = ASTUnderConstruction.idToNode.get(func).getEscapedCodeStr();
							//the function is a sink function
							if(PHPCGFactory.sinks.contains(func)) {
								if( System.getenv("WP_VFLOW_DIAG") != null ) {
									System.err.println("VFLOW_DIAG site2 stmt=" + stmt + " src=" + src
										+ " argList=" + argList + " func=" + func + " funName=" + funName
										+ " node.astId=" + node.astId);
								}
								System.out.println("source is used in sink "+node.astId);
								Stack<Long> tmp = (Stack<Long>) node.caller.clone();
								if(System.getenv("PROD_DIAG")!=null) System.err.println("PRODUCER site=2 java_line=2099 sink="+node.astId+" node_id="+System.identityHashCode(node)+" caller="+tmp+" intro="+node.intro+" inter="+node.inter);
								if(System.getenv("WP_SITE_DIAG")!=null) System.err.println("SITE_DIAG site=2 stmt="+node.astId);
								vulStmts.add(node.astId, tmp);
								vulSources.add(node.astId, src);
								// src and tmp are BOTH live here — this is the moment the pairing exists.
								valueFlowFindings.add(new ValueFlowFinding(node.astId, src, tmp,
									node.astId, "INTERPROCEDURAL_SITE_2051", "PRESERVED"));   // src is the exact source node in scope
								// Defect 3 fix — property def-use backtracking (pre-computed map):
								// propRequestOrigins was built in PHPCGFactory.buildPropRequestOrigins()
								// before the taint analysis ran. It maps property identity → request origin nodes
								// (the $_POST/$_GET/... superglobal nodes that can reach the property through
								// local variable chains). If src is an AST_PROP and the property identity is in
								// the map, emit those superglobal nodes as ADDITIONAL Vul Sources so the adjudicator
								// sees the real request origin instead of just the bare property read.
								{
									ASTNode srcNodeX = ASTUnderConstruction.idToNode.get(src);
									if (srcNodeX instanceof PropertyExpression) {
										String propIden = getPropIdentity(srcNodeX, 0L);
										if (propIden != null && !propIden.isEmpty() && !propIden.startsWith("-1::")) {
											Set<Long> reqOrigins = PHPCGFactory.propRequestOrigins.get(propIden);
											if (reqOrigins != null) {
												for (Long reqNode : reqOrigins) {
													vulSources.add(node.astId, reqNode);
												}
											}
										}
									}
								}
								System.out.println("check: "+node.astId+" "+tmp);
								break;
							}
							//the sourcs is santizized
							else {
								System.out.println("source is sanitized "+node.astId);
								// If the call is a constructor ($w = new Cls(tainted_arg)),
								// enter it to propagate taint into object property inter state.
								// SITE 6 of 6 (§82/83): was a PLAIN HashMap -- its own writes were invisible to
								// everything, and it silently truncated ancestry when later copyFrom()'d elsewhere.
								Node.TracingInterMap ctorInterPatch = new Node.TracingInterMap();
								{
									ASTNode stmtNd = ASTUnderConstruction.idToNode.get(stmt);
									if(stmtNd instanceof AssignmentExpression) {
										Expression rhsX = ((AssignmentExpression)stmtNd).getRight();
										if(rhsX instanceof ast.expressions.NewExpression) {
											List<Long> ctorTgtsX = PHPCGFactory.call2mtd.get(rhsX.getNodeId());
											if(ctorTgtsX != null && !ctorTgtsX.isEmpty()) {
												Stack<Long> ctorStkX = (Stack<Long>) node.caller.clone();
												ctorStkX.push(node.astId);
												for(Long ctorFidX : ctorTgtsX) {
													Long ctorEntX = ctorFidX + 1;
													if(!CSVCFGExporter.cfgSave.containsKey(ctorEntX)) continue;
													if(Edgesize.get(ctorEntX) == null) {
														java.util.ArrayDeque<Long> bfQ = new java.util.ArrayDeque<Long>();
														bfQ.add(ctorEntX);
														java.util.Set<Long> bfS = new java.util.HashSet<Long>();
														while(!bfQ.isEmpty()) {
															Long bfN = bfQ.poll();
															if(!bfS.add(bfN)) continue;
															if(Edgesize.get(bfN) == null) {
																int inD = 0;
																for(Long s : CSVCFGExporter.cfgSave.keySet())
																	if(CSVCFGExporter.cfgSave.get(s).contains(bfN)) inD++;
																Edgesize.put(bfN, Math.max(1, inD));
																Edgetimes.put(bfN, 0);
															}
															java.util.List<Long> nxts = CSVCFGExporter.cfgSave.get(bfN);
															if(nxts != null) bfQ.addAll(nxts);
														}
													}
													// Bind tainted args to constructor params in srcStmt
													ArgumentList ctorAL = ((ast.expressions.NewExpression)rhsX).getArgumentList();
													ASTNode ctorFN = ASTUnderConstruction.idToNode.get(ctorFidX);
													if(ctorAL != null && ctorFN instanceof FunctionDef) {
														ParameterList ctorPL = ((FunctionDef)ctorFN).getParameterList();
														for(int pi = 0; ctorPL != null && pi < ctorAL.size() && pi < ctorPL.size(); pi++) {
															Expression ctorArg = ctorAL.getArgument(pi);
															if(ctorArg == null) continue;
															boolean argTnt = false;
															java.util.ArrayDeque<Long> aQ = new java.util.ArrayDeque<Long>();
															aQ.add(ctorArg.getNodeId());
															java.util.Set<Long> aS = new java.util.HashSet<Long>();
															while(!aQ.isEmpty() && !argTnt) {
																Long aid = aQ.poll();
																if(!aS.add(aid)) continue;
																if(PHPCSVEdgeInterpreter.sources.contains(aid)) { argTnt = true; break; }
																HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(aid);
																if(kids != null) aQ.addAll(kids.values());
															}
															if(!argTnt) continue;
															Parameter ctorPrm = (Parameter)ctorPL.getParameter(pi);
															if(ctorPrm == null) continue;
															String pName = ctorPrm.getName();
															cg.PHPCGFactory.recordScanSite("SA_2753", ASTUnderConstruction.idToNode.size());
															for(ASTNode pn : ASTUnderConstruction.idToNode.values()) {
																if(!(pn instanceof Variable)) continue;
																if(!ctorFidX.equals(pn.getFuncId())) continue;
																Variable pVar = (Variable)pn;
																if(pVar.getNameExpression() == null) continue;
																if(!pName.equals(pVar.getNameExpression().getEscapedCodeStr())) continue;
																Long pStmtId = getStatement(pn.getNodeId());
																// Use the param variable node itself as the srcStmt source,
																// NOT the external arg node (which would make isArg() find
																// an arg list outside the constructor and set isarg=true,
																// bypassing addInter). Using pn.getNodeId() ensures isArg
																// walks to the containing stmt (pStmtId) and returns -1.
																if(pStmtId != null && !srcStmt.containsKey(pStmtId))
																	srcStmt.add(pStmtId, pn.getNodeId());
															}
														}
													}
													active.put(ctorFidX, true);
													Set<Long> ctorIntroX = new HashSet<Long>(node.intro);
													ctorIntroX.add(node.astId);
													Node ctorNdX = mergeNode(ctorEntX, ctorIntroX, node.inter, ctorStkX);
													if(ctorNdX != null && Edgetimes.get(ctorEntX) != null &&
															Edgetimes.get(ctorEntX).equals(Edgesize.get(ctorEntX))) {
														traverse(ctorNdX);
														Long ctorExX = ctorFidX + 2;
														Node ctorExNd = ID2Node.get(ctorExX);
														if(ctorExNd != null) ctorInterPatch.copyFrom(ctorExNd.inter);
														
													}
													active.put(ctorFidX, false);
												}
											}
										}
									}
								}
								// Traverse forward with constructor-derived inter merged in
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									// Merge constructor inter into the forward inter
									Node.TracingInterMap fwdInter = new Node.TracingInterMap(); fwdInter.copyFrom(node.inter);
									fwdInter.copyFrom(ctorInterPatch);
									//update context
									nextNode = mergeNode(next, node.intro, fwdInter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
							}
						}
						else {
							//add source
							isarg = false;
						}
					}
					
					Set<Long> newIntro = new HashSet<Long>(node.intro);
					Node newNode = node;
					
					if(isarg==false) {
						//node.intro.add(node.astId);
						Set<Long> intra=node.intro;
						HashMap<String, Long> inter = node.inter;
						if(System.getenv("SG_PIPELINE_DIAG")!=null) System.err.println("ADDINTER_CALL_SITE_2 astId="+node.astId+" isarg="+isarg+" func="+ASTUnderConstruction.idToNode.get(node.astId).getFuncId());
						newNode = addInter(node);
						if(System.getenv("SG_PIPELINE_DIAG")!=null)
							System.err.println("SITE2_RESULT astId="+node.astId
								+" input_map="+System.identityHashCode(node.inter)
								+" returned_map="+System.identityHashCode(newNode.inter)
								+" returned_keys="+newNode.inter.keySet()
								+" changed="+(!newNode.inter.equals(node.inter)));
						if(newNode.inter.equals(node.inter)) {
							newIntro.add(node.astId);
						}
						addNode(root, node);
						// Constructor step-in inside srcStmt block:
						// $w = new T8Widget($_GET['x']); — source stmt, so call dispatch is skipped.
						// Enter the constructor here so $this->prop = $param propagates taint
						// into inter BEFORE we traverse forward to $w->render().
						{
							ASTNode srcCtorStmt = ASTUnderConstruction.idToNode.get(stmt);
							if(srcCtorStmt instanceof AssignmentExpression) {
								Expression srcCtorRhs = ((AssignmentExpression)srcCtorStmt).getRight();
								if(srcCtorRhs instanceof ast.expressions.NewExpression) {
									List<Long> srcCtorTgts = PHPCGFactory.call2mtd.get(srcCtorRhs.getNodeId());
									if(srcCtorTgts != null && !srcCtorTgts.isEmpty()) {
										Stack<Long> srcCtorStack = (Stack<Long>) node.caller.clone();
										srcCtorStack.push(node.astId);
										for(Long srcCtorFid : srcCtorTgts) {
											Long srcCtorEntry = srcCtorFid + 1;
											if(!CSVCFGExporter.cfgSave.containsKey(srcCtorEntry)) continue;
											// Init Edgesize/Edgetimes if not yet set
											if(Edgesize.get(srcCtorEntry) == null) {
												java.util.ArrayDeque<Long> bQ = new java.util.ArrayDeque<Long>();
												bQ.add(srcCtorEntry);
												java.util.Set<Long> bS = new java.util.HashSet<Long>();
												while(!bQ.isEmpty()) {
													Long bN = bQ.poll();
													if(!bS.add(bN)) continue;
													if(Edgesize.get(bN) == null) {
														int inDeg = 0;
														for(Long s : CSVCFGExporter.cfgSave.keySet()) {
															if(CSVCFGExporter.cfgSave.get(s).contains(bN)) inDeg++;
														}
														Edgesize.put(bN, Math.max(1, inDeg));
														Edgetimes.put(bN, 0);
													}
													java.util.List<Long> nxts = CSVCFGExporter.cfgSave.get(bN);
													if(nxts != null) bQ.addAll(nxts);
												}
											}
											// Activate constructor, traverse, merge exit inter back
											active.put(srcCtorFid, true);
											Set<Long> srcCtorIntro = new HashSet<Long>(node.intro);
											srcCtorIntro.add(node.astId);
											Node srcCtorNode = mergeNode(srcCtorEntry, srcCtorIntro, newNode.inter, srcCtorStack);
											if(srcCtorNode != null && Edgetimes.get(srcCtorEntry) != null &&
													Edgetimes.get(srcCtorEntry).equals(Edgesize.get(srcCtorEntry))) {
												traverse(srcCtorNode);
												// Merge constructor exit inter into newNode.inter
												Long srcCtorExit = srcCtorFid + 2;
												Node srcCtorExitNode = ID2Node.get(srcCtorExit);
												// SITE 5 of 6 (§82/83): constructor-exit copy-forward, wired to copyFrom.
												if(srcCtorExitNode != null && newNode.inter instanceof Node.TracingInterMap) {
													((Node.TracingInterMap) newNode.inter).copyFrom(srcCtorExitNode.inter);
												} else if(srcCtorExitNode != null) {
													if(System.getenv("MUTATION_DAG_DIAG")!=null)
														System.err.println("DIAGNOSTIC_INVARIANT_VIOLATION site5 fallback hit -- newNode.inter not traced");
													for(String k : srcCtorExitNode.inter.keySet()) newNode.inter.put(k, srcCtorExitNode.inter.get(k));
												}
											}
											active.put(srcCtorFid, false);
										}
									}
								}
							}
						}
					}
					
					for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
						Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
						Stack<Long> stack =(Stack<Long>) node.caller.clone();
						//update context
						nextNode = mergeNode(next, newIntro, newNode.inter, stack);
						//merge completed and traverse the next statement
						if(Edgetimes.get(next)==es(next)) {
							//clean(node);
							traverse(nextNode);
						}
						//loop back
						else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
							if(CSVCFGExporter.cfgSave.get(next).size()>1) {
								Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
								while(loop.contains(nextnext)) {
									nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
								}
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								//clean(node);
								if(Edgetimes.get(nextnext)==es(nextnext)) {
									traverse(nextNode);
								}
							}
							else if(forloop.contains(next)){
								Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
								while(loop.contains(nextnext)) {
									nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
								}
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								//clean(node);
								if(Edgetimes.get(nextnext)==es(nextnext)) {
									traverse(nextNode);
								}
							}
							else {
								Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
								nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
								if(Edgetimes.get(nextnext)==es(nextnext)) {
									traverse(nextNode);
								}
							}
						}
						else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
					}
				}
				else{
					//if it reaches sink without sanitization, we save the vulnerable path and return.
					System.out.println("related: "+related);
					if(!related.isEmpty() && sinks.contains(stmt) && !wrapperPositionSuppressed(stmt, related)) {
						// XSS alias-escaper check: if the sink is an echo/print and every tainted
						// variable in `related` appears in the sink's AST subtree ONLY inside an
						// output escaper or XSS input sanitizer call, suppress the finding.
						// Example: $order = $_GET['order']; echo esc_attr($order);
						// — related contains $order, sink subtree is esc_attr($order), the $order
						//   variable is inside esc_attr which credits it as safe.
						// This is checked by testing: for every taint-variable node in related.keySet(),
						// its ancestor path up to the sink passes through an escaper call.
						boolean suppressedByEscaper = false;
						Long xssSinkNode = null;
						for(Long sn : PHPCSVNodeInterpreter.xsssinks) {
							Long sst = getStatement(sn);
							if(node.astId.equals(sst) || node.astId.equals(sn)) { xssSinkNode = sn; break; }
						}
						if(xssSinkNode != null) {
							boolean allTaintsEscaped = !related.isEmpty();
							for(Long taintVar : related.keySet()) {
								// Walk up from taintVar to xssSinkNode; if any ancestor is an escaper/sanitizer, this taint is safe.
								boolean escaped = taintVarEscapedInSink(taintVar, related.get(taintVar), xssSinkNode);
								if(!escaped) { allTaintsEscaped = false; break; }
							}
							if(allTaintsEscaped) {
								suppressedByEscaper = true;
								String escaperName = cg.PHPCGFactory.xssOutputEscaperName(xssSinkNode);
								if(escaperName != null && !cg.PHPCGFactory.NUMERIC_COERCERS.contains(escaperName))
									cg.PHPCGFactory.xssEscaperMatched.put(xssSinkNode, escaperName);
							}
						}
						if(!suppressedByEscaper) {
						Stack<Long> tmp = (Stack<Long>) node.caller.clone();
						if(System.getenv("PROD_DIAG")!=null) System.err.println("PRODUCER site=3 java_line=2444 sink="+node.astId+" node_id="+System.identityHashCode(node)+" caller="+tmp+" intro="+node.intro+" inter="+node.inter);
						if(System.getenv("RELATED_DIAG")!=null) System.err.println("RELATED sink="+node.astId
							+" size="+related.size()+" keys="+related.keySet()+" values="+related.values());
						if(System.getenv("WP_SITE_DIAG")!=null) System.err.println("SITE_DIAG site=3 stmt="+node.astId);
						vulStmts.add(node.astId, tmp);
						// Backward-trace to original source nodes: related maps taint-var → intro nodeID.
						// intro nodeID is the entry-point statement where the taint was first introduced.
						// srcStmt maps those entry-point statements → original source DIM nodes ($_GET/'x' etc).
						// Preference order: (1) srcStmt of the intro entry-point → gives the raw request var;
						// (2) srcDim of the current sink stmt → gives the inline dim if it's a direct hit;
						// (3) the taint key itself → variable at the sink as a last resort.
						// Computed ONCE per sink statement -- authoritative for UNRESOLVED_VALUE_FLOW emission.
						// MUST use the SAME topCaller that produced `related` above (line ~1950), not a
						// re-derived guess -- an earlier attempt used node.caller.peek() directly and it
						// silently diverged from isrelated()'s actual input, producing wrong results that
						// passed compilation and even ran without crashing.
						Long _topCaller = (node.caller==null || node.caller.isEmpty()) ? 0L : node.caller.peek();
						java.util.LinkedHashMap<String,RelatedEvidence> _relEv = isrelatedEvidence(node.astId, node.intro, _topCaller);
						// Migration safeguard: log projection differences against the legacy map for comparison.
						if(System.getenv("RE_MIGRATION_DIAG")!=null) {
							java.util.Set<Long> legacyKeys = related.keySet();
							java.util.Set<Long> newRelatedNodes = new java.util.HashSet<Long>();
							for(RelatedEvidence e : _relEv.values()) newRelatedNodes.add(e.relatedNode);
							System.err.println("REMIGRATE sink="+node.astId+" legacy="+legacyKeys+" new="+newRelatedNodes
								+" new_evidence_count="+_relEv.size());
						}
						for(Long taint: related.keySet()) {
							Long introId = related.get(taint);
							Node introNode = ID2Node.get(introId);
							Long introStmt = (introNode != null) ? introNode.astId : null;
							boolean foundOrigin = false;
							// Walk the intro chain upward (intro nodes can be chained through
							// function boundaries) to find an entry statement with srcStmt data.
							Long cur = introStmt;
							for(int hop = 0; hop < 8 && cur != null; hop++) {
								if(srcStmt.containsKey(cur)) {
									for(Long origSrc : srcStmt.get(cur)) vulSources.add(node.astId, origSrc);
									foundOrigin = true; break;
								}
								// Follow the preNode chain (intro linked list) upward.
								Node curNode = ID2Node.get(cur);
								cur = (curNode != null && curNode.parent != null)
									? ID2Node.containsKey(curNode.parent)
									  ? ID2Node.get(curNode.parent).astId : null
									: null;
							}
							if(!foundOrigin) {
								// NOT source evidence — a flow-state marker. LEGACY behavior restored as
								// authoritative: isrelatedEvidence()'s ARGUMENT_MATCH branch was proven (by the
								// wiring attempt) to answer a different question than this producer needs -- it
								// matches caller-side literal arguments, but real sinks are usually one function
								// boundary inside the callee, where the value is a PARAMETER, not a caller
								// argument. Every real fixture silently fell through to SINK_LEVEL_FALLBACK.
								if(System.getenv("RE_EXPERIMENTAL")!=null) {
									boolean emittedAny = false;
									for(RelatedEvidence _re : _relEv.values()) {
										if(!_re.introNode.equals(introId)) continue;
										UnresolvedValueFlow _u = new UnresolvedValueFlow(node.astId, _re.relatedNode, node.intro,
											node.caller, "LOCAL_ASSIGNMENT_LINEAGE_NOT_RESOLVED");
										_u.relationKind = _re.relationKind; _u.sinkArgumentIndex = _re.sinkArgumentIndex;
										_u.identityPrecision = _re.identityPrecision;
										unresolvedFlows.put(_u.key(), _u); emittedAny = true;
									}
									if(emittedAny) continue;
								}
								{ UnresolvedValueFlow _u = new UnresolvedValueFlow(node.astId, taint, node.intro,
										node.caller, "LOCAL_ASSIGNMENT_LINEAGE_NOT_RESOLVED");
									_u.relationKind = "SINK_LEVEL_FALLBACK"; _u.identityPrecision = "SINK_LEVEL_FALLBACK";
									unresolvedFlows.put(_u.key(), _u); }
								// Defect 3: if the taint variable is a property read (e.g. $this->sql_order),
								// look up the pre-computed propRequestOrigins map to emit the upstream
								// request-superglobal origin as an ADDITIONAL Vul Source.
								{
									ASTNode taintNode = ASTUnderConstruction.idToNode.get(taint);
									if (taintNode instanceof PropertyExpression) {
										String propIden = getPropIdentity(taintNode, 0L);
										if (propIden != null && !propIden.isEmpty() && !propIden.startsWith("-1::")) {
											Set<Long> reqOrigins = PHPCGFactory.propRequestOrigins.get(propIden);
											if (reqOrigins != null) {
												for (Long reqNode : reqOrigins) {
													vulSources.add(node.astId, reqNode);
												}
											}
										}
									}
								}
							}
						}
							System.out.println("check: "+node.astId+" "+tmp);
						//link the callee stmts related to return value to the caller
						for(Long taint: related.keySet()) {
							Long source = related.get(taint);
							Node preNode = ID2Node.get(source);
							addNode(preNode, node);
						}
						} // end if(!suppressedByEscaper)
					}
					
					//the stmt contains a function call
					ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
					//save the caller of the target function
					//this statement is a function call
					// Also handle $w = new ClassName(...): constructor calls are NewExpressions
					// whose call2mtd entries are keyed on the NewExpression node, not the stmt node.
					Long ctorCallNodeId = null;
					if(stmtNode instanceof AssignmentExpression) {
						Expression rhsN = ((AssignmentExpression)stmtNode).getRight();
						if(rhsN instanceof ast.expressions.NewExpression) {
							List<Long> ctorTgts = PHPCGFactory.call2mtd.get(rhsN.getNodeId());
							
							if(ctorTgts != null && !ctorTgts.isEmpty()) {
								ctorCallNodeId = rhsN.getNodeId();
							}
						}
					}
					if(stmtNode instanceof CallExpressionBase || stmtNode instanceof IncludeOrEvalExpression
							|| ctorCallNodeId != null) {
						Long caller = node.astId;
						Stack<Long> callStack = (Stack<Long>) node.caller.clone();
						callStack.push(caller);
						ArgumentList args = null;
						if(stmtNode instanceof CallExpressionBase) {
							 args = ((CallExpressionBase) stmtNode).getArgumentList();
						} else if(ctorCallNodeId != null) {
							// Use the NewExpression's argument list for the constructor
							args = ((ast.expressions.NewExpression)((AssignmentExpression)stmtNode).getRight()).getArgumentList();
						}
						//get the target function of this call site — for constructors use the NewExpression node
						List<Long> targetFuncs = PHPCGFactory.call2mtd.get(ctorCallNodeId != null ? ctorCallNodeId : stmt);
						if(System.getenv("SG_PIPELINE_DIAG")!=null) {
							System.err.println("CALL_OBSERVED stmt="+stmt
								+" arg_count="+(args==null?0:args.size())+" caller_funcid="+ASTUnderConstruction.idToNode.get(node.astId).getFuncId());
							System.err.println("CALL_TARGET_RESULT stmt="+stmt
								+" resolved="+(targetFuncs!=null && !targetFuncs.isEmpty())
								+" targetFuncs="+targetFuncs);
						}
						
						//from argument to the related stmt in caller function
						//built-in function
						if(targetFuncs==null || targetFuncs.isEmpty()){
							Set<Long> intra=node.intro;
							HashMap<String, Long> inter = node.inter;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intra, inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==es(next)) {
									//clean(node);
									traverse(nextNode);
								}
								//loop back
								else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==es(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
						
						//handle target functions and remove infeaisble ones based on the call contexts
						
						List<Long> validFuncs = new LinkedList<Long>();
						if(targetFuncs.size()>=2) {
							validFuncs = handleFunc(targetFuncs, node.caller, node.astId);
						}
						else {
							validFuncs.add(targetFuncs.get(0));
						}
						
						
						for(Long func: targetFuncs) {
							if(!validFuncs.contains(func)) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, node.intro, node.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							//the callee is also the caller
							boolean contains = false;
							for(Long id: node.caller) {
								if(ID2Node.containsKey(id)) {
									Long astId = ID2Node.get(id).astId;
									Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
									if(callerfunc.equals(func)) {
										contains=true;
										break;
									}
								}
							}
							//already contains, we skip the function
							if(contains==true) {
								Set<Long> intra=node.intro;
								HashMap<String, Long> inter = node.inter;
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							FunctionDef funcNode = (FunctionDef) ASTUnderConstruction.idToNode.get(func);
							//if it is an empty function, we skip the function
							if(funcNode.getContent()==null || funcNode.getContent().size()==0) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Set<Long> intra=node.intro;
									HashMap<String, Long> inter = node.inter;
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							Long funcID = ASTUnderConstruction.idToNode.get(stmt).getFuncId();
							Long exitID = funcID+2;
							
							//check weather params are tainted
							Set<Long> intro = new HashSet<Long>();
							HashMap<Long, Long> param2caller = new HashMap<Long, Long>();
							
							//this is a function call instead of a require statement
							if(args!=null) {
								Long _cn1 = stmt;
								ASTNode _sn1 = ASTUnderConstruction.idToNode.get(stmt);
								if(_sn1 instanceof AssignmentExpression && ((AssignmentExpression)_sn1).getRight() instanceof CallExpressionBase)
									_cn1 = ((AssignmentExpression)_sn1).getRight().getNodeId();
								int coff = cg.PHPCGFactory.callableArgOffset.contains(_cn1) ? 1 : 0;   // call_user_func: arg[0] is the callable, real args start at 1
								boolean stmtTaint1 = (coff==1) && related.containsKey(_cn1);   // dispatch statement tainted but maybe not pinned to an arg
								for(int i=0; i<args.size(); i++) {
									int pidx = i - coff;
									if(pidx < 0) continue;
									ASTNode arg = args.getArgument(i); 
									// UNCONDITIONAL structural binding, per the reviewer's exact design --
									// logged BEFORE any taint-match test, so this measures whether the
									// call graph itself connects actual argument to formal parameter,
									// independent of whether existing taint machinery has already
									// recognized this argument. No provenance claim, no taint claim.
									if(System.getenv("FALLBACK_DIAG")!=null && pidx < funcNode.getParameterList().size()) {
										ParameterBase _structParam = funcNode.getParameterList().getParameter(pidx);
										System.err.println("CALL_BINDING_AVAILABLE caller="+node.astId
											+" callsite="+stmt+" callee="+func+" argument_index="+pidx
											+" actual_argument_node="+arg.getNodeId()
											+" parameter_declaration_node="+_structParam.getNodeId());
									}
									Long src = null; boolean matched = false;
									for(Long taint: related.keySet()) {
										if(taint.equals(arg.getNodeId())) { matched = true; src = related.get(taint); break; }
									}
									// A property/local assigned via a wrapper (e.g. $this->data = stripslashes_deep($_POST[..]))
									// taints the call statement node, not the arg node, so the precise match above misses it.
									// For a tainted call_user_func dispatch, the data argument(s) carry that taint.
									if(!matched && stmtTaint1 && (arg instanceof PropertyExpression || arg instanceof Variable)) {
										matched = true; src = related.get(_cn1);
									}
									if(matched && pidx < funcNode.getParameterList().size()) {
										ParameterBase param = funcNode.getParameterList().getParameter(pidx);
										intro.add(param.getNodeId());
										param2caller.put(param.getNodeId(), src);
										if(System.getenv("FALLBACK_DIAG")!=null) {
											System.err.println("CALL_ARGUMENT_BINDING caller_function="+node.astId
												+" caller_context="+node.astId
												+" callsite_ast_id="+stmt
												+" callee_function="+func
												+" argument_index="+pidx
												+" caller_argument_node="+arg.getNodeId()
												+" caller_source_src="+src
												+" parameter_declaration_node="+param.getNodeId());
										}
									}
								}
							}
							//get next statement in the target function
							Long nextId = (long) -1;
							//the param is not tainted
							if(intro.isEmpty()) {
								boolean flag = false;
								if(System.getenv("SG_PIPELINE_DIAG")!=null) {
									for(String _ik : node.inter.keySet()) {
										java.util.List<Long> _tg = name2Func.get(_ik);
										System.err.println("CALL_RELEVANCE_CHECK call_stmt="+stmt+" target_funcid="+func
											+" inter_identity="+_ik+" name2Func_targets="+_tg
											+" matched="+(_tg!=null && _tg.contains(func)));
									}
								}
								for(String inter: node.inter.keySet()) {
									//the inter variables are used in the function or not
									for(String key: name2Func.keySet()) {
										//find the key
										if(key.equals(inter) || check(inter, key)==true) {
											if(name2Func.get(key).contains(func)) {
												System.out.println("name2Func: "+key+" "+name2Stmt.get(key)+" "+name2Func.get(key));
												flag=true;
												break;
											}
										}
									}
								}
								//the function defines source
								HashSet<Long> src = new HashSet<Long>(node.inter.values());
								//the function defines source statement
								if(sourceFunc.containsKey(func)) {
									HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
									def.removeAll(src);
									//the function defines other source statements
									if(!def.isEmpty()) {
										System.out.println("define source: "+func+" "+def);
										flag=true;
									}
									else {
										//System.out.println("not define source: "+func);
									}
								}
								
								Set<Long> intra=node.intro;
								HashMap<String, Long> inter=node.inter;
								
								//step into the function
								if(flag==true && node.caller.size()<9) {
									active.put(func, true);
									System.out.println("step into : "+func);
									if(CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1)==null) {
										return false;
									}
									Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
									ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
									nextId = nextstmt.getNodeId();
									nextNode = new Node(nextId, node.inter, intro, callStack);
									traverse(nextNode);
									
									//the function should exit here
									if(active.get(func)==true) {
										active.put(func, false);
										//it has reaches the exit node
										Node exit=null;
										if(ID2Node.containsKey(func+2)) {
											exit = ID2Node.get(func+2);
										}
										else {
											exit = node;
										}
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											nextNode = mergeNode(next, node.intro, exit.inter, stack);
											if(Edgetimes.get(next)==es(next)) {
												//clean(node);
												traverse(nextNode);
											}
											//loop back
											else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
												if(CSVCFGExporter.cfgSave.get(next).size()>1) {
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
												else if(forloop.contains(next)){
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
												else {
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
											}
											else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
									}
								}
								//the function is not related, thus we do not step into it
								else {
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										//update context
										nextNode = mergeNode(next, intra, node.inter, stack);
										//merge completed and traverse the next statement
										if(Edgetimes.get(next)==es(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									continue;
								}
							}
							//step into the function
							else {
								active.put(func, true);
								Set<Long> newIntro = new HashSet<Long>();
								Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
								for(Long taintParam: intro) {
									Long prev = param2caller.get(taintParam);
									Node preNode = ID2Node.get(prev);
									nextId = taintParam;
									newIntro.add(nextId);
									nextNode = new Node(nextId, node.inter, newIntro, callStack);
									addNode(preNode, nextNode);
								}
								traverse(nextNode);
								
								//the target function should exit here
								if(active.get(func)==true) {
									active.put(func, false);
									//it has reaches the exit node
									Node exit=null;
									if(ID2Node.containsKey(func+2)) {
										exit = ID2Node.get(func+2);
									}
									else {
										exit = node;
									}
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										nextNode = mergeNode(next, node.intro, exit.inter, stack);
										if(Edgetimes.get(next)==es(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
								}
							}	
						}
						
					}
					//the statement's right value is a function call
					else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
						Long caller = node.astId;
						Stack<Long> callStack = (Stack<Long>) node.caller.clone();
						callStack.push(caller);
						CallExpressionBase callsite = (CallExpressionBase) ((AssignmentExpression) stmtNode).getRight();
						ArgumentList args = callsite.getArgumentList();
						//get the target function of this call site
						List<Long> targetFuncs = PHPCGFactory.call2mtd.get(callsite.getNodeId());
						//from argument to the related stmt in caller function
						HashMap<Long, Long> param2caller = new HashMap<Long, Long>();
						//it is built-in function
						if(targetFuncs==null || targetFuncs.isEmpty()) {
							//Taint pass-through: a built-in call whose ARGUMENT is a fresh source
							//(e.g. $v = sanitize_text_field($_POST['x'])) must propagate taint to the
							//result. Without this the taint is dropped at every built-in boundary, so
							//any wrapper (trim/wp_unslash/sanitize_text_field/...) silently launders
							//attacker input to "clean". Whether a genuine SQL sanitizer was on the path
							//is decided separately at the sink check via sqlSanitizers, so we propagate
							//through ALL built-ins here and let the sink check neutralize real sanitizers.
							boolean argSrc = argsContainSource(args==null?null:args.getNodeId(), 0);
							//remove tainted variables
							if(related.keySet().isEmpty() && !argSrc) {
								Set<String> unrelated = RemoveInterTaint(stmt, caller, node.inter);
								HashMap<String, Long> newInter = null;
								//remove unrelated global variables and properties
								if(!unrelated.isEmpty()) {
									newInter = new Node.TracingInterMap();
									java.util.Set<String> _transferKeys = new java.util.HashSet<String>(node.inter.keySet());
									_transferKeys.removeAll(unrelated);
									((Node.TracingInterMap) newInter).copySelectedFrom(node.inter, _transferKeys);
								}
								//the taint status is not changed
								else {
									newInter = node.inter;
								}
								Set<Long> intra=node.intro;
								
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, newInter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								return false;
							}
							//the tainted variables are used as source in built-in function, we think the destination will also be tainted
							else {
								//update context
								Set<Long> save = new HashSet<Long>(node.intro);
								if(System.getenv("SG_PIPELINE_DIAG")!=null) System.err.println("ADDINTER_CALL_SITE_3 astId="+node.astId+" func="+ASTUnderConstruction.idToNode.get(node.astId).getFuncId());
								Node tmp = addInter(node);
								if(tmp.inter.equals(node.inter)) {
									save.add(node.astId);
								}
								Set<Long> save1 = save;
								//link node
								for(Long taint: related.keySet()) {
									Long source = related.get(taint);
									Node preNode = ID2Node.get(source);
									addNode(preNode, node);
								}
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Set<Long> intra=node.intro;
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, save1, tmp.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								return false;
							}
							
						}
						
						List<Long> validFuncs = new LinkedList<Long>();
						if(targetFuncs.size()>=2) {
							validFuncs = handleFunc(targetFuncs, node.caller, node.astId);
						}
						else {
							validFuncs.add(targetFuncs.get(0));
						}
						
						for(Long func: targetFuncs) {
							if(!validFuncs.contains(func)) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, node.intro, node.inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(nextNode);
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							boolean contains = false;
							for(Long id: node.caller) {
								if(ID2Node.containsKey(id)) {
									Long astId = ID2Node.get(id).astId;
									Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
									if(callerfunc.equals(func)) {
										contains=true;
										break;
									}
								}
							}
							//we have already analyzed this function, so we iterate the next stmt
							Set<Long> intra=node.intro;
							HashMap<String, Long> inter = node.inter;
							
							if(contains==true) {
								//iterate the next statement
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(ID2Node.get(next));
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							FunctionDef funcNode = (FunctionDef) ASTUnderConstruction.idToNode.get(func);
							if(funcNode.getContent()==null || funcNode.getContent().size()==0) {
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									
									Stack<Long> stack =(Stack<Long>) node.caller.clone();
									//update context
									nextNode = mergeNode(next, intra, inter, stack);
									//merge completed and traverse the next statement
									if(Edgetimes.get(next)==es(next)) {
										//clean(node);
										traverse(ID2Node.get(next));
									}
									//loop back
									else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
										if(CSVCFGExporter.cfgSave.get(next).size()>1) {
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else if(forloop.contains(next)){
											Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
											while(loop.contains(nextnext)) {
												nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
											}
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											//clean(node);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
										else {
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								continue;
							}
							
							//check weather params are tainted
							Set<Long> intro = new HashSet<Long>();
							Long _cn2 = stmt;
							ASTNode _sn2 = ASTUnderConstruction.idToNode.get(stmt);
							if(_sn2 instanceof AssignmentExpression && ((AssignmentExpression)_sn2).getRight() instanceof CallExpressionBase)
								_cn2 = ((AssignmentExpression)_sn2).getRight().getNodeId();
							int coff2 = cg.PHPCGFactory.callableArgOffset.contains(_cn2) ? 1 : 0;
							boolean stmtTaint2 = (coff2==1) && related.containsKey(_cn2);
							for(int i=0; i<args.size(); i++) {
								int pidx2 = i - coff2;
								if(pidx2 < 0) continue;
								ASTNode arg = args.getArgument(i); 
								if(System.getenv("FALLBACK_DIAG")!=null && pidx2 < funcNode.getParameterList().size()) {
									ParameterBase _structParam2 = funcNode.getParameterList().getParameter(pidx2);
									System.err.println("CALL_BINDING_AVAILABLE caller="+node.astId
										+" callsite="+callsite.getNodeId()+" callee="+func+" argument_index="+pidx2
										+" actual_argument_node="+arg.getNodeId()
										+" parameter_declaration_node="+_structParam2.getNodeId());
								}
								Long src = null; boolean matched = false;
								for(Long taint: related.keySet()) {
									if(taint.equals(arg.getNodeId())) { matched = true; src = related.get(taint); break; }
								}
								if(!matched && stmtTaint2 && (arg instanceof PropertyExpression || arg instanceof Variable)) {
									matched = true; src = related.get(_cn2);
								}
								if(matched && pidx2 < funcNode.getParameterList().size()) {
									ParameterBase param = funcNode.getParameterList().getParameter(pidx2);
									intro.add(param.getNodeId());
									param2caller.put(param.getNodeId(), src);
									if(System.getenv("FALLBACK_DIAG")!=null) {
										System.err.println("CALL_ARGUMENT_BINDING caller_function="+node.astId
											+" caller_context="+caller
											+" callsite_ast_id="+callsite.getNodeId()
											+" callee_function="+func
											+" argument_index="+pidx2
											+" caller_argument_node="+arg.getNodeId()
											+" caller_source_src="+src
											+" parameter_declaration_node="+param.getNodeId());
									}
								}
							}
							
							//get next statement of the target function
							//the param is not tainted
							Long nextId = (long) -1;
							if(intro.isEmpty()) {
								HashMap<String, Long> inter1 = node.inter;
								boolean flag = false;
								for(String interName: node.inter.keySet()) {
									//the inter variables are used in the function
									for(String key: name2Func.keySet()) {
										//find the key
										if(key.equals(interName) || check(interName, key)==true) {
											if(name2Func.get(key).contains(func)) {
												System.out.println("name2Func: "+key+" "+name2Stmt.get(key)+" "+name2Func.get(key));
												flag=true;
												break;
											}
										}
									}
								}
								//the function defines source
								HashSet<Long> src = new HashSet<Long>(node.inter.values());
								//the function defines source statement
								if(sourceFunc.containsKey(func)) {
									HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
									def.removeAll(src);
									//the function defines other source statements
									if(!def.isEmpty()) {
										System.out.println("define source: "+func+" "+def);
										flag=true;
									}
									else {
										//System.err.println("not define source: "+func);
									}
								}
								
								//the function is related, step into it
								if(flag==true && node.caller.size()<9) {
									active.put(func, true);
									System.out.println("step into : "+func);
									Long nextstmtId = CSVCFGExporter.cfgSave.get(funcNode.getNodeId()+1).get(0);
									ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
									nextId = nextstmt.getNodeId();
									nextNode = new Node(nextId, inter1, intro, callStack);
									traverse(nextNode);
									
									//the target function should exit here
									if(active.get(func)==true) {
										active.put(func, false);
										//it has reaches the exit node
										Node exit=null;
										if(ID2Node.containsKey(func+2)) {
											exit = ID2Node.get(func+2);
										}
										else {
											exit = node;
										}
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											nextNode = mergeNode(next, node.intro, exit.inter, stack);
											if(Edgetimes.get(next)==es(next)) {
												//clean(node);
												traverse(nextNode);
											}
											//loop back
											else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
												if(CSVCFGExporter.cfgSave.get(next).size()>1) {
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
												else if(forloop.contains(next)){
													Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
													while(loop.contains(nextnext)) {
														nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
													}
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													//clean(node);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
												else {
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
											}
											else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
									}
								}
								//the function is not related, we traverse the next statement of caller
								else {
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);

										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										//update context
										nextNode = mergeNode(next, intra, inter1, stack);
										//merge completed and traverse the next statement
										if(Edgetimes.get(next)==es(next)) {
											//clean(node);
											traverse(ID2Node.get(next));
										}
										//loop back
										else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
									continue;
								}
							}
							//the parameters are tainted, step into it
							else {
								active.put(func, true);
								Set<Long> newIntro = new HashSet<Long>();
								for(Long taintParam: intro) {
									Long prev = param2caller.get(taintParam);
									Node preNode = ID2Node.get(prev);
									nextId = taintParam;
									newIntro.add(nextId);
									nextNode = new Node(nextId, node.inter, newIntro, callStack);
									addNode(preNode, nextNode);
								}
								traverse(nextNode);
								
								//the target function should exit here
								if(active.get(func)==true) {
									active.put(func, false);
									//it has reaches the exit node
									Node exit=null;
									if(ID2Node.containsKey(func+2)) {
										exit = ID2Node.get(func+2);
									}
									else {
										exit = node;
									}
									for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
										Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
										Stack<Long> stack =(Stack<Long>) node.caller.clone();
										nextNode = mergeNode(next, node.intro, exit.inter, stack);
										if(Edgetimes.get(next)==es(next)) {
											//clean(node);
											traverse(nextNode);
										}
										//loop back
										else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
											if(CSVCFGExporter.cfgSave.get(next).size()>1) {
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else if(forloop.contains(next)){
												Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
												while(loop.contains(nextnext)) {
													nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
												}
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												//clean(node);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
											else {
												Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
												nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
												if(Edgetimes.get(nextnext)==es(nextnext)) {
													traverse(nextNode);
												}
											}
										}
										else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
											Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
											nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
											if(Edgetimes.get(nextnext)==es(nextnext)) {
												traverse(nextNode);
											}
										}
									}
								}
							}
							
						}
					}
					//the statement is a return statement
					else if(stmtNode instanceof ReturnStatement) {
						//the function has exit (because of "return func"
						Long funcId = ASTUnderConstruction.idToNode.get(node.astId).getFuncId();
						if(!(active.containsKey(funcId) && active.get(funcId)==true)) {
							return false;
						}
						
						if(node.caller.isEmpty()) {
							Long nextnext = ASTUnderConstruction.idToNode.get(node.astId).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(node.astId).intro, ID2Node.get(node.astId).inter, ID2Node.get(node.astId).caller);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
							return false;
						}
						Long caller = node.caller.peek();
						Node callerNode = ID2Node.get(caller);
						Long callerID = callerNode.astId;
						//next statement of the caller
						List<Long> nextStmts = CSVCFGExporter.cfgSave.get(callerID);
						HashMap<String, Long> inter = node.inter;
						boolean iscall = false;
						
						ReturnStatement retNode = (ReturnStatement) ASTUnderConstruction.idToNode.get(node.astId);
						ASTNode retValue = retNode.getReturnExpression();
						
						if(retValue instanceof StaticCallExpression || retValue instanceof NewExpression || retValue instanceof MethodCallExpression) {
							Set<Long> validTarget = new HashSet<Long>(); 
							List<Long> validFuncs = new LinkedList<Long>();
							List<Long> funcs = PHPCGFactory.call2mtd.get(retValue.getNodeId());
							if(funcs==null || funcs.isEmpty()){
								iscall = false;
							}
							else {
								iscall = true;
								for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
									Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
									int size = es(next);
									Edgesize.put(next, size-1+funcs.size());
								}
								//get valid target functions
								if(funcs.size()>=2) {
									validFuncs = handleFunc(funcs, node.caller, node.astId);
								}
								else {
									validFuncs.add(funcs.get(0));
								}
								
								for(Long func: funcs) {
									if(!validFuncs.contains(func)) {
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											//update context
											nextNode = mergeNode(next, node.intro, inter, stack);
											//merge completed and traverse the next statement
											if(Edgetimes.get(next)==es(next)) {
												//clean(node);
												traverse(ID2Node.get(next));
											}
										}
										continue;
									}
									
									boolean contains = false;
									for(Long id: node.caller) {
										if(ID2Node.containsKey(id)) {
											Long astId = ID2Node.get(id).astId;
											Long callerfunc = ASTUnderConstruction.idToNode.get(astId).getFuncId();
											if(callerfunc.equals(func)) {
												contains=true;
												break;
											}
										}
									}
									if(contains==true) {
										continue;
									}
									boolean flag = false;
									for(String inter1: node.inter.keySet()) {
										//the inter variables are used in the function or not
										for(String key: name2Func.keySet()) {
											//find the key
											if(key.equals(inter1) || check(inter1, key)==true) {
												if(name2Func.get(key).contains(func)) {
													flag=true;
													break;
												}
											}
										}
									}
									//the function defines source
									HashSet<Long> src = new HashSet<Long>(node.inter.values());
									//the function defines source statement
									if(sourceFunc.containsKey(func)) {
										HashSet<Long> def = new HashSet<Long>(sourceFunc.get(func));
										def.removeAll(src);
										//the function defines new source statements
										if(!def.isEmpty()) {
											System.out.println("define source: "+func+" "+def);
											flag=true;
										}
										else {
											//System.err.println("not define source: "+func);
										}
									}
									
									//the function is related, we step into it
									if(flag==true) {
										validTarget.add(func);
									}
									//else, go to the exit function
									else {
										for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
											Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
											
											Stack<Long> stack =(Stack<Long>) node.caller.clone();
											//update context
											nextNode = mergeNode(next, node.intro, inter, stack);
											//merge completed and traverse the next statement
											if(Edgetimes.get(next)==es(next)) {
												//clean(node);
												traverse(ID2Node.get(next));
											}
										}
									}
								}
								
								if(!validTarget.isEmpty()) {
									Set<Long> intra= new HashSet<Long>();
									Stack<Long> callStack = (Stack<Long>) node.caller.clone();
									callStack.push(node.astId);
									
									for(Long func: validTarget) {
										active.put(func, true);
										System.out.println("step into : "+func);
										Long nextstmtId = CSVCFGExporter.cfgSave.get(func+1).get(0);
										ASTNode nextstmt = ASTUnderConstruction.idToNode.get(nextstmtId);
										Long nextId = nextstmt.getNodeId();
										nextNode = new Node(nextId, node.inter, intra, callStack);
										traverse(nextNode);
										
										//the target function should exit here
										if(active.get(func)==true) {
											active.put(func, false);
											//it has reaches the exit node
											Node exit=null;
											if(ID2Node.containsKey(func+2)) {
												exit = ID2Node.get(func+2);
											}
											else {
												exit = node;
											}
											for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
												Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
												Stack<Long> stack =(Stack<Long>) node.caller.clone();
												nextNode = mergeNode(next, node.intro, exit.inter, stack);
												if(Edgetimes.get(next)==es(next)) {
													//clean(node);
													traverse(nextNode);
												}
												//loop back
												else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
													if(CSVCFGExporter.cfgSave.get(next).size()>1) {
														Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
														while(loop.contains(nextnext)) {
															nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
														}
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														//clean(node);
														if(Edgetimes.get(nextnext)==es(nextnext)) {
															traverse(nextNode);
														}
													}
													else if(forloop.contains(next)){
														Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
														while(loop.contains(nextnext)) {
															nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
														}
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														//clean(node);
														if(Edgetimes.get(nextnext)==es(nextnext)) {
															traverse(nextNode);
														}
													}
													else {
														Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
														nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
														if(Edgetimes.get(nextnext)==es(nextnext)) {
															traverse(nextNode);
														}
													}
												}
												else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
													Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
													nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
													if(Edgetimes.get(nextnext)==es(nextnext)) {
														traverse(nextNode);
													}
												}
											}
										}
									}
								}
							}
						}
						
						
						if(iscall == true) {
							return false;
						}
						
						//if the return value is tainted
						if(!related.keySet().isEmpty()) {
							//update context
							Set<Long> intra=node.intro;
							intra.add((long) (-1));
							//link the callee stmts related to return value to the caller
							for(Long taint: related.keySet()) {
								Long source = related.get(taint);
								Node preNode = ID2Node.get(source);
								addNode(preNode, callerNode);
							}
							//go to the the exit node
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intra, inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==es(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==es(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
						//the return value is not tainted
						else {
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, node.intro, inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==es(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==es(nextnext)) {
										traverse(nextNode);
									}
								}
							}
							return false;
						}
					}
					//the statement is an assignment
					else {
						Long caller;
						if(node.caller.isEmpty()) {
							caller = (long) 0;
						}
						else {
							caller=node.caller.peek();
						}
						
						if(related.keySet().isEmpty()) {
							
							Set<String> unrelated = RemoveInterTaint(stmt, caller, node.inter);
							HashMap<String, Long> newInter = null;
							//remove unrelated global variables and properties
							if(!unrelated.isEmpty()) {
								newInter = new Node.TracingInterMap();
								java.util.Set<String> _transferKeys = new java.util.HashSet<String>(node.inter.keySet());
								_transferKeys.removeAll(unrelated);
								((Node.TracingInterMap) newInter).copySelectedFrom(node.inter, _transferKeys);
							}
							//the taint status is not changed
							else {
								newInter = node.inter;
							}
							Set<Long> intro = node.intro;
							
							Long stmtId = node.astId;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								System.out.println("normal: "+stmt+" "+next);
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, intro, newInter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==es(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==es(nextnext)) {
										traverse(nextNode);
									}
								}
							}
						}
						else {
							//update context
							Set<Long> save = new HashSet<Long>(node.intro);
							if(System.getenv("SG_PIPELINE_DIAG")!=null) System.err.println("ADDINTER_CALL_SITE_4 astId="+node.astId+" func="+ASTUnderConstruction.idToNode.get(node.astId).getFuncId());
							Node tmp = addInter(node);
							if(tmp.inter.equals(node.inter)) {
								save.add(node.astId);
							}
							Set<Long> save1=save;
							//link the callee stmts related to return value to the caller
							for(Long taint: related.keySet()) {
								Long source = related.get(taint);
								Node preNode = ID2Node.get(source);
								addNode(preNode, node);
							}
							//iterate next statement
							Long stmtId = node.astId;
							for(int i=0; i<CSVCFGExporter.cfgSave.get(stmt).size(); i++) {
								Long next = CSVCFGExporter.cfgSave.get(stmt).get(i);
								
								Stack<Long> stack =(Stack<Long>) node.caller.clone();
								//update context
								nextNode = mergeNode(next, save, tmp.inter, stack);
								//merge completed and traverse the next statement
								if(Edgetimes.get(next)==es(next)) {
									//clean(node);
									traverse(ID2Node.get(next));
								}
								//loop back
								else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
									if(CSVCFGExporter.cfgSave.get(next).size()>1) {
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else if(forloop.contains(next)){
										Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
										while(loop.contains(nextnext)) {
											nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
										}
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										//clean(node);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
									else {
										Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
										nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
										if(Edgetimes.get(nextnext)==es(nextnext)) {
											traverse(nextNode);
										}
									}
								}
								else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
									Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
									nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
									if(Edgetimes.get(nextnext)==es(nextnext)) {
										traverse(nextNode);
									}
								}
							}
						}
					}
				}
			}
		}
		//AST Node FUNC_EXIT
		else if(!node.caller.isEmpty()) {
			
			//throw statement, stop here. All normal statements shall exit at FUNC_EXIT
			if(ASTUnderConstruction.idToNode.containsKey(node.astId)) {
				return false;
			}
			
			Edgesize.put(stmt, savesize.get(stmt));
			Long funcID = stmt-2;
			//the function has exited before
			if(active.containsKey(funcID) && active.get(funcID)==false) {
				return false;
			}
			active.put(funcID, false);
			
			//
			if(sourceFunc.containsKey(node.astId-2)) {
				Set<Long> oristmt = new HashSet<Long>(sourceFunc.get(node.astId-2));
				Set<Long> crtstmt = new HashSet<Long>(node.intro);
				for(Long st: node.inter.values()) {
					crtstmt.add(st);
				}
				oristmt.retainAll(crtstmt);
				
				sourceFunc.remove(node.astId-2);
				for(Long st: oristmt) {
					sourceFunc.add(node.astId-2, st);
				}
				
				System.out.println("change sourceFunc: "+(node.astId-2)+" "+oristmt);
			}
			
			HashMap<String, Long> inter = node.inter;
			Long caller = node.caller.peek();
			//clean(callerNode);
			if(clean.containsKey(stmt)) {
				System.out.println("clean stmt: "+stmt);
				for(Long intra: clean.get(stmt)) {
					if(ID2Node.containsKey(intra)) {
						clean(ID2Node.get(intra));
					}
				}
				
			}
			if(ID2Node.containsKey(caller)) {
				Node callerNode = ID2Node.get(caller);
				//the function does not change taint status
				
				Long callerID = ID2Node.get(caller).astId;
				List<Long> nextStmts=CSVCFGExporter.cfgSave.get(callerID);
				//next=CSVCFGExporter.cfgSave.get(next).get(0);
				Stack<Long> callStack = ID2Node.get(caller).caller;
				Set<Long> intro=ID2Node.get(caller).intro;
				//the return value is tainted
				if(!node.intro.isEmpty() && node.intro.contains((long) -1)){
					intro.add(callerID);
				}
				
				if(callerNode.intro.equals(intro) &&
						callerNode.inter.equals(node.inter)) {
					//unused.add(node.astId-2);
				}
				
				
				for(int i=0; i<CSVCFGExporter.cfgSave.get(callerID).size(); i++) {
					Long next = CSVCFGExporter.cfgSave.get(callerID).get(i);
					Stack<Long> stack = callStack;
					//update context
					nextNode = mergeNode(next, intro, inter, stack);
					//merge completed and traverse the next statement
					if(Edgetimes.get(next)==es(next)) {
						traverse(ID2Node.get(next));
					}
					//loop back
					else if(Edgetimes.get(next)>es(next) && loop.contains(next)) {
						if(CSVCFGExporter.cfgSave.get(next).size()>1) {
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(1);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
						else if(forloop.contains(next)){
							Long nextnext = CSVCFGExporter.cfgSave.get(next).get(0);
							while(loop.contains(nextnext)) {
								nextnext = CSVCFGExporter.cfgSave.get(nextnext).get(1);
							}
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							//clean(node);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
						else {
							Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
							nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
							if(Edgetimes.get(nextnext)==es(nextnext)) {
								traverse(nextNode);
							}
						}
					}
					else if(Edgetimes.get(next)>es(next) && ASTUnderConstruction.idToNode.containsKey(next)){
						Long nextnext = ASTUnderConstruction.idToNode.get(next).getFuncId()+2;
						nextNode = mergeNode(nextnext, ID2Node.get(next).intro, ID2Node.get(next).inter, ID2Node.get(next).caller);
						if(Edgetimes.get(nextnext)==es(nextnext)) {
							traverse(nextNode);
						}
					}
				}
			}
		}
		


		return taintFunc;
		
	}
	

	private Long isArg(Long src, Long stmt) {
		 ASTNode srcNode = null;
		 while(true) {
				//reach the stmt
				if(stmt==src) {
					return (long) -1;
				}
				if(!PHPCSVEdgeInterpreter.child2parent.containsKey(src)) {
					return (long) -1;
				}
				src = PHPCSVEdgeInterpreter.child2parent.get(src);
				srcNode = ASTUnderConstruction.idToNode.get(src);
				if(srcNode instanceof ArgumentList) {
					return src;
				}
				//check if the ast node is a CFG node
			}
	}

	private List<Long> handleFunc(List<Long> targetFuncs, Stack<Long> caller, Long astId) {
		System.out.println("Before handle: "+targetFuncs.size());
		Stack<Long> tmp = (Stack<Long>) caller.clone();
		tmp.add(astId);
		Set<String> keywords = new HashSet<String>();
		//get the words used in path
		for(Long c: tmp) {
			Long fileID = toTopLevelFile.getTopLevelId(c);
			String filename = ASTUnderConstruction.idToNode.get(fileID).getEscapedCodeStr();
			String[] words = filename.split("/");
			for(String word: words) {
				word = word.replace(".php", "");
				word = word.toLowerCase();
				word = word.replace("<", "");
				word = word.replace(">", "");
				keywords.add(word);
			}
		}
		
		LinkedList<Long> ret = new LinkedList<Long>();
		MultiHashMap<Integer, Long> map = new MultiHashMap<Integer, Long>();
		int max = -1;
		//get the similarity of path of each target function
		for(Long target: targetFuncs) {
			Long fileID = toTopLevelFile.getTopLevelId(target);
			String filename = ASTUnderConstruction.idToNode.get(fileID).getEscapedCodeStr();
			String[] targetwords = filename.split("/");
			Set<String> targetSet = new HashSet<String>();
			for(String word: targetwords) {
				word = word.replace(".php", "");
				word = word.toLowerCase();
				word = word.replace("<", "");
				word = word.replace(">", "");
				targetSet.add(word);
			}
			targetSet.retainAll(keywords);
			map.add(targetSet.size(), target);
			if(max<targetSet.size()) {
				max = targetSet.size();
			}
		}
		System.out.println("after handle: "+map.get(max).size()+" "+map.get(max));
		return map.get(max);
	}

	private boolean isUsed(Long next, Node context, Long caller) {
		ASTNode node = ASTUnderConstruction.idToNode.get(next);
		//we always step into functions
		if(node instanceof CallExpressionBase || (node instanceof AssignmentExpression && ((AssignmentExpression) node).getRight() instanceof CallExpressionBase)) {
			return true;
		}
		else {
			//the next statement does not use taint variable
			if(!dstProp.containsKey(next) && !dstGlobal.containsKey(next) && !dstGlobalVar.containsKey(next) && isrelated(next, context.intro, context.inter, caller).isEmpty()) {
				return false;
			}
			return true;
		}
	}

	//add inter taint to taint status if the stmt is tainted and the left value is inter variable
	/*
	 * param: node under-construct
	 */
	/** Producer-side sidecar for `inter`, mirroring the RelatedEvidence pattern one layer earlier.
	 *  `inter` (HashMap<String,Long>) is populated by plain put(identity, provenance) at three sites
	 *  inside addInter() -- confirmed via direct mutation tracing (§68.6) to silently overwrite
	 *  same-identity multi-source writes BEFORE any consumer (including the now-correct occurrence-
	 *  keyed Group-A model) ever runs. `inter` itself is NOT replaced -- still authoritative,
	 *  still passed everywhere unchanged. This sidecar preserves what would otherwise be lost. */
	private enum InterProducerKind { PROP, GLOBAL, GLOBAL_VAR }
	private static final class InterEvidence {
		final String identityNode; final long provenanceNode;      // minimum semantically necessary pair
		final Long occurrenceNode;                                  // the AST node written (dst) -- genuinely
																																						// available at the put() site, not reconstructed after
		final long callerContext; final InterProducerKind producerKind;
		InterEvidence(String identityNode, long provenanceNode, Long occurrenceNode,
				long callerContext, InterProducerKind producerKind) {
			this.identityNode=identityNode; this.provenanceNode=provenanceNode;
			this.occurrenceNode=occurrenceNode; this.callerContext=callerContext;
			this.producerKind=producerKind;
		}
	}
	// Keyed on the FULL tuple (identity+provenance+occurrence+caller), never on identity alone --
	// that full-key requirement is what a plain Map.put(identity,...) cannot provide, and is the
	// entire point of this sidecar existing.
	private static final java.util.LinkedHashMap<String,InterEvidence> interEvidenceSidecar =
		new java.util.LinkedHashMap<String,InterEvidence>();
	/** Enforces "valueExpressionId is a pure function of the state node (AST_ASSIGN)" as an
	 *  ACTIVE invariant, per the reviewer's hardening request -- not merely assumed because it
	 *  seemed true across 601 measured cases. First WRITE for a given stateNode establishes the
	 *  mapping; every later WRITE for the SAME stateNode must agree, or this fails loudly rather
	 *  than silently trusting whichever WRITE event liveProvenanceQuery's search happens to find
	 *  first. Also means liveProvenanceQuery no longer needs to search the whole mutation log --
	 *  this index is a direct O(1) lookup, and doing that lookup here also decouples "assert
	 *  consistency" from "search all events", the two concerns the reviewer flagged as conflated. */
	private static final java.util.HashMap<Long, Long> stateNodeToValueExpression =
		new java.util.HashMap<Long, Long>();
	private void recordInter(Map<String, Long> legacy, String identity, long provenance,
			Long occurrenceNode, long callerContext, InterProducerKind kind) {
		legacy.put(identity, provenance);   // UNCHANGED legacy behavior, still authoritative
		if(legacy instanceof Node.TracingInterMap) {
			// SEMANTIC vs STATE identity (reviewer's design): `provenance` here is the WRITE
			// STATEMENT's astId (the legacy inter value -- STATE identity, unchanged). Compute
			// the value-producing EXPRESSION separately, AT THE PRODUCER SITE where the AST
			// context is already available, rather than leaving a consumer to reconstruct it.
			Long valueExpressionId = null;
			ASTNode _stateNode = ASTUnderConstruction.idToNode.get(provenance);
			if(_stateNode instanceof AssignmentExpression) {
				Expression _rhs = ((AssignmentExpression) _stateNode).getRight();
				if(_rhs != null) valueExpressionId = _rhs.getNodeId();
			}
			if(valueExpressionId != null) {
				Long existing = stateNodeToValueExpression.get(provenance);
				if(existing == null) {
					stateNodeToValueExpression.put(provenance, valueExpressionId);
				} else if(!existing.equals(valueExpressionId)) {
					System.err.println("STATE_NODE_VALUE_EXPRESSION_INVARIANT_VIOLATION stateNode="+provenance
						+" existing_valueExpressionId="+existing+" new_valueExpressionId="+valueExpressionId
						+" -- pure-function assumption broken, using EXISTING mapping");
					valueExpressionId = existing;   // fail closed: keep the first-established mapping,
					                                  // don't let the map silently drift
				}
			}
			((Node.TracingInterMap) legacy).writeEvent(identity, provenance, valueExpressionId);
		}
		InterEvidence e = new InterEvidence(identity, provenance, occurrenceNode, callerContext, kind);
		String key = identity+"|"+provenance+"|"+occurrenceNode+"|"+callerContext+"|"+kind;
		interEvidenceSidecar.put(key, e);
		if(System.getenv("FALLBACK_DIAG")!=null)
			System.err.println("INTER_EVIDENCE identity="+identity+" provenance="+provenance
				+" occurrence="+occurrenceNode+" caller="+callerContext+" kind="+kind);
	}

	private Node addInter(Node node) {
		Long astId=node.astId;
		Long caller;
		if(node.caller.isEmpty()) {
			caller=(long) 0;
		}
		else {
			caller = node.caller.peek();
		}
		if(System.getenv("SG_PIPELINE_DIAG")!=null && astId != null)
			System.err.println("ADDINTER_CHECK astId="+astId
				+" dstProp="+dstProp.containsKey(astId)
				+" dstGlobal="+dstGlobal.containsKey(astId)
				+" dstGlobalVar="+dstGlobalVar.containsKey(astId));
		if(System.getenv("SG_PIPELINE_DIAG")!=null)
			System.err.println("ADDINTER_GUARD astId="+astId
				+" dstProp="+dstProp.containsKey(astId)
				+" dstGlobal="+dstGlobal.containsKey(astId)
				+" dstGlobalVar="+dstGlobalVar.containsKey(astId));
		if(!dstProp.containsKey(astId) && !dstGlobal.containsKey(astId) && !dstGlobalVar.containsKey(astId)) {
			return node;
		}
		Node ret = new Node(node);
		Node.TracingInterMap newInter = new Node.TracingInterMap(); newInter.copyFrom(ret.inter); 
		//the statement contains a dst prop
		if(dstProp.containsKey(astId)) {
			List<Long> dstExps = dstProp.get(astId);
			for(Long dst: dstExps) {
				ASTNode dstNode = ASTUnderConstruction.idToNode.get(dst);
				String identity = getPropIdentity(dstNode, caller);
				recordInter(newInter, identity, node.astId, dst, caller, InterProducerKind.PROP);
			}
		}
		//the statement contains a dst Global variable
		if(dstGlobal.containsKey(astId)) {
			List<Long> dstExps = dstGlobal.get(astId);
			for(Long dst: dstExps) {
				ASTNode dstNode = ASTUnderConstruction.idToNode.get(dst);
				String identity = getDIMIdentity(dstNode);
				recordInter(newInter, identity, node.astId, dst, caller, InterProducerKind.GLOBAL);
			}
		}
		//the statement contains a dst global-declared variable (`global $g; $g = ...`)
		if(dstGlobalVar.containsKey(astId)) {
			for(Long dst: dstGlobalVar.get(astId)) {
				String identity = getGlobalVarIdentity(ASTUnderConstruction.idToNode.get(dst));
				if(!identity.equals("-1")) recordInter(newInter, identity, node.astId, dst, caller, InterProducerKind.GLOBAL_VAR);
			}
		}
		ret.inter=newInter;
		return ret;
	}
	
	//add one node to the taint tree
	/*
	 * param: node1 and node2. Set node2 as the children of node1 
	 */
	private void addNode(Node node1, Node node2) {
		node1.children.add(node2);
	}

	//remove inter taints if they are assigned in unrelated statements 
	/*
	 * @param: unrelated statement, caller and inter set of previous node
	 * @return: a set of unrelated global variables and properties 
	 */
	private Set<String> RemoveInterTaint(Long stmt, Long caller, HashMap<String, Long> inter) {
		if(ID2Node.containsKey(caller)) {
			caller = ID2Node.get(caller).astId;
		}
		Set<String> ret = new HashSet<String>();
		//global variable is assigned
		if(dstGlobal.containsKey(stmt)) {
			//location of global expression
			List<Long> dstExps = dstGlobal.get(stmt);
			for(Long exp: dstExps) {
				ASTNode globalNode = ASTUnderConstruction.idToNode.get(exp);
				String globalName = getDIMIdentity(globalNode);
				for(String interTaint: inter.keySet()) {
					if(interTaint.startsWith(globalName) || globalName.startsWith(interTaint)) {
						//inter.remove(interTaint);
						ret.add(interTaint);
					}
				}
			}
		}
		//global-declared variable (`global $g; $g = ...`) is reassigned
		if(dstGlobalVar.containsKey(stmt)) {
			for(Long exp: dstGlobalVar.get(stmt)) {
				String gname = getGlobalVarIdentity(ASTUnderConstruction.idToNode.get(exp));
				if(gname.equals("-1")) continue;
				for(String interTaint: inter.keySet()) {
					if(interTaint.equals(gname)) ret.add(interTaint);
				}
			}
		}
		//global property is assigned
		if(dstProp.containsKey(stmt)) {
			//location of prop expression
			List<Long> dstExps = dstProp.get(stmt);
			for(Long exp: dstExps) {
				ASTNode propNode = ASTUnderConstruction.idToNode.get(exp);
				String propName = getPropIdentity(propNode, caller);
				for(String interTaint: inter.keySet()) {
					if(check(propName, interTaint)) {
						//inter.remove(interTaint);
						ret.add(interTaint);
					}
				}
			}
		}
		return ret;
	}

	/*
	 * @param: one statement
	 * @return: true if the statement is sanitized; otherwise false 
	 */
	private boolean isvalid(Long stmt) {
		if(sqlSanitizers.contains(stmt)) {
			return false;
		}
		return true;
	}

	// True if source dim `dim` is enclosed (within its statement) by a sanitizer call that
	// is still in the AST-node sanitizer set — i.e. the value is sanitized in place. Walks
	// up the parent chain. After context-sensitive demotion, an unquoted esc_sql call is no
	// longer in that set, so a dim it wraps is correctly judged unsanitized.
	// True if `dim` lies within the CONDITION subtree of a ternary (a ? b : c) whose two value
	// arms are both constant-literal-only. Such a source affects only which arm is selected
	// (control-dependence), never the resulting value, so it cannot carry SQL injection. Walks up
	// the AST; at each enclosing ternary, checks the child we ascended through is the condition
	// (not an arm) and that both arms are literal-only. Short ternary (a ?: c) never qualifies —
	// its condition IS the value when truthy.
	private boolean inLiteralTernaryCondition(Long dim) {
		Long cur = dim, prev = null;
		int guard = 0;
		while(cur != null && guard++ < 4096) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			if(n instanceof ast.expressions.ConditionalExpression) {
				ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
				Expression cond = ce.getCondition();
				Expression t = ce.getTrueExpression();
				if(t != null && cond != null && prev != null && prev.equals(cond.getNodeId())
						&& subtreeIsLiteralOnly(t) && subtreeIsLiteralOnly(ce.getFalseExpression())) {
					return true;
				}
			}
			prev = cur;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	// A source that sits in a FULL ternary's condition (cond ? A : B) is control-flow, not data-flow:
	// the value echoed is arm A or B, never the condition, so such a source never reaches output.
	// Unlike inLiteralTernaryCondition this does not require the arms to be literals (e.g.
	// `echo $tab==='x' ? $cls : ''` where $cls is a constant-bearing variable). Short ternary
	// `$a ?: $b` is excluded (getTrueExpression()==null), since there the condition IS the value.
	private boolean inTernaryCondition(Long node) {
		Long cur = node, prev = null;
		int guard = 0;
		while(cur != null && guard++ < 4096) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			if(n instanceof ast.expressions.ConditionalExpression) {
				ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
				Expression cond = ce.getCondition();
				Expression t = ce.getTrueExpression();
				if(t != null && cond != null && prev != null && prev.equals(cond.getNodeId())) return true;
			}
			prev = cur;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	// True if a subtree contains no taint-bearing nodes — no variables, array/property reads, or
	// calls — i.e. it evaluates to a compile-time-ish constant (string/number/const literal).
	private boolean subtreeIsLiteralOnly(ASTNode n) {
		if(n == null) return true;
		String ty = n.getProperty("type");
		if(ty != null && (ty.equals("AST_VAR") || ty.equals("AST_DIM") || ty.equals("AST_PROP")
				|| ty.equals("AST_CALL") || ty.equals("AST_METHOD_CALL") || ty.equals("AST_STATIC_CALL")
				|| ty.equals("AST_NULLSAFE_PROP") || ty.equals("AST_NULLSAFE_METHOD_CALL"))) {
			return false;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if(kids != null) for(Long c: kids.values()) {
			if(!subtreeIsLiteralOnly(ASTUnderConstruction.idToNode.get(c))) return false;
		}
		return true;
	}

	// match-expression analogue of inLiteralTernaryCondition. A `match` is an expression whose
	// value is the RESULT (=> expression) of the selected arm. Its subject and each arm's
	// case-conditions only select which arm — control-dependence. So a request source in the
	// subject (or in an arm's case-condition list) of a match whose every arm RESULT is a constant
	// literal carries no taint into the value. (switch is a statement, not an expression, and its
	// subject is already a separate node from the case-body assignments, so it needs no gate.)
	private boolean inLiteralMatchControl(Long src) {
		Long cur = src, prev = null;
		int guard = 0;
		while(cur != null && guard++ < 4096) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			String ty = (n == null) ? null : n.getProperty("type");
			if("AST_MATCH".equals(ty)) {
				HashMap<Integer,Long> k = PHPCSVEdgeInterpreter.parent2child.get(cur);
				Long subj = (k == null) ? null : k.get(0);   // child 0 = subject
				if(subj != null && subj.equals(prev) && allMatchArmsLiteralOnly(cur)) return true;
			}
			else if("AST_MATCH_ARM".equals(ty)) {
				HashMap<Integer,Long> k = PHPCSVEdgeInterpreter.parent2child.get(cur);
				Long condList = (k == null) ? null : k.get(0);   // child 0 = case-conditions, child 1 = result
				if(condList != null && condList.equals(prev)) {
					Long m = PHPCSVEdgeInterpreter.child2parent.get(cur);   // ARM -> ARM_LIST
					if(m != null) m = PHPCSVEdgeInterpreter.child2parent.get(m);   // ARM_LIST -> MATCH
					if(m != null && "AST_MATCH".equals(typeOfNode(m)) && allMatchArmsLiteralOnly(m)) return true;
				}
			}
			prev = cur;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	private String typeOfNode(Long id) {
		ASTNode n = ASTUnderConstruction.idToNode.get(id);
		return (n == null) ? null : n.getProperty("type");
	}

	// True if every arm of an AST_MATCH produces a constant-literal RESULT (=> expression), so the
	// match value is constant regardless of which arm is selected.
	private boolean allMatchArmsLiteralOnly(Long matchId) {
		HashMap<Integer,Long> mk = PHPCSVEdgeInterpreter.parent2child.get(matchId);
		Long armList = (mk == null) ? null : mk.get(1);   // child 1 = AST_MATCH_ARM_LIST
		if(armList == null) return false;
		HashMap<Integer,Long> arms = PHPCSVEdgeInterpreter.parent2child.get(armList);
		if(arms == null || arms.isEmpty()) return false;
		for(Long arm : arms.values()) {
			HashMap<Integer,Long> ak = PHPCSVEdgeInterpreter.parent2child.get(arm);
			Long result = (ak == null) ? null : ak.get(1);   // child 1 = arm result
			if(result == null || !subtreeIsLiteralOnly(ASTUnderConstruction.idToNode.get(result))) return false;
		}
		return true;
	}

	// Position-aware wrapper-sink filter. A wrapper call is a statement-level sink, so the default
	// dataflow flags any tainted argument anywhere in the call. But a wrapper that sanitizes a
	// parameter internally (e.g. esc_sql) makes that position safe: a tainted argument there cannot
	// inject. This suppresses the flag ONLY when (a) the call is a position-modeled wrapper call
	// (its risky-argument-node set was recorded) AND (b) none of the tainted nodes reaching the sink
	// falls within a risky-position argument subtree. Any uncertainty -> returns false (keep the
	// flag), so it can never introduce a false negative.
	private boolean wrapperPositionSuppressed(Long stmt, HashMap<Long, Long> related) {
		Set<Long> riskyArgs = PHPCGFactory.wrapperCallRiskyArgs.get(stmt);
		if(riskyArgs == null) {
			// stmt may be an assignment whose RHS is the wrapper call; try that call node.
			ASTNode sn = ASTUnderConstruction.idToNode.get(stmt);
			if(sn instanceof AssignmentExpression && ((AssignmentExpression)sn).getRight() instanceof CallExpressionBase) {
				riskyArgs = PHPCGFactory.wrapperCallRiskyArgs.get(((AssignmentExpression)sn).getRight().getNodeId());
			}
		}
		if(riskyArgs == null) return false;            // not a position-modeled wrapper call -> default
		if(riskyArgs.isEmpty()) return true;           // wrapper has NO risky position -> no arg can inject
		for(Long k : related.keySet()) {
			Long cur = k; int g = 0;
			while(cur != null && g++ < 4096) {
				if(riskyArgs.contains(cur)) return false;   // a tainted node sits at a risky position -> keep flag
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
		}
		return true;   // every tainted node is at a non-risky (internally-sanitized) position -> suppress
	}

	// True if any tainted node reaching the statement (a `related` key) lies within the subtree of
	// the given argument node — i.e. that argument carries taint (a direct source or a tainted local).
	private boolean argNodeTainted(Long argNode, HashMap<Long, Long> related) {
		if(argNode == null) return false;
		for(Long k : related.keySet()) {
			Long cur = k; int g = 0;
			while(cur != null && g++ < 4096) {
				if(cur.equals(argNode)) return true;
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
		}
		return false;
	}

	// Walk up the AST from `dim` to `stmt` checking if any ancestor is a sanitizer call
	// appropriate for the given sink class. For SQL sinks: sqlSanitizers (esc_sql, etc).
	// For XSS sinks: xssSanitizers (esc_html, esc_attr, sanitize_text_field, etc). This
	// replaces the original SQL-only check so shortcode/block-callback return sinks (tagged
	// "xss" in sinkClass) are judged against XSS sanitizers, not SQL ones — which caused
	// sanitize_text_field($_GET[...]) to be flagged as a false positive.
	private boolean inlineSanitized(Long dim, Long stmt, boolean xssClass) {
		Long cur = dim;
		int guard = 0;
		while(cur != null && !cur.equals(stmt) && guard++ < 4096) {
			if(xssClass ? PHPCSVEdgeInterpreter.xssSanitizers.contains(cur)
			            : PHPCSVEdgeInterpreter.sqlSanitizers.contains(cur)) {
				return true;
			}
			// Numeric CAST expressions: (int)/(float) coerce to a number, so the result cannot
			// contain HTML/JS metacharacters regardless of the operand -- safe for XSS-context
			// output. Deliberately narrow to TYPE_LONG/TYPE_DOUBLE only (string/array/object casts
			// do not neutralize anything). This is the THIRD sibling of this exact same check
			// (see sanitizedOnPath() and its own cast-recognition comment) -- this file has a
			// documented history (2026-08-08 fix above) of one inline-sanitizer walk getting an
			// escaper-recognition fix while its parallel sibling didn't, so this is applied to all
			// three inline-source mechanisms at once rather than repeating that pattern a third time.
			if(xssClass) {
				ASTNode castCheck = ASTUnderConstruction.idToNode.get(cur);
				if(castCheck instanceof CastExpression) {
					String flags = castCheck.getFlags();
					if("TYPE_LONG".equals(flags) || "TYPE_DOUBLE".equals(flags)) return true;
				}
			}
			// For XSS sinks: also credit input sanitizers that strip HTML/JS metacharacters.
			if(xssClass) {
				ASTNode cn = ASTUnderConstruction.idToNode.get(cur);
				if(cn instanceof CallExpressionBase) {
					String nm = inlineCallName((CallExpressionBase)cn);
					// FIX (2026-08-08): this sibling walk never called isXssOutputEscaper()
					// (the htmlEscapers family: esc_html/esc_attr/esc_url/wp_kses*/...), even
					// though the OTHER inline-sanitizer walk in this file (see the comment near
					// its own isXssOutputEscaper() call, ~line 888) was explicitly fixed for the
					// exact same gap, with a comment documenting it: "the inline path only
					// checked xssSanitizers while the reaching-def path credited htmlEscapers."
					// That fix was never applied here. Confirmed live FP:
					// printf(esc_attr($_GET['x'])) was reported as vulnerable in BOTH the
					// nested-in-assignment case AND the plain top-level case (xssClassSink
					// correctly true in the latter) -- proving this gap, not the sink/statement
					// ID mismatch, is what actually suppressed the escaper credit.
					if(nm != null && cg.PHPCGFactory.isXssOutputEscaper(nm))
						return true;
					if(nm != null && PHPCSVEdgeInterpreter.xssInputSanitizers.contains(nm))
						return true;
					// preg_replace with character-stripping pattern (removes < and >)
					if("preg_replace".equals(nm)
						&& cg.PHPCGFactory.isPregReplaceXssSanitizerPublic((CallExpressionBase)cn))
						return true;
					// wp_kses($x, array()) — empty allowlist strips all tags unconditionally
					if("wp_kses".equals(nm) && isEmptyArrayArg((CallExpressionBase)cn, 1))
						return true;
				}
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	// True if the tainted variable flowing into the sink is fully wrapped by an XSS escaper
	// or input sanitizer everywhere it appears in the sink's AST subtree.
	// Handles the alias pattern: $order = $_GET['order']; echo esc_attr($order);
	//
	// Only returns true if the variable NAME is actually found in the sink subtree
	// AND every occurrence is inside an escaper. Returns false conservatively if the
	// variable is not found (different mechanism carries taint — e.g. inline DIM).
	private boolean taintVarEscapedInSink(Long taintKey, Long introId, Long sinkNode) {
		// Strategy 1: taintKey is a Variable node (call-arg sinks)
		ASTNode tkNode = ASTUnderConstruction.idToNode.get(taintKey);
		if(tkNode instanceof Variable) {
			ast.expressions.Expression ne = ((Variable)tkNode).getNameExpression();
			if(ne != null) {
				String nm = ne.getEscapedCodeStr();
				if(nm != null) {
					boolean[] found = {false};
					boolean allSafe = varEscapedInSubtreeTracked(nm, sinkNode, false, 20, found);
					return found[0] && allSafe;
				}
			}
		}

		// Strategy 2: use the DDG edge tag to recover the variable name.
		// DDG.rels maps (assignStmt → Pair<useStmt, varName>). Walk edges from the
		// intro statement and check if any variable name appears (escaped) in the sink.
		// Only apply to proper assignment statements to avoid suppressing direct-source paths.
		if(introId != null) {
			Node introNode = ID2Node.get(introId);
			Long introStmt = (introNode != null) ? introNode.astId : null;
			if(introStmt != null) {
				// Only activate for plain assignment intros — not function calls or source stmts
				ASTNode introAst = ASTUnderConstruction.idToNode.get(introStmt);
				boolean isAssign = introAst instanceof AssignmentExpression;
				if(isAssign && ddg.DataDependenceGraph.DDG.rels.containsKey(introStmt)) {
					for(misc.Pair<Long, String> edge : ddg.DataDependenceGraph.DDG.rels.get(introStmt)) {
						String varName = edge.getR();
						if(varName == null || varName.isEmpty()) continue;
						boolean[] found = {false};
						boolean allSafe = varEscapedInSubtreeTracked(varName, sinkNode, false, 20, found);
						// Only suppress if the variable was actually found AND is safely wrapped
						if(found[0] && allSafe) return true;
						// If variable found but not safe, definitely don't suppress
						if(found[0] && !allSafe) return false;
						// Variable not found in sink → don't credit (another taint path, e.g. DIM)
					}
				}
			}
		}

		return false; // conservative: don't suppress
	}

	// Like varEscapedInSubtree but also sets found[0]=true when the variable is encountered.
	// Returns true if all occurrences of varName are inside an escaper, false otherwise.
	// Sets found[0] to true on first encounter of the variable.
	private boolean varEscapedInSubtreeTracked(String varName, Long nodeId, boolean inEscaper, int depth, boolean[] found) {
		if(nodeId == null || depth < 0) return true;
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		if(n == null) return true;
		if(n instanceof Variable) {
			ast.expressions.Expression ne = ((Variable)n).getNameExpression();
			String name = (ne != null) ? ne.getEscapedCodeStr() : null;
			if(varName.equals(name)) {
				found[0] = true;
				return inEscaper;   // safe only if already inside an escaper
			}
			return true;  // different variable — not the one we're tracking
		}
		boolean nowInEscaper = inEscaper;
		if(n instanceof CallExpressionBase) {
			String nm = inlineCallName((CallExpressionBase)n);
			// Credit as escaper only if it's a context-adequate XSS OUTPUT escaper.
			// Input sanitizers (json_encode, sanitize_text_field, strip_tags, etc.) are NOT
			// credited here because they don't guarantee XSS safety at output in all contexts:
			// json_encode inside die() or echo can still be reflected XSS; strip_tags leaves
			// JS in event attributes; etc. Only full HTML output escapers (esc_html, esc_attr,
			// esc_url, esc_js, wp_kses*) that are context-adequate suppress the finding.
			boolean adequate = cg.PHPCGFactory.isXssOutputEscaperPublic(nm)
				&& !cg.PHPCGFactory.xssInadequateEscaperNodes.contains(n.getNodeId());
			if(adequate) nowInEscaper = true;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nodeId);
		if(kids == null) return true;
		for(Long child : kids.values()) {
			if(!varEscapedInSubtreeTracked(varName, child, nowInEscaper, depth-1, found)) return false;
		}
		return true;
	}

	// Recursively check if variable `varName` appears in the subtree of `nodeId`
	// and is always wrapped in an XSS escaper/sanitizer call (inEscaper=true when we've
	// already crossed into an escaper's arg list).
	private boolean varEscapedInSubtree(String varName, Long nodeId, boolean inEscaper, int depth) {
		if(nodeId == null || depth < 0) return true;  // no variable found in this subtree → safe
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		if(n == null) return true;
		// Found the variable: is it inside an escaper?
		if(n instanceof Variable) {
			ast.expressions.Expression ne = ((Variable)n).getNameExpression();
			String name = (ne != null) ? ne.getEscapedCodeStr() : null;
			if(varName.equals(name)) return inEscaper;
		}
		// Check if this node is an escaper/sanitizer call — its children are "inside escaper"
		boolean nowInEscaper = inEscaper;
		if(n instanceof CallExpressionBase) {
			String nm = inlineCallName((CallExpressionBase)n);
			if(cg.PHPCGFactory.isXssOutputEscaperPublic(nm)
				|| PHPCSVEdgeInterpreter.xssInputSanitizers.contains(nm)
				|| PHPCSVEdgeInterpreter.xssSanitizers.contains(nm)) {
				nowInEscaper = true;
			}
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nodeId);
		if(kids == null) return true;
		for(Long child : kids.values()) {
			if(!varEscapedInSubtree(varName, child, nowInEscaper, depth-1)) return false;
		}
		return true;
	}
	// the AST that passes through an AST_ARG_LIST → call boundary. Returns true if the dim
	// is "inside" a function call argument (not directly in the output position), meaning its
	// value flows through an opaque function boundary before reaching the sink.
	// Used to suppress false positives for XSS return-sinks where the superglobal is passed
	// as an argument to a function whose return is what the sink actually outputs.
	private boolean dimReachableViaCallArg(Long startNode, Long target, int depth) {
		if(startNode == null || depth > 20) return false;
		if(startNode.equals(target)) return false;   // reached without crossing a call arg
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(startNode);
		if(kids == null) return false;
		ASTNode sn = ASTUnderConstruction.idToNode.get(startNode);
		boolean inArgList = sn != null && "AST_ARG_LIST".equals(sn.getProperty("type"));
		for(Long child : kids.values()) {
			if(child == null) continue;
			if(child.equals(target)) {
				return inArgList;   // found target: safe only if directly under an arg list
			}
			// Check descendants: if target is under this child, check if this child is an
			// arg-list child of a call (meaning there's a call boundary before target)
			if(inArgList) {
				// Already inside an arg list — target under any descendant is "inside call arg"
				if(containsNode(child, target, 15)) return true;
			} else {
				if(dimReachableViaCallArg(child, target, depth+1)) return true;
			}
		}
		return false;
	}

	private boolean containsNode(Long root, Long target, int depth) {
		if(root == null || depth < 0) return false;
		if(root.equals(target)) return true;
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(root);
		if(kids == null) return false;
		for(Long child : kids.values()) if(containsNode(child, target, depth-1)) return true;
		return false;
	}

	// For an XSS-class return-sink, returns true if the dim source is not directly in the
	// return's output position — i.e. it's buried inside a call argument, so what the sink
	// outputs is the *function's return value*, not the dim value itself.
	private boolean xssDimInsideCallArg(Long returnStmt, Long dim) {
		// Get the return expression (child 0 of the return node)
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(returnStmt);
		if(kids == null) return false;
		Long expr = kids.get(0);
		if(expr == null) return false;
		return dimReachableViaCallArg(expr, dim, 0);
	}

	// True if `srcNode` (a superglobal dim access) is buried inside an argument to a function
	// call that is itself part of `returnStmt`. In that case the function's return value —
	// not the source — is what the sink outputs; the dataflow engine handles that separately
	// via retArbitraryFids. Flagging here is a false positive because the source value does
	// not directly appear in the output — it flows through an opaque function boundary first.
	private boolean sourceIsInsideCallArgOf(Long srcNode, Long returnStmt) {
		return xssDimInsideCallArg(returnStmt, srcNode);
	}

	// True if `stmt` contains at least one superglobal source used inline that is not
	// covered by an in-place sanitizer call (per-source, not per-statement). Only request
	// superglobals (srcDim: $_GET/$_POST/...) count as user input here; $GLOBALS[...] reads
	// are ordinary global-variable accesses (e.g. $GLOBALS['wpdb']), NOT user input, so they
	// are deliberately excluded — global taint, if any, is tracked by the global dataflow.
	// For XSS-class sinks (shortcode/block return-sinks): additionally skip sources that are
	// buried inside a call-argument position — those flow through an opaque function and the
	// function's return value is what the sink outputs, not the raw source value. Also skip
	// sources in a ternary CONDITION (e.g. the isset($_GET[...]) check in a ternary) since
	// those only select which value arm is chosen, never propagate directly to the output.
	private boolean hasUnsanitizedInlineSource(Long stmt, boolean xssClass) {
		java.util.List<Long> dims = new java.util.ArrayList<Long>();
		if(srcDim.containsKey(stmt)) dims.addAll(srcDim.get(stmt));
		for(Long dim: dims) {
			if(xssClass && inTernaryCondition(dim)) continue;
			if(xssClass && sourceIsInsideCallArgOf(dim, stmt)) continue;
			if(!inlineSanitized(dim, stmt, xssClass)) return true;
		}
		return false;
	}
	
	/*
	 * @param: the statement ID, the intro set and inter set of previous node, and caller
	 * check if the statement is tainted under the given context
	 * @@return: the taint variable in stmts and and its corresponding related statements  
	 */

	/** First-class relation record, replacing the lossy `Map<Long,Long>` for the ARGUMENT_MATCH
	 *  path specifically. `isrelated()` keeps its original Map<Long,Long> return type unchanged —
	 *  a full 6-branch migration risks destabilizing existing consumers of that map (line 1939's
	 *  keySet()/get() usage spans hundreds of lines) — this covers the branch the gates test.
	 *  NOT YET migrated: DIMENSION_MATCH, SOURCE_PROPERTY_MATCH, CLASS_RETURN_MATCH,
	 *  SOURCE_GLOBAL_MATCH, DECLARED_GLOBAL_MATCH. Those remain on the original lossy map. */
	/** Candidate identity for the fallback redesign. Domain distinguishes provenance origin:
	 *  INTRO (from the outer `for(nodeID: intro)` loop -- ARGUMENT_MATCH, DIMENSION_MATCH,
	 *  ASSIGNMENT_MATCH, ECHO_MATCH, EXIT_MATCH) vs INTER (from `inter.get(interTaint)` directly --
	 *  SOURCE_PROPERTY_MATCH, CLASS_RETURN_MATCH, SOURCE_GLOBAL_MATCH, DECLARED_GLOBAL_MATCH). Do
	 *  not invent more domains until a migrated branch actually needs one. */
	// INTER_OCCURRENCE added per the §65 inventory: the FALLBACK candidate for Group A INTER
	// branches (SOURCE_PROPERTY_MATCH, SOURCE_GLOBAL_MATCH, DECLARED_GLOBAL_MATCH) is the OUTER,
	// statement-filtered occurrence (propId/globalId/gid) -- NOT the same object as the INTER
	// domain used for RelatedEvidence provenance (inter.get(interTaint), the origin). Keeping these
	// as separate enum values prevents re-conflating candidate identity with provenance identity,
	// the exact mistake Phase 1 made for INTER before this inventory.
	private enum CandidateDomain { INTRO, INTER, INTER_OCCURRENCE }
	private static final class CandidateKey {
		final long provenanceNode, callerContext; final CandidateDomain domain;
		CandidateKey(long provenanceNode, long callerContext, CandidateDomain domain) {
			this.provenanceNode=provenanceNode; this.callerContext=callerContext; this.domain=domain;
		}
		@Override public boolean equals(Object o) {
			if(!(o instanceof CandidateKey)) return false;
			CandidateKey k = (CandidateKey)o;
			return provenanceNode==k.provenanceNode && callerContext==k.callerContext && domain==k.domain;
		}
		@Override public int hashCode() { return java.util.Objects.hash(provenanceNode, callerContext, domain); }
		@Override public String toString() { return provenanceNode+"|"+callerContext+"|"+domain; }
	}
	/** Sidecar emission AND candidate-match marking in one call, so a migrated branch cannot update
	 *  one without the other (the exact sync gap the review warned against). `specificallyMatched`
	 *  is INVOCATION-LOCAL (passed in, not static) -- a match at one isrelated() call must never
	 *  suppress fallback for the same provenance examined by a different sink/statement. */
	private void recordSpecificRelation(CandidateKey candidate, RelatedEvidence evidence,
			Set<CandidateKey> specificallyMatched, long stmt) {
		relatedEvidenceSidecar.put(stmt+"|"+evidence.key(), evidence);
		specificallyMatched.add(candidate);
		if(System.getenv("FALLBACK_DIAG")!=null)
			System.err.println("SPECIFIC_CANDIDATE_MATCH stmt="+stmt+" provenanceNode="+candidate.provenanceNode
				+" callerContext="+candidate.callerContext+" domain="+candidate.domain
				+" relationKind="+evidence.relationKind);
	}
	/** Phase 2 SHADOW fallback sidecar. NOT consumed by anything yet -- legacy `relatedNodes.
	 *  isEmpty()` remains the sole production/BRANCH_DIAG-visible fallback definition. This exists
	 *  to prove the candidate-aware decision produces the correct, order-invariant result BEFORE it
	 *  is trusted for anything. Keyed by stmt+candidate so multiple candidates at one stmt never
	 *  collide (the exact defect §59 demonstrated in the legacy shared-isEmpty() check). */
	private static final java.util.LinkedHashMap<String,RelatedEvidence> shadowFallbackSidecar =
		new java.util.LinkedHashMap<String,RelatedEvidence>();
	private void recordShadowFallback(CandidateKey candidate, long stmt) {
		RelatedEvidence e = new RelatedEvidence(stmt, candidate.provenanceNode, candidate.callerContext,
			"SINK_LEVEL_FALLBACK", null, "SINK_LEVEL_FALLBACK");
		shadowFallbackSidecar.put(stmt+"|"+candidate.toString(), e);
		if(System.getenv("FALLBACK_DIAG")!=null)
			System.err.println("SHADOW_FALLBACK stmt="+stmt+" provenanceNode="+candidate.provenanceNode
				+" callerContext="+candidate.callerContext+" domain="+candidate.domain);
	}
	private static void logFallbackCandidate(long stmt, CandidateKey candidate, int relatedNodesSize) {
		if(System.getenv("FALLBACK_DIAG")==null) return;
		System.err.println("FALLBACK_CANDIDATE stmt="+stmt+" provenanceNode="+candidate.provenanceNode
			+" callerContext="+candidate.callerContext+" domain="+candidate.domain+" relatedNodesSize="+relatedNodesSize);
	}

	public static final class RelatedEvidence {
		public final Long relatedNode, introNode, callerContext; public final String relationKind;
		public final Integer sinkArgumentIndex; public final String identityPrecision;
		RelatedEvidence(Long relatedNode, Long introNode, Long callerContext, String kind, Integer argIdx, String precision) {
			this.relatedNode=relatedNode; this.introNode=introNode; this.callerContext=callerContext;
			this.relationKind=kind; this.sinkArgumentIndex=argIdx; this.identityPrecision=precision;
		}
		// dedupe on the COMPLETE tuple INCLUDING callerContext -- one (stmt,related,intro) pair
		// reached under three distinct callers on real `members` code (37441/37447) collapsed to a
		// single sidecar entry until this field was added. Route identity must survive to TAINTVAR.
		String key() { return relatedNode+"|"+introNode+"|"+callerContext+"|"+relationKind+"|"+sinkArgumentIndex; }
	}
	/** Sidecar keyed by stmt+tuple, filled at the EXACT legacy mutation sites (same invocation as
	 *  `related`). Only ARGUMENT_MATCH populates it so far -- other branches must be added the
	 *  same way, beside their own legacy relatedNodes.put() calls, before fallback can be trusted. */
	public static final java.util.LinkedHashMap<String,RelatedEvidence> relatedEvidenceSidecar =
		new java.util.LinkedHashMap<String,RelatedEvidence>();
	static {
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			if(System.getenv("INTER_TRACE_DIAG")!=null) Node.dumpUntracedSummary();
			if(System.getenv("INTER_TRACE_DIAG")!=null) Node.dumpMutationTotal();
			if(System.getenv("SIDECAR_DIAG")==null) return;
			for(java.util.Map.Entry<String,RelatedEvidence> en : relatedEvidenceSidecar.entrySet()) {
				RelatedEvidence e = en.getValue();
				String stmt0 = en.getKey().split("\\|")[0];
				System.err.println("SIDECAR kind="+e.relationKind+" stmt="+stmt0+" relatedNode="+e.relatedNode
					+" introNode="+e.introNode+" caller="+e.callerContext+" argIdx="+e.sinkArgumentIndex);
			}
		}));
	}

	/** ARGUMENT_MATCH-only companion to isrelated(), with the two confirmed defects fixed:
	 *  (1) per-intro fallback flag, so [unmatched,specific] and [specific,unmatched] give the
	 *      SAME evidence set regardless of iteration order (old: shared-map isEmpty() check made
	 *      fallback presence order-dependent);
	 *  (2) a LIST keyed on the full tuple, so two intro entries resolving to the SAME argument
	 *      produce TWO records instead of one overwriting the other. */
	private java.util.LinkedHashMap<String,RelatedEvidence> isrelatedEvidence(
			Long stmt, Set<Long> intro, Long caller) {
		java.util.LinkedHashMap<String,RelatedEvidence> evidence = new java.util.LinkedHashMap<String,RelatedEvidence>();
		if(ID2Node.containsKey(caller)) caller = ID2Node.get(caller).astId;
		ASTNode stmtnode0 = ASTUnderConstruction.idToNode.get(caller);
		if(stmtnode0 instanceof AssignmentExpression && ((AssignmentExpression) stmtnode0).getRight() instanceof CallExpressionBase)
			caller = ((CallExpressionBase)((AssignmentExpression) stmtnode0).getRight()).getNodeId();
		ASTNode stmtNode1 = ASTUnderConstruction.idToNode.get(caller);
		if(!(stmtNode1 instanceof CallExpressionBase)) caller = 0L;

		for(Long nodeID : intro) {
			boolean matchedForThisIntro = false;   // PER-ITERATION flag -- fixes order dependence
			Node introNode = ID2Node.get(nodeID);
			if(introNode == null) continue;
			Long taint = introNode.astId;
			if(taint > stmt) continue;   // no loop support, same as isrelated()
			if(DDG.rels.containsKey(taint)) {
				for(Pair<Long,String> tmp : DDG.rels.get(taint)) {
					if(!tmp.getL().equals(stmt)) continue;
					ASTNode taintNode = ASTUnderConstruction.idToNode.get(taint);
					if(taintNode == null) continue;
					boolean isAssign = taintNode.getProperty("type").equals("AST_ASSIGN")
						|| taintNode.getProperty("type").equals("AST_ASSIGN_OP")
						|| taintNode.getProperty("type").equals("AST_ASSIGN_REF");
					if(!isAssign) continue;
					ASTNode leftValue = ((AssignmentExpression) taintNode).getLeft();
					if(leftValue.getProperty("type").equals("AST_DIM")) continue;   // DIMENSION_MATCH not migrated
					ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
					if(!(stmtNode instanceof CallExpressionBase)) continue;
					String tag = tmp.getR();
					ArgumentList args = ((CallExpressionBase) stmtNode).getArgumentList();
					for(int i=0; i<args.size(); i++) {
						ASTNode arg = args.getArgument(i);
						if(arg instanceof Variable && ((Variable) arg).getNameExpression() != null
								&& tag.equals(((Variable) arg).getNameExpression().getEscapedCodeStr())) {
							RelatedEvidence e = new RelatedEvidence(arg.getNodeId(), nodeID, caller,
								"ARGUMENT_MATCH", i, "VALUE_SPECIFIC");
							evidence.put(e.key(), e);   // full-tuple key -- no overwrite
							matchedForThisIntro = true;
						}
					}
				}
			}
			if(!matchedForThisIntro) {
				RelatedEvidence e = new RelatedEvidence(stmt, nodeID, caller, "SINK_LEVEL_FALLBACK", null, "SINK_LEVEL_FALLBACK");
				evidence.put(e.key(), e);
			}
		}
		return evidence;
	}

	/** Diagnostic-only DAG walk: recovers all TERMINAL WRITE events reachable from a map's current
	 *  state-event-id, following TRANSFER edges back through their parent state at COPY TIME
	 *  (snapshot semantics -- a later write to a source map after it was copied from is correctly
	 *  NOT included, since the TRANSFER event's parent is the source's state-id AT THE MOMENT of
	 *  copyFrom(), not a live reference to the source map's current state). */
	/** STATE_SYNC_GATE: reconstructs the DAG's notion of "current value" for every key in a live
	 *  map (most-recent WRITE or MERGE_OVERWRITE event reaching that key, by eventId order among
	 *  events reachable in this map's own ancestry) and compares against the ACTUAL live value.
	 *  Zero mismatches required before ancestry can be trusted as provenance semantics. */
	/** The actual live-provenance query, per the reviewer's reframed question: "starting from the
	 *  live state at this consumer, what semantic write(s) remain live after following the
	 *  state-event semantics" -- NOT "how many producers anywhere share this identity" (the old,
	 *  wrong question that caused fixture 4's original misinterpretation). Returns key -> single
	 *  live producer (most-recent WRITE/MERGE_OVERWRITE reachable), exactly what stateSyncGate
	 *  already validated against the legacy live map. Also returns the FULL historical observation
	 *  set per key (every producer ever reachable in ancestry, live or superseded) so overwrite
	 *  semantics are directly checkable, not just asserted. */
	/** LIVE_VALUE_PROVENANCE -- diagnostic-only evidence type per the reviewer's staged migration
	 *  plan. Makes the narrow, honest claim liveProvenanceQuery() actually supports:
	 *  "at this consumer/caller/key, this tracked node corresponds to the value CURRENTLY
	 *  represented by legacy inter" -- NOT a source claim, NOT an ultimate-origin claim.
	 *  historicalProvenanceNodes are explanatory/debugging only and must NEVER be emitted as
	 *  separate vulnerability sources -- exactly the flat-sidecar overstatement this whole
	 *  investigation exists to avoid repeating.
	 *  cardinalityModel is stated explicitly rather than implied: the underlying live `inter` is
	 *  Map<String,Long>, structurally single-valued per key. This proves "one live inter value ->
	 *  one reconstructed live provenance node" -- it does NOT prove a richer abstract state
	 *  couldn't legitimately hold multiple simultaneous live values. Declaring this honestly
	 *  prevents an implicit, unearned multiplicity promise. */
	public static final class LiveValueProvenance {
		public final long stmt; public final String interKey; public final long callerContext;
		public final long liveProvenanceNode; public final java.util.Set<Long> historicalProvenanceNodes;
		public final int historicalCount, supersededCount;
		public final String stateSemantics = "LIVE_VALUE";
		public final String evidenceRole = "VALUE_FLOW";
		public final String cardinalityModel = "SINGLE_LIVE_VALUE";
		LiveValueProvenance(long stmt, String interKey, long callerContext, long liveProvenanceNode,
				java.util.Set<Long> historicalProvenanceNodes) {
			this.stmt=stmt; this.interKey=interKey; this.callerContext=callerContext;
			this.liveProvenanceNode=liveProvenanceNode; this.historicalProvenanceNodes=historicalProvenanceNodes;
			this.historicalCount = historicalProvenanceNodes==null ? 0 : historicalProvenanceNodes.size();
			this.supersededCount = Math.max(0, this.historicalCount - 1);
		}
	}
	// Diagnostic sidecar -- populate-only, NOT consumed by production TAINTVAR/relatedEvidenceSidecar/
	// INTEREVIDENCE_EXPANSION. Per the reviewer's staged plan: freeze shadow implementation, add
	// this representation, inspect cardinality across the corpus, only THEN consider narrow enablement.
	public static final java.util.LinkedHashMap<String, LiveValueProvenance> liveValueProvenanceSidecar =
		new java.util.LinkedHashMap<String, LiveValueProvenance>();

	/** Classifies what a liveProvenanceNode AST node ACTUALLY IS, per the reviewer's instruction:
	 *  inspect real AST/producer semantics already instrumented elsewhere in this engine, not
	 *  output shape. liveProvenanceNode is always a WRITE STATEMENT's astId (from recordInter()'s
	 *  call sites in addInter() -- an AssignmentExpression, typically). Classifies by inspecting
	 *  that statement's RHS. Uses PHPCSVEdgeInterpreter.sources -- the engine's OWN existing,
	 *  already-trusted request-source determination -- rather than reimplementing source detection. */
	/** Subdivides CALL_RESULT per the reviewer's exact categories, using the engine's OWN
	 *  call-resolution structure (PHPCGFactory.call2mtd, already used throughout this engine for
	 *  real call-graph decisions -- e.g. the zero-argument-call relevance gate, §57) -- NOT
	 *  function-name heuristics. A node being CALL_RESULT only says the live value came from a
	 *  call's return; it does NOT establish the source is inside that callee (per the reviewer's
	 *  identity()/wp_unslash()/get_option() distinction) -- this classifier stops at dispatch
	 *  SHAPE, deliberately not attempting to resolve further. */
	private String classifyCallDispatch(CallExpressionBase call) {
		boolean isMethod = (call instanceof MethodCallExpression) || (call instanceof StaticCallExpression);
		java.util.List<Long> targets = PHPCGFactory.call2mtd.get(call.getNodeId());
		if(targets == null || targets.isEmpty()) {
			return splitUnresolvedCall(call, isMethod);
		}
		boolean multi = targets.size() >= 2;
		if(isMethod) return multi ? "METHOD_MULTI_TARGET" : "METHOD_SINGLE_TARGET";
		return multi ? "DIRECT_FIRST_PARTY_MULTI_TARGET" : "DIRECT_FIRST_PARTY_SINGLE_TARGET";
	}
	/** Lazily-built, genuine exhaustive registry of every first-party function/method NAME defined
	 *  anywhere in this codebase (scans all FunctionDef nodes once) -- NOT a name heuristic on any
	 *  single call. Membership answers a real structural question: does a user-defined function
	 *  with this exact name exist ANYWHERE, regardless of whether call2mtd managed to resolve
	 *  THIS specific call site to it. */
	private java.util.Set<String> firstPartyFunctionNames = null;
	private java.util.Set<String> getFirstPartyFunctionNames() {
		if(firstPartyFunctionNames != null) return firstPartyFunctionNames;
		firstPartyFunctionNames = new java.util.HashSet<String>();
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(n instanceof FunctionDef) {
				String nm = ((FunctionDef) n).getName();
				if(nm != null) firstPartyFunctionNames.add(nm);
			}
		}
		return firstPartyFunctionNames;
	}
	/** Splits the former monolithic BUILTIN_OR_UNRESOLVED_TARGET/METHOD_UNRESOLVED_TARGET bucket,
	 *  per the reviewer's exact categories -- using real call-target-expression inspection and the
	 *  first-party name registry above, not function-name string matching against a hardcoded
	 *  builtin list. */
	/** Classifies the RETURN SHAPE of a single-target call's callee -- per the reviewer's exact
	 *  categories, using the callee's actual ReturnStatement structure (real AST inspection, not
	 *  inference from the call site). A function can have multiple return statements with
	 *  DIFFERENT shapes -- that's reported honestly as MULTIPLE_RETURN_SHAPES rather than picking
	 *  one arbitrarily, per the same "don't guess, report the ambiguity" discipline used
	 *  throughout this investigation (e.g. \u00a758's ambiguity guard). */
	/** Classifies WHICH sources.add() producer mechanism admitted a given node, per the reviewer's
	 *  exact categories -- using the REAL distinguishing markers that exist in the codebase
	 *  (sourceProducerRule, hookParamSourceNodes), not invented finer categories the engine
	 *  doesn't actually track. Only 2 markers exist that can be checked directly; anything else
	 *  admitted to `sources` without either marker is honestly reported as
	 *  OTHER_SOURCE_REGISTRY_ADMISSION rather than guessed at. */
	private String classifySourceAdmission(long nodeId) {
		if(PHPCSVEdgeInterpreter.RULE_REQUEST_SUPERGLOBAL.equals(PHPCSVEdgeInterpreter.sourceProducerRule.get(nodeId)))
			return "HANDLE_VARIABLE_CANONICAL";
		if("REST_ARRAY_ACCESS".equals(PHPCSVEdgeInterpreter.sourceProducerRule.get(nodeId)))
			return "REST_ARRAY_ACCESS";
		if(PHPCGFactory.hookParamSourceNodes.contains(nodeId))
			return "HOOK_PARAM_SEED";
		return "OTHER_SOURCE_REGISTRY_ADMISSION";
	}
	/** For an AST_DIM node (e.g. $_POST['x']), walks DOWN through ArrayIndexing.getArrayExpression()
	 *  to find the base node the array-access chain is rooted in -- since sources/sourceChannel/
	 *  sourceProducerRule are all keyed on that BASE, never on the DIM itself (confirmed §111). */
	private Long findBaseOfArrayAccess(Long nodeId) {
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		int guard = 0;
		while(n instanceof ArrayIndexing && guard++ < 16) {
			Expression base = ((ArrayIndexing) n).getArrayExpression();
			if(base == null) return nodeId;
			nodeId = base.getNodeId();
			n = ASTUnderConstruction.idToNode.get(nodeId);
		}
		return nodeId;
	}
	/** For a candidate node (a REQUEST_SOURCE_CANDIDATE/RETURN_REQUEST_SOURCE_CANDIDATE's value
	 *  expression), determines source-admission mechanism AND, if HANDLE_VARIABLE_CANONICAL,
	 *  attempts genuine normalization via resolveRequestAccess on the correct BASE node -- per
	 *  the reviewer's exact design. Everything else stays TAINT_SOURCE_CANDIDATE, not
	 *  REQUEST_SOURCE_CANDIDATE, until its own semantics are independently established. */
	private String classifyAndNormalizeCandidate(long candidateNodeId) {
		// FIXED: different admission mechanisms tag different levels -- HANDLE_VARIABLE_CANONICAL
		// tags the BASE Variable, but REST_ARRAY_ACCESS (found via producer trace, this session)
		// tags the AST_DIM node itself. Check the candidate node directly first, THEN its base.
		String directAdmission = classifySourceAdmission(candidateNodeId);
		Long base = findBaseOfArrayAccess(candidateNodeId);
		String baseAdmission = classifySourceAdmission(base);
		String admission = !"OTHER_SOURCE_REGISTRY_ADMISSION".equals(directAdmission) ? directAdmission : baseAdmission;
		if("REST_ARRAY_ACCESS".equals(admission)) {
			// No existing normalizer for WP_REST_Request array access (resolveRequestAccess was
			// built for superglobal channel/key_path semantics specifically) -- report the
			// admission honestly without claiming a normalized result that doesn't exist.
			return "admission="+admission+" label=TAINT_SOURCE_CANDIDATE normalized=NO_NORMALIZER_FOR_THIS_MECHANISM";
		}
		if(!"HANDLE_VARIABLE_CANONICAL".equals(admission))
			return "admission="+admission+" label=TAINT_SOURCE_CANDIDATE";
		String[] acc = PHPCGFactory.resolveRequestAccess(base);
		if(acc == null) return "admission="+admission+" label=TAINT_SOURCE_CANDIDATE normalized=NONE_despite_canonical_admission";
		return "admission="+admission+" label=REQUEST_SOURCE_VALIDATED"
			+" channel="+acc[0]+" key_path="+acc[1]+" precision="+acc[2];
	}

	/** Finds the ACTUAL single return-expression node for a function with exactly one return
	 *  shape (companion to classifyReturnShape, which only reports the shape string) -- needed to
	 *  follow a RETURN_CALL_RESULT chain further. Returns null if zero or multiple returns. */
	private Expression findSingleReturnExpression(long funcId) {
		Expression found = null;
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof ReturnStatement)) continue;
			ReturnStatement rs = (ReturnStatement) n;
			if(rs.getFuncId() == null || !rs.getFuncId().equals(funcId)) continue;
			if(found != null) return null;   // multiple returns -- ambiguous, don't guess which
			found = rs.getReturnExpression();
		}
		return found;
	}
	/** Measures chain depth for a single-target CALL_RESULT node, per the reviewer's exact stop
	 *  conditions -- does NOT assume recursion is needed; measures how far one-hop resolution
	 *  actually needs to go before hitting a terminal shape, a cycle, or a dead end. Bounded (max
	 *  20 hops) as a sanity guard, not because 20 is expected to be reached. */
	private String measureChainDepth(CallExpressionBase startCall) {
		java.util.Set<Long> visitedFuncIds = new java.util.HashSet<Long>();
		java.util.List<String> path = new java.util.ArrayList<String>();
		CallExpressionBase currentCall = startCall;
		int depth = 0;
		while(depth < 20) {
			depth++;
			java.util.List<Long> targets = PHPCGFactory.call2mtd.get(currentCall.getNodeId());
			if(targets == null || targets.isEmpty()) {
				Expression _tf = currentCall.getTargetFunc();
				String _name = null;
				if(_tf instanceof StringExpression) _name = ((StringExpression) _tf).getEscapedCodeStr();
				else if(_tf instanceof Identifier && ((Identifier) _tf).getNameChild() != null)
					_name = ((Identifier) _tf).getNameChild().getEscapedCodeStr();
				if(System.getenv("FALLBACK_DIAG")!=null) {
					String _receiverInfo = "N/A";
					if(currentCall instanceof MethodCallExpression) {
						Expression _target = ((MethodCallExpression) currentCall).getTargetObject();
						boolean _isThis = _target instanceof Variable
							&& ((Variable) _target).getNameExpression() != null
							&& "this".equals(((Variable) _target).getNameExpression().getEscapedCodeStr());
						if(_isThis) {
							String _enc = ((MethodCallExpression) currentCall).getEnclosingClass();
							_receiverInfo = "THIS_RECEIVER_class="+(_enc==null?"UNRESOLVED":_enc);
						} else {
							String _inferredClass = resolveReceiverClassViaConstructor(_target);
							if(_inferredClass != null) {
								String _implShape = resolveClassMethodReturnShape(_inferredClass, _name);
								_receiverInfo = "CONSTRUCTOR_INFERRED_class="+_inferredClass+" method_return_shape=["+_implShape+"]";
							} else {
								_receiverInfo = "NON_THIS_RECEIVER_TYPE_UNRESOLVED origin=["+classifyReceiverOrigin(_target)+"]";
							}
						}
					}
					System.err.println("EXTERNAL_CALL_NAME name="+_name+" isMethod="+(currentCall instanceof MethodCallExpression)
						+" chainTerminal=true receiver="+_receiverInfo);
					if("apply_filters".equals(_name)) {
						ArgumentList _al2 = currentCall.getArgumentList();
						String _tagStatus2;
						if(_al2 == null || _al2.size() < 1) _tagStatus2 = "NO_ARGS";
						else if(_al2.getArgument(0) instanceof StringExpression) {
							String _tag2 = ((StringExpression) _al2.getArgument(0)).getEscapedCodeStr();
							_tagStatus2 = "LITERAL_TAG_NO_REGISTERED_CALLBACK_FOUND tag="+_tag2;
						} else {
							_tagStatus2 = "DYNAMIC_TAG_NAME";
						}
						System.err.println("APPLY_FILTERS_INVESTIGATION status="+_tagStatus2+" chainTerminal=true");
					}
				}
				path.add("depth"+depth+"=NO_TARGET");
				break;
			}
			if(targets.size() > 1) { path.add("depth"+depth+"=MULTI_TARGET_count="+targets.size()); break; }
			long targetFunc = targets.get(0);
			if(!visitedFuncIds.add(targetFunc)) { path.add("depth"+depth+"=CYCLE_func="+targetFunc); break; }
			Expression ret = findSingleReturnExpression(targetFunc);
			if(ret == null) { path.add("depth"+depth+"=NO_SINGLE_RETURN"); break; }
			String shape = classifyExpressionShape(ret);
			path.add("depth"+depth+"="+shape);
			if(ret instanceof CallExpressionBase) { currentCall = (CallExpressionBase) ret; continue; }
			break;   // terminal, non-call shape reached
		}
		return "final_depth="+depth+" path=["+String.join(" -> ", path)+"]";
	}

	private String classifyReturnShape(long calleeFuncId) {
		java.util.Set<String> shapesFound = new java.util.HashSet<String>();
		boolean anyReturn = false;
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof ReturnStatement)) continue;
			ReturnStatement rs = (ReturnStatement) n;
			if(rs.getFuncId() == null || !rs.getFuncId().equals(calleeFuncId)) continue;
			anyReturn = true;
			Expression rv = rs.getReturnExpression();
			if(rv == null) { shapesFound.add("NO_VALUE_RETURN"); continue; }
			Long rvId = rv.getNodeId();
			if(PHPCSVEdgeInterpreter.sources.contains(rvId)) { shapesFound.add("RETURN_REQUEST_SOURCE_CANDIDATE"); continue; }
			if(rv instanceof Variable) {
				ASTNode func = ASTUnderConstruction.idToNode.get(calleeFuncId);
				boolean isParam = false;
				if(func instanceof FunctionDef) {
					ParameterList params = ((FunctionDef) func).getParameterList();
					String vname = ((Variable) rv).getNameExpression() != null
						? ((Variable) rv).getNameExpression().getEscapedCodeStr() : null;
					if(params != null && vname != null) {
						for(int i=0; i<params.size(); i++)
							if(vname.equals(params.getParameter(i).getName())) { isParam = true; break; }
					}
				}
				shapesFound.add(isParam ? "RETURN_PARAMETER" : "RETURN_LOCAL_VARIABLE");
				continue;
			}
			String rvType = rv.getProperty("type");
			if(rv instanceof PropertyExpression || "AST_DIM".equals(rvType)) { shapesFound.add("RETURN_PROPERTY_OR_DIM"); continue; }
			if(rv instanceof CallExpressionBase) { shapesFound.add("RETURN_CALL_RESULT"); continue; }
			if(rv instanceof ast.expressions.ConditionalExpression) { shapesFound.add("RETURN_CONDITIONAL"); continue; }
			shapesFound.add("RETURN_OTHER_"+rvType);
		}
		if(!anyReturn) return "NO_RETURN_STATEMENT_FOUND";
		if(shapesFound.size() > 1) return "MULTIPLE_RETURN_SHAPES:"+shapesFound;
		return shapesFound.iterator().next();
	}

	private String splitUnresolvedCall(CallExpressionBase call, boolean isMethod) {
		Expression tf = call.getTargetFunc();
		String literalName = null;
		if(tf instanceof StringExpression) literalName = ((StringExpression) tf).getEscapedCodeStr();
		else if(tf instanceof Identifier && ((Identifier) tf).getNameChild() != null
				&& "string".equals(((Identifier) tf).getNameChild().getProperty("type")))
			literalName = ((Identifier) tf).getNameChild().getEscapedCodeStr();
		if(tf == null) return "OTHER_NO_TARGET";
		if(literalName == null) {
			// Target isn't a literal name at all -- a variable/expression supplying the callee
			// dynamically (e.g. $fn(), $obj->$method(), call_user_func($var)).
			return "DYNAMIC_OR_INDIRECT_CALL";
		}
		// apply_filters-specific investigation, per the reviewer's design: resolveHookDispatch()
		// (PHPCGFactory) ALREADY attempts this exact resolution and wires resolved callbacks
		// directly into call2mtd -- so any apply_filters call reaching THIS point (call2mtd empty)
		// already FAILED that resolution. Check WHY: dynamic tag name, or literal tag with no
		// matching add_filter() registration found anywhere in this codebase.
		if(System.getenv("FALLBACK_DIAG")!=null && "apply_filters".equals(literalName)) {
			ArgumentList _al = call.getArgumentList();
			String _tagStatus;
			if(_al == null || _al.size() < 1) _tagStatus = "NO_ARGS";
			else if(_al.getArgument(0) instanceof StringExpression) {
				String _tag = ((StringExpression) _al.getArgument(0)).getEscapedCodeStr();
				_tagStatus = "LITERAL_TAG_NO_REGISTERED_CALLBACK_FOUND tag="+_tag;
			} else {
				_tagStatus = "DYNAMIC_TAG_NAME";
			}
			System.err.println("APPLY_FILTERS_INVESTIGATION status="+_tagStatus);
		}
		boolean isFirstPartyName = getFirstPartyFunctionNames().contains(literalName);
		if(isFirstPartyName) {
			// A user-defined function/method with this EXACT name exists SOMEWHERE in the
			// codebase, yet call2mtd never resolved this call site to it -- a genuine call-graph
			// resolution limitation, not an external/builtin call.
			return isMethod ? "METHOD_UNRESOLVED_FIRST_PARTY" : "UNRESOLVED_FIRST_PARTY";
		}
		// No first-party definition exists anywhere -- genuinely external (PHP builtin, WP core,
		// vendor library, etc). "KNOWN" vs "UNKNOWN" would require a maintained builtin-name list
		// this engine doesn't currently have -- reporting as one BUILTIN_OR_FRAMEWORK bucket
		// rather than fabricating a known/unknown distinction with no real registry behind it.
		if(System.getenv("FALLBACK_DIAG")!=null) {
			String receiverInfo = "N/A";
			if(isMethod && call instanceof MethodCallExpression) {
				Expression target = ((MethodCallExpression) call).getTargetObject();
				// HONEST distinction: getEnclosingClass() reports the CALLING context's class, not
				// necessarily the receiver's -- these are the SAME only when the receiver is $this.
				// For any other receiver expression, the actual receiver class is genuinely
				// unresolved by this check (would need real type inference, not attempted here).
				boolean isThisReceiver = target instanceof Variable
					&& ((Variable) target).getNameExpression() != null
					&& "this".equals(((Variable) target).getNameExpression().getEscapedCodeStr());
				if(isThisReceiver) {
					String encClass = ((MethodCallExpression) call).getEnclosingClass();
					receiverInfo = "THIS_RECEIVER_class="+(encClass==null?"UNRESOLVED":encClass);
				} else {
					receiverInfo = "NON_THIS_RECEIVER_TYPE_UNRESOLVED";
				}
			}
			System.err.println("EXTERNAL_CALL_NAME name="+literalName+" isMethod="+isMethod
				+" receiver="+receiverInfo);
		}
		return isMethod ? "METHOD_BUILTIN_OR_FRAMEWORK" : "BUILTIN_OR_FRAMEWORK";
	}

	/** 6B: one-hop promoted-parameter resolution using PHPCGFactory.promotedParamEvidence -- the
	 *  REAL, persistent promotion-event structure found via project-wide search (in
	 *  PHPCGFactory.java, populated by forwardInlineSourceArgs(), NOT the traversal-local
	 *  param2caller this session initially and wrongly assumed was the only option). Given a
	 *  parameter AST node ID, looks up ALL promotion events recorded for it. If EXACTLY ONE
	 *  matches, resolves one hop to its callerSourceNodeId. If zero or multiple, returns
	 *  UNRESOLVED_PROMOTED_PARAMETER -- no guessing, per the reviewer's fail-closed design. */
	/** Classifies a caller-side resolved node's kind, per the reviewer's exact categories for the
	 *  HOOK_PARAM_SEED investigation -- distinct from classifyLiveProvenanceNode (which classifies
	 *  a WRITE STATEMENT's RHS) since this classifies an arbitrary EXPRESSION node directly. */
	private String classifyCallerSideNode(Long nodeId) {
		if(nodeId == null) return "OTHER_NULL_NODE";
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		if(n == null) return "OTHER_NODE_NOT_FOUND";
		Long base = findBaseOfArrayAccess(nodeId);
		if("HANDLE_VARIABLE_CANONICAL".equals(classifySourceAdmission(base))) return "CANONICAL_REQUEST_ACCESS";
		if(PHPCGFactory.hookParamSourceNodes.contains(base)) return "ANOTHER_HOOK_PROMOTION";
		if(n instanceof CallExpressionBase) return "CALL_RESULT";
		if(n instanceof Variable) {
			Long pid = findPromotedParameterNodeId((Expression) n);
			return pid != null ? "PARAMETER_REFERENCE" : "OTHER_LOCAL_VARIABLE";
		}
		if(n instanceof PropertyExpression || "AST_DIM".equals(n.getProperty("type"))) return "PROPERTY_OR_DIM";
		return "OTHER_"+n.getProperty("type");
	}
	/** FIXED (\u00a7118/119): promotedParamEvidence is keyed by the VARIABLE OCCURRENCE node id (a
	 *  specific syntactic use-site inside the callee body), NOT the declared Parameter node --
	 *  one declared parameter can have multiple distinct occurrences, each a separate value-use
	 *  site with its own promotion event. Queries the occurrence directly, then filters candidate
	 *  events by caller context (the current traversal's caller) before applying the 0/1/>1 gate
	 *  -- per the reviewer's exact design: don't take events.values().iterator().next() blindly
	 *  when multiple candidates exist; filter to compatible ones first. */
	private boolean _promEvidenceSizeLogged = false;
	private String resolveByOccurrenceKey(long occurrenceNodeId, long callerContext) {
		if(System.getenv("FALLBACK_DIAG")!=null && !_promEvidenceSizeLogged) {
			int total = 0;
			for(java.util.LinkedHashMap<String, PHPCGFactory.PromotedParameterEvidence> m : PHPCGFactory.promotedParamEvidence.values())
				total += m.size();
			System.err.println("PROMOTED_PARAM_EVIDENCE_TOTAL keys="+PHPCGFactory.promotedParamEvidence.size()+" events="+total);
			_promEvidenceSizeLogged = true;
		}
		java.util.LinkedHashMap<String, PHPCGFactory.PromotedParameterEvidence> events =
			PHPCGFactory.promotedParamEvidence.get(occurrenceNodeId);
		int rawCount = (events==null) ? 0 : events.size();
		if(events == null || events.isEmpty())
			return "occurrence_key="+occurrenceNodeId+" raw_events=0 gate=UNRESOLVED_NO_EVENTS";
		// Caller-context filtering: prefer events whose callsiteAstId's own enclosing caller
		// matches the CURRENT traversal's caller context, when that's determinable. callsiteAstId
		// is the call statement itself -- its own funcId is the caller function, comparable
		// against callerContext's astId's funcId if that context is a resolvable statement.
		java.util.List<PHPCGFactory.PromotedParameterEvidence> filtered = new java.util.ArrayList<PHPCGFactory.PromotedParameterEvidence>();
		for(PHPCGFactory.PromotedParameterEvidence e : events.values()) {
			ASTNode callsiteNode = ASTUnderConstruction.idToNode.get(e.callsiteAstId);
			ASTNode callerCtxNode = ASTUnderConstruction.idToNode.get(callerContext);
			if(callsiteNode != null && callerCtxNode != null
					&& callsiteNode.getFuncId() != null && callerCtxNode.getFuncId() != null
					&& callsiteNode.getFuncId().equals(callerCtxNode.getFuncId())) {
				filtered.add(e);
			}
		}
		int afterFilterCount = filtered.size();
		java.util.List<PHPCGFactory.PromotedParameterEvidence> pool = filtered.isEmpty() ? new java.util.ArrayList<>(events.values()) : filtered;
		String prefix = "occurrence_key="+occurrenceNodeId+" raw_events="+rawCount
			+" after_caller_filter="+afterFilterCount+" ";
		if(pool.size() > 1) return prefix+"gate=AMBIGUOUS_count="+pool.size();
		PHPCGFactory.PromotedParameterEvidence e = pool.get(0);
		String callerKind = classifyCallerSideNode(e.callerSourceNodeId);
		String normalizedPart = "";
		if("CANONICAL_REQUEST_ACCESS".equals(callerKind) && e.callerSourceNodeId != null) {
			// Push the resolved caller-side node through the ACTUAL normalizer, per the 6A
			// discipline (\u00a7110/111) -- classification alone is not the same as confirming the
			// normalizer succeeds and comparing against independently emitted evidence.
			Long _base = findBaseOfArrayAccess(e.callerSourceNodeId);
			String[] acc = PHPCGFactory.resolveRequestAccess(_base);
			normalizedPart = " normalized=["+(acc==null?"NONE":
				"channel="+acc[0]+" key_path="+acc[1]+" precision="+acc[2])+"]";
			// \u00a7123: direct membership check -- is this node EVER registered as a contributing
			// source for ANY sink in vulSources, regardless of which sink? Distinguishes "never
			// reached by the main vulnerability-finding traversal at all" from "reached but
			// excluded by some other logic downstream".
			if(System.getenv("FALLBACK_DIAG")!=null) {
				boolean inVulSources = false;
				for(java.util.List<Long> vals : vulSources.values()) {
					if(vals.contains(e.callerSourceNodeId) || vals.contains(_base)) { inVulSources = true; break; }
				}
				System.err.println("VULSOURCES_MEMBERSHIP_CHECK callerSourceNodeId="+e.callerSourceNodeId
					+" base="+_base+" in_vulSources_as_ANY_sink_contributor="+inVulSources);
			}
		}
		return prefix+"gate=RESOLVED_ONE_HOP callerSourceNodeId="+e.callerSourceNodeId
			+" caller_kind="+callerKind+normalizedPart+" callsite="+e.callsiteAstId+" argIdx="+e.argumentIndex;
	}
	private String resolveHookParamSeed(Long baseNodeId, long callerContext) {
		ASTNode baseNode = ASTUnderConstruction.idToNode.get(baseNodeId);
		if(!(baseNode instanceof Variable)) return "UNRESOLVED_HOOK_PARAM_SEED_NOT_A_VARIABLE";
		return resolveByOccurrenceKey(baseNodeId, callerContext);
	}

	private String resolvePromotedParameter(long occurrenceNodeId, long callerContext) {
		return resolveByOccurrenceKey(occurrenceNodeId, callerContext);
	}
	/** Locates the declared Parameter AST node's own ID for a promoted-parameter RHS variable --
	 *  mirrors the matching logic already used in classifyLiveProvenanceNode, factored out so 6B
	 *  can look up the SAME node identity promotedParamEvidence is keyed by. */
	private Long findPromotedParameterNodeId(Expression rhs) {
		if(!(rhs instanceof Variable)) return null;
		Long funcId = rhs.getFuncId();
		ASTNode func = ASTUnderConstruction.idToNode.get(funcId);
		if(!(func instanceof FunctionDef)) return null;
		ParameterList params = ((FunctionDef) func).getParameterList();
		String vname = ((Variable) rhs).getNameExpression() != null
			? ((Variable) rhs).getNameExpression().getEscapedCodeStr() : null;
		if(params == null || vname == null) return null;
		for(int i=0; i<params.size(); i++) {
			if(vname.equals(params.getParameter(i).getName())) return params.getParameter(i).getNodeId();
		}
		return null;
	}

	/** Classifies a single expression's shape using the SAME categories the top-level classifier
	 *  already uses -- factored out so the OTHER_AST_CONDITIONAL population's two ARMS can be
	 *  classified individually, reusing existing logic rather than inventing new categories for
	 *  what's fundamentally the same question asked about a different node. */
	private String classifyExpressionShape(Expression rv) {
		if(rv == null) return "NULL_ARM";
		Long rvId = rv.getNodeId();
		if(PHPCSVEdgeInterpreter.sources.contains(rvId))
			return "SOURCE_SET_MEMBER["+classifyAndNormalizeCandidate(rvId)+"]";
		String rvType = rv.getProperty("type");
		if(rv instanceof Variable) {
			Long pid = findPromotedParameterNodeId(rv);
			return pid != null ? "PARAMETER_REFERENCE" : "LOCAL_VARIABLE";
		}
		if(rv instanceof PropertyExpression || "AST_DIM".equals(rvType)) return "PROPERTY_OR_DIM_READ";
		if(rv instanceof CallExpressionBase) return "CALL_RESULT";
		if(rv instanceof ast.expressions.ConditionalExpression) return "NESTED_CONDITIONAL";
		if(rv instanceof StringExpression || "integer".equals(rvType) || "double".equals(rvType))
			return "LITERAL_CONSTANT";
		return "OTHER_"+rvType;
	}
	private String classifyConditionalArms(long conditionalNodeId) {
		ASTNode n = ASTUnderConstruction.idToNode.get(conditionalNodeId);
		if(!(n instanceof ast.expressions.ConditionalExpression)) return "NOT_A_CONDITIONAL";
		ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression) n;
		String trueArm = classifyExpressionShape(ce.getTrueExpression());
		String falseArm = classifyExpressionShape(ce.getFalseExpression());
		return "true_arm="+trueArm+" false_arm="+falseArm;
	}

	/** Traces a PROPERTY_OR_DIM_READ's underlying identity to its ACTUAL write site, using the
	 *  ALREADY-BUILT interEvidenceSidecar (\u00a770's producer-side sidecar). CORRECTED: interEvidenceSidecar
	 *  is populated ONLY from addInter()'s PROP/GLOBAL branches (via getPropIdentity's
	 *  `classId::propName` format) -- it does NOT track array-DIM writes at all. getDIMIdentity
	 *  uses a COMPLETELY DIFFERENT internal identity scheme (`$`-separated constant chain) for a
	 *  different mechanism entirely -- attempting to look that format up in interEvidenceSidecar
	 *  is a genuine SCOPE MISMATCH, not a fixable key-format bug (unlike \u00a7118's case). Only
	 *  PropertyExpression reads are in-scope for this trace; AST_DIM reads are honestly reported
	 *  as having no comparable write-tracking sidecar to search. */
	private String traceReadToWrite(Expression readNode, long caller) {
		if(!(readNode instanceof PropertyExpression))
			return "NOT_APPLICABLE_DIM_READ_HAS_NO_COMPARABLE_WRITE_SIDECAR (interEvidenceSidecar is PROP/GLOBAL-scoped only)";
		String identity = getPropIdentity(readNode, caller);
		if(identity == null || identity.equals("-1") || identity.equals("-2"))
			return "identity=UNRESOLVABLE";
		InterEvidence matched = null;
		for(InterEvidence ev : interEvidenceSidecar.values()) {
			if(identity.equals(ev.identityNode)) { matched = ev; break; }
		}
		if(matched == null) return "identity="+identity+" write_found=false";
		ASTNode writeStmt = ASTUnderConstruction.idToNode.get(matched.provenanceNode);
		String writeShape = "UNKNOWN_WRITE_SHAPE";
		if(writeStmt instanceof AssignmentExpression) {
			writeShape = classifyExpressionShape(((AssignmentExpression) writeStmt).getRight());
		}
		return "identity="+identity+" write_found=true write_stmt="+matched.provenanceNode+" write_shape=["+writeShape+"]";
	}

	/** Attempts to statically resolve a NON-$this receiver's class via constructor-site type
	 *  inference -- searches for `$var = new ClassName(...)` assigning to the SAME Variable name
	 *  within the SAME function as the receiver use. Bounded, best-effort: does NOT attempt full
	 *  dataflow (e.g. doesn't follow the variable through intermediate reassignments or across
	 *  function boundaries) -- reports UNRESOLVED honestly rather than guessing when this simple
	 *  check doesn't find a direct constructor assignment. */
	/** Final bounded inventory for the 107 get() cases, per the reviewer's exact spec -- groups by
	 *  containing function, variable name, and whether the receiver matches a declared PARAMETER
	 *  (with its type hint if any), a PROPERTY read, or neither. Does NOT attempt resolution --
	 *  purely descriptive, to determine whether receiver identity collapses to a small, tractable
	 *  pattern (justifying a narrow resolution mechanism) or scatters broadly (evidence receiver
	 *  resolution is a genuinely larger engine problem). */
	private String classifyReceiverOrigin(Expression receiver) {
		if(!(receiver instanceof Variable)) {
			String innerCallName = "N/A";
			if(receiver instanceof CallExpressionBase) {
				Expression itf = ((CallExpressionBase) receiver).getTargetFunc();
				if(itf instanceof StringExpression) innerCallName = ((StringExpression) itf).getEscapedCodeStr();
				else if(itf instanceof Identifier && ((Identifier) itf).getNameChild() != null)
					innerCallName = ((Identifier) itf).getNameChild().getEscapedCodeStr();
				else if(receiver instanceof MethodCallExpression) innerCallName = "METHOD_CALL_dynamic_or_unresolved";
			}
			return "origin=NON_VARIABLE_RECEIVER actual_type="+receiver.getProperty("type")
				+" inner_call_name="+innerCallName;
		}
		String vname = ((Variable) receiver).getNameExpression() != null
			? ((Variable) receiver).getNameExpression().getEscapedCodeStr() : null;
		Long funcId = receiver.getFuncId();
		ASTNode func = funcId == null ? null : ASTUnderConstruction.idToNode.get(funcId);
		if(func instanceof FunctionDef && vname != null) {
			ParameterList params = ((FunctionDef) func).getParameterList();
			if(params != null) {
				for(int i=0; i<params.size(); i++) {
					if(vname.equals(params.getParameter(i).getName())) {
						String typeHint = "NO_TYPE_HINT";
						if(params.getParameter(i) instanceof Parameter) {
							Identifier th = ((Parameter) params.getParameter(i)).getType();
							if(th != null && th.getNameChild() != null) typeHint = th.getNameChild().getEscapedCodeStr();
						}
						return "func="+funcId+" var="+vname+" kind=PARAMETER type_hint="+typeHint;
					}
				}
			}
		}
		if(receiver instanceof PropertyExpression) return "func="+funcId+" var="+vname+" kind=PROPERTY_READ";
		return "func="+funcId+" var="+vname+" kind=LOCAL_OR_OTHER";
	}
	private String resolveReceiverClassViaConstructor(Expression receiver) {
		if(!(receiver instanceof Variable)) return null;
		String vname = ((Variable) receiver).getNameExpression() != null
			? ((Variable) receiver).getNameExpression().getEscapedCodeStr() : null;
		Long funcId = receiver.getFuncId();
		if(vname == null || funcId == null) return null;
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof AssignmentExpression)) continue;
			AssignmentExpression ae = (AssignmentExpression) n;
			if(ae.getFuncId() == null || !ae.getFuncId().equals(funcId)) continue;
			Expression left = ae.getLeft();
			if(!(left instanceof Variable)) continue;
			String lname = ((Variable) left).getNameExpression() != null
				? ((Variable) left).getNameExpression().getEscapedCodeStr() : null;
			if(!vname.equals(lname)) continue;
			Expression right = ae.getRight();
			if(right instanceof NewExpression) {
				Expression tc = ((NewExpression) right).getTargetClass();
				if(tc instanceof Identifier && ((Identifier) tc).getNameChild() != null)
					return ((Identifier) tc).getNameChild().getEscapedCodeStr();
				String raw = tc == null ? null : tc.getEscapedCodeStr();
				if(raw != null) return raw;
			}
		}
		return null;
	}
	/** Given a resolved class name and method name, finds the method's own return-shape --
	 *  reuses classifyReturnShape() directly, no new classification logic. */
	private String resolveClassMethodReturnShape(String className, String methodName) {
		Long classId = PHPCGFactory.classDef.get(className);
		if(classId == null) return "CLASS_NOT_FOUND";
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!(n instanceof FunctionDef)) continue;
			FunctionDef fd = (FunctionDef) n;
			if(!methodName.equals(fd.getName())) continue;
			String encClass = fd.getProperty("classname");
			if(encClass == null || !encClass.equals(className)) continue;
			return classifyReturnShape(fd.getNodeId());
		}
		return "METHOD_NOT_FOUND";
	}

	private String classifyLiveProvenanceNode(long astId) {
		ASTNode n = ASTUnderConstruction.idToNode.get(astId);
		if(n == null) return "UNKNOWN_NODE_NOT_FOUND";
		if(!(n instanceof AssignmentExpression)) return "NON_ASSIGNMENT_"+n.getProperty("type");
		Expression rhs = ((AssignmentExpression) n).getRight();
		if(rhs == null) return "UNKNOWN_NO_RHS";
		Long rhsId = rhs.getNodeId();
		// Existing, already-trusted determination: is any node in this RHS subtree a confirmed
		// request source? (PHPCSVEdgeInterpreter.sources is populated by the engine's own
		// established source-detection logic, used throughout this session's earlier work.)
		// RENAMED (reviewer's §110 correction): 6A's own diagnostic found that membership in
		// PHPCSVEdgeInterpreter.sources is NOT, by itself, equivalent to the normalized
		// REQUEST_SOURCE_EVIDENCE pipeline's semantics (resolveRequestAccess returned NONE for
		// all 14 measured cases; 0 independently-emitted records existed to compare against
		// either way). "REQUEST_SOURCE" claimed more than was established -- CANDIDATE only,
		// until the discrepancy is traced and understood.
		if(PHPCSVEdgeInterpreter.sources.contains(rhsId)) return "REQUEST_SOURCE_CANDIDATE";
		String rhsType = rhs.getProperty("type");
		if(rhs instanceof Variable) {
			// A bare variable RHS: is it a function PARAMETER (promoted) or a plain local?
			Long funcId = rhs.getFuncId();
			ASTNode func = ASTUnderConstruction.idToNode.get(funcId);
			if(func instanceof FunctionDef) {
				ParameterList params = ((FunctionDef) func).getParameterList();
				String vname = ((Variable) rhs).getNameExpression() != null
					? ((Variable) rhs).getNameExpression().getEscapedCodeStr() : null;
				if(params != null && vname != null) {
					for(int i=0; i<params.size(); i++) {
						// RENAMED (reviewer's correction): this is a broad syntactic match (RHS name
						// equals SOME parameter name) -- NOT the same population as PHPCGFactory's
						// PromotedParameterEvidence, which has an established, narrower meaning (nodes
						// backed by forwardInlineSourceArgs()'s inline-source-hook promotion). Using
						// "PROMOTED_PARAMETER" here would conflate two distinct mechanisms.
						if(vname.equals(params.getParameter(i).getName())) return "PARAMETER_REFERENCE";
					}
				}
			}
			return "LOCAL_VARIABLE";
		}		if(rhs instanceof PropertyExpression || "AST_DIM".equals(rhsType)) return "PROPERTY_OR_DIM_READ";
		if(rhs instanceof CallExpressionBase) return classifyCallDispatch((CallExpressionBase) rhs);
		return "OTHER_"+rhsType;
	}

	private java.util.Map<String, Long> liveProvenanceQuery(Node.TracingInterMap tm,
			java.util.Map<String, java.util.Set<Long>> historicalObservationsOut,
			java.util.Map<String, Long> valueExpressionOut) {
		java.util.Set<Long> visited = new java.util.HashSet<Long>();
		java.util.Deque<Long> frontier = new java.util.ArrayDeque<Long>();
		if(tm.currentStateEventId != -1) frontier.push(tm.currentStateEventId);
		java.util.Map<String, Long> bestEventId = new java.util.HashMap<String, Long>();
		java.util.Map<String, Long> liveProvenance = new java.util.HashMap<String, Long>();
		while(!frontier.isEmpty()) {
			Long id = frontier.pop();
			if(!visited.add(id)) continue;
			Node.MutationEvent e = Node.mutationEventLog.get(id);
			if(e == null) continue;
			if(("WRITE".equals(e.kind) || "MERGE_OVERWRITE".equals(e.kind)) && e.identityNode != null) {
				if(historicalObservationsOut != null)
					historicalObservationsOut.computeIfAbsent(e.identityNode, k -> new java.util.HashSet<Long>())
						.add(e.provenanceNode);
				Long best = bestEventId.get(e.identityNode);
				// FAIL-CLOSED (reviewer's staged plan): this tie-break assumes eventIds are totally
				// ordered and exactly one write can be "most recent" per key -- true today because
				// the underlying live `inter` is Map<String,Long>, structurally single-valued per
				// key (cardinalityModel=SINGLE_LIVE_VALUE). If that assumption is ever violated
				// (which should be impossible given a monotonic AtomicLong counter, but is checked
				// rather than silently trusted), fail loudly instead of letting Map iteration order
				// silently pick a winner.
				if(best != null && best.longValue() == e.eventId && System.getenv("MUTATION_DAG_DIAG")!=null)
					System.err.println("CARDINALITY_ASSUMPTION_VIOLATION identity="+e.identityNode
						+" eventId="+e.eventId+" -- duplicate eventId observed, SINGLE_LIVE_VALUE assumption broken");
				if(best == null || e.eventId > best) {
					bestEventId.put(e.identityNode, e.eventId);
					liveProvenance.put(e.identityNode, e.provenanceNode);
					// SEMANTIC identity, captured at the producer site (recordInter) -- exposed
					// here alongside the STATE identity, per the reviewer's separation. May be
					// null if the write's state node wasn't an AssignmentExpression with an RHS.
					if(valueExpressionOut != null) {
						Long vexpr = e.valueExpressionId;
						// FIX (§108), HARDENED (§110): when the WINNING event is a MERGE_OVERWRITE,
						// it never carries valueExpressionId directly (mergeOverwrite() has no AST
						// context of its own). Use the DIRECT index (stateNodeToValueExpression,
						// populated and consistency-enforced at the producer site in recordInter)
						// instead of searching the whole mutation log for a matching WRITE event --
						// O(1), and decouples "assert consistency" (now enforced once, at write
						// time) from "search for an answer" (now a simple lookup).
						if(vexpr == null) vexpr = stateNodeToValueExpression.get(e.provenanceNode);
						if(vexpr != null) valueExpressionOut.put(e.identityNode, vexpr);
						else valueExpressionOut.remove(e.identityNode);
					}
				}
			}
			for(Long p : e.parentStateEventIds) frontier.push(p);
		}
		return liveProvenance;
	}

	private void stateSyncGate(long stmt, Node.TracingInterMap tm) {
		if(System.getenv("MUTATION_DAG_DIAG")==null) return;
		java.util.Set<Long> visited = new java.util.HashSet<Long>();
		java.util.Deque<Long> frontier = new java.util.ArrayDeque<Long>();
		if(tm.currentStateEventId != -1) frontier.push(tm.currentStateEventId);
		java.util.Map<String, Long> reconstructed = new java.util.HashMap<String, Long>();   // key -> best eventId
		java.util.Map<String, Long> reconstructedValue = new java.util.HashMap<String, Long>();
		while(!frontier.isEmpty()) {
			Long id = frontier.pop();
			if(!visited.add(id)) continue;
			Node.MutationEvent e = Node.mutationEventLog.get(id);
			if(e == null) continue;
			if(("WRITE".equals(e.kind) || "MERGE_OVERWRITE".equals(e.kind)) && e.identityNode != null) {
				Long best = reconstructed.get(e.identityNode);
				if(best == null || e.eventId > best) {
					reconstructed.put(e.identityNode, e.eventId);
					reconstructedValue.put(e.identityNode, e.provenanceNode);
				}
			}
			for(Long p : e.parentStateEventIds) frontier.push(p);
		}
		int mismatches = 0;
		for(String key : tm.keySet()) {
			Long live = tm.get(key);
			Long recon = reconstructedValue.get(key);
			boolean match = (recon != null && recon.equals(live));
			if(!match) mismatches++;
			System.err.println("STATE_SYNC_GATE stmt="+stmt+" key="+key+" live="+live
				+" reconstructed="+recon+" match="+match);
		}
		if(mismatches>0) System.err.println("STATE_SYNC_GATE_SUMMARY stmt="+stmt+" mismatches="+mismatches);
	}

	private void dumpReachableWrites(long stmt, Node.TracingInterMap tm) {
		if(System.getenv("MUTATION_DAG_DIAG")==null) return;
		java.util.Set<Long> visited = new java.util.HashSet<Long>();
		java.util.Deque<Long> frontier = new java.util.ArrayDeque<Long>();
		if(tm.currentStateEventId != -1) frontier.push(tm.currentStateEventId);
		java.util.List<Node.MutationEvent> writes = new java.util.ArrayList<Node.MutationEvent>();
		while(!frontier.isEmpty()) {
			Long id = frontier.pop();
			if(!visited.add(id)) continue;
			Node.MutationEvent e = Node.mutationEventLog.get(id);
			if(e == null) continue;
			if("WRITE".equals(e.kind)) writes.add(e);
			for(Long p : e.parentStateEventIds) frontier.push(p);
		}
		System.err.println("DAG_REACHABLE stmt="+stmt+" map="+System.identityHashCode(tm)
			+" currentStateEventId="+tm.currentStateEventId+" terminal_write_count="+writes.size());
		for(Node.MutationEvent w : writes)
			System.err.println("  DAG_WRITE eventId="+w.eventId+" identity="+w.identityNode
				+" provenance="+w.provenanceNode);
	}

	private HashMap<Long, Long> isrelated(Long stmt, Set<Long> intro, HashMap<String, Long> inter, Long caller) {
		if(System.getenv("SG_PIPELINE_DIAG")!=null) {
			if(inter instanceof Node.TracingInterMap) {
				Node.TracingInterMap tm = (Node.TracingInterMap) inter;
				System.err.println("ISRELATED_ENTRY stmt="+stmt+" map="+System.identityHashCode(inter)
					+" size="+inter.size()+" keys="+inter.keySet()
					+" total_mutations_on_map="+tm.totalMutationsOnThisMap
					+" first_mutation=["+tm.firstMutationStack+"]"
					+" last_mutation=["+tm.lastMutationStack+"]");
				dumpReachableWrites(stmt, tm);
				{
					java.util.Map<String, java.util.Set<Long>> historical = new java.util.HashMap<String, java.util.Set<Long>>();
					java.util.Map<String, Long> valueExprMap = new java.util.HashMap<String, Long>();
					java.util.Map<String, Long> live = liveProvenanceQuery(tm, historical, valueExprMap);
					for(String k : tm.keySet()) {
						java.util.Set<Long> hist = historical.get(k);
						Long liveNode = live.get(k);
						int histCount = (hist==null) ? 0 : hist.size();
						// LIMITATION, stated explicitly: liveProvenanceQuery() is Map<String,Long> --
						// structurally single-valued by construction (most-recent-eventId tie-break
						// always collapses to exactly one answer). This means bucket D ("live
						// ambiguous") can NEVER be observed by this measurement, regardless of
						// whether genuine ambiguity exists in the engine -- 0 in bucket D proves the
						// query cannot see it, NOT that no ambiguity exists.
						String bucket;
						if(liveNode == null && histCount == 0) bucket = "E_no_history";
						else if(liveNode == null) bucket = "C_live_missing";
						else if(histCount <= 1) bucket = "A_history_equals_live";
						else bucket = "B_multiple_historical_one_live";
						int supersededCount = Math.max(0, histCount - (liveNode==null?0:1));
						System.err.println("LIVE_PROVENANCE_MEASURE stmt="+stmt+" key="+k+" caller="+caller
							+" live_provenance_node="+liveNode
							+" historical_write_count="+histCount
							+" distinct_historical_write_count="+histCount
							+" live_write_count="+(liveNode==null?0:1)
							+" superseded_write_count="+supersededCount
							+" bucket="+bucket
							+" historical_set="+hist);
						// Diagnostic-only record population (reviewer's staged plan, step 2). NOT
						// consumed by any production evidence path. historicalProvenanceNodes are
						// explanatory ONLY -- never to be emitted as separate vulnerability sources.
						if(liveNode != null) {
							LiveValueProvenance lvp = new LiveValueProvenance(stmt, k, caller, liveNode, hist);
							liveValueProvenanceSidecar.put(stmt+"|"+k+"|"+caller, lvp);
							if(System.getenv("FALLBACK_DIAG")!=null) {
								String classification = classifyLiveProvenanceNode(liveNode);
								String resolution = "";
								if("PARAMETER_REFERENCE".equals(classification)) {
									// FIXED (\u00a7118/119): use the ACTUAL value-expression occurrence
									// (already correctly identified via the hardened valueExprMap,
									// \u00a7108-110) directly as the occurrence key -- NOT a re-derived
									// declared-Parameter node, which promotedParamEvidence never uses.
									Long _occId = valueExprMap.get(k);
									if(_occId != null) resolution = " resolution=["+resolvePromotedParameter(_occId, caller)+"]";
								}
								if("OTHER_AST_CONDITIONAL".equals(classification)) {
									Long _condId = valueExprMap.get(k);
									if(_condId != null) resolution = " arms=["+classifyConditionalArms(_condId)+"]";
								}
								if("PROPERTY_OR_DIM_READ".equals(classification)) {
									Long _readId = valueExprMap.get(k);
									ASTNode _readNode = _readId==null ? null : ASTUnderConstruction.idToNode.get(_readId);
									if(_readNode instanceof Expression)
										resolution = " trace=["+traceReadToWrite((Expression) _readNode, caller)+"]";
								}
								// 6A (reviewer's design): for REQUEST_SOURCE cases, run the value
								// expression through the EXISTING request-source normalizer
								// (resolveRequestAccess -- the SAME function the independent,
								// already-trusted REQUEST_SOURCE_EVIDENCE pipeline uses) and report
								// the normalized (channel, key_path, precision) -- NOT raw node-id
								// equality, per the reviewer's specific caution. Comparison against
								// independently emitted evidence done separately (see below).
								if("REQUEST_SOURCE_CANDIDATE".equals(classification)) {
									Long valueExprId6a = valueExprMap.get(k);
									if(valueExprId6a != null) {
										resolution = " ["+classifyAndNormalizeCandidate(valueExprId6a)+"]";
									} else {
										resolution = " normalized=[NO_VALUE_EXPRESSION]";
									}
								}
								// Return-shape classification for the 253 single-target calls, per
								// the reviewer's original specification -- using the callee's REAL
								// ReturnStatement structure, not inference from the call site.
								if("DIRECT_FIRST_PARTY_SINGLE_TARGET".equals(classification)
										|| "METHOD_SINGLE_TARGET".equals(classification)) {
									Long valueExprIdRS = valueExprMap.get(k);
									ASTNode _callNode = valueExprIdRS==null ? null : ASTUnderConstruction.idToNode.get(valueExprIdRS);
									if(_callNode instanceof CallExpressionBase) {
										java.util.List<Long> _targets = PHPCGFactory.call2mtd.get(_callNode.getNodeId());
										if(_targets != null && _targets.size()==1) {
											String _rshape = classifyReturnShape(_targets.get(0));
											resolution += " return_shape=["+_rshape+"]";
											if("RETURN_CALL_RESULT".equals(_rshape))
												resolution += " chain=["+measureChainDepth((CallExpressionBase) _callNode)+"]";
											// If the callee's return shape is itself a source-set
											// candidate, trace ITS admission too -- these are the
											// 117 RETURN_REQUEST_SOURCE_CANDIDATE (kali-forms) cases.
											if("RETURN_REQUEST_SOURCE_CANDIDATE".equals(_rshape)) {
												// Find the actual returned expression node to trace.
												for(ASTNode _n2 : ASTUnderConstruction.idToNode.values()) {
													if(!(_n2 instanceof ReturnStatement)) continue;
													ReturnStatement _rs = (ReturnStatement) _n2;
													if(_rs.getFuncId()==null || !_rs.getFuncId().equals(_targets.get(0))) continue;
													Expression _rv = _rs.getReturnExpression();
													if(_rv != null && PHPCSVEdgeInterpreter.sources.contains(_rv.getNodeId())) {
														String _admissionResult = classifyAndNormalizeCandidate(_rv.getNodeId());
														resolution += " return_admission=["+_admissionResult+"]";
														if(_admissionResult.contains("HOOK_PARAM_SEED")) {
															Long _base = findBaseOfArrayAccess(_rv.getNodeId());
															resolution += " hook_trace=["+resolveHookParamSeed(_base, caller)+"]";
														}
														break;
													}
												}
											}
										}
									}
								}
								// STATE vs SEMANTIC identity audit (reviewer's exact spec): confirms
								// whether the classifier is consistently operating one AST level
								// below the stored inter identity, or already aligned.
								Long valueExprId = valueExprMap.get(k);
								ASTNode stateNodeAst = ASTUnderConstruction.idToNode.get(liveNode);
								ASTNode valueExprAst = valueExprId==null ? null : ASTUnderConstruction.idToNode.get(valueExprId);
								// \u00a7124: establish whether THIS consultation statement is a
								// RECOGNIZED SINK at all, before treating vulSources absence as
								// meaningful -- per the reviewer's exact question: is this a
								// sink, local-sink-frontier, intermediate write, or mere
								// isrelated() bookkeeping?
								boolean stmtIsSink = PHPCGFactory.sinks.contains(stmt);
								String stmtSinkClass = stmtIsSink ? PHPCGFactory.sinkClass.get(stmt) : null;
								System.err.println("LIVE_PROVENANCE_CLASSIFY stmt="+stmt+" key="+k
									+" live_provenance_node="+liveNode
									+" classification="+classification+resolution
									+" state_node="+liveNode
									+" state_node_type="+(stateNodeAst==null?"null":stateNodeAst.getProperty("type"))
									+" value_expression_node="+valueExprId
									+" value_expression_type="+(valueExprAst==null?"null":valueExprAst.getProperty("type"))
									+" stmt_is_recognized_sink="+stmtIsSink+" stmt_sink_class="+stmtSinkClass);
							}
						}
					}
				}
				stateSyncGate(stmt, tm);
			} else {
				System.err.println("ISRELATED_ENTRY stmt="+stmt+" map="+System.identityHashCode(inter)
					+" UNTRACED_MAP size="+inter.size()+" keys="+inter.keySet());
			}
		}
		if(ID2Node.containsKey(caller)) {
			caller = ID2Node.get(caller).astId;
		}
		
		ASTNode stmtnode = ASTUnderConstruction.idToNode.get(caller);
		
		if(stmtnode instanceof AssignmentExpression && ((AssignmentExpression) stmtnode).getRight() instanceof CallExpressionBase) {
			CallExpressionBase callsite = (CallExpressionBase) ((AssignmentExpression) stmtnode).getRight();
			caller = callsite.getNodeId();
		}
		
		ASTNode stmtNode1 = ASTUnderConstruction.idToNode.get(caller);
		if(!(stmtNode1 instanceof CallExpressionBase)) {
			caller = (long) 0;
		}
			
		HashMap<Long, Long> relatedNodes = new HashMap<Long, Long>();
		// Phase 1 of the fallback redesign: invocation-LOCAL match state. Never static -- a match at
		// this stmt must not suppress fallback for the same provenance at a DIFFERENT isrelated() call.
		// Legacy `relatedNodes` remains production-authoritative for now; this set is sidecar/fallback-
		// redesign bookkeeping only, populated by recordSpecificRelation() at every specific-match site.
		Set<CandidateKey> specificallyMatched = new HashSet<CandidateKey>();
		
		//check intro-data flow relationship
		for(Long nodeID: intro) {
			Node introNode = ID2Node.get(nodeID);
			if(introNode==null) {
				System.out.println("ASTID: "+nodeID);
				continue;
			}
			Long taint = introNode.astId;
			//we do not support loop currently
			if(taint>stmt) {
				continue;
			}
			ASTNode taintNode = ASTUnderConstruction.idToNode.get(taint);
			
			//the dst dim variable is tainted
			if(dstDim.containsKey(taint)) {
				if(srcDim.containsKey(stmt)) {
					List<Long> dims = srcDim.get(stmt);
					for(Long dim: dims) {
						ASTNode srcDimValue = ASTUnderConstruction.idToNode.get(dim);
						String symbol2 = getDIMIdentity(srcDimValue);
						//this srcdim in current statement is related to taint symbol
						if(dstDim.get(taint).startsWith(symbol2) || symbol2.startsWith(dstDim.get(taint))) {
							System.out.println("tainted DIM: "+stmt);
							if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=DIMENSION_MATCH stmt="+stmt+" related="+(dim)+" caller="+caller);
							relatedNodes.put(dim, nodeID);
							{ RelatedEvidence _e = new RelatedEvidence(dim, nodeID, caller,
							  "DIMENSION_MATCH", null, "VALUE_SPECIFIC");
							  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
							  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
						}
					}
					
					
				}
			}
			
			//check if the statement has intro-data flow relationship with taint variable
			if(DDG.rels.containsKey(taint)) {
				//get all the related statements of the taint
				for(Pair<Long, String> tmp: DDG.rels.get(taint)) {
					//the stmt has deta flow relationship with taint statement
					if(tmp.getL().equals(stmt)) {
						//the taint statement is a assignment
						if(taintNode.getProperty("type").equals("AST_ASSIGN") || taintNode.getProperty("type").equals("AST_ASSIGN_OP") || taintNode.getProperty("type").equals("AST_ASSIGN_REF")) {
							ASTNode leftValue = ((AssignmentExpression) taintNode).getLeft();
							//the symbol in taint statement is an array
							if(leftValue.getProperty("type").equals("AST_DIM")) {
								String symbol1 = getDIMIdentity(leftValue);
								//get the source dim in current stmt
								if(srcDim.containsKey(stmt)) {
									//get the locations of dim expressions in stmt
									List<Long> dims = srcDim.get(stmt);
									for(Long dim: dims) {
										ASTNode rightValue = ASTUnderConstruction.idToNode.get(dim);
										String symbol2 = getDIMIdentity(rightValue);
										//this srcdim in current statement is related to taint symbol
										if(symbol1.startsWith(symbol2) || symbol2.startsWith(symbol1)) {
											if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=DIMENSION_MATCH stmt="+stmt+" related="+(dim)+" caller="+caller);
											relatedNodes.put(dim, nodeID);
											{ RelatedEvidence _e = new RelatedEvidence(dim, nodeID, caller,
											  "DIMENSION_MATCH", null, "VALUE_SPECIFIC");
											  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
											  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
										}
									}
								}
							}
							//the taint variable is not an array
							else {
								ASTNode stmtNode = ASTUnderConstruction.idToNode.get(stmt);
								if(stmtNode instanceof CallExpressionBase) {
									String tag = tmp.getR();
									ArgumentList args = ((CallExpressionBase) stmtNode).getArgumentList();
									for(int i=0; i<args.size(); i++) {
										ASTNode arg = args.getArgument(i);
										//the taint variable is used as argument 
										if(arg instanceof Variable && ((Variable) arg).getNameExpression().getEscapedCodeStr().equals(tag)) {
											if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=ARGUMENT_MATCH stmt="+stmt+" related="+(arg.getNodeId())+" caller="+caller);
											relatedNodes.put(arg.getNodeId(), nodeID);
											// SIDECAR at the exact legacy mutation -- same invocation, same nodeID,
											// same DDG.rels state. No recomputation, so parity is true by construction.
											{ RelatedEvidence _e = new RelatedEvidence(arg.getNodeId(), nodeID, caller,
											  "ARGUMENT_MATCH", i, "VALUE_SPECIFIC");
											  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
											  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
										}
									}
								}
								else if(stmtNode instanceof EchoStatement) {
									ASTNode target = ((EchoStatement) stmtNode).getEchoExpression();
									if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=ECHO_MATCH stmt="+stmt+" related="+(target.getNodeId())+" caller="+caller);
									relatedNodes.put(target.getNodeId(), nodeID);
									{ RelatedEvidence _e = new RelatedEvidence(target.getNodeId(), nodeID, caller,
									  "ECHO_MATCH", null, "UNKNOWN");
									  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
									  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
								}
								else if(stmtNode instanceof ExitExpression) {
									ASTNode target = ((ExitExpression) stmtNode).getExpression();
									if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=EXIT_MATCH stmt="+stmt+" related="+(target.getNodeId())+" caller="+caller);
									relatedNodes.put(target.getNodeId(), nodeID);
									{ RelatedEvidence _e = new RelatedEvidence(target.getNodeId(), nodeID, caller,
									  "EXIT_MATCH", null, "UNKNOWN");
									  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
									  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
								}
								else if(stmtNode instanceof AssignmentExpression && ((AssignmentExpression) stmtNode).getRight() instanceof CallExpressionBase) {
									String tag = tmp.getR();
									ArgumentList args = ((CallExpressionBase) ((AssignmentExpression) stmtNode).getRight()).getArgumentList();
									for(int i=0; i<args.size(); i++) {
										ASTNode arg = args.getArgument(i);
										//the taint variable is used as argument 
										if(arg instanceof Variable && ((Variable) arg).getNameExpression().getEscapedCodeStr().equals(tag)) {
											if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=ARGUMENT_MATCH stmt="+stmt+" related="+(arg.getNodeId())+" caller="+caller);
											relatedNodes.put(arg.getNodeId(), nodeID);
											// SIDECAR at the exact legacy mutation -- same invocation, same nodeID,
											// same DDG.rels state. No recomputation, so parity is true by construction.
											{ RelatedEvidence _e = new RelatedEvidence(arg.getNodeId(), nodeID, caller,
											  "ARGUMENT_MATCH", i, "VALUE_SPECIFIC");
											  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
											  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
										}
									}
								}
								//
								else if(stmtNode instanceof AssignmentExpression){
									Expression leftNode = ((AssignmentExpression) stmtNode).getLeft();
									if(leftNode instanceof Variable) {
										if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=ASSIGNMENT_MATCH stmt="+stmt+" related="+(leftNode.getNodeId())+" caller="+caller);
										relatedNodes.put(leftNode.getNodeId(), nodeID);
										// nodeID is the outer intro entry -- same loop structure as
										// ARGUMENT_MATCH/DIMENSION_MATCH. Precision UNKNOWN: an assignment target
										// matching a DDG relationship has not been shown to pin one particular value.
										{ RelatedEvidence _e = new RelatedEvidence(leftNode.getNodeId(), nodeID, caller,
										  "ASSIGNMENT_MATCH", null, "UNKNOWN");
										  CandidateKey _c = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
										  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
									}
									
								}
							}
						}
						if(relatedNodes.isEmpty()) {
							if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=SINK_LEVEL_FALLBACK stmt="+stmt+" related="+(stmt)+" caller="+caller);
							if(System.getenv("FALLBACK_DIAG")!=null) logFallbackCandidate(stmt, new CandidateKey(nodeID, caller, CandidateDomain.INTRO), relatedNodes.size());
							relatedNodes.put(stmt, nodeID);
						}
						// PHASE 2 SHADOW: per-candidate decision, using THIS candidate's own matched state
						// (specificallyMatched), not the shared relatedNodes.isEmpty() check above. This is
						// the order-INDEPENDENT fix for the §59 counterexample -- runs in parallel, changes
						// nothing observable in legacy output.
						{
							CandidateKey _introCandidate = new CandidateKey(nodeID, caller, CandidateDomain.INTRO);
							if(!specificallyMatched.contains(_introCandidate)) {
								recordShadowFallback(_introCandidate, stmt);
							}
						}
					}
				}
			}
		}
		
		//the stmt contains a source prop
		if(srcProp.containsKey(stmt)) {
			//get the property used in this statement
			List<Long> props = srcProp.get(stmt);
			for(Long propId: props) {
				ASTNode propNode=ASTUnderConstruction.idToNode.get(propId);
				//get the identity of the property
				String srcProp = getPropIdentity(propNode, caller);
				// OCCURRENCE-KEYED shadow candidate, per the §65 inventory: propId is the outer,
				// stmt-filtered occurrence -- the correct fallback candidate. Structurally identical to
				// INTRO's matchedForThisIntro pattern (§58.2's per-candidate approach applied here).
				CandidateKey _occCandidate = new CandidateKey(propId, caller, CandidateDomain.INTER_OCCURRENCE);
				boolean _occurrenceMatched = false;
				for(String interTaint: inter.keySet()) {
					if(check(srcProp, interTaint)) {
						// LEGACY PREDICATE UNCHANGED (check() against inter.keySet()) -- decides WHETHER to
						// match, exactly as before. What changes below is provenance EXPANSION: instead of
						// emitting one RelatedEvidence keyed to inter.get(interTaint) (the single surviving,
						// possibly-overwritten value), consult interEvidenceSidecar for every producer that
						// wrote this identity UNDER THE SAME CALLER CONTEXT (identity alone is NOT sufficient
						// -- §71.2 -- the sidecar is a single shared map across the whole traversal, and an
						// identity-only lookup would join provenance from unrelated invocations that happen to
						// share the same class::property string).
						if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=SOURCE_PROPERTY_MATCH stmt="+stmt+" related="+(propId)+" caller="+caller);
						relatedNodes.put(propId, inter.get(interTaint));   // legacy output UNCHANGED
						// SAFETY FIX (§73): identity+caller is CONFIRMED INSUFFICIENT to distinguish separate
						// occurrences sharing the same class::property identity in the same function (proven via
						// direct adversarial test -- two objects, same property name, same function). Collect
						// candidates FIRST; expand ONLY when exactly one is found (unambiguous). When 0 or 2+
						// match, fall back to the single legacy-value record -- CONSERVATIVE, not wrong, just
						// not richer. This does not fix the underlying discrimination gap (needs occurrence/
						// path-scoped producer tracking, not yet implemented) but it eliminates the CONFIRMED
						// contamination bug without reverting the entire feature.
						java.util.List<InterEvidence> _candidates = new java.util.ArrayList<InterEvidence>();
						for(InterEvidence _prod : interEvidenceSidecar.values()) {
							if(!_prod.identityNode.equals(interTaint)) continue;
							if(_prod.callerContext != caller) continue;
							_candidates.add(_prod);
						}
						// EXPERIMENTAL/DEFERRED (§74-75): default OFF. The ambiguity guard is confirmed safe for
						// the measured collision but NOT proven globally sound (a single-but-wrong candidate
						// would still pass silently). Root defect (occurrence/path info lost before the join)
						// is unresolved. Requires INTEREVIDENCE_EXPANSION=1 to even attempt expansion; without
						// it, every occurrence gets exactly the legacy single-value record, unconditionally.
						if(System.getenv("INTEREVIDENCE_EXPANSION")!=null && _candidates.size() == 1) {
							InterEvidence _prod = _candidates.get(0);
							{ RelatedEvidence _e = new RelatedEvidence(propId, _prod.provenanceNode, caller,
							  "SOURCE_PROPERTY_MATCH", null, "UNKNOWN");
							  relatedEvidenceSidecar.put(stmt+"|"+_e.key(), _e);
							  if(System.getenv("FALLBACK_DIAG")!=null)
								System.err.println("SPECIFIC_CANDIDATE_MATCH stmt="+stmt+" provenanceNode="+propId
									+" callerContext="+caller+" domain=INTER_OCCURRENCE relationKind=SOURCE_PROPERTY_MATCH"
									+" expandedProvenance="+_prod.provenanceNode+" unambiguous=true"); }
						} else {
							{ RelatedEvidence _e = new RelatedEvidence(propId, inter.get(interTaint), caller,
							  "SOURCE_PROPERTY_MATCH", null, "UNKNOWN");
							  relatedEvidenceSidecar.put(stmt+"|"+_e.key(), _e);
							  if(System.getenv("FALLBACK_DIAG")!=null)
								System.err.println("SPECIFIC_CANDIDATE_MATCH stmt="+stmt+" provenanceNode="+propId
									+" callerContext="+caller+" domain=INTER_OCCURRENCE relationKind=SOURCE_PROPERTY_MATCH"
									+" expandedProvenance=NONE_ambiguous_candidates="+_candidates.size()); }
						}
						_occurrenceMatched = true;
					}
				}
				if(_occurrenceMatched) {
					specificallyMatched.add(_occCandidate);   // marks the OCCURRENCE, not the origin
				} else if(System.getenv("FALLBACK_DIAG")!=null) {
					// SHADOW occurrence-keyed fallback -- replaces the earlier branch-level
					// FALLBACK_DOMAIN_STATUS telemetry (§62, now superseded per §66) with the correct
					// per-occurrence signal.
					recordShadowFallback(_occCandidate, stmt);
					System.err.println("FALLBACK_DOMAIN_STATUS stmt="+stmt+" provenanceNode="+propId
						+" callerContext="+caller+" domain=INTER_OCCURRENCE fallback_status=EVALUATED source=SOURCE_PROPERTY_MATCH");
				}
			}
		}
		
		//the stmt is a return statement and it returns a class, we directly get its identity from comments
		if(System.getenv("CRGUARD_DIAG")!=null) System.err.println("CRGUARD stmt="+stmt
			+" isReturnStmt="+(ASTUnderConstruction.idToNode.get(stmt) instanceof ReturnStatement)
			+" inter_keys="+inter.keySet());
		if(ASTUnderConstruction.idToNode.get(stmt) instanceof ReturnStatement) {
			//get the function of return statement
			ReturnStatement retNode = (ReturnStatement) ASTUnderConstruction.idToNode.get(stmt);
			Long funcId = retNode.getFuncId();
			if(System.getenv("CRGUARD_DIAG")!=null) System.err.println("CRGUARD funcId="+funcId
				+" retClsContainsKey="+PHPCGFactory.retCls.containsKey(funcId)
				+" retClsValue="+PHPCGFactory.retCls.get(funcId));
			//the function returns a class
			if(PHPCGFactory.retCls.containsKey(funcId)) {
				Long classID = PHPCGFactory.retCls.get(funcId);
				String srcProp = classID+"::-1";
				if(System.getenv("CRGUARD_DIAG")!=null) System.err.println("CRGUARD expectedKey="+srcProp
					+" keyPresentInInter="+inter.containsKey(srcProp));
				for(String interTaint: inter.keySet()) {
					if(check(srcProp, interTaint)) {
						if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=CLASS_RETURN_MATCH stmt="+stmt+" related="+((long) -1)+" caller="+caller);
						relatedNodes.put((long) -1, inter.get(interTaint));
						{ RelatedEvidence _e = new RelatedEvidence(-1L, inter.get(interTaint), caller,
						  "CLASS_RETURN_MATCH", null, "UNKNOWN");
						  CandidateKey _c = new CandidateKey(inter.get(interTaint), caller, CandidateDomain.INTER);
						  recordSpecificRelation(_c, _e, specificallyMatched, stmt); }
					}
				}
			}
		}
		
		//the stmt contains a source global variable
		if(System.getenv("SG_PIPELINE_DIAG")!=null && srcGlobal.containsKey(stmt)) {
			System.err.println("SG_CONSUMER_REACHED stmt="+stmt+" inter_keys="+inter.keySet());
		}
		if(srcGlobal.containsKey(stmt)) {
			List<Long> globals = srcGlobal.get(stmt);
			for(Long globalId: globals) {
				ASTNode globalNode = ASTUnderConstruction.idToNode.get(globalId);
				String srcGlobal = getDIMIdentity(globalNode);
				if(System.getenv("SG_PIPELINE_DIAG")!=null)
					System.err.println("SG_COMPARE stmt="+stmt+" globalId="+globalId+" srcGlobal_identity="+srcGlobal
						+" against_inter_keys="+inter.keySet());
				// OCCURRENCE-KEYED, confirmed empirically via SG_COMPARE trace on sgdg_flat (§68).
				CandidateKey _occCandidateSGM = new CandidateKey(globalId, caller, CandidateDomain.INTER_OCCURRENCE);
				boolean _occMatchedSGM = false;
				for(String interTaint: inter.keySet()) {
					if(interTaint.startsWith(srcGlobal) || srcGlobal.startsWith(interTaint)) {
						if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=SOURCE_GLOBAL_MATCH stmt="+stmt+" related="+(globalId)+" caller="+caller);
						relatedNodes.put(globalId, inter.get(interTaint));
						{ RelatedEvidence _e = new RelatedEvidence(globalId, inter.get(interTaint), caller,
						  "SOURCE_GLOBAL_MATCH", null, "UNKNOWN");
						  relatedEvidenceSidecar.put(stmt+"|"+_e.key(), _e);
						  if(System.getenv("FALLBACK_DIAG")!=null)
							System.err.println("SPECIFIC_CANDIDATE_MATCH stmt="+stmt+" provenanceNode="+globalId
								+" callerContext="+caller+" domain=INTER_OCCURRENCE relationKind=SOURCE_GLOBAL_MATCH"); }
						_occMatchedSGM = true;
					}
				}
				if(_occMatchedSGM) {
					specificallyMatched.add(_occCandidateSGM);
				} else if(System.getenv("FALLBACK_DIAG")!=null) {
					recordShadowFallback(_occCandidateSGM, stmt);
					System.err.println("FALLBACK_DOMAIN_STATUS stmt="+stmt+" provenanceNode="+globalId
						+" callerContext="+caller+" domain=INTER_OCCURRENCE fallback_status=EVALUATED source=SOURCE_GLOBAL_MATCH");
				}
			}
		}
		//the stmt contains a source global-declared variable (`global $g; ... $g ...`)
		if(srcGlobalVar.containsKey(stmt)) {
			for(Long gid: srcGlobalVar.get(stmt)) {
				String sid = getGlobalVarIdentity(ASTUnderConstruction.idToNode.get(gid));
				if(sid.equals("-1")) continue;
				if(System.getenv("FALLBACK_DIAG")!=null)
					System.err.println("DGM_COMPARE stmt="+stmt+" gid="+gid+" sid="+sid
						+" against_inter_keys="+inter.keySet());
				// OCCURRENCE-KEYED, confirmed empirically (not assumed from shape) via DGM_COMPARE trace.
				CandidateKey _occCandidateDGM = new CandidateKey(gid, caller, CandidateDomain.INTER_OCCURRENCE);
				boolean _occMatchedDGM = false;
				for(String interTaint: inter.keySet()) {
					if(interTaint.equals(sid)) {
						if(System.getenv("BRANCH_DIAG")!=null) System.err.println("BRANCH kind=DECLARED_GLOBAL_MATCH stmt="+stmt+" related="+gid+" caller="+caller);
						relatedNodes.put(gid, inter.get(interTaint));
						{ RelatedEvidence _e = new RelatedEvidence(gid, inter.get(interTaint), caller,
						  "DECLARED_GLOBAL_MATCH", null, "UNKNOWN");
						  relatedEvidenceSidecar.put(stmt+"|"+_e.key(), _e);
						  if(System.getenv("FALLBACK_DIAG")!=null)
							System.err.println("SPECIFIC_CANDIDATE_MATCH stmt="+stmt+" provenanceNode="+gid
								+" callerContext="+caller+" domain=INTER_OCCURRENCE relationKind=DECLARED_GLOBAL_MATCH"); }
						_occMatchedDGM = true;
					}
				}
				if(_occMatchedDGM) {
					specificallyMatched.add(_occCandidateDGM);
				} else if(System.getenv("FALLBACK_DIAG")!=null) {
					recordShadowFallback(_occCandidateDGM, stmt);
					System.err.println("FALLBACK_DOMAIN_STATUS stmt="+stmt+" provenanceNode="+gid
						+" callerContext="+caller+" domain=INTER_OCCURRENCE fallback_status=EVALUATED source=DECLARED_GLOBAL_MATCH");
				}
			}
		}
		
		return relatedNodes;
	}
	
	//check if two properties represent the same variable
	// FIX (2026-08-08): the "-1" branch used substring-containment on the raw stripped strings,
	// which conflates two DIFFERENT bugs' worth of "-1" usage into one crude check:
	//   (a) receiver="-1" (e.g. "-1::gateway") is a DELIBERATE unresolved-receiver wildcard --
	//       confirmed intentional, matches the documented receiver-insensitivity tradeoff.
	//   (b) property="-1" (e.g. classID+"::-1", constructed explicitly at the
	//       CLASS_RETURN_MATCH_WILDCARD call site) is a DELIBERATE property wildcard -- "this
	//       class, property unknown."
	// Substring-containment on the concatenated string made BOTH of these work by accident, but
	// ALSO let two textually-similar but semantically distinct properties collide: confirmed live
	// on business-directory-plugin, "-1::gateway" vs "-1::gateway_tx_id" stripped to "::gateway"
	// vs "::gateway_tx_id", and "::gateway_tx_id".contains("::gateway") is true -- two DIFFERENT
	// properties treated as the same because one name is a prefix of the other. Fixed by parsing
	// each side into (receiver, property) on the invariant "receiver::property" delimiter and
	// comparing each field independently: property must match EXACTLY unless one side's property
	// slot is literally "-1" (preserves the deliberate class-wildcard case); receiver must match
	// exactly unless one side's receiver slot is literally "-1" (preserves the deliberate
	// unresolved-receiver wildcard). A malformed shape (no "::") fails closed to false rather
	// than guessing -- this function's own default elsewhere.
	private boolean check(String srcProp, String interTaint) {
		if(srcProp.contains("-1") || interTaint.contains("-1")) {
			String[] a = splitPropRef(srcProp);
			String[] b = splitPropRef(interTaint);
			if (a == null || b == null) return false;
			boolean propertyOk = a[1].equals(b[1]) || a[1].equals("-1") || b[1].equals("-1");
			boolean receiverOk = a[0].equals(b[0]) || a[0].equals("-1") || b[0].equals("-1");
			return propertyOk && receiverOk;
		}
		else {
			if(srcProp.equals(interTaint)) {
				return true;
			}
		}
		return false;
	}

	// Splits a "receiver::property" identity string on the FIRST "::" occurrence. PHP identifiers
	// (variable/property names) and the numeric/"-1" receiver markers used throughout this file
	// cannot themselves contain "::" (it is PHP's own scope-resolution token), so splitting on
	// the first occurrence is unambiguous for every construction site this file uses
	// (getPropIdentity()/getDIMIdentity() results, and the explicit classID+"::-1"/classID+"::"+
	// propName patterns). Returns null (not a best-effort guess) if the shape doesn't match.
	private static String[] splitPropRef(String s) {
		int idx = s.indexOf("::");
		if (idx < 0) return null;
		return new String[]{ s.substring(0, idx), s.substring(idx + 2) };
	}
	
	
	//get the identity of property variable
	/*
	 * @param: propert ast ID, caller
	 * @return: the identity of the property. e.g., $a->b=>astnode(a)::b; returns -1 if cannot get the identity
	 */
	// ITEM49 FIX: getPropIdentity() previously scanned ASTUnderConstruction.idToNode.values() --
	// every node in the ENTIRE corpus -- once per call, filtered down to "$var = new ClassName()"
	// assignments in the SAME function as the property's receiver variable. Confirmed via live
	// jstack capture (ITEM48) as a genuine hot path: seedPropertyTaintSources() calls this once per
	// property-access node in the corpus (2 loop sites), each call re-scanning the whole corpus.
	// O(properties x corpus_size). Fix indexes the SEARCH INPUTS ONCE (which assignments, in which
	// function, have a Variable LHS and a NewExpression RHS) -- NOT the final per-property identity
	// answer, since that answer depends on caller-specific state (varName, receiver-class
	// resolution via ParseVar, retCls, constructor info) that isn't safe to memoize blindly. The
	// per-call resolution logic below (varName matching, static/self resolution, getClassId) is
	// otherwise UNCHANGED from the original -- only the source of the candidate list changed, from
	// "every corpus node" to "this function's pre-indexed new-expression assignments".
	private static java.util.HashMap<Long, java.util.List<AssignmentExpression>> propIdentNewExprAssignByFunc = null;

	private static void buildPropIdentIndexIfNeeded() {
		if( propIdentNewExprAssignByFunc != null ) return;
		propIdentNewExprAssignByFunc = new java.util.HashMap<Long, java.util.List<AssignmentExpression>>();
		for( ASTNode a : ASTUnderConstruction.idToNode.values() ) {
			if( !(a instanceof AssignmentExpression) ) continue;
			Expression lhs = ((AssignmentExpression)a).getLeft();
			Expression rhs = ((AssignmentExpression)a).getRight();
			if( lhs == null || rhs == null ) continue;
			if( !(lhs instanceof Variable) ) continue;
			if( !(rhs instanceof ast.expressions.NewExpression) ) continue;
			Long fid = a.getFuncId();
			if( fid == null ) continue;
			java.util.List<AssignmentExpression> l = propIdentNewExprAssignByFunc.get(fid);
			if( l == null ) { l = new java.util.ArrayList<AssignmentExpression>(); propIdentNewExprAssignByFunc.put(fid, l); }
			l.add((AssignmentExpression)a);
		}
	}

	// Instrumentation, per ITEM49's acceptance criteria. PI_fallbackScans specifically counts
	// disagreements between the new indexed lookup and the original raw-scan logic, verified via
	// WP_VERIFY_PROP_INDEX=1 (which runs BOTH and compares on every call -- expensive, for testing
	// only, never enabled in normal operation). The acceptance target is 0 disagreements on real
	// corpora, proving the index is a faithful pre-filter of the original scan rather than assumed.
	public static long PI_calls = 0, PI_indexedHits = 0, PI_fallbackScans = 0, PI_unresolved = 0;

	private static String legacyPropIdentAssignScan(Long fid, String varName) {
		// Byte-for-byte the original pre-ITEM49 scan logic, kept ONLY as a verification oracle
		// for WP_VERIFY_PROP_INDEX=1 -- never called in normal operation.
		for( ASTNode a : ASTUnderConstruction.idToNode.values() ) {
			if( !(a instanceof AssignmentExpression) ) continue;
			if( !fid.equals(a.getFuncId()) ) continue;
			Expression lhs = ((AssignmentExpression)a).getLeft();
			Expression rhs = ((AssignmentExpression)a).getRight();
			if( lhs == null || rhs == null ) continue;
			if( !(lhs instanceof Variable) ) continue;
			String lhsName = ((Variable)lhs).getNameExpression() != null
				? ((Variable)lhs).getNameExpression().getEscapedCodeStr() : null;
			if( !varName.equals(lhsName) ) continue;
			if( !(rhs instanceof ast.expressions.NewExpression) ) continue;
			Expression classNameNode = ((ast.expressions.NewExpression)rhs).getTargetClass();
			if( classNameNode == null ) continue;
			if( !"AST_NAME".equals(classNameNode.getProperty("type")) ) continue;
			String cls = ((ast.expressions.StringExpression)((ast.expressions.Identifier)classNameNode).getNameChild()).getEscapedCodeStr();
			if( cls == null ) continue;
			if( "static".equals(cls) || "self".equals(cls) ) cls = rhs.getEnclosingClass();
			Long cid = PHPCGFactory.getClassId(cls, classNameNode.getNodeId(), rhs.getEnclosingNamespace());
			if( cid != null && cid != -1 ) return cid.toString();
		}
		return "-1";
	}

	private String getPropIdentity(ASTNode node, Long caller) {
		if(node instanceof PropertyExpression) {
			String objValue="-1", propValue="*";
			
			//get prop's class
			Expression objNode = ((PropertyExpression) node).getObjectExpression();
			String type = objNode.getProperty("type");
			switch(type) {
			//$this->prop
			case "AST_VAR":
				if(((Variable) objNode).getNameExpression().getEscapedCodeStr()==null) {
					System.out.println("2887: "+objNode.getNodeId());
				}
				else if(((Variable) objNode).getNameExpression().getEscapedCodeStr().equals("this")) {
					objValue = objNode.getEnclosingClass();
					String namespace = objNode.getEnclosingNamespace();
					objValue = PHPCGFactory.getClassId(objValue, objNode.getNodeId(), namespace).toString();
				}
				break;
			//func()->prop
			case "AST_CALL":
			case "AST_METHOD_CALL":
			case "AST_STATIC_CALL":
				if(PHPCGFactory.call2mtd.containsKey(objNode.getNodeId())) {
					Long targetFuncID = PHPCGFactory.call2mtd.get(objNode.getNodeId()).get(0);
					if(PHPCGFactory.retCls.containsKey(targetFuncID)){
						objValue = PHPCGFactory.retCls.get(targetFuncID).toString(); 
					}
				}
				break;
			
			}
			//we do not know the objValue yet, thus we parse its value
			if(objValue.equals("-1")) {
				PI_calls++;
				// Strategy 1: scan assignments in the same function for $var = new ClassName()
				// This handles the common case: $w = new Widget(); $w->prop without relying
				// on ParseVar's class-tracking which can return stale/indirect results.
				if(objNode instanceof Variable) {
					String varName = ((Variable)objNode).getNameExpression() != null
						? ((Variable)objNode).getNameExpression().getEscapedCodeStr() : null;
					Long fid = objNode.getFuncId();
					if(varName != null && fid != null) {
						buildPropIdentIndexIfNeeded();
						java.util.List<AssignmentExpression> candidates =
							propIdentNewExprAssignByFunc.get(fid);
						String indexedResult = "-1";
						if( candidates != null ) {
							outer:
							for(AssignmentExpression a : candidates) {
								Expression lhs = a.getLeft();
								Expression rhs = a.getRight();
								String lhsName = ((Variable)lhs).getNameExpression() != null
									? ((Variable)lhs).getNameExpression().getEscapedCodeStr() : null;
								if(!varName.equals(lhsName)) continue;
								Expression classNameNode = ((ast.expressions.NewExpression)rhs).getTargetClass();
								if(classNameNode == null) continue;
								if(!"AST_NAME".equals(classNameNode.getProperty("type"))) continue;
								String cls = ((ast.expressions.StringExpression)((ast.expressions.Identifier)classNameNode).getNameChild()).getEscapedCodeStr();
								if(cls == null) continue;
								if("static".equals(cls) || "self".equals(cls)) cls = rhs.getEnclosingClass();
								Long cid = PHPCGFactory.getClassId(cls, classNameNode.getNodeId(),
									rhs.getEnclosingNamespace());
								if(cid != null && cid != -1) { indexedResult = cid.toString(); break outer; }
							}
						}
						if( System.getenv("WP_VERIFY_PROP_INDEX") != null ) {
							String legacyResult = legacyPropIdentAssignScan(fid, varName);
							if( !indexedResult.equals(legacyResult) ) {
								PI_fallbackScans++;
								System.err.println("PROP_IDENTITY_MISMATCH fid=" + fid + " varName=" + varName
									+ " indexed=" + indexedResult + " legacy=" + legacyResult);
								indexedResult = legacyResult; // trust the verified-correct legacy path if they disagree
							}
						}
						if( !indexedResult.equals("-1") ) { objValue = indexedResult; PI_indexedHits++; }
					}
				}
				// Strategy 2: ParseVar trace (handles call-return class resolution)
				if(objValue.equals("-1")) {
					ParseVar parsevar = new ParseVar();
					parsevar.init(1, true, "");
					Set<String> classValues = parsevar.IntroDataflow(objNode.getNodeId());
					String className = classValues.isEmpty() ? "-1" : classValues.iterator().next();
					if(className.startsWith("$")) {
						try {
							Long classId = Long.parseLong(className.substring(1, className.length() - 1));
							ASTNode classNode = ASTUnderConstruction.idToNode.get(classId);
							if(classNode instanceof CallExpressionBase) {
								if(PHPCGFactory.call2mtd.containsKey(classNode.getNodeId())) {
									Long targetFuncID = PHPCGFactory.call2mtd.get(classNode.getNodeId()).get(0);
									if(PHPCGFactory.retCls.containsKey(targetFuncID)){
										objValue = PHPCGFactory.retCls.get(targetFuncID).toString();
									}
								}
							}
							// Handle AST_NEW case: classNode is the new-expression itself
							if(objValue.equals("-1") && classNode instanceof ast.expressions.NewExpression) {
								Expression cn = ((ast.expressions.NewExpression)classNode).getTargetClass();
								if(cn != null && "AST_NAME".equals(cn.getProperty("type"))) {
									String clsN = ((ast.expressions.StringExpression)((ast.expressions.Identifier)cn).getNameChild()).getEscapedCodeStr();
									if("static".equals(clsN)||"self".equals(clsN)) clsN = classNode.getEnclosingClass();
									Long cid = PHPCGFactory.getClassId(clsN, cn.getNodeId(), classNode.getEnclosingNamespace());
									if(cid != null && cid != -1) objValue = cid.toString();
								}
							}
						} catch(Exception e) {}
					} else {
						objValue = className;
					}
				}
				if(objValue.equals("-1")) PI_unresolved++;
			}
			
			//get prop's name
			Expression propNode = ((PropertyExpression) node).getPropertyExpression();
			//the prop name is an identifier
			if(propNode.getProperty("type").equals("string")) {
				propValue = propNode.getEscapedCodeStr();
			}
			//the prop name is a variable and it is assigned by the parameter
			else if(propNode.getProperty("type").equals("AST_VAR")) {
				//get the variable name of prop
				String varName = ((Variable) propNode).getNameExpression().getEscapedCodeStr();
				//get prop variable's function
				FunctionDef currentFunc = (FunctionDef) ASTUnderConstruction.idToNode.get(propNode.getFuncId());
				ParameterList paramList = currentFunc.getParameterList();
				//we do not know the property name
				if(paramList==null) {
					System.out.println("null param: "+currentFunc.getNodeId());
					return "-2";
				}
				for(int i=0; i<paramList.size(); i++) {
					Parameter param = (Parameter) paramList.getParameter(i);
					String paramName = param.getName();
					//i'th param name is equal to prop's variable name
					if(paramName.equals(varName) && caller!=0) {
						ASTNode callerAst = ASTUnderConstruction.idToNode.get(caller);
						if( !(callerAst instanceof CallExpressionBase) ) {
							// `caller` in this traversal context isn't actually a call-site node
							// (e.g. it's an AssignmentExpression or other context node) -- there is
							// no argument list to resolve this parameter's value against. Crashed
							// the whole analysis with an unguarded cast here on real-world code
							// (confirmed on Smush 4.2.0); stay conservative instead, matching the
							// existing "-2" (unknown identity) sentinel already used above for the
							// paramList==null case, rather than assume a shape that isn't there.
							return "-2";
						}
						CallExpressionBase callerNode = (CallExpressionBase) callerAst;
						ArgumentList argList = (ArgumentList) callerNode.getArgumentList();
						//get the i'th argument value
						if(i>=argList.size()) {
							break;
						}
						Expression arg = argList.getArgument(i);
						if(arg.getProperty("type").equals("string")) {
							propValue = arg.getEscapedCodeStr();
						}
					}
				}
			}
			
			//we at least know the prop name
			if(!propValue.equals("*")) {
				return objValue+"::"+propValue;
			}
		}
		return "-2";
	}
	
	//get the identity of DIM variable
	/*
	 * @param: node($a[b][c])
	 * @return a$b$c
	 */
	// $_FILES[*]['tmp_name'|'size'|'error'] are populated by PHP, not the attacker (only ['name']
	// and ['type'] carry the uploaded filename / client MIME). The inline-source check would
	// otherwise treat the always-present move_uploaded_file($_FILES[..]['tmp_name'], ...) argument
	// (and its structural inner $_FILES[field] dim) as user input and flag every upload. Suppress
	// any $_FILES-rooted dim whose own key is not 'name'/'type'; ['name']/['type'] and any non-$_FILES
	// dim are left untouched, so this is FN-free for real arbitrary-upload bugs (destination built
	// from ['name']).
	private boolean isBenignFilesSubfield(ASTNode node) {
		if(!(node instanceof ArrayIndexing)) return false;
		ast.expressions.Expression base = ((ArrayIndexing) node).getArrayExpression();
		while(base instanceof ArrayIndexing) base = ((ArrayIndexing) base).getArrayExpression();
		boolean rootIsFiles = base instanceof Variable
			&& ((Variable) base).getNameExpression() instanceof StringExpression
			&& "_FILES".equals(((StringExpression) ((Variable) base).getNameExpression()).getEscapedCodeStr());
		if(!rootIsFiles) return false;
		ast.expressions.Expression idx = ((ArrayIndexing) node).getIndexExpression();
		if(idx instanceof StringExpression) {
			String key = ((StringExpression) idx).getEscapedCodeStr();
			if("name".equals(key) || "type".equals(key)) return false;   // attacker-controlled -> keep
		}
		return true;   // $_FILES-rooted but not ['name']/['type'] -> structural/server -> suppress
	}

	// identity for a `global $g;` variable: globals are a flat namespace, so the bare name suffices.
	private String getGlobalVarIdentity(ASTNode node) {
		if(node instanceof Variable && ((Variable) node).getNameExpression() != null) {
			String nm = ((Variable) node).getNameExpression().getEscapedCodeStr();
			if(nm != null && !nm.isEmpty()) return "GVAR::" + nm;
		}
		return "-1";
	}

	public String getDIMIdentity(ASTNode node) {
		//$a[b][c], we do not return $a or $a[b], instead we only return $a[b][c]
		if(PHPCSVEdgeInterpreter.child2parent.containsKey(node.getNodeId())) {
			//the the parent of DIM variable
			ASTNode parent = ASTUnderConstruction.idToNode.get(PHPCSVEdgeInterpreter.child2parent.get(node.getNodeId()));
			//DIM's parent is a a DIM variable
			if(parent instanceof ArrayIndexing) {
				return "-1";
			}
		}
		while(node instanceof ArrayIndexing) {
			node = ((ArrayIndexing) node).getArrayExpression();
		}
		//AST_DIM. AST_VAR, AST_NAME
		Long constantId = node.getNodeId()+2;
		String identity="";
		while(true) {
			if(!ASTUnderConstruction.idToNode.containsKey(constantId)) {
				return "-1";
			}
			ASTNode constant = ASTUnderConstruction.idToNode.get(constantId);
			if(constant.getEscapedCodeStr()==null || constant.getEscapedCodeStr().isEmpty()) {
				break;
			}
			identity = identity+constant.getEscapedCodeStr()+"$";
			constantId = constantId+1;
		}
		//fail to get DIM identity
		if(identity.equals("")) {
			return "-1";
		}
		return identity;
	} 

	//get the statement of taint node
	/*
	 * @param: astID
	 * @return: <statement, stmtList>
	 */
	private Long getStatement(Long astId) {
		while(true) {
			//check if astId is cfg node
			if(cfgNode.contains(astId)) {
				return astId;
			}
			//get astId's parent
			if(!PHPCSVEdgeInterpreter.child2parent.containsKey(astId)) {
				return null;
			}
			astId = PHPCSVEdgeInterpreter.child2parent.get(astId);
			//check if the ast node is a CFG node
		}
	}
}







