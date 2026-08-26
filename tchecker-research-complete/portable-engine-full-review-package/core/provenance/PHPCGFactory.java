package cg;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import ast.ASTNode;
import ast.expressions.BinaryOperationExpression;
import ast.expressions.CallExpressionBase;
import ast.expressions.Expression;
import ast.expressions.Identifier;
import ast.expressions.NewExpression;
import ast.expressions.AssignmentExpression;
import ast.expressions.ArrayIndexing;
import ast.expressions.Constant;
import ast.expressions.ClassConstantExpression;
import ast.statements.blockstarters.ForEachStatement;
import ast.php.statements.ConstantElement;
import ast.expressions.PropertyExpression;
import ast.expressions.StaticPropertyExpression;
import ast.expressions.StringExpression;
import ast.expressions.ConditionalExpression;
import ast.logical.statements.CompoundStatement;
import ast.php.statements.blockstarters.IfElement;
import ast.php.statements.blockstarters.SwitchCase;
import ast.expressions.Variable;
import ast.functionDef.FunctionDefBase;
import ast.functionDef.ParameterList;
import ast.php.declarations.ClassDef;
import ast.php.expressions.ArrayElement;
import ast.php.expressions.ArrayExpression;
import ast.php.expressions.IncludeOrEvalExpression;
import ast.php.expressions.MethodCallExpression;
import ast.php.expressions.StaticCallExpression;
import ast.php.functionDef.Closure;
import ast.expressions.ArgumentList;
import ast.php.expressions.EncapsListExpression;
import ast.php.functionDef.Method;
import ast.php.functionDef.Parameter;
import ast.php.functionDef.FunctionDef;
import ast.php.functionDef.TopLevelFunctionDef;
import inputModules.csv.PHPCSVNodeTypes;
import inputModules.csv.csv2ast.ASTUnderConstruction;
import misc.MultiHashMap;
import tools.php.ast2cpg.PHPCSVEdgeInterpreter;

public class PHPCGFactory {

	// ---- fields recovered from Jul-31 base ----
	private static final java.util.Set<String> JSON_ESCAPERS = new java.util.HashSet<String>(
		java.util.Arrays.asList("wp_json_encode","json_encode"));
	public static java.util.HashMap<Long,String> retBufferedFids = new java.util.HashMap<Long,String>();
	public static java.util.HashMap<Long,String> retSafeContext = new java.util.HashMap<Long,String>();
	public static java.util.Set<Long> retSafeFids = new java.util.HashSet<Long>();
	private static java.util.Set<String> wpdbAccessorMethods = new java.util.HashSet<String>();

	// maintains a map of known function names (e.g., "B\foo" -> function foo() in namespace B)
	private static MultiHashMap<String,FunctionDef> functionDefs = new MultiHashMap<String,FunctionDef>();
	// maintains a list of function calls
	private static LinkedList<CallExpressionBase> functionCalls = new LinkedList<CallExpressionBase>();
	
	// maintains a map of known static method names (e.g., "B\A::foo" -> static function foo() in class A in namespace B)
	private static MultiHashMap<String,Method> staticMethodDefs = new MultiHashMap<String,Method>();
	// maintains a list of static method calls
	private static LinkedList<StaticCallExpression> staticMethodCalls = new LinkedList<StaticCallExpression>();
	
	// maintains a map of known constructors (e.g., "B\A" -> static function __construct() in class A in namespace B)
	public static MultiHashMap<String,Method> constructorDefs = new MultiHashMap<String,Method>();
	public static MultiHashMap<String,Method> constructorNameDefs = new MultiHashMap<String,Method>();
	//maintains a map of known destructors
	public static MultiHashMap<String, Method> destructorDefs = new MultiHashMap<String,Method>();
	// maintains a list of static method calls
	private static LinkedList<NewExpression> constructorCalls = new LinkedList<NewExpression>();
	
	//Full name=>methodDef AST node
	private static MultiHashMap<String,Method> nonStaticMethodDefs = new MultiHashMap<String,Method>();
	//method name=>methodDef AST node
	private static MultiHashMap<String,Method> nonStaticMethodNameDefs = new MultiHashMap<String,Method>();
	//maintains a list of non-static method calls
	private static LinkedList<MethodCallExpression> nonStaticMethodCalls = new LinkedList<MethodCallExpression>();
	//resolve variable value
	private static HashMap<String, Long> topLevelFunctionDefs = new HashMap<String, Long>();
	
	//private static ParseVar parsevar = new ParseVar();
	public static HashMap<String, Long> classDef = new HashMap<String, Long>();
	public static MultiHashMap<Long, Long> inhe = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> ch2prt = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> prt2ch = new MultiHashMap<Long, Long>();
	//MethodDef node id => return classDef node id 
	public static HashMap<Long, Long> ret = new HashMap<Long, Long>();
	public static MultiHashMap<Long, Long> call2mtd = new MultiHashMap<Long, Long>();
	// Gate 6: frontend-provided call-resolution facts.  This sidecar is intentionally
	// separate from call2mtd so AMBIGUOUS/UNRESOLVED facts are not flattened into hard
	// legacy call edges.  Only EXACT facts are admitted to call2mtd, and even then via
	// addCallEdge() so the engine's existing arity/vendor/test guards still apply.
	public static java.util.HashMap<Long,String> frontendCallResolution = new java.util.HashMap<Long,String>();
	public static MultiHashMap<Long,Long> frontendCallTargets = new MultiHashMap<Long,Long>();
	public static java.util.HashMap<String,Integer> frontendResolutionCounts = new java.util.HashMap<String,Integer>();
	// Gate 11: frontend/state-model return-dependency summaries. Kept separate from the
	// legacy return summary computation and applied only when explicitly enabled. A row
	// marked COMPLETE means the frontend has a receiver-sensitive state proof for the
	// function return and may replace the legacy param-position summary for that fid.
	public static java.util.HashMap<Long, Set<Integer>> frontendStateReturnPositions = new java.util.HashMap<Long, Set<Integer>>();
	public static java.util.HashSet<Long> frontendStateReturnComplete = new java.util.HashSet<Long>();
	public static java.util.HashMap<Long, Set<Integer>> frontendClosureReturnPositions = new java.util.HashMap<Long, Set<Integer>>();
	public static java.util.HashSet<Long> frontendClosureReturnComplete = new java.util.HashSet<Long>();
	// Gate 14: parallel uncertain return-provenance channel. These facts NEVER enter
	// returnTaintPositions/returnTaintAnalyzed; consumers must opt into uncertainty explicitly.
	public static java.util.HashMap<Long, Set<Integer>> frontendStateReturnMayPositions = new java.util.HashMap<Long, Set<Integer>>();
	public static java.util.HashMap<Long, String> frontendStateReturnMayResolution = new java.util.HashMap<Long, String>();
	public static java.util.HashMap<Long, Set<Integer>> returnMayTaintPositions = new java.util.HashMap<Long, Set<Integer>>();
	public static java.util.HashMap<Long, String> returnMayTaintResolution = new java.util.HashMap<Long, String>();
	// Return-taint summary (interproc): fid -> param positions whose value flows (unsanitized)
	// into a `return`. Lets a caller's `$v = f($tainted)` propagate taint to $v when the
	// tainted arg lands on a return-relevant position. Mirrors the wrapper param-derived model.
	public static HashMap<Long, Set<Integer>> returnTaintPositions = new HashMap<Long, Set<Integer>>();
	// Distinguishes "analyzed, and no parameter position taints the return" (safe to trust) from
	// "never analyzed" (unresolved/external/no-return function -- must stay conservative). A fid
	// missing from returnTaintPositions is ambiguous between these two on its own; this set resolves
	// the ambiguity. Populated only alongside returnTaintPositions, by the same computation.
	public static Set<Long> returnTaintAnalyzed = new HashSet<Long>();
	// Snapshot collectUnsanitizedVarNames() actually reads when consulting a callee's return-taint
	// summary. During the fixed-point computation below these are swapped to the PREVIOUS pass's
	// stable results before each new pass (so a single pass's results are internally consistent and
	// don't depend on HashMap iteration order); once the fixed point is reached they're set to the
	// final, fully-converged values so every other caller of collectUnsanitizedVarNames elsewhere in
	// the codebase benefits from the same precision.
	private static HashMap<Long, Set<Integer>> returnTaintConsultPositions = new HashMap<Long, Set<Integer>>();
	private static Set<Long> returnTaintConsultAnalyzed = new HashSet<Long>();
	// Wrapper risky positions (interproc): wrapper fid -> param positions whose value reaches a
	// $wpdb sink UNSANITIZED inside the wrapper. A tainted argument at a NON-risky position (one the
	// wrapper sanitizes internally, e.g. esc_sql, or that never reaches the sink) cannot inject, so
	// only risky-position args make a wrapper call a live sink. FN-safe by default: a position is
	// treated as risky unless the param-derivation closure proves it never reaches a sink unsanitized.
	public static HashMap<Long, Set<Integer>> wrapperRiskyPositions = new HashMap<Long, Set<Integer>>();
	// Per wrapper-call-site: the set of ARGUMENT node ids that sit at a risky position of the
	// wrapper being called. Consumed by the dataflow sink check so a tainted argument at a
	// non-risky (internally-sanitized) position does not flag the call. Empty set => wrapper is
	// known but has no risky positions; absent key => not a position-modeled wrapper call (the
	// sink check then falls back to the default whole-call behavior — FN-safe).
	public static HashMap<Long, Set<Long>> wrapperCallRiskyArgs = new HashMap<Long, Set<Long>>();
	public static MultiHashMap<Long, Long> mtd2call = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> mtd2mtd = new MultiHashMap<Long, Long>();
	public static LinkedList<Long> collectAllFun = new LinkedList<Long>();
	public static MultiHashMap<String, Long> globalMap = new MultiHashMap<String, Long>();
	public static Set<Long> func_get_args = new HashSet<Long>();
	public static Set<Long> call_user = new HashSet<Long>();
	private final static Lock lock = new ReentrantLock();
	private final static Lock lockC = new ReentrantLock();
	private final static Lock lockp = new ReentrantLock();
	
	//public static MultiHashMap<Long, Long> parentCall = new MultiHashMap<Long, Long>();
	//public static MultiHashMap<Long, String> collectThis = new MultiHashMap<Long, String>();
	//public static MultiHashMap<Long, String> collectParent = new MultiHashMap<Long, String>();;
	public static Set<Long> topFunIds = new HashSet<Long>();
	//private static MultiHashMap<Long, Long> func2cls = new MultiHashMap<Long, Long>();
	public static Set<Long> magicMtdDefs = new HashSet<Long>();  
	public static Set<String> classUsed = new HashSet<String>();
	public static MultiHashMap<String, Long> fullname2Id = new MultiHashMap<String, Long>();
	public static MultiHashMap<String, Long> name2Id = new MultiHashMap<String, Long>();
	public static int callsiteNumber = 0;
	//public static int unknownCallsite = 0;
	public static Set<Long> unknownIds = new HashSet<Long>();
	//public static HashMap<Long, Set<Long>> cls2Allcls = new HashMap<Long, Set<Long>>();
	public static HashMap<Long, Long> ignoreIds = new HashMap<Long, Long>();
	public static Set<Long> allFuncDef = new HashSet<Long>();
	public static int omit=0;
	public static Set<Long> omitIds = new HashSet<Long>();
	public static HashMap<String, Long> path2TopFile = new HashMap<String, Long>();
	public static Set<String> removed = new HashSet<String>();
	//public static HashMap<Long, String> topIdcache= new HashMap<Long, String>();
	public static MultiHashMap<String, String> filepaths = new MultiHashMap<String, String>();
	public static HashMap<Long, String> id2Name = new HashMap<Long, String>();
	
	//public static Map<Long, Long> howmany = new TreeMap<Long, Long>();
	public static MultiHashMap<Long, String> allUse = new MultiHashMap<Long, String>();
	
	public static Set<String> initial = new HashSet<String>();
	public static Set<Long> suspicious = new HashSet<Long>();
	
	public static Set<Long> Abstract = new TreeSet<Long>();
	
	//public static MultiHashMap<String, FunctionDef> name2Def = new MultiHashMap<String, FunctionDef>();
	
	//public static int entry=0, dependent=0;
	public static Set<Long> removeId = new HashSet<Long>();
	public static int topsum = 0;
	public static Set<Long> condes = new HashSet<Long>();
	public static HashMap<Long, Long> paramCls = new HashMap<Long, Long>();
	public static HashMap<Long, Long> retCls = new HashMap<Long, Long>();
	//public static Set<String> indirect = new HashSet<String>();
	public static HashSet<Long> sinks = new HashSet<Long>();
	public static List<Long> objCaller = new ArrayList<Long>();
	//public static MultiHashMap<Long, Long> file2file = new MultiHashMap<Long, Long>();
	public static MultiHashMap<Long, Long> callee2caller = new MultiHashMap<Long, Long>();
	//public static HashMap<Long, String> caller2path = new HashMap<Long, String>();
	public static HashSet<String> bwlines = new HashSet<String>();
	public static MultiHashMap<String, Long> path2callee = new MultiHashMap<String, Long>();
	public static HashSet<String> entrypoint = new HashSet<String>();
	public static HashSet<Long> allFunc = new HashSet<Long>();
	public static HashSet<Long> allStaticMtd = new HashSet<Long>();
	public static HashSet<Long> allMtd = new HashSet<Long>();
	public static HashSet<Long> allConstructor = new HashSet<Long>();
	
	//public static Set<FunctionDef> constructSet = new HashSet<FunctionDef>();
	/**
	 * Creates a new CG instance based on the lists of known function definitions and function calls.
	 * 
	 * Call this after all function definitions and calls have been added to the lists using
	 * addFunctionDef(FunctionDef) and addFunctionCall(CallExpression).
	 * 
	 * After a call graph has been constructed, these lists are automatically reset.
	 * 
	 * @return A new call graph instance.
	 */
	// Names that are aliases of $wpdb, e.g. via  $_db = $wpdb;  self::$_db = $wpdb;
	// $this->wpdb = $wpdb;  Populated by collectWpdbAliases() before sink detection.
	private static java.util.Set<String> wpdbAliases = new java.util.HashSet<String>();

	// Extract a simple receiver name from a method-call target object:
	//   $wpdb            (Variable)            -> "wpdb"
	//   $_db             (Variable)            -> "_db"
	//   $this->wpdb      (PropertyExpression)  -> "wpdb"   (the property name)
	//   self::$_db       (StaticPropertyExpression) -> "_db"
	private static String receiverName(Expression target) {
		if( target instanceof Variable
			&& ((Variable)target).getNameExpression() instanceof StringExpression) {
			return ((StringExpression)((Variable)target).getNameExpression()).getEscapedCodeStr();
		}
		if( target instanceof PropertyExpression ) {
			Expression p = ((PropertyExpression)target).getPropertyExpression();
			if( p instanceof StringExpression ) return ((StringExpression)p).getEscapedCodeStr();
			if( p instanceof Variable
				&& ((Variable)p).getNameExpression() instanceof StringExpression )
				return ((StringExpression)((Variable)p).getNameExpression()).getEscapedCodeStr();
		}
		if( target instanceof StaticPropertyExpression ) {
			Expression p = ((StaticPropertyExpression)target).getPropertyExpression();
			if( p instanceof StringExpression ) return ((StringExpression)p).getEscapedCodeStr();
			if( p instanceof Variable
				&& ((Variable)p).getNameExpression() instanceof StringExpression )
				return ((StringExpression)((Variable)p).getNameExpression()).getEscapedCodeStr();
		}
		return "";
	}

	// Enclosing class name of an AST node (via its containing function/method). Returns null if not
	// inside a method. Used to scope receiver-type resolution to the dispatch's own class, so that
	// `$this->commands` in class A does not pick up `$this->commands = new B()` written in class C.
	private static String enclosingClassName(ASTNode n) {
		try {
			Long fid = n.getFuncId();
			ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
			if( fn instanceof Method ) return ((Method)fn).getEnclosingClass();
		} catch(Exception e) {}
		return null;
	}

	// True if the method-call receiver is $wpdb or a known alias of it.
	private static boolean receiverIsWpdb(Expression target) {
		String n = receiverName(target);
		return n.equals("wpdb") || wpdbAliases.contains(n);
	}

	// ---- Context-sensitive esc_sql (CVE-2021-24340 class) ----------------------
	// esc_sql() only neutralizes a value placed INSIDE SQL string quotes. In an
	// unquoted (e.g. numeric) context — `WHERE id = " . esc_sql($x)` — escaping the
	// quote characters accomplishes nothing and the value is still injectable. The
	// parser adds every esc_sql call to sqlSanitizers unconditionally; below we walk
	// a $wpdb sink's query argument and DROP any esc_sql call that sits in an unquoted
	// concat position, so its taint is no longer cleared and the flow is reported.
	// Limitation: only inline esc_sql(...) within the sink's concat is judged; esc_sql
	// applied to a value through an intermediate variable is not yet context-checked.
	private static Long escSqlCallNode(Expression e) {
		if( e instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)e).getTargetFunc();
			if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null ) {
				String nm = ((Identifier)tf).getNameChild().getEscapedCodeStr();
				if( "esc_sql".equals(nm) || inferredQuoteEscapers.contains(nm) ) return e.getNodeId();
			}
		}
		return null;
	}

	// Rightmost string-literal value of a (possibly nested-concat) expression, or null.
	private static String rightmostLiteral(Expression e) {
		if( e == null ) return null;
		if( e instanceof StringExpression ) return ((StringExpression)e).getEscapedCodeStr();
		if( e instanceof BinaryOperationExpression
			&& "BINARY_CONCAT".equals(((BinaryOperationExpression)e).getFlags()) ) {
			String r = rightmostLiteral(((BinaryOperationExpression)e).getRight());
			return (r != null) ? r : rightmostLiteral(((BinaryOperationExpression)e).getLeft());
		}
		return null;
	}

	// True if the literal preceding the inserted value closes inside a quote, i.e. the
	// value lands in quoted string context (where esc_sql is actually effective).
	private static boolean inQuotedContext(String lit) {
		if( lit == null ) return false;          // unknown left context -> treat as unquoted
		int end = lit.length();
		while( end > 0 && Character.isWhitespace(lit.charAt(end-1)) ) end--;
		return end > 0 && lit.charAt(end-1) == '\'';
	}

	// Global pass: demote every unquoted inline esc_sql across ALL concat expressions,
	// not only those that are directly a sink argument. This covers queries assembled
	// into a variable first, e.g.  $sql = "... id = " . esc_sql($id);  $wpdb->query($sql).
	private static void demoteAllUnquotedEscSql() {
		PHPCGFactory.recordScanSite("PCG_302", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof BinaryOperationExpression) ) continue;
			BinaryOperationExpression bin = (BinaryOperationExpression) n;
			if( !"BINARY_CONCAT".equals(bin.getFlags()) ) continue;
			Long esc = escSqlCallNode(bin.getRight());
			if( esc != null && !inQuotedContext(rightmostLiteral(bin.getLeft())) ) {
				PHPCSVEdgeInterpreter.sqlSanitizers.remove(esc);
				System.err.println("WPUNQUOTED esc_sql node "+esc+" demoted (unquoted SQL context)");
			}
		}
	}

	// ---- Inferred user-defined sanitizers (prove-before-recognize) ----------------
	// A user function is recognized as an INTEGER sanitizer iff EVERY return is provably
	// integer: intval/absint/(int) cast / integer literal / a bare $v returned only inside
	// an if(ctype_digit($v)) guard / a call to an already-inferred int sanitizer. Integers
	// are safe in ANY SQL context, so these are credited unconditionally (like intval/absint).
	// A user function is a quote-ESCAPER iff EVERY return is addslashes/esc_sql/*_real_escape
	// or strtr/str_replace with a map escaping BOTH the single-quote and backslash. Escapers
	// are credited ONLY in quoted context: their calls join sqlSanitizers and ride the existing
	// unquoted-demotion, so an escaped value in an unquoted (numeric/ORDER BY) context still
	// reports. A function name is whitelisted only if EVERY definition of that name classifies
	// the same way (guards against same-name collisions). FN-free by construction.
	static Set<String> inferredIntSanitizers = new HashSet<String>();
	static Set<String> inferredQuoteEscapers = new HashSet<String>();
	private static final int RET_UNSAFE=0, RET_INT=1, RET_ESC=2;

	private static String varNameOf(ast.expressions.Expression e) {
		if( e instanceof Variable && ((Variable)e).getNameExpression() instanceof StringExpression )
			return ((StringExpression)((Variable)e).getNameExpression()).getEscapedCodeStr();
		return null;
	}

	// Constant key for an array index — a string or integer literal, else null (a dynamic index is
	// not keyed, so $a[$i] stays untracked rather than aliasing every element).
	private static String constIndexKey(Expression idx) {
		if( idx instanceof StringExpression ) return ((StringExpression)idx).getEscapedCodeStr();
		if( idx != null && idx.getClass().getSimpleName().contains("Integer") ) return idx.getEscapedCodeStr();
		return null;
	}

	// Lvalue key covering a simple $var, an array element $a['k'] (literal key only), and a property
	// $obj->p / $this->p. Returns null for dynamic shapes. This is what lets the assignment map track
	// array elements and object properties (R5), not just simple variables. For a plain Variable it is
	// identical to varNameOf, so simple-variable behaviour is unchanged.
	private static String lvalKey(Expression e) {
		if( e == null ) return null;
		if( e instanceof Variable ) {
			Expression ne = ((Variable)e).getNameExpression();
			return (ne instanceof StringExpression) ? ((StringExpression)ne).getEscapedCodeStr() : null;
		}
		if( e instanceof ArrayIndexing ) {
			String base = lvalKey(((ArrayIndexing)e).getArrayExpression());
			String dim  = constIndexKey(((ArrayIndexing)e).getIndexExpression());
			return ( base != null && dim != null ) ? base + "[" + dim + "]" : null;
		}
		if( e instanceof PropertyExpression ) {
			String base = lvalKey(((PropertyExpression)e).getObjectExpression());
			Expression prop = ((PropertyExpression)e).getPropertyExpression();
			String pn = (prop instanceof StringExpression) ? ((StringExpression)prop).getEscapedCodeStr() : null;
			return ( base != null && pn != null ) ? base + "->" + pn : null;
		}
		return null;
	}

	// ---- R4 return-name summaries -------------------------------------------------------------
	// retArbitraryFids: functions that can RETURN an attacker-controlled, un-prefixed value read
	// internally (e.g. `function f(){ return $_POST['k']; }`), so `$n = f(); update_option($n)` is
	// arbitrary. retPrefixFids: functions whose every return is namespaced with a constant literal
	// prefix (e.g. `return 'plugin_'.$x`), so `$n = f()` is a fixed-prefix name — the precision
	// coupling that stops a prefixed helper from being treated as arbitrary. retSummaryReady gates
	// the call-return check inside valueIsTainted off during the summary build itself (no recursion).
	public static Set<Long> retArbitraryFids = new HashSet<Long>();
	private static HashMap<Long,String> retPrefixFids = new HashMap<Long,String>();
	private static boolean retSummaryReady = false;

	// ---- #6 constant evaluation -------------------------------------------------------------
	// Resolved string values of program-defined constants: define('X','v'), const X='v', and class
	// const X='v'. Lets optionNameLiteralPrefix see `MY_PREFIX . $name` as a fixed-prefix (namespaced)
	// name instead of an arbitrary one — closes a false-positive class. Class constants are keyed by
	// their bare name (self::X / C::X both resolve); a name defined to two different values is dropped
	// as ambiguous (-> unresolved -> conservatively treated as no prefix).
	private static HashMap<String,String> constValues = new HashMap<String,String>();
	private static void recordConst(java.util.Set<String> amb, String k, String v) {
		if( k == null || v == null || amb.contains(k) ) return;
		String prev = constValues.get(k);
		if( prev != null && !prev.equals(v) ) { amb.add(k); constValues.remove(k); }
		else constValues.put(k, v);
	}
	private static void buildConstantValues() {
		constValues.clear();
		java.util.HashSet<String> ambiguous = new java.util.HashSet<String>();
		PHPCGFactory.recordScanSite("PCG_394", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( n instanceof CallExpressionBase && "define".equals(callTargetName((CallExpressionBase)n)) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() >= 2 ) {
					Expression a0 = al.getArgument(0), a1 = al.getArgument(1);
					String nm = (a0 instanceof StringExpression) ? ((StringExpression)a0).getEscapedCodeStr() : null;
					String vl = (a1 instanceof StringExpression) ? ((StringExpression)a1).getEscapedCodeStr() : null;
					recordConst(ambiguous, nm, vl);
				}
			}
			if( n instanceof ConstantElement ) {
				ConstantElement ce = (ConstantElement)n;
				String nm = (ce.getNameChild() != null) ? ce.getNameChild().getEscapedCodeStr() : null;
				Expression v = ce.getValue();
				String vl = (v instanceof StringExpression) ? ((StringExpression)v).getEscapedCodeStr() : null;
				recordConst(ambiguous, nm, vl);
			}
		}
	}

	// ---- CSRF nonce-dominance analysis (AST-structural) --------------------------------------
	// The CSRF lint must only clear a write a nonce actually *dominates*, not one merely reachable
	// in the same handler. These helpers approximate control-flow dominance on the AST: a nonce
	// executes unconditionally if the climb to the function root never enters a conditional body
	// (an if/elseif/else/switch-case/loop body); an if-CONDITION is unconditional (always evaluated,
	// so the early-return idiom `if(!wp_verify_nonce(..)) die();` gates everything after it).

	private static void addNode(java.util.HashMap<Long,java.util.List<Long>> m, Long key, Long val) {
		java.util.List<Long> l = m.get(key);
		if( l == null ) { l = new java.util.ArrayList<Long>(); m.put(key, l); }
		l.add(val);
	}

	// Returns the op of the first sink in the handler's call-closure that no nonce dominates, or null
	// if every sink is dominated. A sink is dominated when it falls in the guarded region of a nonce
	// check (or of a call to a nonce-gating helper), or sits in a callee entered through a dominated
	// call. This is the path-domination the plain reachability check lacked.
	private static String firstUnguardedSink(Set<Long> closure,
			java.util.HashMap<Long,java.util.List<Long>> nonceNodesByFid,
			java.util.HashMap<Long,java.util.List<Long>> sinkNodesByFid,
			java.util.HashMap<Long,java.util.List<Long>> callSitesByFid,
			Set<Long> nonceGates,
			java.util.HashMap<Long,String> localSens) {
		Set<Long> guarded = new HashSet<Long>();
		for( Long f : closure ) {
			java.util.List<Long> nes = new java.util.ArrayList<Long>();
			if( nonceNodesByFid.get(f) != null ) nes.addAll(nonceNodesByFid.get(f));
			if( callSitesByFid.get(f) != null ) for( Long cs : callSitesByFid.get(f) ) {
				java.util.List<Long> tg = call2mtd.get(cs);
				if( tg != null ) for( Long t : tg ) if( nonceGates.contains(t) ) { nes.add(cs); break; }
			}
			for( Long ne : nes ) guarded.addAll(guardedRegion(ne, f));
		}
		// A call dominated by a nonce fully-guards its callee (the callee body runs after the nonce).
		Set<Long> fullyGuarded = new HashSet<Long>();
		boolean ch = true; int g = 0;
		while( ch && g++ < 50 ) {
			ch = false;
			for( Long f : closure ) {
				boolean fg = fullyGuarded.contains(f);
				if( callSitesByFid.get(f) == null ) continue;
				for( Long cs : callSitesByFid.get(f) ) {
					if( !fg && !guarded.contains(cs) ) continue;
					java.util.List<Long> tg = call2mtd.get(cs);
					if( tg != null ) for( Long t : tg )
						if( closure.contains(t) && fullyGuarded.add(t) ) ch = true;
				}
			}
		}
		for( Long f : closure ) {
			if( fullyGuarded.contains(f) ) continue;
			java.util.List<Long> sinks = sinkNodesByFid.get(f);
			if( sinks == null ) continue;
			for( Long s : sinks ) if( !guarded.contains(s) ) {
				String o = localSens.get(f); return o != null ? o : "state change";
			}
		}
		return null;
	}

	// ---- IDOR owned-object model -------------------------------------------------------------
	// An object is IDOR-relevant only if it is user-OWNED. WP posts/users/comments/terms are owned
	// inherently (post_author / user identity / comment author). A custom $wpdb table is owned only
	// if the code shows it is partitioned per user — i.e. some query on that table references an
	// ownership column. A table that is never filtered by an owner (settings, rooms, global config)
	// is NOT an IDOR object, which is what tames the global-object false positives.
	private static final java.util.regex.Pattern OWN_COL = java.util.regex.Pattern.compile(
		"\\b(user_id|userid|post_author|author_id|owner_id|owner|customer_id|customer|created_by|account_id|member_id|user_email|author)\\b");
	private static final Set<String> SQL_NONTABLE = new HashSet<String>(Arrays.asList(
		"select","from","where","join","inner","left","right","outer","update","insert","into",
		"set","values","and","or","order","group","limit","null","true","false","like","prepare",
		"user_id","userid","post_author","author_id","owner_id","owner","customer_id","customer",
		"created_by","account_id","member_id","user_email","author"));

	// Lowercased concatenation of every string literal in a call's argument subtree.
	private static String callSqlText(Long callNode) {
		StringBuilder sb = new StringBuilder();
		for( Long id : subtreeIds(callNode) ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( n instanceof StringExpression ) {
				String s = ((StringExpression)n).getEscapedCodeStr();
				if( s != null ) sb.append(' ').append(s.toLowerCase());
			}
		}
		return sb.toString();
	}

	// Candidate table tokens in SQL/text: words after FROM/JOIN/INTO/UPDATE, plus any underscore-bearing
	// identifier (custom tables are almost always prefixed, e.g. wp_hb_orders), minus SQL/ownership words.
	private static Set<String> extractTableTokens(String text) {
		Set<String> out = new HashSet<String>();
		java.util.regex.Matcher m = java.util.regex.Pattern
			.compile("(?:from|join|into|update)\\s+[`'\"]?(?:\\{?\\$?[a-z]*wpdb[^a-z0-9_]*prefix\\}?\\.?\\s*)?[`'\"]?([a-z][a-z0-9_]{2,})")
			.matcher(text);
		while( m.find() ) { String t = m.group(1); if( !SQL_NONTABLE.contains(t) ) out.add(t); }
		java.util.regex.Matcher u = java.util.regex.Pattern.compile("\\b([a-z][a-z0-9]*_[a-z0-9_]{2,})\\b").matcher(text);
		while( u.find() ) { String t = u.group(1); if( !SQL_NONTABLE.contains(t) && !OWN_COL.matcher(t).matches() ) out.add(t); }
		return out;
	}

	// Per-function variable -> list of assignment RHS nodes (flow-insensitive intraprocedural defs).
	// Shared by the paired stored-taint flow-binding and the IDOR id-binding.
	private static java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> buildVarAssigns() {
		java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va =
			new java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>>();
		PHPCGFactory.recordScanSite("PCG_519", ASTUnderConstruction.idToNode.size());
		for( ASTNode nd : ASTUnderConstruction.idToNode.values() ) {
			if( !(nd instanceof AssignmentExpression) ) continue;
			Long fid = nd.getFuncId(); if( fid == null ) continue;
			Expression lhs = ((AssignmentExpression)nd).getLeft();
			Expression rhs = ((AssignmentExpression)nd).getRight();
			String vn = lvalKey(lhs);
			if( vn == null || rhs == null ) continue;
			va.computeIfAbsent(fid, k -> new java.util.HashMap<String,java.util.List<ASTNode>>())
				.computeIfAbsent(vn, k -> new java.util.ArrayList<ASTNode>()).add(rhs);
		}
		return va;
	}

	// True if `e` is the current user's id: a get_current_user_id() call, or a variable that resolves
	// (through the assignment map) to one. Used so user_can($id,$cap) is only treated as a self-auth
	// capability guard when $id is actually the current user (not some other/target user).
	private static boolean isCurrentUserId(Expression e, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		if( e == null || depth > 6 ) return false;
		if( e instanceof CallExpressionBase
				&& "get_current_user_id".equals(callTargetName((CallExpressionBase)e)) ) return true;
		if( e instanceof Variable && va != null ) {
			java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
			String vn = lvalKey(e);
			if( m != null && vn != null && m.containsKey(vn) )
				for( ASTNode rhs : m.get(vn) )
					if( rhs instanceof Expression && !rhs.getNodeId().equals(e.getNodeId())
							&& isCurrentUserId((Expression)rhs, fid, va, depth+1) ) return true;
		}
		return false;
	}

	// Does this current_user_can() argument PROVABLY require a management capability? Handles a string
	// literal, a variable followed to its assignment(s), the WordPress filtered-cap idiom
	// apply_filters('hook','DEFAULT') (the shipped default is the cap), and a ternary $x?'cap_a':'cap_b'
	// where BOTH branches must be management — if any runtime path requires only a lesser capability the
	// handler is not provably cross-object authorized. A variable with multiple assignments must have EVERY
	// assignment be management. Used ONLY to clear an IDOR finding, so every unresolved or odd shape returns
	// false (fail-safe toward reporting, never toward silently clearing). A filter can widen the cap at
	// runtime, but the default is what the plugin ships and what a reviewer reasons about.
	private static boolean capArgIsManagement(ASTNode arg, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va) {
		return capArgIsManagement(arg, fid, va, 0);
	}
	private static boolean capArgIsManagement(ASTNode arg, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		if( arg == null || depth > 6 ) return false;
		if( arg instanceof StringExpression ) {
			String s = ((StringExpression)arg).getEscapedCodeStr();
			if( s != null && s.length() >= 2 ) {
				char a = s.charAt(0), b = s.charAt(s.length()-1);
				if( (a=='"' || a=='\'') && a==b ) s = s.substring(1, s.length()-1);
			}
			return s != null && isManagementCap(s);
		}
		if( arg instanceof ConditionalExpression ) {
			ConditionalExpression ce = (ConditionalExpression)arg;
			ASTNode t = ce.getTrueExpression(); ASTNode f = ce.getFalseExpression();
			if( t == null || f == null ) return false;   // short ternary $a ?: $b — be conservative
			return capArgIsManagement(t, fid, va, depth+1) && capArgIsManagement(f, fid, va, depth+1);
		}
		if( arg instanceof CallExpressionBase ) {
			String cn = callTargetName((CallExpressionBase)arg);
			if( "apply_filters".equals(cn) || "apply_filters_deprecated".equals(cn) ) {
				ArgumentList fal = ((CallExpressionBase)arg).getArgumentList();
				if( fal != null && fal.size() >= 2 ) return capArgIsManagement(fal.getArgument(1), fid, va, depth+1);
			}
			return false;
		}
		String vn = varNameOf(arg);
		if( vn == null || va == null ) return false;
		java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
		if( m == null ) return false;
		java.util.List<ASTNode> rhss = m.get(vn);
		if( rhss == null || rhss.isEmpty() ) return false;
		for( ASTNode rhs : rhss ) if( !capArgIsManagement(rhs, fid, va, depth+1) ) return false;
		return true;
	}
	//   2 = BOUND   — a request source flows into it (inline or via an in-function variable). Genuine IDOR.
	//   1 = INDET   — depends on a parameter/global/unresolved variable; cannot prove either way -> the
	//                 verdict falls back to co-occurrence (keeps recall: no false negative).
	//   0 = CLEAN   — fully determined by in-function constants/non-request values. NOT request-selected;
	//                 this is the co-occurrence false positive the binding removes.
	private static final int ID_BOUND = 2, ID_INDET = 1, ID_CLEAN = 0;
	private static int idArgState(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		if( node == null || depth > 8 ) return ID_INDET;     // unknown depth -> fall back safely
		Set<Long> sub = subtreeIds(node);
		for( Long id : sub ) if( PHPCSVEdgeInterpreter.sources.contains(id) ) return ID_BOUND;
		java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
		int state = ID_CLEAN;
		for( Long id : sub ) {
			ASTNode x = ASTUnderConstruction.idToNode.get(id);
			if( !(x instanceof Variable) ) continue;
			String v = varNameOf((Expression)x);
			if( v == null ) { state = ID_INDET; continue; }      // variable-variable
			java.util.List<ASTNode> rhss = m == null ? null : m.get(v);
			if( rhss == null ) { state = ID_INDET; continue; }   // param / global / loop var: unresolved
			for( ASTNode rhs : rhss ) {
				if( rhs.getNodeId().equals(node) ) continue;
				int s = idArgState(rhs.getNodeId(), fid, va, depth+1);
				if( s == ID_BOUND ) return ID_BOUND;
				if( s == ID_INDET ) state = ID_INDET;
			}
		}
		return state;
	}

	// Record (max of) the id-binding state for an object op in funcId. A null id node means the id arg
	// was not isolable (array-form op / missing arg) -> INDET, which keeps the co-occurrence fallback.
	private static void recordIdState(java.util.HashMap<Long,Integer> objIdState, Long fid, Long idArgNode,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va) {
		int s = idArgNode == null ? ID_INDET : idArgState(idArgNode, fid, va, 0);
		Integer cur = objIdState.get(fid);
		if( cur == null || s > cur ) objIdState.put(fid, s);
	}

	// True if a call is an ownership/authorization guard that correlates an object with the CURRENT USER —
	// e.g. belongs_to_user($id, $current_user->ID), can_edit($post, get_current_user_id()). The signal is
	// a call that receives BOTH a current-user identity AND another (non-current-user) variable argument.
	// This catches custom guards that the IDOR_OWNERSHIP name list cannot enumerate, while a bare display
	// use of $current_user (no other variable correlated) does NOT count — that would risk a false negative.
	private static boolean isCurrentUserGuard(CallExpressionBase call) {
		ArgumentList al = call.getArgumentList();
		if( al == null || al.size() < 2 ) return false;
		// Implicit-current-user permission wrapper: the callee NAME carries the current-user semantics
		// (um_current_user_can('edit',$user_id), current_user_can($cap,$post_id), wc_current_user_can(...))
		// rather than passing the current user as an argument. A non-constant Variable argument is the object
		// being authorized, making this a current-user-vs-object ownership correlation — the same meta-cap
		// semantics core current_user_can($cap,$id) already gets. A flat current_user_can($cap) with only a
		// constant capability is size<2 and is handled by the admin-cap path instead, so it is not matched.
		String cn = callTargetName(call);
		if( cn != null && cn.contains("current_user_can") ) {
			for( int i = 0; i < al.size(); i++ ) {
				Expression arg = al.getArgument(i);
				if( arg == null ) continue;
				for( Long id : subtreeIds(arg.getNodeId()) ) {
					ASTNode x = ASTUnderConstruction.idToNode.get(id);
					if( x instanceof Variable && varNameOf((Expression)x) != null ) return true;
				}
			}
		}
		boolean hasCU = false, hasOtherVar = false;
		for( int i = 0; i < al.size(); i++ ) {
			Expression arg = al.getArgument(i);
			if( arg == null ) continue;
			boolean argCU = false, argOther = false;
			for( Long id : subtreeIds(arg.getNodeId()) ) {
				ASTNode x = ASTUnderConstruction.idToNode.get(id);
				if( x instanceof Variable ) {
					String vn = varNameOf((Expression)x);
					if( "current_user".equals(vn) ) argCU = true;
					else if( vn != null ) argOther = true;
				} else if( x instanceof CallExpressionBase ) {
					String t = callTargetName((CallExpressionBase)x);
					if( "get_current_user_id".equals(t) || "wp_get_current_user".equals(t) ) argCU = true;
				}
			}
			if( argCU ) hasCU = true;
			if( argOther && !argCU ) hasOtherVar = true;
		}
		return hasCU && hasOtherVar;
	}

	private static int indexInParent(Long child) {
		Long p = PHPCSVEdgeInterpreter.child2parent.get(child);
		if( p == null ) return -1;
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(p);
		if( kids == null ) return -1;
		for( java.util.Map.Entry<Integer,Long> e : kids.entrySet() )
			if( child.equals(e.getValue()) ) return e.getKey();
		return -1;
	}

	private static boolean isConditionalBody(ASTNode parentOfBlock) {
		if( parentOfBlock == null ) return false;
		if( parentOfBlock instanceof IfElement || parentOfBlock instanceof SwitchCase ) return true;
		String sn = parentOfBlock.getClass().getSimpleName();
		// loops and try/catch bodies are conditionally executed (jar-resident classes, matched by name)
		return sn.contains("While") || sn.contains("For") || sn.contains("Foreach")
			|| sn.contains("Do") || sn.contains("Try") || sn.contains("Catch");
	}

	// True if `node` is reached from its function's entry without passing through any conditional body.
	// isUnconditional(node,funcId) is a pure function of the static CFG, called repeatedly on the same
	// pairs inside the nonce/cap/own/halt dominance fixpoints (up to 50 iterations each). Memoize.
	private static final java.util.HashMap<Long,java.util.HashMap<Long,Boolean>> isUncondCache
		= new java.util.HashMap<Long,java.util.HashMap<Long,Boolean>>();
	static long isUncondCalls = 0, isUncondMiss = 0;
	private static boolean isUnconditional(Long node, Long funcId) {
		isUncondCalls++;
		java.util.HashMap<Long,Boolean> byFunc = isUncondCache.get(node);
		if( byFunc != null ) { Boolean c = byFunc.get(funcId); if( c != null ) return c; }
		isUncondMiss++;
		boolean res = isUnconditionalUncached(node, funcId);
		isUncondCache.computeIfAbsent(node, k -> new java.util.HashMap<Long,Boolean>()).put(funcId, res);
		return res;
	}
	private static boolean isUnconditionalUncached(Long node, Long funcId) {
		Long cur = node; int guard = 0;
		while( cur != null && guard++ < 10000 ) {
			Long p = PHPCSVEdgeInterpreter.child2parent.get(cur);
			if( p == null ) return true;
			if( p.equals(funcId) ) return true;
			ASTNode pn = ASTUnderConstruction.idToNode.get(p);
			if( pn instanceof FunctionDef ) return true;
			if( pn instanceof CompoundStatement ) {
				ASTNode gpn = ASTUnderConstruction.idToNode.get(PHPCSVEdgeInterpreter.child2parent.get(p));
				if( isConditionalBody(gpn) ) return false;
				cur = p;
			} else if( pn instanceof IfElement ) {
				if( indexInParent(cur) == 0 ) cur = PHPCSVEdgeInterpreter.child2parent.get(p); // condition: climb past the if
				else return false;                                                             // body: conditional
			} else {
				cur = p;
			}
		}
		return true;
	}

	// The set of AST node-ids that a nonce check (or nonce-gating call) at `start` dominates: every
	// statement executed after it on the path out of the function, bounded by the enclosing branch.
	// True if a block's subtree contains a terminating statement (return / die / exit / wp_die /
	// wp_send_json*). Distinguishes the bail form `if(!guard){return;}` (body halts, so the rest of the
	// function is guarded) from the positive form `if(guard){sink}` (body does not halt, so only the
	// body is guarded and a later sibling sink is NOT).
	private static boolean blockHalts(Long blockNode) {
		if( blockNode == null ) return false;
		for( Long id : subtreeIds(blockNode) ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( n instanceof ast.statements.jump.ReturnStatement ) return true;
			if( n instanceof ast.php.expressions.ExitExpression ) return true;   // die / exit language construct
			if( n instanceof CallExpressionBase
					&& HALT_FUNCS.contains(callTargetName((CallExpressionBase)n)) ) return true;
		}
		return false;
	}

	// guardedRegion(start,funcId) is a pure function of the static CFG (child2parent/parent2child/
	// idToNode). firstUnguardedSink calls it per guard-node per handler, so the same (start,funcId)
	// regions were recomputed across all ~150 handlers. Memoize; callers only addAll from the result.
	private static final java.util.HashMap<Long,java.util.HashMap<Long,Set<Long>>> guardedRegionCache
		= new java.util.HashMap<Long,java.util.HashMap<Long,Set<Long>>>();
	static long guardedRegionCalls = 0, guardedRegionMiss = 0;
	private static Set<Long> guardedRegion(Long start, Long funcId) {
		guardedRegionCalls++;
		java.util.HashMap<Long,Set<Long>> byFunc = guardedRegionCache.get(start);
		if( byFunc != null ) { Set<Long> c = byFunc.get(funcId); if( c != null ) return c; }
		guardedRegionMiss++;
		Set<Long> region = new HashSet<Long>();
		Long cur = start; int guard = 0;
		while( cur != null && guard++ < 10000 ) {
			Long p = PHPCSVEdgeInterpreter.child2parent.get(cur);
			if( p == null || p.equals(funcId) ) break;
			ASTNode pn = ASTUnderConstruction.idToNode.get(p);
			if( pn instanceof FunctionDef ) break;
			if( pn instanceof CompoundStatement ) {
				int idx = indexInParent(cur);
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(p);
				if( kids != null ) for( java.util.Map.Entry<Integer,Long> e : kids.entrySet() )
					if( e.getKey() > idx ) region.addAll(subtreeIds(e.getValue()));   // later statements in this block
				ASTNode gpn = ASTUnderConstruction.idToNode.get(PHPCSVEdgeInterpreter.child2parent.get(p));
				if( isConditionalBody(gpn) ) break;       // this block is a conditional body: don't escape it
				cur = p;
			} else if( pn instanceof IfElement ) {
				if( indexInParent(cur) == 0 ) {           // guard sits in the if-condition
					HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(p);
					Long body = ( kids != null ) ? kids.get(1) : null;
					if( body != null ) region.addAll(subtreeIds(body));   // the if-body is always guarded
					// Only the BAIL form (if(!guard){die/return}) guards statements AFTER the if: its body
					// halts. The POSITIVE form (if(guard){sink}) guards ONLY the body — a later sibling sink
					// is NOT guarded. Without this gate an allowlist on if(in_array){sink} leaked onto the
					// next sink (concern #5 / a5).
					if( body != null && blockHalts(body) )
						cur = PHPCSVEdgeInterpreter.child2parent.get(p);   // bail form: keep collecting the rest
					else break;                                            // positive form: stop at the body
				} else break;
			} else {
				cur = p;
			}
		}
		guardedRegionCache.computeIfAbsent(start, k -> new java.util.HashMap<Long,Set<Long>>()).put(funcId, region);
		return region;
	}

	// subtreeIds is a pure function of the static parent2child map (stable for the whole run), yet it
	// was re-BFS'd on every call — and valueIsTainted calls it in an inner loop, so on a large plugin
	// the same expression subtrees were walked millions of times. Memoize. The queried roots in the hot
	// path are small value/argument expressions, so the cache stays bounded; a huge subtree (rare) is
	// still cached once. Cleared implicitly by the fresh per-plugin JVM.
	private static final java.util.HashMap<Long,Set<Long>> subtreeIdsCache = new java.util.HashMap<Long,Set<Long>>();
	static long subtreeIdsCalls = 0, subtreeIdsMiss = 0;
	private static Set<Long> subtreeIds(Long root) {
		subtreeIdsCalls++;
		if( root == null ) return new HashSet<Long>();
		Set<Long> cached = subtreeIdsCache.get(root);
		if( cached != null ) return cached;
		subtreeIdsMiss++;
		Set<Long> out = new HashSet<Long>();
		java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
		work.add(root);
		int guard=0;
		while( !work.isEmpty() && guard++ < 200000 ) {
			Long id = work.poll();
			if( id == null || !out.add(id) ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
			if( kids != null ) work.addAll(kids.values());
		}
		subtreeIdsCache.put(root, out);
		return out;
	}

	// ITEM55 FIX: ctypeGuardRegions() previously scanned ASTUnderConstruction.idToNode.values()
	// -- the entire corpus -- once per call, filtered afterward by funcId. Confirmed as a genuine
	// hot path via full read-only trace (ITEM54): called from classifyUserSanitizers() inside a
	// two-pass loop over every function/method/static-method in the corpus with a return
	// statement (922 calls on AIOWM alone, each visiting ~74,001 nodes). Unlike ITEM53, no
	// existing index covered this shape (IfStatement nodes grouped by funcId) -- built one here,
	// following the exact same "byFunc" idiom classifyUserSanitizers() ALREADY uses two lines
	// above this call site for retByFid/assignsByFid, just applied to a new node type. Only the
	// SOURCE of candidate nodes changes (every corpus node -> this function's pre-indexed
	// IfStatements); every downstream filter (ifElement/cond/ctype_digit/argument shape) is
	// byte-for-byte unchanged from the original inline loop.
	private static HashMap<Long, java.util.List<ast.php.statements.blockstarters.IfStatement>> ifStmtsByFunc = null;

	private static void buildIfStmtIndexIfNeeded() {
		if( ifStmtsByFunc != null ) return;
		ifStmtsByFunc = new HashMap<Long, java.util.List<ast.php.statements.blockstarters.IfStatement>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.php.statements.blockstarters.IfStatement) ) continue;
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			java.util.List<ast.php.statements.blockstarters.IfStatement> l = ifStmtsByFunc.get(fid);
			if( l == null ) { l = new java.util.ArrayList<ast.php.statements.blockstarters.IfStatement>(); ifStmtsByFunc.put(fid, l); }
			l.add((ast.php.statements.blockstarters.IfStatement)n);
		}
	}

	public static long CTYPE_calls = 0, CTYPE_fallbackScans = 0;

	private static HashMap<String,Set<Long>> legacyCtypeGuardRegions(Long fid) {
		// Byte-for-byte the original pre-ITEM55 scan logic, kept ONLY as a verification oracle
		// for WP_VERIFY_CTYPE_INDEX=1 -- never called in normal operation.
		HashMap<String,Set<Long>> regions = new HashMap<String,Set<Long>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.php.statements.blockstarters.IfStatement) ) continue;
			if( fid == null || !fid.equals(n.getFuncId()) ) continue;
			ast.php.statements.blockstarters.IfStatement is = (ast.php.statements.blockstarters.IfStatement)n;
			if( is.size() < 1 ) continue;
			Long elemId;
			try { elemId = is.getIfElement(0).getNodeId(); } catch( Exception ex ) { continue; }
			HashMap<Integer,Long> ec = PHPCSVEdgeInterpreter.parent2child.get(elemId);
			if( ec == null ) continue;
			Long condId = ec.get(0), bodyId = ec.get(1);
			if( condId == null || bodyId == null ) continue;
			ASTNode cond = ASTUnderConstruction.idToNode.get(condId);
			if( !(cond instanceof CallExpressionBase) ) continue;
			if( !"ctype_digit".equals(callTargetName((CallExpressionBase)cond)) ) continue;
			ArgumentList ca = ((CallExpressionBase)cond).getArgumentList();
			if( ca == null || ca.size() != 1 ) continue;
			String v = varNameOf(ca.getArgument(0));
			if( v == null ) continue;
			Set<Long> region = regions.get(v);
			if( region == null ) { region = new HashSet<Long>(); regions.put(v, region); }
			region.addAll(subtreeIds(bodyId));
		}
		return regions;
	}

	private static boolean sameRegionMaps(HashMap<String,Set<Long>> a, HashMap<String,Set<Long>> b) {
		if( a.size() != b.size() ) return false;
		for( java.util.Map.Entry<String,Set<Long>> e : a.entrySet() ) {
			Set<Long> bv = b.get(e.getKey());
			if( bv == null || !bv.equals(e.getValue()) ) return false;
		}
		return true;
	}

	// var name -> node-id set of the true-branch of an if(ctype_digit($var)) in function fid.
	private static HashMap<String,Set<Long>> ctypeGuardRegions(Long fid) {
		CTYPE_calls++;
		buildIfStmtIndexIfNeeded();
		java.util.List<ast.php.statements.blockstarters.IfStatement> candidates = ifStmtsByFunc.get(fid);
		PHPCGFactory.recordScanSite("PCG_834", candidates == null ? 0 : candidates.size());
		HashMap<String,Set<Long>> regions = new HashMap<String,Set<Long>>();
		if( candidates != null ) {
			for( ast.php.statements.blockstarters.IfStatement is : candidates ) {
				if( is.size() < 1 ) continue;
				Long elemId;
				try { elemId = is.getIfElement(0).getNodeId(); } catch( Exception ex ) { continue; }
				HashMap<Integer,Long> ec = PHPCSVEdgeInterpreter.parent2child.get(elemId);
				if( ec == null ) continue;
				Long condId = ec.get(0), bodyId = ec.get(1);
				if( condId == null || bodyId == null ) continue;
				ASTNode cond = ASTUnderConstruction.idToNode.get(condId);
				if( !(cond instanceof CallExpressionBase) ) continue;
				if( !"ctype_digit".equals(callTargetName((CallExpressionBase)cond)) ) continue;
				ArgumentList ca = ((CallExpressionBase)cond).getArgumentList();
				if( ca == null || ca.size() != 1 ) continue;
				String v = varNameOf(ca.getArgument(0));
				if( v == null ) continue;
				Set<Long> region = regions.get(v);
				if( region == null ) { region = new HashSet<Long>(); regions.put(v, region); }
				region.addAll(subtreeIds(bodyId));
			}
		}
		if( System.getenv("WP_VERIFY_CTYPE_INDEX") != null ) {
			HashMap<String,Set<Long>> legacy = legacyCtypeGuardRegions(fid);
			if( !sameRegionMaps(regions, legacy) ) {
				CTYPE_fallbackScans++;
				System.err.println("CTYPE_GUARD_MISMATCH fid=" + fid
					+ " indexed_keys=" + regions.keySet() + " legacy_keys=" + legacy.keySet());
				regions = legacy; // trust the verified-correct legacy path if they disagree
			}
		}
		return regions;
	}

	// strtr/str_replace whose (array or paired) argument escapes BOTH ' and \ .
	private static boolean escapesQuoteAndBackslash(CallExpressionBase c) {
		ArgumentList al = c.getArgumentList();
		if( al == null ) return false;
		for( int i=0; i<al.size(); i++ ) {
			ASTNode a = al.getArgument(i);
			if( !(a instanceof ast.php.expressions.ArrayExpression) ) continue;
			ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression)a;
			boolean q=false, b=false;
			for( int j=0; j<arr.size(); j++ ) {
				ArrayElement el = arr.getArrayElement(j);
				ast.expressions.Expression k = (el != null) ? el.getKey() : null;
				if( k instanceof StringExpression ) {
					String ks = ((StringExpression)k).getEscapedCodeStr();
					if( ks != null ) { if( ks.indexOf('\'')>=0 ) q=true; if( ks.indexOf('\\')>=0 ) b=true; }
				}
			}
			if( q && b ) return true;
		}
		return false;
	}

	// True if `e` provably evaluates to a number or bool — never an attacker-controlled string.
	// In PHP the arithmetic operators (+ - * / % **) and numeric casts coerce their operands to
	// numbers, and comparison/boolean operators yield bool, so such a result cannot carry SQL
	// injection regardless of operand taint. String concatenation (BINARY_CONCAT) and string
	// bitwise ops are deliberately NOT included. Follows in-function variable assignments (every
	// assignment must be numeric) with cycle and depth guards. One-directional: only returns true
	// when the value cannot be an injectable string, so it can never introduce a false negative.
	private static boolean isNumericValued(ASTNode e,
			HashMap<String,java.util.List<ASTNode>> assigns, Set<String> visiting, int depth) {
		if( e == null || depth > 12 ) return false;
		if( e instanceof ast.expressions.IntegerExpression ) return true;
		String sn = e.getClass().getSimpleName();
		if( sn.contains("Double") || sn.contains("Float") ) return true;
		if( e instanceof ast.expressions.CastExpression ) {
			ast.expressions.Expression ct = ((ast.expressions.CastExpression)e).getCastTarget();
			String t = (ct != null) ? ct.getEscapedCodeStr() : null;
			if( t != null ) { t = t.toLowerCase();
				if( t.indexOf("int")>=0 || t.indexOf("float")>=0 || t.indexOf("double")>=0 || t.indexOf("bool")>=0 ) return true; }
			return false;
		}
		if( e instanceof BinaryOperationExpression ) {
			String op = e.getFlags();
			if( op == null ) return false;
			if( op.equals("BINARY_ADD")||op.equals("BINARY_SUB")||op.equals("BINARY_MUL")
					||op.equals("BINARY_DIV")||op.equals("BINARY_MOD")||op.equals("BINARY_POW")
					||op.startsWith("BINARY_IS_")||op.startsWith("BINARY_BOOL_") ) return true;
			return false;                                  // CONCAT and string-bitwise stay unsafe
		}
		if( e instanceof ast.expressions.ConditionalExpression ) {
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)e;
			ast.expressions.Expression t = ce.getTrueExpression(), f = ce.getFalseExpression();
			if( t == null ) t = ce.getCondition();         // ?: short form
			return isNumericValued(t, assigns, visiting, depth+1) && isNumericValued(f, assigns, visiting, depth+1);
		}
		if( e instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)e);
			return nm != null && ( "intval".equals(nm)||"absint".equals(nm)||"floatval".equals(nm)
				||"doubleval".equals(nm)||"count".equals(nm)||"sizeof".equals(nm)||"strlen".equals(nm)
				||"time".equals(nm)||inferredIntSanitizers.contains(nm) );
		}
		String v = varNameOf(e);
		if( v != null && assigns != null && assigns.containsKey(v) ) {
			if( visiting.contains(v) ) return true;        // self-cycle ($p=$p-1): other assigns still checked
			visiting.add(v);
			boolean all = true;
			for( ASTNode rhs : assigns.get(v) ) if( !isNumericValued(rhs, assigns, visiting, depth+1) ) { all=false; break; }
			visiting.remove(v);
			return all;
		}
		return false;
	}

	private static int classifyReturn(ast.statements.jump.ReturnStatement r, HashMap<String,Set<Long>> guards,
			HashMap<String,java.util.List<ASTNode>> assigns) {
		ast.expressions.Expression e = r.getReturnExpression();
		if( e == null ) return RET_UNSAFE;
		if( e instanceof ast.expressions.IntegerExpression ) return RET_INT;
		if( e instanceof ast.expressions.CastExpression ) {
			ast.expressions.Expression ct = ((ast.expressions.CastExpression)e).getCastTarget();
			String t = (ct != null) ? ct.getEscapedCodeStr() : null;
			return ( t != null && t.toLowerCase().indexOf("int") >= 0 ) ? RET_INT : RET_UNSAFE;
		}
		if( e instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)e);
			if( nm != null ) {
				if( "intval".equals(nm) || "absint".equals(nm) || inferredIntSanitizers.contains(nm) ) return RET_INT;
				if( "addslashes".equals(nm) || "esc_sql".equals(nm) || "mysqli_real_escape_string".equals(nm)
					|| "mysql_real_escape_string".equals(nm) || "mysql_escape_string".equals(nm)
					|| inferredQuoteEscapers.contains(nm) ) return RET_ESC;
				if( ("strtr".equals(nm) || "str_replace".equals(nm)) && escapesQuoteAndBackslash((CallExpressionBase)e) ) return RET_ESC;
			}
			return RET_UNSAFE;
		}
		String v = varNameOf(e);
		if( v != null ) {
			Set<Long> region = guards.get(v);
			if( region != null && region.contains(r.getNodeId()) ) return RET_INT;
		}
		if( isNumericValued(e, assigns, new HashSet<String>(), 0) ) return RET_INT;
		return RET_UNSAFE;
	}

	// ITEM58/59 FIX: declarative-dispatch resolver (design: ITEM58). Recognizes the shape
	// `array of ::class literals -> foreach -> new $var() -> method call on the fresh instance`,
	// confirmed to recur across GiveWP and two independent Jetpack packages (ITEM57). Behind a
	// flag (WP_DECLARATIVE_DISPATCH=1), diagnostic-only in this revision -- prints one explicit
	// verdict per candidate `new $var()` site, never silent, per the explicit instruction that
	// uncertainty must be observable rather than inferred from absence. Does NOT feed entry
	// seeding, reachability, or any finding in this revision -- that would be a separate,
	// later wiring decision after the verdicts themselves are trusted.
	//
	// Deliberately narrow, per instruction: three proofs only (CLASS_SET, DYNAMIC_INSTANTIATION,
	// DISPATCH_EDGE), no generalized dynamic-type inference. Handles exactly the array/return/
	// foreach shapes the six ITEM58 fixtures exercise -- a literal array, a property holding a
	// literal array, a method returning a literal array, and an apply_filters()-wrapped array
	// (explicitly refused, not silently missed). Anything else falls through to
	// UNRESOLVED_DYNAMIC_SOURCE, not a guess.
	private enum DispatchVerdict {
		RESOLVED_FINITE_SET, UNRESOLVED_MUTATED_SET, UNRESOLVED_DYNAMIC_SOURCE, UNRESOLVED_NO_DISPATCH_EDGE
	}

	private static final class ClassSetResult {
		DispatchVerdict verdict; java.util.List<String> classes; String reason;
		ClassSetResult(DispatchVerdict v, java.util.List<String> c, String r) { verdict=v; classes=c; reason=r; }
	}

	// Resolves an expression to a finite set of class names if -- and only if -- every step is
	// one of the specific, narrow shapes below. Anything not explicitly recognized refuses rather
	// than guesses.
	private static ClassSetResult resolveClassLiteralSet(Expression e, int depth) {
		if( depth > 4 ) return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
			"resolution depth exceeded -- refusing rather than chasing an unbounded chain");

		// Shape: a bare local variable, e.g. `$classes` in `foreach ($classes as $cls)`. Trace
		// back to its SINGLE, unambiguous assignment within the same function (same "one write
		// cannot launder another" discipline used elsewhere in this file for other resolvers --
		// more than one assignment to the same variable name in the same function, or none
		// found, leaves it unresolved rather than guessing which one applies) and recurse into
		// that assignment's RHS. One hop only (depth-guarded above).
		if( e instanceof Variable ) {
			String vName = varNameOf(e);
			Long fid = e.getFuncId();
			if( vName == null || fid == null )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"variable name or enclosing function could not be identified");
			Expression singleRhs = null;
			int assignCount = 0;
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				if( !(n instanceof AssignmentExpression) ) continue;
				if( !fid.equals(n.getFuncId()) ) continue;
				Expression lhs = ((AssignmentExpression)n).getLeft();
				if( !(lhs instanceof Variable) || !vName.equals(varNameOf(lhs)) ) continue;
				assignCount++;
				singleRhs = ((AssignmentExpression)n).getRight();
			}
			if( assignCount == 0 )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"no assignment to this variable found in the same function -- likely a parameter "
					+ "or external source, cannot prove finiteness");
			if( assignCount > 1 )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"more than one assignment to this variable in the same function -- ambiguous, "
					+ "refusing rather than guessing which one applies");
			return resolveClassLiteralSet(singleRhs, depth + 1);
		}

		// Shape: a literal array, e.g. [ A::class, B::class ]
		if( e instanceof ast.php.expressions.ArrayExpression ) {
			ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression)e;
			java.util.List<String> names = new java.util.ArrayList<String>();
			for( int i = 0; i < arr.size(); i++ ) {
				ArrayElement el = arr.getArrayElement(i);
				Expression v = (el != null) ? el.getValue() : null;
				if( !(v instanceof ClassConstantExpression) )
					return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
						"array element is not a ::class literal -- refusing the whole set, not just that element");
				ClassConstantExpression cc = (ClassConstantExpression)v;
				StringExpression cn = cc.getConstantName();
				if( cn == null || !"class".equals(cn.getEscapedCodeStr()) )
					return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
						"class-constant element is not the ::class magic constant");
				Expression classExpr = cc.getClassExpression();
				String className = null;
				if( classExpr instanceof Identifier && ((Identifier)classExpr).getNameChild() != null )
					className = ((Identifier)classExpr).getNameChild().getEscapedCodeStr();
				if( className == null )
					return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
						"could not read the class name out of a ::class literal");
				names.add(className);
			}
			if( names.isEmpty() )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null, "empty array, nothing to dispatch");
			return new ClassSetResult(DispatchVerdict.RESOLVED_FINITE_SET, names, null);
		}

		// Shape: $this->propName, where propName's OWN class-level declaration has a literal
		// array default value -- recurse into that default, one hop only (depth-guarded above).
		if( e instanceof PropertyExpression ) {
			PropertyExpression pe = (PropertyExpression)e;
			Expression propNameExpr = pe.getPropertyExpression();
			String propName = (propNameExpr instanceof StringExpression)
				? ((StringExpression)propNameExpr).getEscapedCodeStr() : null;
			// pe.getEnclosingClass() is unreliable at this AST position (unset for a property
			// access used directly as a foreach's iterated object) -- derive the enclosing class
			// from the containing function's own (reliably-set) enclosing-class metadata instead.
			String enclClass = null;
			Long enclFid = pe.getFuncId();
			if( enclFid != null ) {
				ASTNode fnNode = ASTUnderConstruction.idToNode.get(enclFid);
				if( fnNode != null ) enclClass = simpleClassName(fnNode.getEnclosingClass());
			}
			if( propName == null || enclClass == null )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"property access target or enclosing class could not be identified");
			buildPropertyDefaultIndexIfNeeded();
			ast.php.statements.PropertyElement decl = propertyDefaultsByClassAndName.get(enclClass + "|" + propName);
			if( decl == null || decl.getDefault() == null )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"no class-level default value found for this property -- cannot prove finiteness");
			return resolveClassLiteralSet(decl.getDefault(), depth + 1);
		}

		// Shape: $this->methodName(), where the target method's body is a single `return <array>`
		// -- recurse into the returned expression, one hop only.
		if( e instanceof MethodCallExpression ) {
			MethodCallExpression mc = (MethodCallExpression)e;
			java.util.List<Long> targets = call2mtd.get(mc.getNodeId());
			if( targets == null || targets.size() != 1 )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"method call target is not uniquely resolved -- cannot prove which method's return value this is");
			ASTNode target = ASTUnderConstruction.idToNode.get(targets.get(0));
			if( !(target instanceof Method) )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null, "call target is not a method definition");
			Expression singleReturn = findSingleReturnExpressionNarrow(targets.get(0));
			if( singleReturn == null )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
					"target method does not have exactly one return statement -- refusing rather than guessing which return applies");
			return resolveClassLiteralSet(singleReturn, depth + 1);
		}

		// Shape: apply_filters(...) (or apply_filters_ref_array) wrapping an otherwise-provable
		// array -- explicitly refused with a named reason, per instruction, not silently missed.
		// A filter hook can be registered by ANY other code and return an arbitrary array; the
		// finite set proven up to this point does not survive the call.
		if( e instanceof CallExpressionBase ) {
			String fn = callTargetName((CallExpressionBase)e);
			if( "apply_filters".equals(fn) || "apply_filters_ref_array".equals(fn) )
				return new ClassSetResult(DispatchVerdict.UNRESOLVED_MUTATED_SET, null,
					"class array passed through " + fn + "() before use -- a hooked filter could return an "
					+ "arbitrary array; the finite set proven at declaration time does not survive this call");
		}

		return new ClassSetResult(DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE, null,
			"iterated expression's source is not one of the recognized finite-set shapes");
	}

	private static java.util.HashMap<String, ast.php.statements.PropertyElement> propertyDefaultsByClassAndName = null;

	private static void buildPropertyDefaultIndexIfNeeded() {
		if( propertyDefaultsByClassAndName != null ) return;
		propertyDefaultsByClassAndName = new java.util.HashMap<String, ast.php.statements.PropertyElement>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.php.statements.PropertyElement) ) continue;
			ast.php.statements.PropertyElement pel = (ast.php.statements.PropertyElement)n;
			StringExpression nameChild = pel.getNameChild();
			// PropertyElement's getEnclosingClass()/getProperty(CLASSNAME) both return null at
			// this node type -- the raw CSV has the classname column populated, but it never
			// makes it into the generic property bag for AST_PROP_ELEM specifically. Walk up
			// child2parent to the enclosing ClassDef directly instead of relying on either
			// accessor.
			String cls = null;
			Long cur = PHPCSVEdgeInterpreter.child2parent.get(pel.getNodeId());
			int hops = 0;
			while( cur != null && hops++ < 20 ) {
				ASTNode cn = ASTUnderConstruction.idToNode.get(cur);
				// A class body's own wrapper is represented as an AST_TOPLEVEL/TOPLEVEL_CLASS
				// node -> Java type TopLevelFunctionDef (extends FunctionDef), NOT a separate
				// ClassDef ancestor -- confirmed directly against the raw parsed CSV (node's own
				// "name" column literally holds the class name at this wrapper). getName() wraps
				// it in literal "[...]" brackets -- stripped below.
				if( cn instanceof FunctionDef ) {
					String flags = cn.getFlags();
					// Check the node's own TOPLEVEL_CLASS flag directly, not classDef membership
					// -- confirmed against real GiveWP source that classDef stores a NAMESPACED
					// class ONLY under its fully-qualified name (PHPCSVNodeInterpreter's own
					// if/else), never the bare simple name, so a bare-name classDef.containsKey()
					// check silently failed for every namespaced class while working for legacy
					// non-namespaced ones. The flag needs no cross-referencing and has no
					// namespace-dependent failure mode.
					if( flags != null && flags.contains("TOPLEVEL_CLASS") ) {
						String nm = ((FunctionDef)cn).getName();
						if( nm != null && nm.startsWith("[") && nm.endsWith("]") )
							nm = nm.substring(1, nm.length() - 1);
						if( nm != null ) { cls = simpleClassName(nm); break; }
					}
				}
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
			if( nameChild == null || cls == null ) continue;
			propertyDefaultsByClassAndName.put(cls + "|" + nameChild.getEscapedCodeStr(), pel);
		}
	}

	// Narrow, self-contained "does this function have exactly one return, and if so what does it
	// return" check -- NOT a reuse of the diagnostic-only findSingleReturnExpression() in
	// StaticAnalysis.java (confirmed dead code, ITEM51/ITEM54), a fresh, small implementation
	// scoped only to what this resolver needs.
	private static Expression findSingleReturnExpressionNarrow(Long methodId) {
		Expression found = null;
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			if( !methodId.equals(n.getFuncId()) ) continue;
			if( found != null ) return null;   // more than one return -- ambiguous, refuse
			found = ((ast.statements.jump.ReturnStatement)n).getReturnExpression();
		}
		return found;
	}

	// DISPATCH_EDGE: within the SAME foreach body, find a method call whose target is either the
	// NewExpression directly (chained: `(new $cls())->method()`) or a variable that was assigned
	// the NewExpression's result earlier in the same body (`$obj = new $cls(); $obj->method();`).
	private static String findDispatchEdge(NewExpression newExpr, ast.logical.statements.Statement foreachBody) {
		java.util.Set<Long> bodyIds = subtreeIds(foreachBody.getNodeId());
		String assignedVarName = null;
		for( Long id : bodyIds ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( !(n instanceof AssignmentExpression) ) continue;
			if( ((AssignmentExpression)n).getRight() != newExpr ) continue;
			Expression lhs = ((AssignmentExpression)n).getLeft();
			if( lhs instanceof Variable ) assignedVarName = varNameOf(lhs);
			break;
		}
		for( Long id : bodyIds ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( !(n instanceof MethodCallExpression) ) continue;
			MethodCallExpression mc = (MethodCallExpression)n;
			Expression tgt = mc.getTargetObject();
			boolean matches = (tgt == newExpr)
				|| (assignedVarName != null && tgt instanceof Variable && assignedVarName.equals(varNameOf(tgt)));
			if( !matches ) continue;
			Expression methodExpr = mc.getTargetFunc();
			if( methodExpr instanceof StringExpression )
				return ((StringExpression)methodExpr).getEscapedCodeStr();
			if( methodExpr instanceof Identifier && ((Identifier)methodExpr).getNameChild() != null )
				return ((Identifier)methodExpr).getNameChild().getEscapedCodeStr();
			return "(unnamed)";
		}
		return null;
	}

	private static void scanDeclarativeDispatchCandidates() {
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof NewExpression) ) continue;
			NewExpression ne = (NewExpression)n;
			Expression targetClass = ne.getTargetClass();
			if( !(targetClass instanceof Variable) ) continue;   // literal `new SomeClass()` is not this pattern at all
			String varName = varNameOf(targetClass);
			if( varName == null ) continue;

			// Find the innermost enclosing ForEachStatement whose value-expression is this same
			// variable, by walking the same funcId's foreach statements and checking subtree
			// containment -- narrow, no general enclosing-scope walker built for this.
			ForEachStatement enclosing = null;
			Long fid = ne.getFuncId();
			if( fid == null ) continue;
			for( ASTNode cand : ASTUnderConstruction.idToNode.values() ) {
				if( !(cand instanceof ForEachStatement) ) continue;
				if( !fid.equals(cand.getFuncId()) ) continue;
				ForEachStatement fe = (ForEachStatement)cand;
				Expression valExpr = fe.getValueExpression();
				if( !(valExpr instanceof Variable) || !varName.equals(varNameOf(valExpr)) ) continue;
				ast.logical.statements.Statement body = fe.getStatement();
				if( body == null ) continue;
				if( !subtreeIds(body.getNodeId()).contains(ne.getNodeId()) ) continue;
				enclosing = fe; break;
			}

			if( enclosing == null ) {
				System.err.println("DECLARATIVE_DISPATCH_VERDICT newExprNode=" + ne.getNodeId()
					+ " verdict=" + DispatchVerdict.UNRESOLVED_DYNAMIC_SOURCE
					+ " reason=\"dynamic instantiation target is not a foreach loop variable with a provable source\""
					+ " classes=[] bootstrap_method=null");
				continue;
			}

			ClassSetResult csr = resolveClassLiteralSet(enclosing.getIteratedObject(), 0);
			if( csr.verdict != DispatchVerdict.RESOLVED_FINITE_SET ) {
				System.err.println("DECLARATIVE_DISPATCH_VERDICT newExprNode=" + ne.getNodeId()
					+ " verdict=" + csr.verdict + " reason=\"" + csr.reason + "\" classes=[] bootstrap_method=null");
				continue;
			}

			String bootstrapMethod = findDispatchEdge(ne, enclosing.getStatement());
			if( bootstrapMethod == null ) {
				System.err.println("DECLARATIVE_DISPATCH_VERDICT newExprNode=" + ne.getNodeId()
					+ " verdict=" + DispatchVerdict.UNRESOLVED_NO_DISPATCH_EDGE
					+ " reason=\"finite class set and dynamic instantiation proven, but no method call on the "
					+ "fresh instance found in the same loop body\" classes=" + csr.classes + " bootstrap_method=null");
				continue;
			}

			System.err.println("DECLARATIVE_DISPATCH_VERDICT newExprNode=" + ne.getNodeId()
				+ " verdict=" + DispatchVerdict.RESOLVED_FINITE_SET + " reason=null"
				+ " classes=" + csr.classes + " bootstrap_method=" + bootstrapMethod);
		}
	}

	private static void classifyUserSanitizers() {
		inferredIntSanitizers.clear(); inferredQuoteEscapers.clear();
		// Skip on very large ASTs: building retByFid/assignsByFid over the full AST
		// causes OOM on 1M+ node codebases (WPForms, GiveWP). Inferred sanitizers are a
		// precision improvement, not a correctness requirement — skipping them produces
		// false positives (taint not stopped at a user sanitizer) but never false negatives.
		// Threshold: 500k nodes covers ~95% of real-world plugins comfortably.
		if( ASTUnderConstruction.idToNode.size() > 500_000 ) {
			System.err.println("CLASSIFY_SKIP large AST ("+ASTUnderConstruction.idToNode.size()+" nodes) — inferred sanitizer pass skipped to prevent OOM");
			return;
		}
		HashMap<Long, java.util.List<ast.statements.jump.ReturnStatement>> retByFid =
			new HashMap<Long, java.util.List<ast.statements.jump.ReturnStatement>>();
		HashMap<Long, HashMap<String, java.util.List<ASTNode>>> assignsByFid =
			new HashMap<Long, HashMap<String, java.util.List<ASTNode>>>();
		PHPCGFactory.recordScanSite("PCG_978", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			Long fid; try { fid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( fid == null ) continue;
			if( n instanceof ast.statements.jump.ReturnStatement ) {
				java.util.List<ast.statements.jump.ReturnStatement> l = retByFid.get(fid);
				if( l == null ) { l = new ArrayList<ast.statements.jump.ReturnStatement>(); retByFid.put(fid, l); }
				l.add((ast.statements.jump.ReturnStatement)n);
			}
			else if( n instanceof AssignmentExpression ) {
				String av = varNameOf(((AssignmentExpression)n).getLeft());
				ASTNode arhs = ((AssignmentExpression)n).getRight();
				if( av != null && arhs != null ) {
					HashMap<String,java.util.List<ASTNode>> m = assignsByFid.get(fid);
					if( m == null ) { m = new HashMap<String,java.util.List<ASTNode>>(); assignsByFid.put(fid, m); }
					java.util.List<ASTNode> al = m.get(av);
					if( al == null ) { al = new ArrayList<ASTNode>(); m.put(av, al); }
					al.add(arhs);
				}
			}
		}
		Set<Long> defs = new HashSet<Long>();
		defs.addAll(allFunc); defs.addAll(allMtd); defs.addAll(allStaticMtd);
		// Two passes so int-sanitizer chains (a fn returning another inferred int sanitizer) resolve.
		for( int pass=0; pass<2; pass++ ) {
			HashMap<String,Integer> nameKind = new HashMap<String,Integer>();   // name -> consistent kind, or -1 mixed
			for( Long fid : defs ) {
				ASTNode dn = ASTUnderConstruction.idToNode.get(fid);
				if( !(dn instanceof FunctionDef) ) continue;
				String name = ((FunctionDef)dn).getName();
				if( name == null || name.isEmpty() ) continue;
				java.util.List<ast.statements.jump.ReturnStatement> rets = retByFid.get(fid);
				if( rets == null || rets.isEmpty() ) { nameKind.put(name, -1); continue; }   // no return -> not a sanitizer
				HashMap<String,Set<Long>> guards = ctypeGuardRegions(fid);
				HashMap<String,java.util.List<ASTNode>> fassigns = assignsByFid.get(fid);
				boolean allInt=true, allEsc=true;
				for( ast.statements.jump.ReturnStatement r : rets ) {
					int k = classifyReturn(r, guards, fassigns);
					if( k != RET_INT ) allInt=false;
					if( k != RET_ESC ) allEsc=false;
				}
				int kind = allInt ? RET_INT : (allEsc ? RET_ESC : -1);
				Integer prev = nameKind.get(name);
				if( prev == null ) nameKind.put(name, kind);
				else if( !prev.equals(kind) ) nameKind.put(name, -1);   // same name, different kind -> disqualify
			}
			inferredIntSanitizers.clear(); inferredQuoteEscapers.clear();
			for( java.util.Map.Entry<String,Integer> en : nameKind.entrySet() ) {
				if( en.getValue() == RET_INT ) inferredIntSanitizers.add(en.getKey());
				else if( en.getValue() == RET_ESC ) inferredQuoteEscapers.add(en.getKey());
			}
		}
		for( String s : inferredIntSanitizers ) System.err.println("WPINTSAN inferred integer sanitizer: "+s);
		for( String s : inferredQuoteEscapers ) System.err.println("WPESCSAN inferred quote-escaper: "+s);
	}

	// Add every call to an inferred sanitizer to sqlSanitizers. Integer-sanitizer calls are
	// safe in any context; escaper calls are then subject to demoteAllUnquotedEscSql (which
	// recognizes them via escSqlCallNode), so unquoted uses are dropped back to risky.
	private static void registerInferredSanitizerNodes() {
		if( inferredIntSanitizers.isEmpty() && inferredQuoteEscapers.isEmpty() ) return;
		PHPCGFactory.recordScanSite("PCG_1038", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof CallExpressionBase) ) continue;
			String nm = callTargetName((CallExpressionBase)n);
			if( nm == null ) continue;
			if( inferredIntSanitizers.contains(nm) || inferredQuoteEscapers.contains(nm) )
				PHPCSVEdgeInterpreter.sqlSanitizers.add(n.getNodeId());
		}
	}

	// Scan all assignments for  <lhs> = $wpdb  and record the lhs name as an alias.
	// Plugins commonly stash $wpdb in a class property or local ($_db = $wpdb), and
	// then issue all SQL through that alias; without this the tool is blind to them.
	private static void collectWpdbAliases() {
		wpdbAliases.clear();
		PHPCGFactory.recordScanSite("PCG_1052", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;

			AssignmentExpression asn = (AssignmentExpression) n;
			Expression rhs = asn.getRight();
			// RHS must be the $wpdb variable
			if( rhs instanceof Variable
				&& ((Variable)rhs).getNameExpression() instanceof StringExpression
				&& ((StringExpression)((Variable)rhs).getNameExpression()).getEscapedCodeStr().equals("wpdb") ) {
				String lhsName = receiverName(asn.getLeft());
				if( !lhsName.isEmpty() && !lhsName.equals("wpdb") ) {
					wpdbAliases.add(lhsName);
				}
			}
		}
	}

	// Privilege classes for seeded entry points. "public" mode (WP_SEED_MODE=public)
	// seeds ONLY unauth + lowpriv entries, so any resulting flag is reachable without
	// privileged access by construction — this is what makes a flag bounty-relevant
	// rather than privilege-agnostic.
	private static final String SEED_MODE =
		System.getenv("WP_SEED_MODE") != null ? System.getenv("WP_SEED_MODE")
		: (System.getProperty("wp.seed.mode") != null ? System.getProperty("wp.seed.mode") : "all");

	// Extended sink classes beyond SQLi. Off by default (SINK_MODE="sqli") so the core
	// behavior and the SQLi regression suite are unchanged; WP_SINKS=extended opts in.
	private static final String SINK_MODE =
		System.getenv("WP_SINKS") != null ? System.getenv("WP_SINKS")
		: (System.getProperty("wp.sinks") != null ? System.getProperty("wp.sinks") : "sqli");
	// node id -> vuln class, so a flagged node can be labeled (object-injection/ssrf/etc.)
	public static HashMap<Long,String> sinkClass = new HashMap<Long,String>();

	// WP_SQLI_ONLY=1 drops the output sinks (echo/print/printf/print_r/exit/die/vprintf)
	// from the sink set. Those are XSS-class OUTPUT sinks: in a SQLi-focused scan they are
	// pure noise (an escaped-or-not echo of a request var is an XSS question, not a SQL one)
	// and they dominate the residual false positives on output-heavy plugins. SQLi detection
	// ($wpdb / mysql_query / wrappers) is unaffected, so the SQLi regression suite is
	// unchanged. Default off (output sinks remain), preserving the existing XSS surface.
	public static final boolean SQLI_ONLY =
		"1".equals(System.getenv("WP_SQLI_ONLY")) || "true".equals(System.getenv("WP_SQLI_ONLY"))
		// Priv-esc and file-read scans suppress output sinks too — echo/print paths are XSS,
		// not priv-esc or file-read, and including them causes pagination FPs.
		|| "1".equals(System.getenv("WP_PRIV_ESC")) || "1".equals(System.getenv("WP_FILE_READ"));

	// WP_XSS_ONLY=1 is the symmetric counterpart: keep the XSS-class OUTPUT sinks
	// (echo/print/printf/print_r/exit/die/vprintf) and DROP the SQL ($wpdb/mysql_query/wrapper)
	// and extended (SSRF/LFI/object-injection/...) sinks, so an XSS scan is not polluted by SQL
	// noise. Output sinks are tagged sinkClass "xss" so the StaticAnalysis collector can keep
	// only those. In this mode the XSS-neutralizing wrappers (wp_kses*) also stop taint.
	public static final boolean XSS_ONLY =
		"1".equals(System.getenv("WP_XSS_ONLY")) || "true".equals(System.getenv("WP_XSS_ONLY"));

	// WP_PRIV_ESC_ONLY=1 / WP_FILE_READ_ONLY=1: keep ONLY the sinks of that class, dropping
	// SQL/XSS/extended sinks. Without this, a WP_PRIV_ESC=1 run on a plugin that also has SQLi
	// emits both classes in one stream, and the adjudicator labels the SQLi findings PRIV_ESC
	// (wrong sink_hint, wrong evaluation question). Mirrors XSS_ONLY.
	// CORRECTNESS-FIRST BY DEFAULT: every reachable role assignment is a privilege-change sink.
	// WP_PRIV_ESC_ECONOMY=1 opts into a documented cost-saving suppression (constant LOW-privilege
	// role targeting the CURRENT user) that has KNOWN false negatives — controls R5/R6: a plugin may
	// grant powerful capabilities to 'customer', and a site may define a custom role weaker than
	// 'subscriber', neither of which static analysis can see. Never on unless explicitly requested.
	public static final boolean PRIV_ESC_ECONOMY =
		"1".equals(System.getenv("WP_PRIV_ESC_ECONOMY")) || "true".equalsIgnoreCase(System.getenv("WP_PRIV_ESC_ECONOMY"));
	public static final boolean PRIV_ESC_ONLY =
		"1".equals(System.getenv("WP_PRIV_ESC_ONLY")) || "true".equals(System.getenv("WP_PRIV_ESC_ONLY"));
	public static final boolean FILE_DELETE_ONLY =
		"1".equals(System.getenv("WP_FILE_DELETE_ONLY")) || "true".equals(System.getenv("WP_FILE_DELETE_ONLY"));
	public static final boolean FILE_READ_ONLY =
		"1".equals(System.getenv("WP_FILE_READ_ONLY")) || "true".equals(System.getenv("WP_FILE_READ_ONLY"));
	// True in the extended sink mode (LFI/RFI/SSRF/file/object-injection). Enables the path/URL allow-list
	// sanitizers (sanitize_title, sanitize_file_name, basename, …) that neutralize traversal and remote-URL
	// payloads — the wp-job-manager-style false positive where a request value reaching include() is first
	// reduced to [a-z0-9-] by sanitize_title.
	public static final boolean EXTENDED = "extended".equals(SINK_MODE);

	private static final Set<String> OBJ_INJECTION_SINKS =
		new HashSet<String>(Arrays.asList("unserialize","maybe_unserialize"));
	private static final Set<String> CALLABLE_SINKS =
		new HashSet<String>(Arrays.asList("call_user_func","call_user_func_array"));
	private static final Set<String> SSRF_SINKS =
		new HashSet<String>(Arrays.asList("wp_remote_get","wp_remote_post","wp_remote_request",
			"wp_remote_head","wp_remote_fopen","wp_safe_remote_get","wp_safe_remote_post"));
	// FILE SINKS, SPLIT BY OPERATION. Previously one bundled set tagged "file-access", which meant
	// an unlink() finding was handed the file-READ evaluation question ("is the path confined, could
	// it read wp-config?") instead of the deletion one. Split so each class carries its own sink tag
	// and its own adjudicator hint.
	private static final Set<String> FILE_READ_SINKS =
		new HashSet<String>(Arrays.asList("file_get_contents","readfile","fread","fgets","fgetss",
			"file","fpassthru","gzfile","readgzfile"));
	private static final Set<String> FILE_WRITE_SINKS =
		new HashSet<String>(Arrays.asList("file_put_contents","fwrite","fputs","fopen",
			"move_uploaded_file","copy","rename"));
	// Arbitrary file DELETION with a request-derived path. Dominant high-severity shape in the
	// Jul-2026 bulletin (8 CVEs, two 9.1 unauthenticated). wp_delete_file is WordPress's wrapper.
	private static final Set<String> FILE_DELETE_SINKS =
		new HashSet<String>(Arrays.asList("unlink","wp_delete_file","rmdir",
			"wp_delete_attachment","wp_delete_file_from_directory"));
	// Retained for the legacy bundled "extended" mode: union of the three.
	private static final Set<String> FILE_SINKS = new HashSet<String>() {{
		addAll(FILE_READ_SINKS); addAll(FILE_WRITE_SINKS); addAll(FILE_DELETE_SINKS);
	}};
	// Privilege escalation: functions that SET user roles or capabilities.
	// When REQUEST-TAINTED data flows into these calls, a low-privilege attacker can
	// elevate to administrator — the dominant unauthenticated privilege escalation class
	// (CVE-2026-15982 Aimogen Pro, CVE-2026-14956 Bricksforge, CVE-2026-61951 TrueBooker,
	//  CVE-2026-13741 Digits subscriber priv-esc).
	// set_role() is a METHOD call on WP_User; handled separately in the method-sink block.
	// update_user_meta with wp_capabilities is also tracked; add_role modifies global roles.
	// FIX (2026-08-08): account-takeover sink expansion. reset_password()/wp_set_password() set a
	// TARGET user's password directly and take no "role" argument at all -- unlike
	// wp_update_user/wp_insert_user/wp_create_user, there is no legitimate "just updating an
	// unrelated profile field" shape to guard against with an array-key check, so these are added
	// to the SAME unconditional-sink bucket as add_role/remove_role/add_cap/remove_cap (see
	// isUserArrayFunc below -- these two names are deliberately NOT added there). Motivated by two
	// independently-evaluated real CVEs (Single Sign On for TNG, CVE-2026-15964; SMS Alert,
	// CVE-2026-15014) both calling reset_password() from an unauthenticated-reachable handler with
	// no capability check -- confirmed SINK_MISS under the frozen baseline; this is a targeted,
	// evidenced expansion, not a speculative addition.
	// KNOWN LIMITATION (verified, not new -- pre-existing on add_role/add_cap/etc too): this bare-
	// function-call sink set has no receiver/namespace-aware guard (unlike PRIV_ESC_METHODS, which
	// has privEscMethodProvablyNotWpUser()), so a plugin defining its own unrelated function with
	// one of these names (e.g. namespace MyPlugin; function reset_password(...)) will also match.
	// Confirmed via adversarial fixture that this applies identically to the pre-existing
	// add_role entry, not just the new additions -- an existing, accepted tradeoff of this
	// mechanism, not something this change makes worse.
	private static final Set<String> PRIV_ESC_SINKS =
		new HashSet<String>(Arrays.asList(
			"wp_update_user","wp_insert_user","wp_create_user",
			"add_role","remove_role","add_cap","remove_cap",
			"reset_password","wp_set_password",
			// FIX (2026-08-08): wp_delete_user() bridged in as a bare, unconditional sink,
			// matching add_role/remove_role's treatment rather than wp_update_user's role-key-
			// gated treatment. Unlike wp_update_user (called routinely for benign profile edits,
			// where role-key presence is the actual signal), there is no benign call shape for
			// wp_delete_user -- deleting a user is inherently sensitive regardless of any
			// argument, so no argument-shape analysis is warranted here, only the same
			// reachability/guard treatment every other bare-function sink in this set already
			// gets. Motivated by a real, confirmed gap: PZ Frontend Manager (CVE-2026-3477)
			// reaches wp_delete_user() from wp_ajax_pzfm_user_request_action with zero guards,
			// and this sink's absence was the entire reason that finding stayed SINK_MISS.
			"wp_delete_user"
			// update_option removed: too broad (any update_option fires, including pagination/CSS);
			// role-escalation via option needs a name-aware check ('default_role', 'users_can_register').
		));
	// FIX (2026-08-08): a new, semantically distinct shape (not folded into PRIV_ESC_SINKS).
	// wp_insert_post/wp_update_post/wp_delete_post/wp_trash_post are already in ACL_WRITES (the
	// engine's existing, separate access-control-lint sensitive-operation list) but were never
	// bridged into the structured ControlReachPath/auth-evidence-v1 pipeline. These are content-
	// mutation operations, not role/capability changes -- PRIV_ESC's own name and existing
	// role-key-presence filtering (for wp_update_user etc.) don't fit this category, so this gets
	// its own SecurityShape ("POST_WRITE") rather than being semantically overloaded into
	// PRIV_ESC. Treated as bare, unconditional sinks (matching FILE_DELETE/FILE_READ's
	// simplicity, not PRIV_ESC's role-key filtering) since there is no analogous "is this
	// specific post-array dangerous" signal to filter on -- unlike a 'role' key, no field in a
	// post array structurally indicates privilege relevance. Whether a given under-authorized
	// wp_insert_post() call matters is exactly the kind of sufficiency question this session's
	// authorization-sufficiency fix now correctly routes to REVIEW rather than silently
	// resolving. Motivated by a real, confirmed gap: User Registration & Membership
	// (CVE-2026-4056) reaches wp_insert_post() from a REST route whose real permission_callback
	// checks 'edit_posts' -- too weak for site-wide content-access-rule management -- and this
	// sink's absence was the entire reason that finding stayed SINK_MISS despite a real,
	// present, controlling-but-insufficient permission_callback.
	private static final Set<String> POST_WRITE_SINKS =
		new HashSet<String>(Arrays.asList("wp_insert_post","wp_update_post","wp_delete_post","wp_trash_post"));
	// FIX (2026-08-08): update_user_meta/add_user_meta/delete_user_meta bridged in, but NOT as a
	// bare unconditional sink like wp_delete_user or POST_WRITE -- unlike those, these functions
	// are called constantly for entirely benign, routine per-user setting storage (a fixed,
	// literal meta key is the overwhelming common case and carries no risk by itself). The real
	// risk signal, confirmed against the actual motivating CVE's source before designing this
	// (Users manager - PN, CVE-2026-4003): the META KEY NAME itself is attacker-controlled --
	// `foreach ($userspn_key_value as $userspn_key => $userspn_value) { update_user_meta($user_id,
	// $userspn_key, $userspn_value); }`, where $userspn_key traces directly to
	// $_POST['ajax_keys'][...]['id']. This is an arbitrary-key write, structurally the same risk
	// shape as an attacker choosing to overwrite wp_capabilities or any other sensitive field,
	// regardless of which specific key names are known to be dangerous -- so this is gated on KEY
	// ARGUMENT TAINT (reusing valueIsTainted()/varAssignsByFunc, the same machinery already used
	// for the wp_update_user role-key check immediately below in this same loop), not on a
	// curated list of "dangerous" key names. A fixed, literal meta key -- the overwhelmingly
	// common, benign call shape -- is deliberately NOT flagged at all, rather than flagging every
	// update_user_meta call and relying on adjudication to sort it out; the false-positive volume
	// from doing that would have been the same mistake already made and reverted for
	// update_option earlier this session.
	private static final Set<String> USER_META_SINKS =
		new HashSet<String>(Arrays.asList("update_user_meta","add_user_meta","delete_user_meta"));
	// Method-call privilege escalation sinks (called on WP_User / WP_Role objects)
	private static final Set<String> PRIV_ESC_METHODS =
		new HashSet<String>(Arrays.asList("set_role","add_role","remove_role","add_cap","remove_cap"));

	// Second-order / stored taint (EXTENSION beyond upstream TChecker, which models no
	// persistent stores). Treat reads from WordPress persistent stores as potential sources:
	// data written by one request and read back in another can carry attacker control.
	// Higher FP rate (stored data is often trusted), so gated OFF by default.
	// WP_STORED_TAINT: unset (or 0/false) = off. When on, the write-provenance-scoped model is the
	// default — a stored READ is a source only when a request-tainted WRITE to the same key exists in
	// code, which cuts the dominant FP vector (config read from get_option() that no request writes).
	// The explicit value "broad" opts into the old recall-max behavior (every stored read a source;
	// higher FP rate, kept only as an escape hatch). Gated OFF by default (stored data is often trusted).
	private static final String STORED_TAINT_ENV = System.getenv("WP_STORED_TAINT");
	// WP_WPDB_STORED=1 (or WP_STORED_TAINT=wpdb): pair writes/reads on a plugin's OWN $wpdb tables.
	// The option/meta pairing below keys on a literal option name; a custom table's column lives
	// inside a SQL STRING on the read side, so that machinery cannot express it. Without this, a
	// second-order path ($_POST -> $wpdb->insert(custom_table) -> $wpdb->get_var(SELECT col) -> sink)
	// is invisible — the miss confirmed against CVE-2026-59555 (Participants Database file deletion).
	public static final boolean WPDB_STORED =
		"1".equals(System.getenv("WP_WPDB_STORED")) || "true".equalsIgnoreCase(System.getenv("WP_WPDB_STORED"))
		|| "wpdb".equalsIgnoreCase(System.getenv("WP_STORED_TAINT"));
	private static final boolean STORED_TAINT =
		"1".equals(STORED_TAINT_ENV) || "true".equalsIgnoreCase(STORED_TAINT_ENV)
		|| "paired".equalsIgnoreCase(STORED_TAINT_ENV) || "broad".equalsIgnoreCase(STORED_TAINT_ENV)
		|| "wpdb".equalsIgnoreCase(STORED_TAINT_ENV) || "1".equals(System.getenv("WP_WPDB_STORED"))
		|| "1".equals(System.getProperty("wp.stored.taint"));
	// Scoped is the default whenever stored-taint is on; only the explicit "broad" value opts back into
	// the blunt all-reads-are-sources mode. (Replaces the old =1/=paired + WP_STORED_PAIRED split.)
	private static final boolean STORED_PAIRED =
		STORED_TAINT && !"broad".equalsIgnoreCase(STORED_TAINT_ENV);
	private static final Set<String> STORED_SOURCE_FUNCS =
		new HashSet<String>(Arrays.asList("get_option","get_site_option","get_post_meta",
			"get_user_meta","get_term_meta","get_comment_meta","get_metadata",
			"get_transient","get_site_transient"));
	// Read function -> argument index of the key (the option/meta/transient name).
	private static final java.util.Map<String,Integer> STORED_READ_KEYIDX = new java.util.HashMap<String,Integer>();
	// Write function -> {key index, value index}. A non-literal value is treated as potentially tainted.
	private static final java.util.Map<String,int[]> STORED_WRITE_KEYVAL = new java.util.HashMap<String,int[]>();
	static {
		STORED_READ_KEYIDX.put("get_option",0); STORED_READ_KEYIDX.put("get_site_option",0);
		STORED_READ_KEYIDX.put("get_transient",0); STORED_READ_KEYIDX.put("get_site_transient",0);
		STORED_READ_KEYIDX.put("get_post_meta",1); STORED_READ_KEYIDX.put("get_user_meta",1);
		STORED_READ_KEYIDX.put("get_term_meta",1); STORED_READ_KEYIDX.put("get_comment_meta",1);
		STORED_READ_KEYIDX.put("get_metadata",2);
		STORED_WRITE_KEYVAL.put("update_option",new int[]{0,1});   STORED_WRITE_KEYVAL.put("add_option",new int[]{0,1});
		STORED_WRITE_KEYVAL.put("update_site_option",new int[]{0,1}); STORED_WRITE_KEYVAL.put("update_network_option",new int[]{0,1});
		STORED_WRITE_KEYVAL.put("set_transient",new int[]{0,1});   STORED_WRITE_KEYVAL.put("set_site_transient",new int[]{0,1});
		STORED_WRITE_KEYVAL.put("update_post_meta",new int[]{1,2}); STORED_WRITE_KEYVAL.put("add_post_meta",new int[]{1,2});
		STORED_WRITE_KEYVAL.put("update_user_meta",new int[]{1,2}); STORED_WRITE_KEYVAL.put("add_user_meta",new int[]{1,2});
		STORED_WRITE_KEYVAL.put("update_term_meta",new int[]{1,2}); STORED_WRITE_KEYVAL.put("add_term_meta",new int[]{1,2});
		STORED_WRITE_KEYVAL.put("update_comment_meta",new int[]{1,2}); STORED_WRITE_KEYVAL.put("add_comment_meta",new int[]{1,2});
		STORED_WRITE_KEYVAL.put("update_metadata",new int[]{2,3}); STORED_WRITE_KEYVAL.put("add_metadata",new int[]{2,3});
	}

	// Access-control lint (NOT taint): does each public-reachable handler guard itself?
	// Gated behind WP_ACCESS_CONTROL=1. Best run with WP_SEED_MODE=all so every entry is
	// classified; the lint itself filters to unauth/low-priv handlers.
	private static final boolean ACCESS_CONTROL =
		"1".equals(System.getenv("WP_ACCESS_CONTROL"))
		|| "true".equalsIgnoreCase(System.getenv("WP_ACCESS_CONTROL"))
		|| "1".equals(System.getProperty("wp.access.control"));
	// FN-3 disclosure pass (opt-in via WP_DISCLOSURE=1). Models unauthorized information disclosure —
	// a sensitive stored/file read returned to the requester by an under-authorized handler. Kept
	// OFF by default: the current trigger is CO-OCCURRENCE (sensitive read + return sink in one
	// handler), not read->response DATAFLOW, so it over-fires when the secret flows elsewhere (e.g.
	// customer-reviews download_addon reads the license key but sends it to a remote API and returns
	// only a URL). Default runs stay clean; enable for disclosure-focused hunting until the dataflow
	// refinement lands.
	private static final boolean DISCLOSURE =
		"1".equals(System.getenv("WP_DISCLOSURE"))
		|| "true".equalsIgnoreCase(System.getenv("WP_DISCLOSURE"));
	// Gated behind WP_CSRF=1. The cross-site-request-forgery complement of the access-control lint:
	// an AUTHENTICATED state-changing action handler (logged-in wp_ajax_/admin_post_) that carries no
	// nonce. The cap check (if any) passes because the victim genuinely holds the privilege; the missing
	// nonce is what lets an attacker forge the request from the victim's browser. Shares the same BFS,
	// guard sets, and sensitivity model as the ACL audit — it is exactly the authed/no-nonce quadrant.
	private static final boolean CSRF =
		"1".equals(System.getenv("WP_CSRF"))
		|| "true".equalsIgnoreCase(System.getenv("WP_CSRF"));
	// funcid -> privilege tag for every seeded entry (populated in registerCallbackAsEntry).
	public static HashMap<Long,String> entryPriv = new HashMap<Long,String>();

	// ITEM42 FIX: WordPress's REST API registers 'callback' and 'permission_callback' as two
	// independent closures on the same register_rest_route() call; WordPress core invokes
	// permission_callback separately from -- not as a caller of -- the handler, so no PHP-level
	// call edge ever links them. objectAuthorizationFacts() searches only functions reachable via
	// actual call-graph edges from the entry to the sink, so a permission_callback's own
	// current_user_can(cap,obj)-shaped object check (even when fully resolvable, e.g. a plain
	// array($this,'method') reference, not merely an opaque inline closure) was invisible to that
	// analysis regardless of whether it existed and was correct. This map records, per REST
	// handler function id, the resolved permission_callback function id(s) found alongside it on
	// the same register_rest_route() call, so objectAuthorizationFacts() can additionally search
	// those bodies. Populated only in seedRestRoute(); empty/absent for every non-REST entry, so
	// this is additive and cannot affect any previously-computed evidence for other shapes.
	public static HashMap<Long,Set<Long>> restHandlerToPermCallbackFuncIds = new HashMap<Long,Set<Long>>();

	// ITEM52: runtime-instrumented performance inventory over the 76 PRODUCTION_REACHABLE_UNMEASURED
	// scan sites the ITEM51 reachability tracer identified. Per the requester's explicit design:
	// record how many times each specific scan site is actually reached (calls) and the total
	// corpus size visited across all those reaches (total_nodes) -- NOT the loop body's internal
	// work, just calls x corpus_size, the "total_work" proxy the requester specified, with actual
	// measured runtime as the tie-breaker via the existing performance timing already in the
	// harness. Auto-inserted by scripts/instrument_scan_sites.py, one call per targeted site,
	// immediately before that site's for-loop -- never hand-edited per-site, to avoid the same
	// error-prone one-at-a-time process ITEM48/51 exist to move away from.
	public static java.util.HashMap<String, long[]> scanSiteStats = new java.util.HashMap<String, long[]>();
	public static void recordScanSite(String siteId, long nodesVisited) {
		long[] s = scanSiteStats.get(siteId);
		if( s == null ) { s = new long[]{0, 0}; scanSiteStats.put(siteId, s); }
		s[0]++;            // calls
		s[1] += nodesVisited; // total_nodes (sum across all calls -- this IS the total_work proxy)
	}

	// PERFORMANCE FIX (unbounded corpus-wide scan, site #3 -- same architectural class as the
	// WPForms finding this bundle already documents and partially remediated). findTemplateLoaderShape()
	// and findPropertyMediatedLoaderShape() each scanned ASTUnderConstruction.idToNode.values() (every
	// node in the ENTIRE parsed corpus) AND allCallSites() (every call site in the entire corpus) fresh,
	// PER FUNCTION being resolved -- O(functions x total_nodes) and worse in the fallback path. Fine on
	// a 733-file standalone plugin; catastrophic (confirmed via two jstack thread dumps 15s apart landing
	// on the identical stack, CPU pegged, zero forward progress) on a 2,092-file fully-vendored build with
	// much heavier cross-file interconnection. Fix follows this codebase's own established idiom for
	// exactly this problem (see oneHopGuardWrapperFunctions's byFunc grouping, assignsByFunc/callsByFunc/
	// sinksByFunc/returnsByFunc elsewhere): build each index ONCE, in one pass over the corpus, keyed by
	// funcId, then look up by funcId instead of rescanning. This is a non-semantic performance fix --
	// output must be byte-identical to the unbounded version, just computed in O(total_nodes + functions)
	// instead of O(functions * total_nodes).
	private static java.util.Map<Long,java.util.List<IncludeOrEvalExpression>> includeOrEvalByFunc = null;
	private static java.util.Map<Long,java.util.List<CallExpressionBase>> callSitesByFuncCache = null;

	private static void buildTemplateLoaderIndicesIfNeeded() {
		if( includeOrEvalByFunc != null && callSitesByFuncCache != null ) return;
		includeOrEvalByFunc = new java.util.HashMap<Long,java.util.List<IncludeOrEvalExpression>>();
		PHPCGFactory.recordScanSite("PCG_1370", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof IncludeOrEvalExpression) ) continue;
			Long fid = null; try { fid = n.getFuncId(); } catch( Exception e ) {}
			if( fid == null ) continue;
			java.util.List<IncludeOrEvalExpression> l = includeOrEvalByFunc.get(fid);
			if( l == null ) { l = new java.util.ArrayList<IncludeOrEvalExpression>(); includeOrEvalByFunc.put(fid, l); }
			l.add((IncludeOrEvalExpression)n);
		}
		callSitesByFuncCache = new java.util.HashMap<Long,java.util.List<CallExpressionBase>>();
		PHPCGFactory.recordScanSite("PCG_1379", ((java.util.List<?>)allCallSites()).size());
		for( CallExpressionBase call : allCallSites() ) {
			Long fid = null; try { fid = call.getFuncId(); } catch( Exception e ) {}
			if( fid == null ) continue;
			java.util.List<CallExpressionBase> l = callSitesByFuncCache.get(fid);
			if( l == null ) { l = new java.util.ArrayList<CallExpressionBase>(); callSitesByFuncCache.put(fid, l); }
			l.add(call);
		}
	}

	private static java.util.List<IncludeOrEvalExpression> includeOrEvalNodesInFunc(Long funcId) {
		buildTemplateLoaderIndicesIfNeeded();
		java.util.List<IncludeOrEvalExpression> l = includeOrEvalByFunc.get(funcId);
		return l == null ? java.util.Collections.<IncludeOrEvalExpression>emptyList() : l;
	}

	private static java.util.List<CallExpressionBase> callSitesInFunc(Long funcId) {
		buildTemplateLoaderIndicesIfNeeded();
		java.util.List<CallExpressionBase> l = callSitesByFuncCache.get(funcId);
		return l == null ? java.util.Collections.<CallExpressionBase>emptyList() : l;
	}

	// ITEM42 FIX (closure case, phase 2): CSVFunctionExtractor splits nodes.csv into one CSVAST
	// unit per function/closure (each closure's declaration becomes the ROOT of its OWN unit, per
	// its own code comment: "we now only add function declarations once, as root node of the
	// CSVAST that corresponds to this function itself"). The edge from an array-literal element to
	// an inline closure used as its value therefore crosses a unit boundary and is silently
	// dropped before ever reaching PHPCSVEdgeInterpreter.handle() -- confirmed empirically via
	// targeted logging (the edge is present in raw rels.csv but its handle() call never occurs),
	// not assumed from the pre-existing code comment alone. Rather than reworking the per-function
	// extraction architecture (broad blast radius: closures are used throughout WordPress hook
	// registration generally, not just here), this reads nodes.csv/rels.csv directly and once,
	// completely independently of the existing extraction pipeline, to recover just the one
	// relationship this detector needs: which AST_CLOSURE node (if any) is the direct PARENT_OF
	// child of a given node. Read-only, additive, and unable to affect any other code path: it
	// touches no shared mutable state the existing pipeline reads from.
	private static HashMap<Long,Long> rawParentToClosureChild = null;

	private static void loadRawClosureLinksIfNeeded() {
		if( rawParentToClosureChild != null ) return;
		rawParentToClosureChild = new HashMap<Long,Long>();
		try {
			HashMap<Long,String> idToType = new HashMap<Long,String>();
			BufferedReader nr = new BufferedReader(new FileReader("nodes.csv"));
			try {
				String header = nr.readLine();
				if( header != null ) {
					String[] cols = header.split("\t", -1);
					int idIdx = -1, typeIdx = -1;
					for( int i = 0; i < cols.length; i++ ) {
						if( cols[i].equals("id:int") ) idIdx = i;
						else if( cols[i].equals("type") ) typeIdx = i;
					}
					if( idIdx >= 0 && typeIdx >= 0 ) {
						String line;
						while( (line = nr.readLine()) != null ) {
							String[] f = line.split("\t", -1);
							if( f.length <= Math.max(idIdx, typeIdx) ) continue;
							try { idToType.put(Long.parseLong(f[idIdx]), f[typeIdx]); }
							catch( NumberFormatException nfe ) { /* non-numeric id row, skip */ }
						}
					}
				}
			} finally { nr.close(); }

			BufferedReader er = new BufferedReader(new FileReader("rels.csv"));
			try {
				String header = er.readLine();
				if( header != null ) {
					String[] cols = header.split("\t", -1);
					int startIdx = -1, endIdx = -1, typeIdx = -1;
					for( int i = 0; i < cols.length; i++ ) {
						if( cols[i].equals("start") ) startIdx = i;
						else if( cols[i].equals("end") ) endIdx = i;
						else if( cols[i].equals("type") ) typeIdx = i;
					}
					if( startIdx >= 0 && endIdx >= 0 && typeIdx >= 0 ) {
						String line;
						while( (line = er.readLine()) != null ) {
							String[] f = line.split("\t", -1);
							if( f.length <= Math.max(startIdx, Math.max(endIdx, typeIdx)) ) continue;
							if( !"PARENT_OF".equals(f[typeIdx]) ) continue;
							try {
								Long s = Long.parseLong(f[startIdx]);
								Long e = Long.parseLong(f[endIdx]);
								if( "AST_CLOSURE".equals(idToType.get(e)) ) rawParentToClosureChild.put(s, e);
							} catch( NumberFormatException nfe ) { /* skip */ }
						}
					}
				}
			} finally { er.close(); }
		} catch( IOException ioe ) {
			// nodes.csv/rels.csv not found in CWD, or unreadable -- leave the map empty. This is
			// additive evidence only; its absence cannot break anything the existing pipeline does.
			rawParentToClosureChild = new HashMap<Long,Long>();
		}
	}
	// Authorization guards: they restrict WHO may act. On an anonymous-reachable endpoint any of
	// these (capability or authentication) is adequate — it excludes the unauthenticated attacker.
	private static final Set<String> AUTHZ_GUARDS =
		new HashSet<String>(Arrays.asList("current_user_can","user_can","author_can",
			"map_meta_cap","current_user_can_for_blog","is_user_logged_in",
			"wp_check_password","wp_validate_auth_cookie",
			// Credential / explicit-authentication primitives: a handler that authenticates the
			// caller by verifying supplied credentials (application password, wp_signon) or compares
			// a request secret against a stored one (hash_equals) is NOT anonymously reachable, even
			// when its REST permission_callback is __return_true. This is the suretriggers shape
			// (create_wp_connection gates on wp_authenticate_application_password) and the generic
			// secret-token handshake. hash_equals is included as the constant-time secret check that
			// dominates such handlers; it restricts WHO may act just as a capability check does.
			"wp_authenticate","wp_authenticate_application_password",
			"wp_authenticate_application_passwords","wp_signon","hash_equals"));
	// Nonce guards: they prove the request originated from a site page (CSRF protection) but do
	// NOT restrict who may act. On a nopriv / open-REST endpoint the nonce is served to the same
	// anonymous users, so a nonce *alone* is not authorization — this is the fm5 upload shape.
	private static final Set<String> NONCE_GUARDS =
		new HashSet<String>(Arrays.asList("check_ajax_referer","wp_verify_nonce","check_admin_referer"));
	// State-changing operations whose presence (without a guard) makes a handler interesting.
	private static final Set<String> ACL_WRITES =
		new HashSet<String>(Arrays.asList("update_option","add_option","delete_option",
			"update_site_option","update_user_meta","add_user_meta","delete_user_meta",
			"update_post_meta","add_post_meta","delete_post_meta","update_metadata","delete_metadata",
			"wp_insert_post","wp_update_post","wp_delete_post","wp_trash_post",
			"wp_insert_user","wp_update_user","wp_delete_user","wp_create_user","wp_set_password",
			"wp_insert_term","wp_update_term","wp_delete_term","update_user_option"));
	// $wpdb methods that change state. Reads (get_var/get_row/get_results) and the ambiguous
	// query() are deliberately excluded: a missing-auth read is a separate, lower-severity class,
	// and counting reads as state-changes was a false-positive source (e.g. a "refresh list"
	// handler running a SELECT). FN-accepted: query('DELETE ...') is not counted.
	private static final Set<String> WPDB_WRITES =
		new HashSet<String>(Arrays.asList("insert","update","delete","replace"));
	// File operations that CHANGE state. Reads (file_get_contents/readfile) are excluded: an
	// unauth file read is an info-disclosure/SSRF concern, not a missing-authorization-for-write,
	// and counting them was a false-positive source (a handler reading a template via
	// file_get_contents is not a state change).
	private static final Set<String> ACL_FILE_WRITES =
		new HashSet<String>(Arrays.asList("file_put_contents","fwrite","fputs","fopen",
			"move_uploaded_file","copy","rename","unlink"));
	// File READ sinks. A read with a REQUEST-TAINTED path is an admin-class arbitrary-file-read
	// (the CVE-2025-11705 wp-config disclosure). Gated on path taint at the call site so fixed-path
	// reads (readme.txt, ABSPATH.'.htaccess', a bundled template) are NOT flagged — which is why
	// reads were originally excluded wholesale; taint-gating recovers the real bugs without the FP.
	private static final Set<String> ACL_FILE_READS =
		new HashSet<String>(Arrays.asList("file_get_contents","readfile","fread","fgets","fgetss",
			"file","fpassthru","gzfile","readgzfile"));

	// ---- IDOR (insecure direct object reference) — EXPERIMENTAL, gated WP_IDOR=1 ----------------
	// Object operations keyed by an identifier: acting on the WRONG id is the IDOR. Function-name form.
	private static final Set<String> IDOR_OBJECT_OPS =
		new HashSet<String>(Arrays.asList("get_post","get_page","wp_update_post","wp_delete_post",
			"wp_trash_post","get_post_meta","update_post_meta","delete_post_meta","get_userdata",
			"get_user_by","get_user_meta","update_user_meta","delete_user_meta","get_comment",
			"wp_update_comment","wp_delete_comment","get_term","wp_update_term","wp_delete_term"));
	// $wpdb methods that read/write a row typically selected by a request id.
	private static final Set<String> IDOR_OBJECT_METHODS =
		new HashSet<String>(Arrays.asList("update","delete","replace","get_row","get_var","get_results"));
	// Write object ops — the exploitable IDOR targets. Ownership DOMINANCE is applied to these (a guard
	// must dominate the write to clear it). Read ops (get_*/get_*_meta) are instead cleared by an ownership
	// check anywhere in the handler, because a read frequently IS the ownership fetch itself (e.g.
	// $o=get_var("SELECT owner..."); if($o!=current_user) die();) and would otherwise self-flag.
	private static final Set<String> IDOR_WRITE_FUNCS = new HashSet<String>(Arrays.asList(
		"wp_update_post","wp_delete_post","wp_trash_post","update_post_meta","delete_post_meta",
		"update_user_meta","delete_user_meta","wp_update_comment","wp_delete_comment",
		"wp_update_term","wp_delete_term"));
	private static final Set<String> IDOR_WRITE_METHODS = new HashSet<String>(Arrays.asList("update","delete","replace"));
	// Identifier-argument index per object op — the argument that selects WHICH object. The request-id
	// flow-binding checks taint into THIS argument, not the whole handler. WP funcs: usually arg 0;
	// get_user_by selects by arg 1. Array-form ops (wp_update_post/_comment) and anything not listed are
	// left indeterminate (the id is inside an array we do not isolate) and fall back to co-occurrence.
	// $wpdb: delete -> $where (arg 1); update -> $where (arg 2); replace -> data (arg 1); get_* -> SQL (arg 0).
	private static final java.util.Map<String,Integer> IDOR_ID_ARGIDX = new java.util.HashMap<String,Integer>();
	static {
		for( String op : new String[]{"get_post","get_page","wp_delete_post","wp_trash_post",
				"get_post_meta","update_post_meta","delete_post_meta","get_userdata","get_user_meta",
				"update_user_meta","delete_user_meta","get_comment","wp_delete_comment","get_term",
				"wp_update_term","wp_delete_term"} ) IDOR_ID_ARGIDX.put(op, 0);
		IDOR_ID_ARGIDX.put("get_user_by", 1);
		// $wpdb method id-arg indices (keyed with a "$" prefix to avoid colliding with WP func names)
		IDOR_ID_ARGIDX.put("$delete", 1); IDOR_ID_ARGIDX.put("$update", 2);
		IDOR_ID_ARGIDX.put("$replace", 1); IDOR_ID_ARGIDX.put("$get_row", 0);
		IDOR_ID_ARGIDX.put("$get_var", 0); IDOR_ID_ARGIDX.put("$get_results", 0);
	}
	// Signals that the handler binds the object to the current user (so it is NOT IDOR): the meta-cap
	// form current_user_can($cap,$id) is detected separately by arg count.
	private static final Set<String> IDOR_OWNERSHIP =
		new HashSet<String>(Arrays.asList("get_current_user_id","wp_get_current_user","author_can",
			"get_post_field","current_user_can_for_blog"));
	// Calls that terminate request handling. Used to recognise a "validate-and-die" ownership wrapper: a
	// function that computes an ownership correlation and, on failure, halts. wp_send_json* always wp_die()
	// internally, so they count as halts too.
	private static final Set<String> HALT_FUNCS =
		new HashSet<String>(Arrays.asList("wp_die","die","exit","wp_send_json","wp_send_json_error",
			"wp_send_json_success"));
	// Capabilities/roles whose holder is authorized to act ACROSS users' objects, so a handler gated on
	// one is doing authorized cross-object work, not IDOR. Real-plugin triage showed the dominant IDOR
	// false-positive class is back-office handlers gated on a management cap (list_users, edit_products,
	// the 'administrator' role, edit_others_*, …) that the original manage_options-only list missed.
	private static final Set<String> IDOR_ADMIN_CAPS =
		new HashSet<String>(Arrays.asList("manage_options","manage_network","manage_network_options",
			"activate_plugins","manage_network_users","edit_users","delete_users","promote_users",
			"remove_users","list_users","create_users","manage_sites","setup_network",
			"moderate_comments","edit_theme_options","edit_pages","publish_pages",
			"edit_products","publish_products","manage_woocommerce","manage_categories","manage_links",
			// Administrator-exclusive plugin/theme/core/site management caps (no editor/author/contributor/
			// subscriber role holds any of these on a default single site). Crediting them is FN-safe for
			// the privesc class: a holder is already an administrator, so a sub-admin cannot reach the sink.
			"install_plugins","update_plugins","delete_plugins","edit_plugins",
			"install_themes","update_themes","delete_themes","edit_themes","switch_themes",
			"update_core","edit_files","unfiltered_upload","export","import",
			"edit_dashboard","customize","manage_privacy_options","update_languages","install_languages",
			// role names used as pseudo-capabilities in current_user_can('administrator') checks
			"administrator","editor","shop_manager","super_admin"));
	// Pattern form for cross-object management caps, including custom ones a fixed list cannot enumerate:
	// edit_others_*, delete_others_*, publish_others_*, and any manage_*. A holder of these is authorized
	// to act on objects they do not own. (edit_posts / publish_posts — own-content caps — are NOT here:
	// a contributor acting on another user's content is a genuine gap, so those stay candidates.)
	private static boolean isManagementCap(String cap) {
		if( cap == null ) return false;
		if( IDOR_ADMIN_CAPS.contains(cap) ) return true;
		// Commerce shop-administration caps (EDD/WooCommerce: edit_shop_payments, view_shop_reports,
		// manage_shop_settings, …) authorize action across all customers' objects, like manage_options.
		if( cap.contains("_shop_") ) return true;
		// Financial / administration caps in commerce & donation plugins (GiveWP: edit_give_payments,
		// view_give_reports, export_give_reports; WooCommerce, EDD, …) are manager-only by construction —
		// a donor, customer or subscriber never holds a *_payments or *_reports capability — so, like the
		// _shop_ family, they authorize action across every customer's objects. Excludes an "_own_" variant
		// out of caution (an own-scoped report cap would not authorize cross-object action).
		if( (cap.endsWith("_payments") || cap.endsWith("_reports")) && !cap.contains("_own") ) return true;
		return cap.startsWith("manage_") || cap.startsWith("edit_others_")
			|| cap.startsWith("delete_others_") || cap.startsWith("publish_others_");
	}
	private static final boolean IDOR =
		"1".equals(System.getenv("WP_IDOR")) || "true".equalsIgnoreCase(System.getenv("WP_IDOR"));
	// WP_OPTIONS_WRITE: arbitrary-options-update / privilege-escalation lint. Distinct from ACCESS_CONTROL
	// in two ways that the InstaWP CVE-2024-22145 corpus case proved necessary: (1) it covers AUTHENTICATED
	// (subscriber+) handlers, not just anonymous-reachable ones — the entire options-update CVE class is
	// subscriber-level; (2) for an options-write sink a NONCE does NOT clear the handler, because the
	// attacker is a logged-in subscriber who legitimately holds a valid nonce. Only a MANAGEMENT capability
	// (manage_options-class) on the path clears it. The exploit primitive is update_option('default_role',
	// 'administrator') + update_option('users_can_register','1'), i.e. privilege escalation to admin.
	private static final boolean OPTIONS_WRITE =
		"1".equals(System.getenv("WP_OPTIONS_WRITE")) || "true".equalsIgnoreCase(System.getenv("WP_OPTIONS_WRITE"));
	// Site-options writes specifically (a subset of ACL_WRITES). Writing an arbitrary option name is the
	// privilege-escalation primitive; meta/post/user writes are handled by the IDOR/ACL passes instead.
	private static final Set<String> OPTION_SINKS =
		new HashSet<String>(Arrays.asList("update_option","add_option","delete_option",
			"update_site_option","update_network_option","add_site_option","update_user_option"));

	// Option-NAME argument index per sink. update_option/add_option/delete_option/*_site_option take
	// the name at arg 0; update_user_option($user_id, name, val) and update_network_option($net_id,
	// name, val) take it at arg 1. Reading arg 0 for the latter mis-reads the (request-controlled)
	// user/network id as the option name and produces a bogus "arbitrary option name" privesc FP.
	private static final java.util.Map<String,Integer> OPTION_NAME_ARGIDX = new java.util.HashMap<String,Integer>();
	static {
		OPTION_NAME_ARGIDX.put("update_user_option", 1);
		OPTION_NAME_ARGIDX.put("update_network_option", 1);
	}

	// Resolve a callable-reference expression (a function name) to its string name.
	// Handles 'name' and bare identifiers; arrays/closures return null (treated as authed).
	private static String callableRefName(Expression e) {
		if( e instanceof StringExpression ) return ((StringExpression)e).getEscapedCodeStr();
		if( e instanceof Identifier && ((Identifier)e).getNameChild()!=null )
			return ((Identifier)e).getNameChild().getEscapedCodeStr();
		return null;
	}

	// Classify a register_rest_route permission_callback into a privilege class.
	// hasPermKey distinguishes an ABSENT permission_callback (WP treats the route as open
	// => unauth) from one that is present but not resolvable to a simple name.
	//
	// Note on closures: phpjoern extracts each closure as a separate function unit, so an
	// inline `function(){ ... }` permission_callback is not wired to its array element in
	// the child map and its body cannot be inspected reliably here. We therefore treat an
	// unresolvable callback conservatively as authed. This still flags the dominant
	// permissive pattern, the '__return_true' string, which is by far the common case
	// (e.g. webhook endpoints); a literal `return true` *closure* is the residual blind spot.
	private static String classifyRestPermission(Expression permCb, boolean hasPermKey) {
		if( !hasPermKey ) return "unauth";                 // key absent => effectively open
		if( permCb == null ) return "authed";              // present but unresolvable (closure) => assume gated
		String name = callableRefName(permCb);
		if( name == null ) return "authed";                // [obj,'method'] array / closure => assume gated
		if( name.equals("__return_true") ) return "unauth";
		if( name.equals("__return_false") ) return "authed";
		if( name.equals("is_user_logged_in") ) return "lowpriv";
		return "authed";                                   // current_user_can-based callbacks etc.
	}

	private static void seedRestRoute(Expression cfg, boolean publicOnly) {
		if( !(cfg instanceof ArrayExpression) ) return;
		ArrayExpression arr = (ArrayExpression)cfg;
		Expression cb = null, perm = null; boolean hasCallback = false, hasPermKey = false;
		Long permElemNodeId = null;
		for( ArrayElement el : arr ) {
			if( el.getKey() instanceof StringExpression ) {
				String k = ((StringExpression)el.getKey()).getEscapedCodeStr();
				if( k.equals("callback") ) { cb = el.getValue(); hasCallback = true; }
				else if( k.equals("permission_callback") ) {
					perm = el.getValue(); hasPermKey = true;
					permElemNodeId = el.getNodeId();
				}
			}
		}
		if( hasCallback ) {
			String priv = classifyRestPermission(perm, hasPermKey);
			// ITEM42 FIX: link this route's resolved permission_callback function id(s) to its
			// resolved handler function id(s), BEFORE the publicOnly-mode early return below --
			// this map feeds objectAuthorizationFacts()'s search set regardless of which mode
			// seeded the entry, and must not depend on publicOnly's unrelated seeding decision.
			if( hasPermKey ) {
				java.util.Set<Long> permFids = (perm != null) ? resolveCallableFuncIds(perm) : new HashSet<Long>();
				// Closure case: el.getValue() returned null (the known, now-root-caused gap --
				// see loadRawClosureLinksIfNeeded()'s comment), so fall back to the raw-CSV link.
				if( permFids.isEmpty() && permElemNodeId != null ) {
					loadRawClosureLinksIfNeeded();
					Long closureId = rawParentToClosureChild.get(permElemNodeId);
					if( closureId != null ) permFids.add(closureId);
				}
				if( !permFids.isEmpty() ) {
					java.util.Set<Long> cbFids = resolveCallableFuncIds(cb);
					for( Long cbFid : cbFids ) {
						java.util.Set<Long> existing = restHandlerToPermCallbackFuncIds.get(cbFid);
						if( existing == null ) { existing = new HashSet<Long>(); restHandlerToPermCallbackFuncIds.put(cbFid, existing); }
						existing.addAll(permFids);
					}
				}
			}
			if( publicOnly && priv.equals("authed") ) return;
			registerCallbackAsEntry(cb, "rest:"+priv);
		} else {
			// nested form: register_rest_route(ns, route, array( array('callback'=>...), ... ))
			for( ArrayElement el : arr )
				if( el.getValue() instanceof ArrayExpression ) seedRestRoute(el.getValue(), publicOnly);
		}
	}

	// FIX (2026-08-08): reusable custom-router entry-point rule, motivated by FormGent
	// (CVE-2026-3141) but written generally rather than as a one-off "if plugin==FormGent" patch.
	// Many WordPress plugins bundle a small, Laravel-inspired routing DSL of the shape
	// Route::get('path', [Controller::class,'method']) / Route::post(...) / Route::delete(...) /
	// Route::put(...) / Route::patch(...), often nested inside Route::group(function(){...}).
	// This is a STRUCTURALLY RESOLVED registration, matching the same discipline as
	// seedFromHookRegistration(): the class must be literally named "Route" (not a generic
	// "any static method named delete" match -- that would hit unrelated things like
	// Cache::delete($key) constantly), the verb must be a literal HTTP-verb-like method name, the
	// route argument must be a literal string, and the callback must be a structurally resolvable
	// shape (array-callback, string, or first-class-callable). A dynamic/unresolvable callback or
	// route argument is left unseeded rather than guessed, exactly as the existing hook-
	// registration path already does. Route::group(...) itself is not specially handled: the verb
	// calls nested inside its closure argument are ordinary static calls this same loop already
	// visits, so grouping/prefixing is transparent to this rule without extra code.
	private static final java.util.Set<String> ROUTE_HTTP_VERBS = new java.util.HashSet<String>(
		java.util.Arrays.asList("get", "post", "put", "patch", "delete", "options"));

	private static void seedCustomRouterVerb(StaticCallExpression sc, String methodName, boolean publicOnly) {
		if( !ROUTE_HTTP_VERBS.contains(methodName) ) return;
		String cls = exprClassName(sc.getTargetClass());
		if( !"Route".equals(cls) ) return;
		ArgumentList args = sc.getArgumentList();
		if( args == null || args.size() < 2 ) return;
		// Route argument must be a literal string -- a dynamically-built route pattern is not
		// itself disqualifying (the callback is what matters for entry-seeding), but requiring it
		// here keeps this rule narrowly scoped to the literal-registration shape it was verified
		// against, consistent with "unresolved stays unresolved" rather than guessing.
		if( !(args.getArgument(0) instanceof StringExpression) ) return;
		Expression cb = args.getArgument(1);
		if( !(cb instanceof StringExpression || cb instanceof ArrayExpression || cb instanceof CallExpressionBase) )
			return;
		// Access classification: this DSL has no WordPress-native permission_callback convention
		// to inspect. FormGent's real vulnerable registration takes exactly two arguments (route,
		// callback) with no third middleware/guard argument at all -- treated as unauth
		// (unrestricted), matching the confirmed real-world shape. A present, non-empty third
		// argument suggests *some* framework-level gating exists whose semantics this rule cannot
		// verify, so it is classified unknown-not-classified rather than confidently "authed" --
		// unknown must reduce confidence, not remove the path (same principle as wpEntryAccess()).
		String access;
		if( args.size() >= 3 && args.getArgument(2) instanceof ArrayExpression
		    && ((ArrayExpression)args.getArgument(2)).size() == 0 ) {
			access = "unauth";
		} else if( args.size() < 3 ) {
			access = "unauth";
		} else {
			access = "unknown-not-classified";
		}
		if( publicOnly && !"unauth".equals(access) ) return;
		registerCallbackAsEntry(cb, "route:" + methodName + ":" + access);
	}

	// operation without ADEQUATE authorization is a missing-authorization candidate — the #1
	// WordPress bug class, invisible to taint. Adequacy is guard-class-aware:
	//   * an authorization guard (current_user_can/is_user_logged_in/...) excludes the anonymous
	//     attacker => adequate => clean;
	//   * a nonce guard alone (check_ajax_referer/wp_verify_nonce/...) is CSRF protection only, and
	//     on an anonymous endpoint the nonce is public to those same users => NOT authorization =>
	//     flagged as NONCE-ONLY (the fm5 upload shape);
	//   * no guard at all => flagged as NO-GUARD.
	// Interprocedural and reachability-based (not CFG dominance): a guard anywhere in the handler's
	// reachable closure clears that class, so "handler calls a verify() helper" does not FP.
	// Sensitivity includes file sinks and $wpdb writes. Anonymous-reachable = nopriv admin-ajax /
	// admin-post / open REST; logged-in-gated endpoints (rest:lowpriv/authed) are out of scope here
	// (that is the separate authed-privilege-escalation tier). Output is a triage list, not a verdict;
	// an endpoint intended to be public (e.g. a contact form insert) will appear and needs human
	// adjudication of intent.
	private static void auditAccessControl() {
		// FIX (2026-08-08): XSS_ONLY was missing from this guard, confirmed against the block
		// below (buildReturnNameSummaries) whose own comment explicitly states "Also needed in
		// XSS_ONLY mode" -- a genuine intent/implementation mismatch, verified by direct trace: a
		// pure WP_XSS_ONLY=1 run returns here before ever reaching that block. Included XSS_ONLY
		// in the guard so the block is at least reachable in that mode.
		// IMPORTANT, reported honestly rather than glossed over: fixing this gating alone does
		// NOT fully resolve the motivating example the original comment gives (function
		// get_name(){return $_GET['name'];} $x=get_name(); echo $x;). Confirmed by direct testing
		// before and after this change: retArbitraryFids is correctly populated with get_name's
		// fid once this block runs (verified via direct instrumentation), yet the finding still
		// does not surface, in EVERY mode tested including modes where the block already ran
		// before this fix (e.g. WP_ACCESS_CONTROL=1 alone). This means the actual remaining
		// blocker is downstream, in StaticAnalysis.java's separate dataflow-graph traversal (the
		// "TAINT PASS-THROUGH" mechanism consuming retArbitraryFids), not in this gating condition
		// -- a materially deeper investigation than this fix, not attempted here. This fix closes
		// the specific, confirmed intent/implementation mismatch the review identified; it does
		// not claim to close the broader recall gap the review's motivating example illustrates.
		if( !ACCESS_CONTROL && !CSRF && !IDOR && !OPTIONS_WRITE && !XSS_ONLY ) return;
		long auditStart = System.currentTimeMillis();
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-0 audit-entered");
		java.util.HashMap<Long,Boolean> localAuthz = new java.util.HashMap<Long,Boolean>();
		java.util.HashMap<Long,Boolean> localNonce = new java.util.HashMap<Long,Boolean>();
		java.util.HashMap<Long,String> localSens = new java.util.HashMap<Long,String>();
		java.util.HashMap<Long,Set<Long>> callees = new java.util.HashMap<Long,Set<Long>>();
		// Finer-grained tracking for the CSRF nonce-dominance check: the actual node ids of nonce
		// checks, sinks, and call sites in each function (so we can ask whether a nonce *dominates*
		// a write, not merely co-occurs with it).
		java.util.HashMap<Long,java.util.List<Long>> nonceNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		java.util.HashMap<Long,java.util.List<Long>> sinkNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		java.util.HashMap<Long,java.util.List<Long>> callSitesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		// IDOR ownership dominance: ownership-guard nodes and object-op nodes, so an ownership check only
		// clears the ops it actually dominates (reusing the CSRF dominance machinery).
		java.util.HashMap<Long,java.util.List<Long>> ownNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		java.util.HashMap<Long,java.util.List<Long>> objOpNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		// Functions that perform a READ object op (cleared by ownership presence, not dominance).
		java.util.HashMap<Long,Boolean> localReadOp = new java.util.HashMap<Long,Boolean>();
		// FN-3 disclosure modeling: localSensRead[f] = f reads a SENSITIVE-NAMED stored value
		// (get_option('..._secret'), get_user_meta(..,'..._token'..)) or a sensitive server file
		// (wp-config, .env, id_rsa). localRetSink[f] = f passes data back to the caller
		// (wp_send_json_success/wp_send_json/echo/print/readfile). A handler doing BOTH, reached
		// under-authorized, is unauthorized information disclosure (CWE-200) — the class the write-only
		// sink model was blind to (essential-blocks get / WPCode auth key / gotmls wp-config read).
		java.util.HashMap<Long,String> localSensRead = new java.util.HashMap<Long,String>();
		java.util.HashMap<Long,Boolean> localRetSink = new java.util.HashMap<Long,Boolean>();
		// Node-level tracking for the PRECISE (default-on) disclosure path: the sensitive-read RESULT
		// nodes and the data-return-sink ARGUMENT nodes, per fid. A handler is a precise disclosure only
		// when some return-sink argument actually DERIVES FROM some sensitive read (intraprocedural
		// def-use via valueDerivesFrom) — so a secret read that flows elsewhere (customer-reviews
		// download_addon: license key -> wp_remote_get, response is only a URL) is NOT flagged.
		// directDiscFids = a self-outputting sensitive-file read (readfile/fpassthru), which is its own sink.
		java.util.HashMap<Long,java.util.List<Long>> sensReadNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		java.util.HashMap<Long,java.util.List<Long>> retSinkArgsByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		Set<Long> directDiscFids = new HashSet<Long>();
		java.util.HashMap<Long,String> localObjOp = new java.util.HashMap<Long,String>();
		java.util.HashMap<Long,Boolean> localOwnership = new java.util.HashMap<Long,Boolean>();
		// localHalt[f] = f directly calls a request-terminating function (wp_die/exit/wp_send_json*).
		java.util.HashMap<Long,Boolean> localHalt = new java.util.HashMap<Long,Boolean>();
		java.util.HashMap<Long,Boolean> localAdminCap = new java.util.HashMap<Long,Boolean>();
		// WP_OPTIONS_WRITE cap-dominance: management-cap-check nodes and option-write sink nodes, so a
		// manage_options check only clears the option sinks it actually DOMINATES (a cap in a callee
		// invoked after the sink, or in a sibling branch, no longer clears it — reuses the CSRF/IDOR
		// dominance machinery via firstUnguardedSink, instead of a flat closure-wide boolean).
		java.util.HashMap<Long,java.util.List<Long>> capNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		java.util.HashMap<Long,java.util.List<Long>> optSinkNodesByFid = new java.util.HashMap<Long,java.util.List<Long>>();
		// Functions whose option-write sink has an option-NAME argument with NO fixed literal prefix
		// (a bare variable / request value, not 'wpfoo_'.$x or "wpfoo_{$x}" or a literal). Only these
		// can be the privesc primitive (attacker-chosen name -> default_role). A fixed-prefix name is
		// namespaced to the plugin and downgraded to "fixed option name (settings change)".
		Set<Long> optArbitraryNameFids = new HashSet<Long>();
		// Handlers whose option-write VALUE argument is attacker-tainted. Privilege escalation via an
		// options write needs BOTH an attacker-chosen NAME and an attacker-chosen VALUE — a request-named
		// option set to a CONSTANT (e.g. add_option($_POST['k'].'_never_show','yes')) cannot set
		// default_role=administrator. Without a tainted value the write is at most a fixed-content
		// settings toggle, not privesc. (getgenie / gutenkit Wpmet rating-notice FP, batch #8.)
		Set<Long> optValueTaintedFids = new HashSet<Long>();
		// Handlers that reach an ADMIN-CLASS sink: a request-tainted arbitrary file read or write.
		// These are operations no Subscriber should ever perform, so an authenticated low-privilege
		// handler reaching one without a management capability check is Missing Authorization.
		Set<Long> adminClassSink = new HashSet<Long>();
		// Functions that read a request superglobal (the request-supplied object id originates here).
		Set<Long> requestFuncs = new HashSet<Long>();
		for( Long sid : PHPCSVEdgeInterpreter.sources ) {
			ASTNode sn = ASTUnderConstruction.idToNode.get(sid);
			if( sn != null && sn.getFuncId() != null ) requestFuncs.add(sn.getFuncId());
		}
		// Owned-table inference: a $wpdb call whose SQL/args reference an ownership column marks the
		// tables it touches as user-owned. Object ops on tables NOT in this set are global (settings,
		// rooms) and are not IDOR. WP-core post/user/comment/term ops are owned inherently (below).
		Set<String> ownedTables = new HashSet<String>();
		// objIdState: funcId -> strongest id-binding state across its owned object ops (BOUND>INDET>CLEAN).
		java.util.HashMap<Long,Integer> objIdState = new java.util.HashMap<Long,Integer>();
		// Built unconditionally: auditAccessControl has already returned unless one of
		// ACCESS_CONTROL/CSRF/IDOR/OPTIONS_WRITE is active, and the shared option-sink block below
		// resolves option NAMES through this map in every one of those modes (not just IDOR/OPTIONS_WRITE).
		// Gating it to (IDOR||OPTIONS_WRITE) left it null under ACL/CSRF and NPE'd valueIsTainted.
		java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> idVarAssigns =
			buildVarAssigns();
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE buildVarAssigns-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s");
		// R4: summarise which functions return an internally-read request source (-> retArbitraryFids)
		// and which return a constant-prefixed name (-> retPrefixFids), so `$n = helper()` resolves.
		// Also needed in XSS_ONLY mode to detect function-return taint propagation:
		//   function get_name() { return $_GET['name']; }  $x = get_name(); echo $x;
		if( OPTIONS_WRITE || ACCESS_CONTROL || XSS_ONLY ) {
			boolean PF = System.getenv("WP_AUDIT_PROF")!=null; long tt;
			tt=System.currentTimeMillis(); augmentStaticDispatchEdges();   if(PF) System.err.println("WPPHASE augmentStaticDispatch "+(System.currentTimeMillis()-tt)+"ms");
			tt=System.currentTimeMillis(); augmentInstanceDispatchEdges(); if(PF) System.err.println("WPPHASE augmentInstanceDispatch "+(System.currentTimeMillis()-tt)+"ms");
			tt=System.currentTimeMillis(); buildConstantValues();          if(PF) System.err.println("WPPHASE buildConstantValues "+(System.currentTimeMillis()-tt)+"ms");
			tt=System.currentTimeMillis(); buildReturnNameSummaries(idVarAssigns); if(PF) System.err.println("WPPHASE buildReturnNameSummaries "+(System.currentTimeMillis()-tt)+"ms");
		}
		if( IDOR ) {
			for( MethodCallExpression mc : nonStaticMethodCalls ) {
				String txt = callSqlText(mc.getNodeId());
				if( txt.isEmpty() || !OWN_COL.matcher(txt).find() ) continue;
				ownedTables.addAll(extractTableTokens(txt));
			}
			for( CallExpressionBase fc : functionCalls ) {
				String txt = callSqlText(fc.getNodeId());
				if( txt.isEmpty() || !OWN_COL.matcher(txt).find() ) continue;
				ownedTables.addAll(extractTableTokens(txt));
			}
		}
		// Pre-pass: collect membership-allowlist guard calls per function. Used below to suppress
		// arbitrary-option-name FPs when the name is constrained to a known-key set (in_array/
		// array_search/array_key_exists) by a guard that dominates the write.
		java.util.HashMap<Long,java.util.List<CallExpressionBase>> memGuardsByFid =
			OPTIONS_WRITE ? new java.util.HashMap<Long,java.util.List<CallExpressionBase>>() : null;
		if( OPTIONS_WRITE ) {
			for( CallExpressionBase mg : functionCalls ) {
				String mn = callTargetName(mg);
				if( "in_array".equals(mn) || "array_search".equals(mn) || "array_key_exists".equals(mn) ) {
					Long mf = mg.getFuncId();
					java.util.List<CallExpressionBase> l = memGuardsByFid.get(mf);
					if( l == null ) { l = new java.util.ArrayList<CallExpressionBase>(); memGuardsByFid.put(mf, l); }
					l.add(mg);
				}
			}
		}
		// Reverse call graph (target fid -> calls TO it), for the wrapper-sink (R7) resolution: when an
		// option-name argument is a bare parameter, find the call sites that bind it and evaluate the
		// bound argument in the caller's context. Covers function and instance-method wrappers.
		java.util.HashMap<Long,java.util.List<CallExpressionBase>> mtd2calls =
			( OPTIONS_WRITE || ACCESS_CONTROL ) ? new java.util.HashMap<Long,java.util.List<CallExpressionBase>>() : null;
		if( mtd2calls != null ) {
			for( CallExpressionBase c : functionCalls ) {
				java.util.List<Long> tg = call2mtd.get(c.getNodeId());
				if( tg != null ) for( Long t : tg )
					mtd2calls.computeIfAbsent(t, k -> new java.util.ArrayList<CallExpressionBase>()).add(c);
			}
			for( MethodCallExpression c : nonStaticMethodCalls ) {
				java.util.List<Long> tg = call2mtd.get(c.getNodeId());
				if( tg != null ) for( Long t : tg )
					mtd2calls.computeIfAbsent(t, k -> new java.util.ArrayList<CallExpressionBase>()).add(c);
			}
			for( StaticCallExpression c : staticMethodCalls ) {
				java.util.List<Long> tg = call2mtd.get(c.getNodeId());
				if( tg != null ) for( Long t : tg )
					mtd2calls.computeIfAbsent(t, k -> new java.util.ArrayList<CallExpressionBase>()).add(c);
			}
		}
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-preMain mtd2calls+staticlink-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s");
		for( CallExpressionBase fc : functionCalls ) {
			Long caller = fc.getFuncId();
			String nm = callTargetName(fc);
			if( nm != null ) {
				if( AUTHZ_GUARDS.contains(nm) ) localAuthz.put(caller, Boolean.TRUE);
				if( NONCE_GUARDS.contains(nm) ) {
					localNonce.put(caller, Boolean.TRUE);
					addNode(nonceNodesByFid, caller, fc.getNodeId());
				}
				// Arbitrary file READ with a request-tainted path -> admin-class sensitive sink.
				// (Not added to sinkNodesByFid: a read is not a state change, so it must not feed the
				// CSRF nonce-dominance check; it drives ACL/missing-cap reporting only.)
				if( ACL_FILE_READS.contains(nm) ) {
					ArgumentList ral = fc.getArgumentList();
					Expression pa = ( ral != null && ral.size() > 0 ) ? ral.getArgument(0) : null;
					if( pa != null && valueIsTainted(pa.getNodeId(), caller, idVarAssigns, 0) ) {
						if( !localSens.containsKey(caller) ) localSens.put(caller, nm+"()[arb-read]");
						adminClassSink.add(caller);
					}
				}
				// File WRITE with a request-tainted path is admin-class too (arbitrary write).
				if( ACL_FILE_WRITES.contains(nm) ) {
					ArgumentList wal = fc.getArgumentList();
					Expression wa = ( wal != null && wal.size() > 0 ) ? wal.getArgument(0) : null;
					if( wa != null && valueIsTainted(wa.getNodeId(), caller, idVarAssigns, 0) ) adminClassSink.add(caller);
				}
				// FN-3 disclosure detection. A SENSITIVE-NAMED stored read: get_option/get_*_meta/get_transient
				// whose resolvable key name looks like a secret (key/token/secret/auth/password/license/api/
				// credential/salt/private). Scoped to sensitive names so ordinary settings reads are not flagged.
				if( STORED_SOURCE_FUNCS.contains(nm) ) {
					Integer ki = STORED_READ_KEYIDX.get(nm);
					ArgumentList sal = fc.getArgumentList();
					Expression keyArg = ( ki != null && sal != null && sal.size() > ki ) ? sal.getArgument(ki) : null;
					String key = ( keyArg != null ) ? resolveStoredKey(keyArg, caller, idVarAssigns) : null;
					// (a) fixed key that names a secret, or (b) a REQUEST-TAINTED key (attacker chooses which
					// option/meta to read = arbitrary read, the essential-blocks get class). Either is disclosure.
					// The tainted-key (arbitrary-read) case excludes transients: a request-keyed get_transient is
					// almost always a per-request cache lookup (woolentor suggest_price), not a secret store.
					if( key != null && isSensitiveName(key) && !localSensRead.containsKey(caller) ) {
						localSensRead.put(caller, nm+"('"+key+"')");
						addNode(sensReadNodesByFid, caller, fc.getNodeId());
					}
					else if( key == null && keyArg != null && !nm.contains("transient")
							&& valueIsTainted(keyArg.getNodeId(), caller, idVarAssigns, 0)
							&& !localSensRead.containsKey(caller) ) {
						localSensRead.put(caller, nm+"([request-chosen key])");
						addNode(sensReadNodesByFid, caller, fc.getNodeId());
					}
				}
				// A sensitive SERVER FILE read (wp-config/.env/id_rsa/…). readfile/fpassthru also self-output,
				// so they double as the return sink; file_get_contents/fread require a separate return sink.
				if( ACL_FILE_READS.contains(nm) ) {
					ArgumentList ral2 = fc.getArgumentList();
					Expression pa2 = ( ral2 != null && ral2.size() > 0 ) ? ral2.getArgument(0) : null;
					String plit = ( pa2 != null ) ? resolveStoredKey(pa2, caller, idVarAssigns) : null;
					if( plit != null && isSensitiveFile(plit) ) {
						if( !localSensRead.containsKey(caller) ) localSensRead.put(caller, nm+"('"+plit+"')");
						if( nm.equals("readfile") || nm.equals("fpassthru") ) {
							localRetSink.put(caller, Boolean.TRUE);
							directDiscFids.add(caller);           // self-outputting: read IS the disclosure
						} else {
							addNode(sensReadNodesByFid, caller, fc.getNodeId());   // needs a return sink + dataflow
						}
					}
				}
				// Data-returning response sink: the read value is handed back to the requester. Record the
				// argument nodes so the precise path can check the returned value derives from a sensitive read.
				if( isDataReturnSink(nm) ) {
					localRetSink.put(caller, Boolean.TRUE);
					ArgumentList dal = fc.getArgumentList();
					if( dal != null ) for( int ai = 0; ai < dal.size(); ai++ )
						addNode(retSinkArgsByFid, caller, dal.getArgument(ai).getNodeId());
				}
				if( ACL_WRITES.contains(nm) || ACL_FILE_WRITES.contains(nm) ) {
					if( !localSens.containsKey(caller) ) localSens.put(caller, nm+"()");
					addNode(sinkNodesByFid, caller, fc.getNodeId());
					if( OPTION_SINKS.contains(nm) ) {
						addNode(optSinkNodesByFid, caller, fc.getNodeId());
						// Privesc requires an attacker-CHOSEN option NAME. Two conditions, both needed:
						//   (1) no fixed literal prefix (literal / concat / encaps) — a prefix namespaces
						//       the write to the plugin and cannot reach a core option (default_role); and
						//   (2) request taint actually REACHES the name argument intraprocedurally
						//       (valueIsTainted) — so update_option($_POST['k']) / $n=$_POST['k'];...($n)
						//       qualify, but a wrapper-parameter name fed fixed keys (updateOption($key))
						//       or a namespacing wrapper (update_option(getKey($k))) does NOT.
						ArgumentList oal = fc.getArgumentList();
						int nIdx = OPTION_NAME_ARGIDX.containsKey(nm) ? OPTION_NAME_ARGIDX.get(nm) : 0;
						Expression nameArg = ( oal != null && oal.size() > nIdx ) ? oal.getArgument(nIdx) : null;
						String npfx = optionNameLiteralPrefix(nameArg, caller, idVarAssigns, 0);
						boolean prefixed = ( npfx != null && !npfx.isEmpty() );
						boolean nameTainted = ( nameArg != null
						    && valueIsTainted(nameArg.getNodeId(), caller, idVarAssigns, 0) );
						// An attacker-influenced, unprefixed name is STILL not privesc if a membership
						// allowlist guard against a plugin-defined set dominates the write — the name is
						// then constrained to known keys and can never be a core option (default_role).
						boolean allowlisted = ( !prefixed && nameTainted )
							&& nameIsAllowlisted(nameArg, caller, fc.getNodeId(), idVarAssigns, memGuardsByFid);
						if( !prefixed && nameTainted && !allowlisted )
							optArbitraryNameFids.add(caller);
						// VALUE-argument taint: privesc needs an attacker-controlled value, not just name.
						// delete_option has no value arg; add_option/update_option/*_user_option take the
						// value immediately after the name. A tainted value marks the handler; a constant
						// value (add_option($n,'yes')) does not, so it can never set default_role=administrator.
						if( !"delete_option".equals(nm) ) {
							int vIdx = nIdx + 1;
							Expression valArg = ( oal != null && oal.size() > vIdx ) ? oal.getArgument(vIdx) : null;
							if( valArg != null && valueIsTainted(valArg.getNodeId(), caller, idVarAssigns, 0) )
								optValueTaintedFids.add(caller);
						}
						// R7 wrapper-sink: the option NAME is a bare PARAMETER of the sink's function, so its
						// taint/prefix live at the CALL SITES, not here. resolveWrapperArbitrary walks the
						// wrapper chain — each call binding this parameter is evaluated in the CALLER's context
						// (where a literal prefix like 'pfx_'.$x is visible); a caller binding a tainted,
						// unprefixed, non-allowlisted value is attributed the arbitrary-name privesc, and a
						// bound arg that is ITSELF a bare parameter is climbed another level. Per-caller, so a
						// sibling passing a fixed/prefixed name is unaffected; namespacing at ANY level stops
						// the climb; (fn,pidx) visited-set + depth bound guarantee termination on recursion.
						if( !prefixed && !nameTainted && mtd2calls != null && nameArg instanceof Variable ) {
							Integer pidx = paramIndexOf(caller, varNameOf(nameArg));
							if( pidx != null )
								resolveWrapperArbitrary(caller, pidx, mtd2calls, idVarAssigns, memGuardsByFid,
									optArbitraryNameFids, new java.util.HashSet<String>(), 0);
						}
						if( System.getenv("WPDBG_OPTNAME") != null ) {
							ASTNode cn = ASTUnderConstruction.idToNode.get(caller);
							String cname = (cn instanceof FunctionDef) ? ((FunctionDef)cn).getName() : "?";
							System.err.println("WPDBGOPT fn="+cname+" caller="+caller+" node="+fc.getNodeId()
								+" nm="+nm+" nameArg="+(nameArg==null?"null":nameArg.getClass().getSimpleName())
								+" npfx=["+npfx+"] prefixed="+prefixed+" tainted="+nameTainted
								+" allowlisted="+allowlisted+" ADDED="+(!prefixed && nameTainted && !allowlisted));
						}
					}
				}
				if( IDOR || OPTIONS_WRITE || ACCESS_CONTROL ) {
					if( HALT_FUNCS.contains(nm) ) localHalt.put(caller, Boolean.TRUE);
					if( IDOR_OBJECT_OPS.contains(nm) ) {
						if( !localObjOp.containsKey(caller) ) localObjOp.put(caller, nm+"()");
						if( IDOR_WRITE_FUNCS.contains(nm) ) addNode(objOpNodesByFid, caller, fc.getNodeId());
						else localReadOp.put(caller, Boolean.TRUE);
						Integer ix = IDOR_ID_ARGIDX.get(nm);
						ArgumentList ial = fc.getArgumentList();
						Long idn = (ix != null && ial != null && ial.size() > ix) ? ial.getArgument(ix).getNodeId() : null;
						recordIdState(objIdState, caller, ix == null ? null : idn, idVarAssigns);
					}
					if( IDOR_OWNERSHIP.contains(nm) ) { localOwnership.put(caller, Boolean.TRUE); addNode(ownNodesByFid, caller, fc.getNodeId()); }
					if( isCurrentUserGuard(fc) ) { localOwnership.put(caller, Boolean.TRUE); addNode(ownNodesByFid, caller, fc.getNodeId()); }
					// current_user_can($cap,$id): the 2-arg meta-cap form maps to ownership via
					// map_meta_cap, so it DOES bind the object; the 1-arg form does not. Also flag a
					// broad admin capability (handler legitimately acts across users).
					if( nm.equals("current_user_can") || nm.equals("user_can") ) {
						ArgumentList al = fc.getArgumentList();
						int ac = al == null ? 0 : al.size();
						if( ac >= 2 ) { localOwnership.put(caller, Boolean.TRUE); addNode(ownNodesByFid, caller, fc.getNodeId()); }   // meta-cap form binds the object
						// capability arg: current_user_can($cap,..) -> arg 0; user_can($id,$cap,..) -> arg 1.
						// user_can only authorizes THIS request when its $id is the current user.
						int capIdx = nm.equals("user_can") ? 1 : 0;
						if( al != null && ac > capIdx ) {
							boolean selfScope = !nm.equals("user_can")
								|| isCurrentUserId(al.getArgument(0), caller, idVarAssigns, 0);
							if( selfScope && capArgIsManagement(al.getArgument(capIdx), caller, idVarAssigns) ) { localAdminCap.put(caller, Boolean.TRUE); addNode(capNodesByFid, caller, fc.getNodeId()); }
						}
					}
					// is_super_admin() — the no-argument form tests the CURRENT user and is the highest
					// privilege in WordPress (strictly above manage_options), so a handler gated by it is
					// administrator-only and clears the privesc/IDOR classes like a management capability.
					// The 1-arg form is_super_admin($uid) targets an arbitrary user (not self-authorization),
					// so only the 0-arg form is credited (FN-safe).
					if( nm.equals("is_super_admin") ) {
						ArgumentList sal = fc.getArgumentList();
						if( sal == null || sal.size() == 0 ) { localAdminCap.put(caller, Boolean.TRUE); addNode(capNodesByFid, caller, fc.getNodeId()); }
					}
				}
			}
			java.util.List<Long> tgts = call2mtd.get(fc.getNodeId());
			if( tgts != null ) {
				addNode(callSitesByFid, caller, fc.getNodeId());
				for( Long t : tgts ) {
					Set<Long> s = callees.get(caller);
					if( s == null ) { s = new HashSet<Long>(); callees.put(caller, s); }
					s.add(t);
				}
			}
		}
		for( MethodCallExpression mc : nonStaticMethodCalls ) {
			Expression tf = mc.getTargetFunc();
			String mname = (tf instanceof StringExpression) ? ((StringExpression)tf).getEscapedCodeStr() : null;
			if( mname != null && WPDB_WRITES.contains(mname) ) {
				if( !localSens.containsKey(mc.getFuncId()) ) localSens.put(mc.getFuncId(), "$wpdb->"+mname+"()");
				addNode(sinkNodesByFid, mc.getFuncId(), mc.getNodeId());
			}
			if( IDOR && mname != null && IDOR_OBJECT_METHODS.contains(mname) ) {
				// Owned-object gate: only a $wpdb op on a user-owned table is an IDOR object. A table
				// with no ownership evidence anywhere (global config) is not. Unextractable tables are
				// kept (conservative — better a candidate than a missed IDOR).
				Set<String> tt = extractTableTokens(callSqlText(mc.getNodeId()));
				boolean owned = tt.isEmpty();
				for( String t : tt ) if( ownedTables.contains(t) ) { owned = true; break; }
				if( owned ) {
					if( !localObjOp.containsKey(mc.getFuncId()) ) localObjOp.put(mc.getFuncId(), "$wpdb->"+mname+"()");
					if( IDOR_WRITE_METHODS.contains(mname) ) addNode(objOpNodesByFid, mc.getFuncId(), mc.getNodeId());
					else localReadOp.put(mc.getFuncId(), Boolean.TRUE);
					Integer ix = IDOR_ID_ARGIDX.get("$"+mname);
					ArgumentList mal = mc.getArgumentList();
					Long idn = (ix != null && mal != null && mal.size() > ix) ? mal.getArgument(ix).getNodeId() : null;
					recordIdState(objIdState, mc.getFuncId(), ix == null ? null : idn, idVarAssigns);
				}
			}
			if( IDOR && isCurrentUserGuard(mc) ) { localOwnership.put(mc.getFuncId(), Boolean.TRUE); addNode(ownNodesByFid, mc.getFuncId(), mc.getNodeId()); }
			// Method-call reachability: trace into the called method so a guard/sensitive op inside a
			// wrapper (e.g. $this->validate_form_and_nonce(), $this->save_settings()) is seen by the BFS.
			// Without this, a nonce checked one method-hop away reads as "no nonce" — a CSRF false positive.
			java.util.List<Long> mt = call2mtd.get(mc.getNodeId());
			if( mt != null ) {
				Long caller = mc.getFuncId();
				addNode(callSitesByFid, caller, mc.getNodeId());
				Set<Long> s = callees.get(caller);
				if( s == null ) { s = new HashSet<Long>(); callees.put(caller, s); }
				for( Long t : mt ) s.add(t);
			}
		}
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-A functionCalls-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s subtreeIds="+subtreeIdsCalls+" isUncond="+isUncondCalls);
		// Static-method guards (e.g. AWPCP_Ad::belongs_to_user($id, $current_user->ID)) — the audit
		// otherwise never inspects static calls, so a custom ownership check made statically read as no
		// ownership. Only the current-user-correlating form counts (same precise signal as above).
		// Also wire static calls into the reachability graph so the BFS follows them into their target
		// methods: a handler that delegates its nonce/capability check to a static wrapper (e.g. FluentForm's
		// Acl::verify(), which internally calls wp_verify_nonce() and current_user_can()) inherits that
		// guard interprocedurally, instead of reading as unguarded. Applies to every audit mode.
		for( StaticCallExpression sc : staticMethodCalls ) {
			if( IDOR && isCurrentUserGuard(sc) ) { localOwnership.put(sc.getFuncId(), Boolean.TRUE); addNode(ownNodesByFid, sc.getFuncId(), sc.getNodeId()); }
			java.util.List<Long> st = call2mtd.get(sc.getNodeId());
			if( st != null ) {
				Long caller = sc.getFuncId();
				addNode(callSitesByFid, caller, sc.getNodeId());
				Set<Long> s = callees.get(caller);
				if( s == null ) { s = new HashSet<Long>(); callees.put(caller, s); }
				for( Long t : st ) s.add(t);
			}
		}
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-B static-calls-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s subtreeIds="+subtreeIdsCalls+" isUncond="+isUncondCalls);
		// Which functions are "nonce-gated": an unconditional nonce check guarantees a nonce runs on
		// entry. Fixpoint: also gated if the function unconditionally calls an already-gated callee
		// (the wrapper-method case). Used so a call to a gating helper counts as a nonce at the call site.
		Set<Long> nonceGates = new HashSet<Long>();
		for( Long f : nonceNodesByFid.keySet() )
			for( Long nn : nonceNodesByFid.get(f) )
				if( isUnconditional(nn, f) ) { nonceGates.add(f); break; }
		boolean changed = true; int gguard = 0;
		while( changed && gguard++ < 50 ) {
			changed = false;
			for( Long f : callSitesByFid.keySet() ) {
				if( nonceGates.contains(f) ) continue;
				for( Long cs : callSitesByFid.get(f) ) {
					java.util.List<Long> tg = call2mtd.get(cs);
					if( tg == null ) continue;
					boolean gated = false;
					for( Long t : tg ) if( nonceGates.contains(t) ) { gated = true; break; }
					if( gated && isUnconditional(cs, f) ) { nonceGates.add(f); changed = true; break; }
				}
			}
		}
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-C nonceGates-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s subtreeIds="+subtreeIdsCalls+" isUncond="+isUncondCalls);
		// Management-capability gates (same dominance fixpoint as nonces, applied to manage_options-class
		// checks): a function is cap-gated if it holds an unconditional management-cap check, or makes an
		// unconditional call to a cap-gated callee. Used by firstUnguardedSink so an option-write sink is
		// cleared only when a management cap actually dominates it.
		Set<Long> capGates = new HashSet<Long>();
		for( Long f : capNodesByFid.keySet() )
			for( Long cn : capNodesByFid.get(f) )
				if( isUnconditional(cn, f) ) { capGates.add(f); break; }
		boolean capChanged = true; int capGuard = 0;
		while( capChanged && capGuard++ < 50 ) {
			capChanged = false;
			for( Long f : callSitesByFid.keySet() ) {
				if( capGates.contains(f) ) continue;
				for( Long cs : callSitesByFid.get(f) ) {
					java.util.List<Long> tg = call2mtd.get(cs);
					if( tg == null ) continue;
					boolean gated = false;
					for( Long t : tg ) if( capGates.contains(t) ) { gated = true; break; }
					if( gated && isUnconditional(cs, f) ) { capGates.add(f); capChanged = true; break; }
				}
			}
		}
		if( System.getenv("WP_AUDIT_PROF")!=null ) System.err.println("WPPHASE PHASE-D capGates-done t="+((System.currentTimeMillis()-auditStart)/1000)+"s subtreeIds="+subtreeIdsCalls+" isUncond="+isUncondCalls);
		// Ownership-gated functions (same dominance fixpoint as nonces, applied to ownership guards):
		// an unconditional ownership check, or an unconditional call to an ownership-gated callee.
		Set<Long> ownGates = new HashSet<Long>();
		if( IDOR ) {
			for( Long f : ownNodesByFid.keySet() )
				for( Long on : ownNodesByFid.get(f) )
					if( isUnconditional(on, f) ) { ownGates.add(f); break; }
			// Validate-and-die ownership wrappers. A dedicated gate function performs an ownership
			// correlation and, on failure, halts (wp_die/exit/wp_send_json*) — possibly via a halt-wrapper
			// of its own (e.g. Tutor LMS check_access() -> json_response() -> wp_send_json()). Strict
			// dominance misses it because the correlation is computed conditionally
			//   $ok=false; if($id){ $ok = can_user_edit_course(get_current_user_id(),$id); } if(!$ok){ halt; }
			// and only enforced later. We treat such a function as an unconditional ownership gate IF it
			// (a) carries an ownership node, (b) reaches a halt, and (c) has NO object-op sink of its own
			// (it is a pure gate, not a worker). A handler that unconditionally calls it before the sink then
			// inherits the gate via the fixpoint below. This never clears a handler whose call chain carries
			// no ownership node (e.g. Dokan change_order_status), so the cross-vendor true positive stands.
			Set<Long> haltReach = new HashSet<Long>(localHalt.keySet());
			boolean hchanged = true; int hguard = 0;
			while( hchanged && hguard++ < 50 ) {
				hchanged = false;
				for( Long f : callSitesByFid.keySet() ) {
					if( haltReach.contains(f) ) continue;
					for( Long cs : callSitesByFid.get(f) ) {
						java.util.List<Long> tg = call2mtd.get(cs);
						if( tg == null ) continue;
						boolean h = false;
						for( Long t : tg ) if( haltReach.contains(t) ) { h = true; break; }
						if( h ) { haltReach.add(f); hchanged = true; break; }
					}
				}
			}
			for( Long f : ownNodesByFid.keySet() )
				if( haltReach.contains(f) && !objOpNodesByFid.containsKey(f) ) ownGates.add(f);
			boolean ochanged = true; int oguard = 0;
			while( ochanged && oguard++ < 50 ) {
				ochanged = false;
				for( Long f : callSitesByFid.keySet() ) {
					if( ownGates.contains(f) ) continue;
					for( Long cs : callSitesByFid.get(f) ) {
						java.util.List<Long> tg = call2mtd.get(cs);
						if( tg == null ) continue;
						boolean gated = false;
						for( Long t : tg ) if( ownGates.contains(t) ) { gated = true; break; }
						if( gated && isUnconditional(cs, f) ) { ownGates.add(f); ochanged = true; break; }
					}
				}
			}
		}
		// Secret-token guard recognition (clears the NO-GUARD/NONCE-ONLY FP on SaaS "connect"
		// callbacks — the Awesome Motive pattern in WPForms/MonsterInsights/OptinMonster/AIOSEO/WPCode,
		// and any plugin that authorizes a nopriv endpoint with a one-time token instead of a
		// capability/nonce). The shape:
		//     $oth = get_option('x_connect_token');
		//     if ( hash_hmac('sha512', $oth, wp_salt()) !== $_REQUEST['oth'] ) wp_send_json_error();
		//     ... sinks ...
		// A comparison (=== / !== / == / !=) or hash_equals() of a REQUEST value against a STORED-SECRET
		// value, whose region DOMINATES the sink, is authorization. Request-vs-request comparisons are
		// NOT trusted (no secret => bypassable). Gated to fids that actually have a sink, so the taint
		// checks stay cheap.
		Set<Long> tokenAuthzFids = new HashSet<Long>();
		if( ACCESS_CONTROL || CSRF ) {
			PHPCGFactory.recordScanSite("PCG_2289", ASTUnderConstruction.idToNode.size());
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				Long gf; try { gf = n.getFuncId(); } catch( Exception e ) { continue; }
				if( gf == null || tokenAuthzFids.contains(gf) ) continue;
				java.util.List<Long> sinks = sinkNodesByFid.get(gf);
				if( sinks == null || sinks.isEmpty() ) continue;
				Long aId = null, bId = null;
				if( n instanceof CallExpressionBase && "hash_equals".equals(callTargetName((CallExpressionBase)n)) ) {
					ArgumentList al = ((CallExpressionBase)n).getArgumentList();
					if( al != null && al.size() >= 2 ) { aId = al.getArgument(0).getNodeId(); bId = al.getArgument(1).getNodeId(); }
				} else if( n instanceof BinaryOperationExpression ) {
					String op = n.getFlags();
					if( op != null && ( op.equals("BINARY_IS_IDENTICAL") || op.equals("BINARY_IS_NOT_IDENTICAL")
							|| op.equals("BINARY_IS_EQUAL") || op.equals("BINARY_IS_NOT_EQUAL") ) ) {
						Expression l = ((BinaryOperationExpression)n).getLeft();
						Expression r = ((BinaryOperationExpression)n).getRight();
						if( l != null && r != null ) { aId = l.getNodeId(); bId = r.getNodeId(); }
					}
				}
				if( aId == null ) continue;
				// FIX (2026-08-08): the "request side" of this comparison was only required to be
				// tainted (valueIsTainted()), which -- confirmed by direct trace, not assumed --
				// also returns true for a stored-read call (get_option/get_*_meta/get_transient)
				// whenever WP_STORED_TAINT=broad is the active mode (the "blunt, all-reads-are-
				// sources" variant; the default WP_STORED_TAINT=1/paired mode already requires a
				// proven tainted write before a read counts, and was directly confirmed NOT to
				// exhibit this issue -- so the practical exposure is narrower than "any stored-
				// taint mode", though broad mode is a real, supported configuration). Without this
				// exclusion, if (get_option('a') === get_option('b')) { wp_delete_user(...); } --
				// two stored reads, no request value or secret comparison at all -- was credited
				// as a valid request-vs-secret token guard, clearing a genuine missing-
				// authorization finding. Confirmed via direct instrumentation before and after:
				// req was true (and the WPACL count dropped from 1 finding to 0) under
				// WP_STORED_TAINT=broad before this fix. Fixed by requiring the "request" side to
				// NOT itself satisfy subtreeHasSecretFetch() -- a genuine request value should
				// never also be a stored/secret read, so a side matching both is not the request
				// side of anything, regardless of which global source set flagged it tainted.
				boolean req = ( valueIsTainted(aId, gf, idVarAssigns, 0) && !subtreeHasSecretFetch(aId, gf, idVarAssigns, 0)
						&& subtreeHasSecretFetch(bId, gf, idVarAssigns, 0) )
						   || ( valueIsTainted(bId, gf, idVarAssigns, 0) && !subtreeHasSecretFetch(bId, gf, idVarAssigns, 0)
						&& subtreeHasSecretFetch(aId, gf, idVarAssigns, 0) );
				if( !req ) continue;
				Set<Long> region = guardedRegion(n.getNodeId(), gf);
				for( Long sk : sinks ) if( region.contains(sk) ) { tokenAuthzFids.add(gf); break; }
			}
		}
		int reported = 0, csrf = 0, idor = 0, optw = 0;
		boolean PROF = System.getenv("WP_AUDIT_PROF") != null;
		long profT0 = System.currentTimeMillis(); int profH = 0; long profSub0 = subtreeIdsCalls;
		if( PROF ) System.err.println("WPPROG SETUP-DONE entering handler loop setup-took="
			+((System.currentTimeMillis()-auditStart)/1000)+"s handlers="+entryPriv.size()
			+" subtreeIds-so-far="+subtreeIdsCalls);
		for( Long fid : entryPriv.keySet() ) {
			String priv = entryPriv.get(fid);
			if( priv == null ) continue;
			String hook = priv.contains(":") ? priv.substring(0, priv.indexOf(':')) : priv;
			boolean anon = priv.contains("unauth");
			// Only genuine request-dispatched ACTION endpoints. Lifecycle hooks (init/wp/
			// wp_enqueue_scripts/...) fire on every page load as bootstrap, so a state-change in them
			// is routine, not a missing-authorization action — auditing them was an FP source.
			boolean ajaxOrPost = hook.startsWith("wp_ajax_") || hook.startsWith("admin_post");
			boolean actionEndpoint = ajaxOrPost || priv.startsWith("rest:");
			if( !actionEndpoint ) continue;
			if( PROF && (++profH % 3 == 0) )
				System.err.println("WPPROG handler#"+profH+" t="+((System.currentTimeMillis()-profT0)/1000)
					+"s subtreeIds+="+(subtreeIdsCalls-profSub0)+" (fid "+fid+")");
			Set<Long> seen = new HashSet<Long>();
			java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
			seen.add(fid); work.add(fid);
			boolean authz = false, nonce = false, sensitive = false; String op = null; int cap = 0;
			boolean objOp = false, ownership = false, adminCap = false, readsReq = false, readOp = false; String objName = null;
			boolean optSink = false; String optOp = null; boolean arbitraryName = false; boolean valueTainted = false;
			boolean sensRead = false, retSink = false; String discOp = null;
			int maxIdState = ID_CLEAN;
			while( !work.isEmpty() && cap++ < 5000 ) {
				Long f = work.poll();
				if( Boolean.TRUE.equals(localAuthz.get(f)) ) authz = true;
				if( tokenAuthzFids.contains(f) ) authz = true;   // secret one-time-token guard authorizes the callback
				if( Boolean.TRUE.equals(localNonce.get(f)) ) nonce = true;
				if( localSensRead.containsKey(f) ) { sensRead = true; if( discOp == null ) discOp = localSensRead.get(f); }
				if( Boolean.TRUE.equals(localRetSink.get(f)) ) retSink = true;
				if( localSens.containsKey(f) ) { sensitive = true; if( op == null ) op = localSens.get(f); }
				if( localSens.containsKey(f) ) { String sv = localSens.get(f);
					String svBare = sv.endsWith("()") ? sv.substring(0, sv.length()-2) : sv;
					if( OPTION_SINKS.contains(svBare) ) { optSink = true; if( optOp == null ) optOp = sv; } }
				if( localObjOp.containsKey(f) ) { objOp = true; if( objName == null ) objName = localObjOp.get(f); }
				if( Boolean.TRUE.equals(localReadOp.get(f)) ) readOp = true;
				if( objIdState.containsKey(f) ) maxIdState = Math.max(maxIdState, objIdState.get(f));
				if( Boolean.TRUE.equals(localOwnership.get(f)) ) ownership = true;
				if( Boolean.TRUE.equals(localAdminCap.get(f)) ) adminCap = true;
				if( requestFuncs.contains(f) ) readsReq = true;
				if( optArbitraryNameFids.contains(f) ) arbitraryName = true;
				if( optValueTaintedFids.contains(f) ) valueTainted = true;
				Set<Long> cs = callees.get(f);
				if( cs != null ) for( Long c : cs ) if( seen.add(c) ) work.add(c);
			}
			// IDOR: an authenticated handler that operates on a request-supplied object id with no
			// ownership binding and no broad-admin capability. Orthogonal to authz/nonce — runs even
			// when sensitive (ACL_WRITES) is false, since a get_post_meta/$wpdb->get_row read is enough.
			// Flow-binding (scoping item 1): require the request to actually reach the object op's
			// IDENTIFIER argument (BOUND), not merely co-occur in the handler. An INDETERMINATE id (the
			// selector comes from a parameter/global we cannot resolve intraprocedurally) falls back to
			// the old co-occurrence test so no genuine IDOR is dropped; a CLEAN id (constant / current
			// user / local non-request value) is now correctly NOT flagged.
			boolean idBound = maxIdState == ID_BOUND;
			boolean idFallback = maxIdState == ID_INDET && readsReq;
			// Ownership clearing is op-kind aware. WRITES (the exploitable IDOR targets) must be DOMINATED
			// by an ownership guard — a guard in a different branch does not clear a write reached without
			// it. READS are cleared by an ownership check anywhere in the handler, because a read is often
			// the ownership fetch itself and strict dominance would make that fetch self-flag.
			String unownedWrite = firstUnguardedSink(seen, ownNodesByFid, objOpNodesByFid, callSitesByFid, ownGates, localObjOp);
			boolean writeUncleared = unownedWrite != null;
			boolean readUncleared = readOp && !ownership;
			// Id-evidence gating is op-kind aware (validated against event-post CVE-2024-1376):
			//   WRITES keep the weak co-occurrence fallback — save_bulkdatas updates post_meta by a
			//     foreach loop var over $_POST['post_ids'] (unbindable -> ID_INDET -> co-occur), and is a
			//     real TP; an unauthorized MODIFICATION is worth flagging even on weak binding.
			//   READS require a BOUND id. Co-occur reads are FP-dominated: a handler that displays object
			//     data and also reads the request, where the id never reaches the object op's id position
			//     (event-post ajaxlist/ajaxTimeline public event listings; UM get_users). Strong evidence
			//     (the request id actually reaches the read's id arg) is required to flag a read.
			boolean writeFinding = writeUncleared && ( idBound || idFallback );
			boolean readFinding  = readUncleared && idBound;
			if( IDOR && !anon && ajaxOrPost && objOp && ( writeFinding || readFinding ) && !adminCap ) {
				ASTNode hn = ASTUnderConstruction.idToNode.get(fid);
				String hname = (hn instanceof FunctionDef) ? ((FunctionDef)hn).getName() : "?";
				String kind = writeFinding ? "write" : "read";
				System.err.println("WPIDOR [IDOR]["+priv+"] handler "+hname+" node "+fid+" acts on "
					+objName+" by request id with no ownership check [id:"+(idBound?"bound":"co-occur")+"]["+kind+"]");
				idor++;
			}
			// FN-3: a handler that reads a sensitive stored value / server file AND returns it to the
			// requester is unauthorized information disclosure. Model it as an admin-class sink so the
			// existing guard/cap/anon/nonce-dominance logic decides whether it is under-authorized — a
			// Subscriber+ handler (MISSING-CAP) or an anonymous one (NO-GUARD/NONCE-ONLY) reaching it
			// without a management capability is the finding. A disclosure READ is not a state change, so
			// it is deliberately NOT added to the CSRF/option-write sink sets.
			// FN-3 disclosure decision. PRECISE (default-on): some return-sink argument in the closure
			// actually derives from a sensitive read in the SAME function (intraprocedural dataflow), or a
			// self-outputting sensitive-file read (readfile). CO-OCCURRENCE (opt-in via WP_DISCLOSURE):
			// a sensitive read and a return sink merely co-occur — looser, for disclosure-focused hunting.
			boolean preciseDisc = false;
			for( Long F : seen ) {
				if( directDiscFids.contains(F) ) { preciseDisc = true; break; }
				java.util.List<Long> reads = sensReadNodesByFid.get(F);
				java.util.List<Long> sinkArgs = retSinkArgsByFid.get(F);
				if( reads != null && sinkArgs != null ) {
					Set<Long> seed = new HashSet<Long>(reads);
					java.util.HashMap<Long,Boolean> dmemo = new java.util.HashMap<Long,Boolean>();
					for( Long sa : sinkArgs )
						if( valueDerivesFrom(sa, F, idVarAssigns, seed, 0, dmemo) ) { preciseDisc = true; break; }
					if( preciseDisc ) break;
				}
			}
			if( ACCESS_CONTROL && !sensitive
					&& ( preciseDisc || ( DISCLOSURE && sensRead && retSink ) ) ) {
				sensitive = true;
				op = ( discOp != null ? discOp : "sensitive read" )
					+ " returned to caller [disclosure" + (preciseDisc ? "" : ":co-occur") + "]";
				adminClassSink.add(fid);
			}
			if( !sensitive ) continue;
			ASTNode n = ASTUnderConstruction.idToNode.get(fid);
			String name = (n instanceof FunctionDef) ? ((FunctionDef)n).getName() : "?";
			// Authenticated LOW-PRIVILEGE reachable (wp_ajax_/admin_post_ = any logged-in user incl.
			// Subscriber): reaching an admin-class sink (arbitrary file read/write, or an arbitrary
			// option name) with NO management capability check is Missing Authorization to
			// Authenticated (Subscriber+) — the CVE-2025-11705 class. Independent of the anon and CSRF
			// quadrants; scoped to admin-class sinks so legitimate self-service writes are not flagged.
			if( !anon && ACCESS_CONTROL && ajaxOrPost
					&& ( adminClassSink.contains(fid) || optArbitraryNameFids.contains(fid) )
					&& !adminCap ) {
				String why = nonce ? "nonce present but no capability check (authenticated Subscriber+)"
				                   : "no capability check (authenticated Subscriber+)";
				System.err.println("WPACL [MISSING-CAP]["+priv+"] handler "+name+" node "+fid
					+" reaches "+op+" — "+why);
				reported++;
			}
			// Anonymous-reachable handlers (nopriv ajax/post, open REST): missing AUTHORIZATION.
			if( anon && ACCESS_CONTROL ) {
				if( !authz ) {
					String cls = nonce ? "NONCE-ONLY" : "NO-GUARD";
					String why = nonce ? "nonce present but no authorization check (anonymous-reachable)"
					                   : "no authorization or nonce guard";
					System.err.println("WPACL ["+cls+"]["+priv+"] handler "+name+" node "+fid
						+" reaches "+op+" — "+why);
					reported++;
				}
			}
			// Authenticated handlers (logged-in ajax/post): state-change without a NONCE is CSRF.
			// REST is excluded: its cookie-auth path requires the X-WP-Nonce header by design, a
			// separate nonce model the audit does not see in the handler body.
			else if( !anon && CSRF && ajaxOrPost ) {
				// Flag only if some sink is NOT dominated by a nonce — a nonce merely reachable in a
				// sibling branch (or after the write) no longer clears the handler.
				String unguardedOp = firstUnguardedSink(seen, nonceNodesByFid, sinkNodesByFid,
					callSitesByFid, nonceGates, localSens);
				if( unguardedOp != null ) {
					String why = authz ? "authorized but no nonce dominates the write — forgeable in the victim's session"
					                   : "logged-in handler, no nonce dominates the write — forgeable in the victim's session";
					System.err.println("WPCSRF [CSRF]["+priv+"] handler "+name+" node "+fid
						+" reaches "+unguardedOp+" — "+why);
					csrf++;
				}
			}
			// Arbitrary options update -> privilege escalation (WP_OPTIONS_WRITE). An action handler that
			// reaches an options-write sink with NO management capability on the path. Crucially, unlike the
			// CSRF and ACL passes, a NONCE does not clear this and neither does is_user_logged_in or a weak
			// (non-management) capability: the attacker is an authenticated subscriber who legitimately holds
			// all of those. Only a manage_options-class capability clears it. readsReq separates the
			// privesc-capable case (option NAME influenced by request data -> set default_role=administrator)
			// from a fixed-name settings write. This pass runs independently of ACCESS_CONTROL/CSRF/IDOR.
			// A management capability clears this handler only if it DOMINATES the option-write sink.
			// A cap check in a callee invoked after the sink, or in a sibling branch, does not protect it
			// (the arbitrary update_option runs first). Mirrors the CSRF pass's nonce-dominance test.
			String unguardedOpt = ( OPTIONS_WRITE && actionEndpoint && optSink )
				? firstUnguardedSink(seen, capNodesByFid, optSinkNodesByFid, callSitesByFid, capGates, localSens)
				: null;
			if( OPTIONS_WRITE && System.getenv("WP_OPT_DEBUG") != null ) {
				System.err.println("WPDBG handler "+name+" fid "+fid+" action="+actionEndpoint
					+" optSink="+optSink+" sensitive="+sensitive+" adminCap="+adminCap
					+" unguardedOpt="+unguardedOpt+" anon="+anon+" readsReq="+readsReq+" optOp="+optOp);
			}
			if( OPTIONS_WRITE && actionEndpoint && optSink && unguardedOpt != null ) {
				// Privilege-escalation requires attacker control of BOTH the option name AND the value.
				// arbitraryName+readsReq alone (request-influenced name, constant value) is a settings
				// write, not privesc — you cannot set default_role=administrator with a fixed value.
				String tag = ( arbitraryName && readsReq && valueTainted )
					? "arbitrary — option name and value request-influenced, privilege-escalation capable"
					: "fixed option name (settings change)";
				// A handler nominally anonymous (nopriv / __return_true REST) but carrying a dominating
				// is_user_logged_in()/current_user_can() early-return guard in its body is NOT actually
				// anonymous-reachable — that internal guard re-establishes authentication (getgenie,
				// suretriggers). Credit authz here so the reach is not mislabeled.
				String reach = ( anon && !authz ) ? "anonymous-reachable" : "authenticated (subscriber+)";
				System.err.println("WPOPT [OPTIONS-WRITE]["+priv+"] handler "+name+" node "+fid
					+" reaches "+optOp+" with no management capability — "+reach+", "+tag);
				optw++;
			}
		}
		if( ACCESS_CONTROL )
			System.err.println("WPACL "+reported+" anonymous-reachable handlers without adequate authorization (WP_ACCESS_CONTROL)");
		if( CSRF )
			System.err.println("WPCSRF "+csrf+" authenticated state-changing handlers without a nonce (WP_CSRF)");
		if( IDOR )
			System.err.println("WPIDOR "+idor+" authenticated handlers acting on a request object id without an ownership check (WP_IDOR)");
		if( OPTIONS_WRITE )
			System.err.println("WPOPT "+optw+" handlers reaching an options-write sink without a management capability (WP_OPTIONS_WRITE)");
		if( System.getenv("WP_AUDIT_PROF") != null )
			System.err.println("WPPROF subtreeIds calls="+subtreeIdsCalls+" misses="+subtreeIdsMiss
				+" cacheSize="+subtreeIdsCache.size()
				+" (hit-rate="+(subtreeIdsCalls>0?(100*(subtreeIdsCalls-subtreeIdsMiss)/subtreeIdsCalls):0)+"%)"
				+" | guardedRegion calls="+guardedRegionCalls+" misses="+guardedRegionMiss
				+" (hit-rate="+(guardedRegionCalls>0?(100*(guardedRegionCalls-guardedRegionMiss)/guardedRegionCalls):0)+"%)");
	}

	// Setting-getter wrapper resolution. A function/method whose returned value derives from a stored
	// read (STORED_SOURCE_FUNC) with a constant key — directly, through a local var or an array-index,
	// or through another already-resolved wrapper — is itself a stored read of that backing key.
	// Registering calls to these wrappers as stored reads lets wrapper-mediated stored XSS (e.g.
	// $obj->get_setting('k') / a global getter over get_post_meta) be reached. Bounded fixpoint so short
	// getter chains resolve. funcId -> backing constant key.
	static final java.util.Map<Long,String> storedWrapperKey = new java.util.HashMap<Long,String>();

	private static void resolveStoredReadWrappers(
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> varAssigns ) {
		if( !STORED_TAINT ) return;
		java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>> retByFid =
			new java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			Long fid; try { fid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( fid == null || !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			retByFid.computeIfAbsent(fid, k -> new java.util.ArrayList<ast.statements.jump.ReturnStatement>())
				.add((ast.statements.jump.ReturnStatement)n);
		}
		boolean changed = true; int round = 0;
		while( changed && round++ < 4 ) {
			changed = false;
			for( java.util.Map.Entry<Long,java.util.List<ast.statements.jump.ReturnStatement>> e : retByFid.entrySet() ) {
				Long fid = e.getKey();
				if( storedWrapperKey.containsKey(fid) ) continue;
				for( ast.statements.jump.ReturnStatement r : e.getValue() ) {
					String key = storedConstKeyOf(r.getReturnExpression(), fid, varAssigns, new java.util.HashSet<String>(), 0);
					if( key != null ) { storedWrapperKey.put(fid, key); changed = true; break; }
				}
			}
		}
		if( !storedWrapperKey.isEmpty() )
			System.err.println("WPSTORED resolved "+storedWrapperKey.size()+" setting-getter wrapper(s) to backing keys");
	}

	// Backing constant key of an expression that reads a stored value (STORED_SOURCE_FUNC or a resolved
	// wrapper), seen through a local var, an array-index, or one call hop; else null.
	private static String storedConstKeyOf( ASTNode e, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> varAssigns,
			java.util.Set<String> visiting, int depth ) {
		if( e == null || depth > 8 ) return null;
		if( e instanceof CallExpressionBase ) {
			CallExpressionBase c = (CallExpressionBase)e;
			String nm = callTargetName(c);
			if( nm != null && STORED_SOURCE_FUNCS.contains(nm) ) {
				Integer ki = STORED_READ_KEYIDX.get(nm);
				ArgumentList al = c.getArgumentList();
				if( ki != null && al != null && al.size() > ki )
					return resolveStoredKey(al.getArgument(ki), fid, varAssigns);
				return null;
			}
			java.util.List<Long> tg = call2mtd.get(c.getNodeId());
			if( tg != null ) for( Long t : tg ) if( storedWrapperKey.containsKey(t) ) return storedWrapperKey.get(t);
			return null;
		}
		String etype = e.getProperty("type");
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(e.getNodeId());
		if( "AST_DIM".equals(etype) && kids != null && kids.get(0) != null )
			return storedConstKeyOf(ASTUnderConstruction.idToNode.get(kids.get(0)), fid, varAssigns, visiting, depth+1);
		String vn = varNameOf(e);
		if( vn != null && !visiting.contains(vn) ) {
			visiting.add(vn);
			java.util.HashMap<String,java.util.List<ASTNode>> m = varAssigns.get(fid);
			if( m != null && m.get(vn) != null )
				for( ASTNode rhs : m.get(vn) ) {
					String k = storedConstKeyOf(rhs, fid, varAssigns, visiting, depth+1);
					if( k != null ) { visiting.remove(vn); return k; }
				}
			visiting.remove(vn);
		}
		return null;
	}

	// True if a call resolves (via the call graph) to a stored-read wrapper. Used by the risk-name walk
	// and the source seeder so wrapper calls behave like direct stored reads.
	private static Long storedWrapperTargetOf( CallExpressionBase c ) {
		java.util.List<Long> tg = call2mtd.get(c.getNodeId());
		if( tg != null ) for( Long t : tg ) if( storedWrapperKey.containsKey(t) ) return t;
		return null;
	}

	// file_get_contents('php://input') returns the raw HTTP request body — attacker-controlled exactly
	// like $_POST. Modern JSON/REST AJAX handlers read input this way instead of superglobals
	// (e.g. json_decode(file_get_contents('php://input'))), so the whole save path is otherwise invisible
	// to taint. Model the call result as a request source. Runs in all modes (helps reflected too).
	private static void seedRawInputSources() {
		int n = 0;
		for( CallExpressionBase fc : functionCalls ) {
			String name = callTargetName(fc);
			// getallheaders()/apache_request_headers() return the full set of request headers — entirely
			// attacker-controlled (Host, X-Forwarded-For, Referer, custom headers), a common source for
			// header-driven logic. Model the whole return as a request source.
			if( "getallheaders".equals(name) || "apache_request_headers".equals(name) ) {
				PHPCSVEdgeInterpreter.sources.add(fc.getNodeId()); n++;
				continue;
			}
			if( !"file_get_contents".equals(name) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 1 ) continue;
			String a0 = literalString(al.getArgument(0));
			if( a0 != null && a0.toLowerCase().contains("php://input") ) {
				PHPCSVEdgeInterpreter.sources.add(fc.getNodeId()); n++;
			}
		}
		if( n > 0 ) System.err.println("WPRAWIN modeled "+n+" php://input request source(s)");
	}

	// Stored-read taint sources (get_option/get_post_meta/...). See STORED_TAINT note above.
	private static void seedStoredTaintSources() {
		if( !STORED_TAINT ) return;
		// Paired mode: collect the keys that receive a tainted (request-derived) write somewhere in-code.
		// Flow-binding: a variable key is resolved to its literal (so dynamic-key writes/reads match), and
		// a value is tainted only if it actually traces to a request source (so $v='x';write($v) does NOT
		// taint, while $v=$_POST['x'];write($v) does) — precise where the old non-literal proxy was coarse.
		Set<String> taintedKeys = STORED_PAIRED ? new HashSet<String>() : null;
		java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> varAssigns =
			new java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>>();
		if( STORED_PAIRED ) {
			PHPCGFactory.recordScanSite("PCG_2662", ASTUnderConstruction.idToNode.size());
			for( ASTNode nd : ASTUnderConstruction.idToNode.values() ) {
				if( !(nd instanceof AssignmentExpression) ) continue;
				Long fid = nd.getFuncId(); if( fid == null ) continue;
				Expression lhs = ((AssignmentExpression)nd).getLeft();
				Expression rhs = ((AssignmentExpression)nd).getRight();
				if( rhs == null ) continue;
				String vn = varNameOf(lhs);
				if( vn != null )
					varAssigns.computeIfAbsent(fid, k -> new java.util.HashMap<String,java.util.List<ASTNode>>())
						.computeIfAbsent(vn, k -> new java.util.ArrayList<ASTNode>()).add(rhs);
				// Element write $base[..] = rhs: attribute rhs to the base array var too, so a tainted
				// element write makes the whole array trace as tainted. Closes the
				// $arr[$k]=$_POST[..]; update_option('opt',$arr) pattern (dynamic index -> base invisible).
				if( lhs instanceof ArrayIndexing ) {
					String bk = varNameOf(((ArrayIndexing)lhs).getArrayExpression());
					if( bk != null && !bk.equals(vn) )
						varAssigns.computeIfAbsent(fid, k -> new java.util.HashMap<String,java.util.List<ASTNode>>())
							.computeIfAbsent(bk, k -> new java.util.ArrayList<ASTNode>()).add(rhs);
				}
			}
			for( CallExpressionBase fc : functionCalls ) {
				String name = callTargetName(fc);
				int[] kv = name == null ? null : STORED_WRITE_KEYVAL.get(name);
				if( kv == null ) continue;
				ArgumentList al = fc.getArgumentList();
				if( al == null || al.size() <= kv[1] ) continue;
				if( !valueIsTainted(al.getArgument(kv[1]).getNodeId(), fc.getFuncId(), varAssigns, 0) ) continue;
				String key = resolveStoredKey(al.getArgument(kv[0]), fc.getFuncId(), varAssigns);
				if( key != null ) taintedKeys.add(key);     // resolvable key (literal or var->literal)
			}
			// WordPress core saves $_POST[option_name] to the option when a register_setting()'d settings
			// form posts to options.php, so a registered option is request-writable even though the write
			// itself lives in core, not plugin code. Model that: register_setting(group, option_name).
			for( CallExpressionBase fc : functionCalls ) {
				if( !"register_setting".equals(callTargetName(fc)) ) continue;
				ArgumentList al = fc.getArgumentList();
				if( al == null || al.size() < 2 ) continue;
				String key = resolveStoredKey(al.getArgument(1), fc.getFuncId(), varAssigns);
				if( key != null ) taintedKeys.add(key);
			}
		}
		int n = 0, suppressed = 0, wrap = 0;
		boolean dbg = System.getenv("WP_STORED_DEBUG") != null;
		if( dbg && STORED_PAIRED ) System.err.println("WPTAINTEDKEYS "+taintedKeys);
		for( CallExpressionBase fc : functionCalls ) {
			String name = callTargetName(fc);
			String key = null; boolean isStored = false, isWrap = false;
			if( name != null && STORED_SOURCE_FUNCS.contains(name) ) {
				isStored = true;
				Integer ki = STORED_READ_KEYIDX.get(name);
				ArgumentList al = fc.getArgumentList();
				key = (ki != null && al != null && al.size() > ki)
					? resolveStoredKey(al.getArgument(ki), fc.getFuncId(), varAssigns) : null;
			} else {
				Long wt = storedWrapperTargetOf(fc);
				if( wt != null ) { isWrap = true; key = storedWrapperKey.get(wt); }
			}
			if( !isStored && !isWrap ) continue;
			if( STORED_PAIRED ) {
				// Resolvable key with no tainted write to it -> suppress. Unresolvable (truly dynamic)
				// read key -> keep (conservative: cannot prove it is unpaired).
				if( key != null && !taintedKeys.contains(key) ) {
					suppressed++;
					if( dbg ) System.err.println("WPSUPPRESS "+fc.getNodeId()+" key="+key
						+" via="+(isWrap?"wrapper":name)+" func="+fc.getFuncId());
					continue;
				}
			}
			PHPCSVEdgeInterpreter.sources.add(fc.getNodeId()); n++; if( isWrap ) wrap++;
		}
		// ---- custom $wpdb table pairing (WP_WPDB_STORED=1) ----------------------------------
		// Write side: $wpdb->insert/update/replace whose DATA argument traces to a request source.
		// Read side:  $wpdb->get_var/get_row/get_results/get_col.
		// Pairing is PLUGIN-level, not column-level: a custom table name is normally built at
		// runtime ($wpdb->prefix.'x', or a helper like Participants_Db::participants_table()), and
		// the read's column sits inside a SQL string — neither is statically resolvable, so a
		// column-keyed pair cannot be formed. Requiring a proven tainted write somewhere in the
		// plugin keeps this from degrading into "every DB read is a source".
		if( WPDB_STORED ) {
			boolean taintedDbWrite = false;
			for( MethodCallExpression mc : nonStaticMethodCalls ) {
				if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
				String mn = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
				if( !("insert".equals(mn) || "update".equals(mn) || "replace".equals(mn)) ) continue;
				if( !receiverIsWpdb(mc.getTargetObject()) ) continue;
				ArgumentList wal = mc.getArgumentList();
				if( wal == null || wal.size() < 2 ) continue;
				try {
					if( valueIsTainted(wal.getArgument(1).getNodeId(), mc.getFuncId(), varAssigns, 0) ) {
						taintedDbWrite = true;
						System.err.println("WPDBSTORED tainted write via $wpdb->"+mn+" node "+mc.getNodeId());
						break;
					}
				} catch( Exception e ) {}
			}
			if( taintedDbWrite ) {
				int dbn = 0;
				for( MethodCallExpression mc : nonStaticMethodCalls ) {
					if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
					String mn = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
					if( !("get_var".equals(mn) || "get_row".equals(mn)
					      || "get_results".equals(mn) || "get_col".equals(mn)) ) continue;
					if( !receiverIsWpdb(mc.getTargetObject()) ) continue;
					PHPCSVEdgeInterpreter.sources.add(mc.getNodeId()); dbn++;
				}
				System.err.println("WPDBSTORED added "+dbn+" $wpdb read sources (custom-table pairing)");
			} else {
				System.err.println("WPDBSTORED no request-tainted $wpdb write found - custom-table reads not seeded");
			}
		}
		System.err.println("WPSTORED added "+n+" stored-read taint sources ("+wrap+" via wrapper)"
			+ (STORED_PAIRED ? (" (scoped write-provenance; suppressed "+suppressed+" unpaired reads)") : " (broad recall-max)"));
	}

	// Resolve a stored-op key argument to a constant: a string literal, or a variable assigned exactly
	// one (consistent) string literal in its function. Returns null if dynamic/unresolvable.
	// FN-3 helpers. A stored-key name is "sensitive" if it names a secret/credential — the disclosure
	// class worth flagging (leaking a settings toggle is noise; leaking an API key is a vuln). Tight by
	// design: matched on word-ish boundaries to avoid catching e.g. "monkey" for "key".
	private static final java.util.regex.Pattern SENSITIVE_NAME = java.util.regex.Pattern.compile(
		"(?i)(^|[_\\-])(secret|token|auth[_\\-]?key|api[_\\-]?key|apikey|access[_\\-]?token|"
		+ "refresh[_\\-]?token|client[_\\-]?secret|password|passwd|pwd|private[_\\-]?key|credential|"
		+ "license[_\\-]?key|licence[_\\-]?key|salt|nonce[_\\-]?key)($|[_\\-])");
	private static boolean isSensitiveName(String key) {
		if( key == null ) return false;
		return SENSITIVE_NAME.matcher(key).find();
	}
	// A server-file path is sensitive if it points at credentials/config the requester should never read.
	private static final java.util.regex.Pattern SENSITIVE_FILE = java.util.regex.Pattern.compile(
		"(?i)(wp-config\\.php|\\.env|\\.htpasswd|\\.htaccess|id_rsa|\\.pem|\\.ppk|credentials|\\.ssh|"
		+ "\\.aws|shadow$|\\.git[/\\\\]config)");
	private static boolean isSensitiveFile(String path) {
		if( path == null ) return false;
		return SENSITIVE_FILE.matcher(path).find();
	}
	// Data-returning response sinks: the handler hands a value back to the requester. wp_send_json_error
	// is EXCLUDED (an error string is not the sensitive payload); wp_die/die/exit alone are excluded.
	private static final Set<String> DATA_RETURN_SINKS =
		new HashSet<String>(Arrays.asList("wp_send_json_success","wp_send_json","echo","print",
			"printf","vprintf","print_r","var_dump","var_export","fpassthru","readfile"));
	private static boolean isDataReturnSink(String nm) {
		return nm != null && DATA_RETURN_SINKS.contains(nm);
	}

	private static String resolveStoredKey(Expression arg, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va) {
		String lit = literalString(arg);
		if( lit != null ) return lit;
		String v = varNameOf(arg);
		if( v == null ) return null;
		java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
		if( m == null || !m.containsKey(v) ) return null;
		String found = null;
		for( ASTNode rhs : m.get(v) ) {
			String rl = (rhs instanceof StringExpression) ? ((StringExpression)rhs).getEscapedCodeStr() : null;
			if( rl == null ) return null;                       // a non-literal assignment -> unresolvable
			if( found == null ) found = rl; else if( !found.equals(rl) ) return null;  // conflicting -> unresolvable
		}
		return found;
	}

	// True if `node`'s value traces to a request source — inline, or through a variable whose assignment
	// is itself tainted (intraprocedural, depth-bounded). Replaces the coarse "non-literal = tainted".
	// Intrinsic-source variant used ONLY by retArbitraryFids's own computation (below). Identical to
	// valueIsTainted/valueIsTaintedMemo in every respect except the leaf source check: a node in
	// PHPCSVEdgeInterpreter.sources ONLY because forwardInlineSourceArgs() synthetically forwarded a
	// caller's argument into it (forwardedParamSources) does NOT count as evidence this function
	// intrinsically reads a request source -- it only proves a caller COULD pass attacker data at
	// that parameter, which is exactly the caller-argument-dependent case returnTaintPositions (the
	// Return-taint interproc block in StaticAnalysis.java) already exists to handle precisely.
	// Deliberately a SEPARATE function, not a flag added to valueIsTaintedMemo: that function is a
	// shared, widely-used primitive (confirmed consumer: update_user_meta's key-taint check, per its
	// own comment above) and changing its semantics for every caller was explicitly the wrong move --
	// this bug is specifically about retArbitraryFids conflating two provenance categories, not about
	// valueIsTainted's general behavior being wrong.
	private static boolean valueIsTaintedIntrinsic(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		return valueIsTaintedIntrinsicMemo(node, fid, va, depth, new java.util.HashMap<Long,Boolean>());
	}
	private static boolean valueIsTaintedIntrinsicMemo(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth,
			java.util.HashMap<Long,Boolean> memo) {
		if( node == null || depth > 40 ) return false;
		long key = node.longValue()*256L + depth;
		Boolean c = memo.get(key); if( c != null ) return c;
		boolean res = false;
		Set<Long> sub = subtreeIds(node);
		found:
		{
			// The ONE line that differs from valueIsTaintedMemo: exclude nodes whose ONLY reason for
			// being in `sources` is synthetic parameter forwarding, not a genuine inline source.
			for( Long id : sub )
				if( PHPCSVEdgeInterpreter.sources.contains(id) && !forwardedParamSources.contains(id) ) { res = true; break found; }
			if( va == null ) break found;
			java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
			if( m == null ) break found;
			for( Long id : sub ) {
				ASTNode x = ASTUnderConstruction.idToNode.get(id);
				// R4: a call to a helper ALREADY confirmed intrinsically arbitrary. Using
				// retArbitraryFids here (not a separate "intrinsic-only" set) is intentional: by the
				// time this fixpoint round runs, any callee already in retArbitraryFids got there via
				// this same intrinsic check, so the property is preserved transitively as designed.
				if( retSummaryReady && x instanceof CallExpressionBase ) {
					java.util.List<Long> tg = call2mtd.get(x.getNodeId());
					if( tg != null ) for( Long t : tg ) if( retArbitraryFids.contains(t) ) { res = true; break found; }
				}
				if( !(x instanceof Expression) ) continue;
				String v = lvalKey((Expression)x);
				if( v == null || !m.containsKey(v) ) continue;
				for( ASTNode rhs : m.get(v) ) {
					if( !rhs.getNodeId().equals(node)
						&& valueIsTaintedIntrinsicMemo(rhs.getNodeId(), fid, va, depth+1, memo) ) { res = true; break found; }
				}
			}
		}
		memo.put(key, res);
		return res;
	}

	private static boolean valueIsTainted(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		// Per-query memoization. Within one top-level query fid and va are constant and depth strictly
		// increases on recursion, so the result of (node,depth) is deterministic — memoizing it is exact
		// and collapses the exponential re-convergence of assignment chains (the buildReturnNameSummaries
		// blow-up on large plugins) to O(nodes x depth). Fresh map per top-level call, so no staleness
		// across the retSummaryReady transition or between different fids.
		return valueIsTaintedMemo(node, fid, va, depth, new java.util.HashMap<Long,Boolean>());
	}
	private static boolean valueIsTaintedMemo(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth,
			java.util.HashMap<Long,Boolean> memo) {
		// FIX (2026-08-08): depth ceiling raised from 8 to 40, confirmed as a genuine, deterministic
		// recall defect via a hop-count sweep before touching anything: detection of a plain,
		// acyclic $a1=$_GET['x']; $a2=$a1; ... assignment chain into a WordPress-specific sink
		// (verified against update_user_meta's key-taint check, an actual confirmed consumer of
		// this function -- the baseline SQLi/XSS scan uses a separate mechanism in
		// StaticAnalysis.java entirely unaffected by this limit) disappeared exactly at 8 hops and
		// stayed gone through 12, the sweep's ceiling. A separate cycle test ($a=$b;$b=$a;) resolved
		// correctly well within the original bound, confirming this ceiling was truncating ordinary
		// acyclic chains, not primarily guarding against runaway cycle recursion -- recursion
		// through a cycle is already naturally bounded by this same depth-incrementing structure
		// regardless of where the ceiling sits.
		// Deliberately NOT flipped to unconditional fail-open (return true past the ceiling) as an
		// initial review suggested -- this is a shared, core primitive many different sink checks
		// depend on, and an unconditional fail-open could inflate false positives broadly and
		// unpredictably across all of them. A generous but still-finite ceiling preserves the
		// original fail-closed safety net for genuinely pathological/adversarial chains while
		// covering realistic code. The original comment's stated concern (avoiding "the exponential
		// re-convergence of assignment chains... on large plugins") is a MEMOIZATION concern, not a
		// ceiling-height one -- the memo already bounds work to the number of distinct (node,depth)
		// pairs actually visited, independent of how high the ceiling is set, so raising the ceiling
		// does not reintroduce the blow-up the memoization was built to prevent.
		if( node == null || depth > 40 ) return false;
		// Memo key packs (node, depth) into one long. Was node*16 + depth (4 bits for depth, valid
		// only up to depth 15) -- silently WRONG, not merely suboptimal, for any depth above that:
		// two different (node, depth) pairs could collide onto the same key and return each other's
		// cached answer. Widened to node*256 + depth (8 bits, valid to depth 255) with comfortable
		// margin above the new ceiling. Real AST node ids run from the low thousands to low millions
		// in every plugin seen this session, nowhere near overflowing a long at this multiplier.
		long key = node.longValue()*256L + depth;   // depth in 0..40
		Boolean c = memo.get(key); if( c != null ) return c;
		boolean res = false;
		Set<Long> sub = subtreeIds(node);
		found:
		{
			for( Long id : sub ) if( PHPCSVEdgeInterpreter.sources.contains(id) ) { res = true; break found; }   // request source inline
			if( va == null ) break found;   // no assignment map -> only inline sources are knowable
			java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
			if( m == null ) break found;
			for( Long id : sub ) {
				ASTNode x = ASTUnderConstruction.idToNode.get(id);
				// R4: a call to a helper that returns an internally-read request source.
				if( retSummaryReady && x instanceof CallExpressionBase ) {
					java.util.List<Long> tg = call2mtd.get(x.getNodeId());
					if( tg != null ) for( Long t : tg ) if( retArbitraryFids.contains(t) ) { res = true; break found; }
				}
				if( !(x instanceof Expression) ) continue;
				// R5: lvalKey resolves $a['k'] / $obj->p as well as a simple $var.
				String v = lvalKey((Expression)x);
				if( v == null || !m.containsKey(v) ) continue;
				for( ASTNode rhs : m.get(v) ) {
					if( !rhs.getNodeId().equals(node)
						&& valueIsTaintedMemo(rhs.getNodeId(), fid, va, depth+1, memo) ) { res = true; break found; }
				}
			}
		}
		memo.put(key, res);
		return res;
	}

	// FN-3 precise dataflow: true if `node` (a return-sink argument) derives from one of `seeds` (the
	// sensitive-read RESULT nodes) — the read call inline in the arg, or through a variable whose
	// assignment chain reaches a seed. Mirrors valueIsTaintedMemo but seeded from the read result
	// instead of a request source. Intraprocedural, depth-bounded, memoized per query.
	private static boolean valueDerivesFrom(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va,
			Set<Long> seeds, int depth, java.util.HashMap<Long,Boolean> memo) {
		// FIX (2026-08-08): same depth-ceiling and memo-key-width fix as valueIsTaintedMemo above,
		// applied here for the same reason -- this is the "FN-3 precise dataflow" sensitive-read
		// derivation check (confirmed actively consumed, not dead), structurally identical in its
		// depth-bounded recursion, so it inherits the exact same deterministic false-negative on
		// acyclic chains past the old 8-hop ceiling and the exact same latent memo-key-collision
		// risk the old 4-bit encoding had. Not independently re-verified with its own hop sweep --
		// the mechanism is identical to the one that was swept, not merely similar, so the same
		// diagnosis applies without needing to re-derive it from scratch.
		if( node == null || depth > 40 ) return false;
		long key = node.longValue()*256L + depth;   // depth in 0..40
		Boolean c = memo.get(key); if( c != null ) return c;
		boolean res = false;
		Set<Long> sub = subtreeIds(node);
		found:
		{
			for( Long id : sub ) if( seeds.contains(id) ) { res = true; break found; }   // read call inline in arg
			if( va == null ) break found;
			java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
			if( m == null ) break found;
			for( Long id : sub ) {
				ASTNode x = ASTUnderConstruction.idToNode.get(id);
				if( !(x instanceof Expression) ) continue;
				String v = lvalKey((Expression)x);
				if( v == null || !m.containsKey(v) ) continue;
				for( ASTNode rhs : m.get(v) ) {
					if( seeds.contains(rhs.getNodeId()) ) { res = true; break found; }
					if( !rhs.getNodeId().equals(node)
						&& valueDerivesFrom(rhs.getNodeId(), fid, va, seeds, depth+1, memo) ) { res = true; break found; }
				}
			}
		}
		memo.put(key, res);
		return res;
	}
	// The string value of a literal argument, or null if it is not a plain string literal (dynamic).
	private static String literalString(Expression e) {
		return (e instanceof StringExpression) ? ((StringExpression)e).getEscapedCodeStr() : null;
	}

	// (retained) A write value is a plain scalar literal — kept for reference; flow-binding now uses
	// valueIsTainted instead of this coarse proxy.
	private static boolean isLiteralValue(Expression e) {
		if( e == null ) return false;
		if( e instanceof StringExpression ) return true;
		String sn = e.getClass().getSimpleName();
		return sn.contains("Integer") || sn.contains("Double") || sn.contains("Float")
			|| sn.contains("Bool") || sn.contains("Null");
	}

	// True if an unserialize() call passes ['allowed_classes' => false] (or => []) as its options,
	// which disables object instantiation entirely (PHP 7.0+) — provably safe from object injection.
	private static boolean hasAllowedClassesFalse(CallExpressionBase fc) {
		ArgumentList al = fc.getArgumentList();
		if( al == null || al.size() < 2 ) return false;
		Expression opts = al.getArgument(1);
		if( !(opts instanceof ArrayExpression) ) return false;
		for( ArrayElement el : (ArrayExpression)opts ) {
			Expression k = el.getKey();
			Expression v = el.getValue();
			if( k instanceof StringExpression
				&& "allowed_classes".equals(((StringExpression)k).getEscapedCodeStr())
				&& isFalseOrEmptyArray(v) ) return true;
		}
		return false;
	}

	// allowed_classes value is provably "no classes": the boolean false (an AST_CONST wrapping the
	// name `false`, so the literal may sit one level down) or an empty array literal.
	private static boolean isFalseOrEmptyArray(ASTNode v) {
		if( v == null ) return false;
		if( v instanceof ArrayExpression ) return ((ArrayExpression)v).size() == 0;
		String s = v.getEscapedCodeStr();
		if( s != null && s.equalsIgnoreCase("false") ) return true;
		if( v instanceof ast.expressions.Constant ) {
			ast.expressions.Identifier id = ((ast.expressions.Constant)v).getIdentifier();
			if( id != null && id.getNameChild() != null
				&& "false".equalsIgnoreCase(id.getNameChild().getEscapedCodeStr()) ) return true;
		}
		return false;
	}

	// The boolean literal `true` (an AST_CONST wrapping the name `true`, possibly one level down).
	// Used to require STRICT membership (in_array/array_search 3rd arg) before an allowlist guard
	// is trusted to constrain an option name.
	private static boolean isTrueLiteral(Expression e) {
		if( e == null ) return false;
		String s = e.getEscapedCodeStr();
		if( s != null && s.equalsIgnoreCase("true") ) return true;
		if( e instanceof ast.expressions.Constant ) {
			ast.expressions.Identifier id = ((ast.expressions.Constant)e).getIdentifier();
			if( id != null && id.getNameChild() != null
				&& "true".equalsIgnoreCase(id.getNameChild().getEscapedCodeStr()) ) return true;
		}
		return false;
	}

	// True if `node`'s value traces to a SERVER-SIDE SECRET — a stored-option/meta/transient read, a
	// wp_salt(), or an hmac/hash of one — inline or through a variable assignment (intraprocedural,
	// depth-bounded). The complement of valueIsTainted: used to recognize a secret-token guard, where
	// a request value is compared against a stored secret to authorize an unauthenticated callback.
	private static boolean subtreeHasSecretFetch(Long node, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		if( node == null || depth > 6 ) return false;
		Set<Long> sub = subtreeIds(node);
		for( Long id : sub ) {
			ASTNode x = ASTUnderConstruction.idToNode.get(id);
			if( x instanceof CallExpressionBase ) {
				String tn = callTargetName((CallExpressionBase)x);
				if( tn != null && ( STORED_SOURCE_FUNCS.contains(tn) || tn.equals("wp_salt")
						|| tn.equals("hash_hmac") || tn.equals("hash_hkdf") || tn.equals("hash") ) ) return true;
			}
		}
		if( va == null ) return false;
		java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
		if( m == null ) return false;
		for( Long id : sub ) {
			ASTNode x = ASTUnderConstruction.idToNode.get(id);
			if( !(x instanceof Variable) ) continue;
			String v = varNameOf((Expression)x);
			if( v == null || !m.containsKey(v) ) continue;
			for( ASTNode rhs : m.get(v) )
				if( rhs instanceof Expression && !rhs.getNodeId().equals(node)
					&& subtreeHasSecretFetch(rhs.getNodeId(), fid, va, depth+1) ) return true;
		}
		return false;
	}

	// Extended (non-SQLi) sink detection: object injection (unserialize), SSRF (wp_remote_*),
	// dynamic callables (call_user_func), file access (file_put_contents/fopen/...), and
	// LFI/RFI/RCE (include/require/eval). Each flagged node is tagged with its vuln class.
	// Gated behind WP_SINKS=extended so default SQLi runs are byte-for-byte unchanged.
	// True if the first argument of a call_user_func[_array] names a FIXED callable — a string
	// literal 'funcname' or an array whose method element (index 1) is a string literal, e.g.
	// array($obj,'render'). Only the object/args vary in that case, so it is not a callable
	// injection. An attacker-influenced callable (a bare variable, or an array with a variable
	// method) is NOT fixed and remains a sink.
	private static final java.util.Set<String> WP_URL_GENERATOR_FNS = new java.util.HashSet<String>(java.util.Arrays.asList(
		"admin_url", "site_url", "home_url", "rest_url", "plugins_url", "includes_url",
		"content_url", "network_admin_url", "network_site_url", "network_home_url",
		"get_admin_url", "get_site_url", "get_home_url", "get_rest_url"
	));

	private static String simpleVarName(Expression e) {
		if( !(e instanceof Variable) ) return null;
		Expression ne = ((Variable)e).getNameExpression();
		return (ne instanceof StringExpression) ? ((StringExpression)ne).getEscapedCodeStr() : null;
	}

	// SSRF sink registration should be based ONLY on whether the URL (argument 0) is
	// attacker-influenced -- never on any other argument (request body, headers, cookies,
	// timeouts, etc.). This mirrors the existing literal-string check immediately below, but
	// also recognizes: (a) a direct call to a well-known WordPress URL-generator function
	// (admin_url/site_url/home_url/...), which returns a server-controlled URL never influenced
	// by request data, and (b) a variable traced, via a single-hop same-function assignment, to
	// either of those. Confirmed real false-positive shape via Smush 4.2.0:
	// wp_remote_post(admin_url('admin-post.php'), ['cookies' => $_COOKIE]) -- the URL is fixed;
	// $_COOKIE only reaches an unrelated request-options argument, never the destination.
	private static boolean isProvablyFixedUrl(Expression e, Long funcId) {
		if( e instanceof StringExpression ) return true;
		if( e instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)e);
			return nm != null && WP_URL_GENERATOR_FNS.contains(nm);
		}
		if( e instanceof Variable && funcId != null ) {
			String varName = simpleVarName(e);
			if( varName == null ) return false;
			PHPCGFactory.recordScanSite("PCG_3125", ASTUnderConstruction.idToNode.size());
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				Long nfid;
				try { nfid = n.getFuncId(); } catch( Exception ex ) { continue; }
				if( nfid == null || !nfid.equals(funcId) ) continue;
				if( !(n instanceof AssignmentExpression) ) continue;
				AssignmentExpression ae = (AssignmentExpression) n;
				String lname = simpleVarName(ae.getLeft());
				if( varName.equals(lname) && ae.getRight() != null && isProvablyFixedUrl(ae.getRight(), funcId) ) return true;
			}
		}
		return false;
	}

	// Is the callable-target expression `e` (a call_user_func-family argument, or the second
	// element of an array(obj,'method') callable) FULLY FIXED -- i.e. attacker input plays no
	// role in choosing which callable gets invoked. Checked only one way: a single-hop
	// same-function assignment tracing the variable to a literal string (or the expression is
	// already a literal string directly). Deliberately does NOT credit in_array()-style
	// allowlist bounding here -- bounding a dispatch to a finite set of literal targets proves
	// "arbitrary_injection = false", but not "authorization = true" or "target_safety = true".
	// Two structurally identical in_array(...) guards can differ entirely in whether the
	// specific allowlisted targets are safe to reach (confirmed via an adversarial fixture pair
	// during this session: identical shape, 'download'/'delete' vs. 'view'/'delete_everything'
	// -- nothing at the AST level distinguishes them, and treating an added method_exists()
	// check as changing that conclusion would repeat the exact mistake this session already
	// flagged method_exists() for). See callableInArrayBoundEvidence() for how the bounded-but-
	// not-cleared case is instead recorded as evidence, not used to suppress the finding.
	private static boolean isCallableTargetProvablyBounded(Expression e, Long callNodeId, Long funcId) {
		if( e instanceof StringExpression ) return true;
		if( !(e instanceof Variable) || funcId == null ) return false;
		String varName = simpleVarName(e);
		if( varName == null ) return false;
		PHPCGFactory.recordScanSite("PCG_3157", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			Long nfid;
			try { nfid = n.getFuncId(); } catch( Exception ex ) { continue; }
			if( nfid == null || !nfid.equals(funcId) ) continue;
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression ae = (AssignmentExpression) n;
			String lname = simpleVarName(ae.getLeft());
			if( varName.equals(lname) && ae.getRight() instanceof StringExpression ) return true;
		}
		return false;
	}

	// Evidence-only (never suppresses): if `e` is a variable gated, somewhere in an ancestor
	// IfElement within the same function, by in_array($e, [literal,...], true), returns the
	// literal target names for reporting alongside the (still-active) finding -- e.g.
	// "BOUNDED_TARGET_SET=[download, delete]". Reuses the same ancestor-walk shape as
	// isCallableTargetProvablyBounded used to use for suppression; kept as a separate,
	// non-suppressing path per this session's explicit decision to encode finite-target-set as
	// evidence, not as a safety verdict.
	private static java.util.List<String> callableInArrayBoundEvidence(Expression e, Long callNodeId, Long funcId) {
		if( !(e instanceof Variable) || funcId == null ) return null;
		String varName = simpleVarName(e);
		if( varName == null ) return null;
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(callNodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception ex ) { nfid = null; }
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) {
				java.util.List<String> targets = findBoundingInArrayLiterals(cur, varName);
				if( targets != null ) return targets;
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return null;
	}

	private static java.util.List<String> findBoundingInArrayLiterals(Long root, String varName) {
		java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
		java.util.Set<Long> seen = new HashSet<Long>();
		work.add(root);
		while( !work.isEmpty() ) {
			Long id = work.poll();
			if( id == null || !seen.add(id) ) continue;
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( n instanceof CallExpressionBase ) {
				String nm = callTargetName((CallExpressionBase)n);
				if( "in_array".equals(nm) ) {
					ArgumentList al = ((CallExpressionBase)n).getArgumentList();
					if( al != null && al.size() >= 2 && varName.equals(simpleVarName(al.getArgument(0)))
						&& al.getArgument(1) instanceof ast.php.expressions.ArrayExpression ) {
						ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression) al.getArgument(1);
						java.util.List<String> lits = new java.util.ArrayList<String>();
						boolean allLiteral = true;
						for( int i=0;i<arr.size();i++ ) {
							ast.php.expressions.ArrayElement el = arr.getArrayElement(i);
							if( el == null || !(el.getValue() instanceof StringExpression) ) { allLiteral = false; break; }
							lits.add(((StringExpression)el.getValue()).getEscapedCodeStr());
						}
						if( allLiteral ) return lits;
					}
				}
			}
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
			if( kids != null ) work.addAll(kids.values());
		}
		return null;
	}

	private static boolean callableTargetIsFixed( CallExpressionBase fc ) {
		ArgumentList al = fc.getArgumentList();
		if( al == null || al.size() < 1 ) return false;
		Expression a0 = al.getArgument(0);
		Long funcId = fc.getFuncId();
		if( a0 instanceof StringExpression ) return true;
		if( a0 instanceof ast.php.expressions.ArrayExpression ) {
			ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression)a0;
			if( arr.size() >= 2 ) {
				ast.php.expressions.ArrayElement me = arr.getArrayElement(1);
				if( me != null && isCallableTargetProvablyBounded(me.getValue(), fc.getNodeId(), funcId) ) return true;
			}
		}
		if( isCallableTargetProvablyBounded(a0, fc.getNodeId(), funcId) ) return true;
		return false;
	}

	private static void detectAdditionalSinks() {
		// Gate: extended mode; priv_esc mode adds privilege escalation sinks only.
		boolean runExtended = "extended".equals(SINK_MODE);
		boolean runPrivEsc = runExtended || "priv_esc".equals(SINK_MODE)
			|| "priv-esc".equals(SINK_MODE) || "1".equals(System.getenv("WP_PRIV_ESC"));
		// WP_FILE_READ=1: taint mode for arbitrary-file-read shape (file_get_contents/readfile
		// with request-derived path). Separate from extended to avoid ssrf/object-injection noise.
		boolean runFileRead = runExtended || "file_read".equals(SINK_MODE)
			|| "1".equals(System.getenv("WP_FILE_READ"));
		boolean runFileDelete = runExtended || "file_delete".equals(SINK_MODE)
			|| "1".equals(System.getenv("WP_FILE_DELETE"));
		boolean runPostWrite = runExtended || "post_write".equals(SINK_MODE)
			|| "1".equals(System.getenv("WP_POST_WRITE"));
		boolean runUserMeta = runExtended || "user_meta".equals(SINK_MODE)
			|| "1".equals(System.getenv("WP_USER_META"));
		if( !runExtended && !runPrivEsc && !runFileRead && !runFileDelete && !runPostWrite && !runUserMeta ) return;
		int n = 0;
		for( CallExpressionBase fc : functionCalls ) {
			String name = callTargetName(fc);
			if( name == null ) continue;
			// FIX (2026-08-08): namespace-aware bare-function sink resolution. PRIV_ESC_SINKS,
			// FILE_DELETE_SINKS, FILE_READ_SINKS, POST_WRITE_SINKS, and USER_META_SINKS all match
			// on the bare call name alone (unlike PRIV_ESC_METHODS, which has a receiver-type
			// guard via privEscMethodProvablyNotWpUser()). PHP resolves an unqualified function
			// call from within a namespace to a same-named function IN THAT NAMESPACE first,
			// falling back to the global scope only if no such function exists --
			// `namespace MyPlugin\Utils; function reset_password($a,$b){return $a*$b;}` followed
			// by an unqualified reset_password($a,$b) call from elsewhere in that same namespace
			// resolves to the harmless local function, not WordPress core's global one, but the
			// bare-name match here could not previously tell them apart. Confirmed as a real,
			// pre-existing false-positive risk via adversarial fixture during the password-reset
			// sink extension earlier this session (reset_password AND the already-present
			// add_role both exhibited it identically) and deliberately deferred until now, per
			// the agreed priority order, since no actual false positive from it had been observed
			// on any real-world case evaluated. Fixed once, here, for every bare-function sink set
			// sharing this loop, rather than duplicated per sink family. functionDefs is already
			// keyed by fully-namespace-qualified name ("A\B\foo"), so this needs no new function-
			// identity infrastructure -- only a lookup against a map this engine already builds.
			// A fully-qualified call (\reset_password(...), leading backslash) always means the
			// global function regardless of local namespace context -- PHP itself never
			// namespace-relativizes an FQ call, so this must not be suppressed; reuses the exact
			// FLAG_NAME_FQ check already used elsewhere in this file for the same distinction.
			String callerNs = null;
			try { callerNs = fc.getEnclosingNamespace(); } catch( Exception e ) {}
			boolean fullyQualifiedCall = false;
			try {
				Expression tfCheck = fc.getTargetFunc();
				if( tfCheck instanceof Identifier
				    && ((Identifier)tfCheck).getFlags().contains(PHPCSVNodeTypes.FLAG_NAME_FQ) )
					fullyQualifiedCall = true;
			} catch( Exception e ) {}
			if( !fullyQualifiedCall && callerNs != null && !callerNs.isEmpty()
			    && functionDefs.containsKey(callerNs + "\\" + name) ) {
				continue;   // resolves to the local, namespaced function -- not the global sink
			}
			String cls = null;
			if( runPrivEsc && PRIV_ESC_SINKS.contains(name) ) {
				// Privilege escalation: tainted role/capability data → user-mutation function.
				// For wp_update_user/wp_insert_user/wp_create_user: only flag when the array argument
				// explicitly contains a 'role' key — otherwise any profile update fires falsely
				// (e.g. wp_update_user(['first_name' => $tainted]) from a profile-edit form).
				// add_role/remove_role/add_cap/remove_cap take the role/cap as direct args — always flag.
				boolean isUserArrayFunc = name.equals("wp_update_user") || name.equals("wp_insert_user")
					|| name.equals("wp_create_user");
				if( isUserArrayFunc ) {
					// Check if arg 0 is an array literal containing a 'role' key
					ArgumentList privArgList = fc.getArgumentList();
					boolean hasRoleKey = false;
					if( privArgList != null && privArgList.size() >= 1 ) {
						ASTNode arg0 = privArgList.getArgument(0);
						if( arg0 instanceof ast.php.expressions.ArrayExpression ) {
							ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression)arg0;
							for( int ai = 0; ai < arr.size() && !hasRoleKey; ai++ ) {
								ast.php.expressions.ArrayElement ae = arr.getArrayElement(ai);
								if( ae != null && ae.getKey() instanceof StringExpression
								    && "role".equals(((StringExpression)ae.getKey()).getEscapedCodeStr()) ) {
									// A CONSTANT role does NOT make the call safe: assigning a literal
									// 'administrator' to an attacker-chosen ID, or creating an attacker-named
									// account AS administrator, is privilege escalation even though the role
									// itself never varies. Register unless the role is a constant LOW-privilege
									// role AND the call targets the CURRENT user (self-service profile update).
									if( !PRIV_ESC_ECONOMY ) hasRoleKey = true;          // correctness-first default
									else if( !isConstantRhs(ae.getValue()) ) hasRoleKey = true;
									else if( !isLowPrivRoleLiteral(ae.getValue()) ) hasRoleKey = true;
									else if( !targetsCurrentUser(arr) ) hasRoleKey = true;
								}
							}
						}
						// arg0 is a variable/property: trace back to its assignment(s) and look for a
						// 'role' key in the array literal that builds it. Only if we cannot resolve the
						// assignment at all do we conservatively keep it (unknown construction).
						// Without this, every wp_update_user($args) fires regardless of what $args holds,
						// which was the dominant priv_esc false positive (profile-edit forms).
						if( !hasRoleKey && (arg0 instanceof Variable || arg0 instanceof PropertyExpression) ) {
							String vn0 = varNameOf(arg0);
							Long encFid0 = enclosingFunctionId(fc.getNodeId());
							if( varAssignsByFunc == null ) computeEnumValidated();
							java.util.List<ASTNode> rhsList0 = null;
							if( vn0 != null && encFid0 != null && varAssignsByFunc.containsKey(encFid0) )
								rhsList0 = varAssignsByFunc.get(encFid0).get(vn0);
							// RECALL GUARD: if this base array is EVER written with a dynamic/append key
							// ($args[$k] = …), a later write could set 'role' and the array-literal scan
							// below cannot see it. Cannot prove absence -> keep. (Control case C2.)
							if( !hasRoleKey && vn0 != null && dynKeyedWriteBases != null
							    && dynKeyedWriteBases.contains(vn0) ) {
								hasRoleKey = true;
							}
							// RECALL GUARD: an explicit $args['role'] = … element write also sets the role
							// without appearing in the array literal. Scan this function for such a write.
							if( !hasRoleKey && vn0 != null && encFid0 != null ) {
								PHPCGFactory.recordScanSite("PCG_3355", ASTUnderConstruction.idToNode.size());
								for( ASTNode an : ASTUnderConstruction.idToNode.values() ) {
									if( hasRoleKey ) break;
									if( !(an instanceof AssignmentExpression) ) continue;
									Long af = null; try { af = an.getFuncId(); } catch( Exception e ) {}
									if( af == null || !af.equals(encFid0) ) continue;
									Expression al2 = ((AssignmentExpression)an).getLeft();
									if( !(al2 instanceof ArrayIndexing) ) continue;
									if( !vn0.equals(varNameOf(((ArrayIndexing)al2).getArrayExpression())) ) continue;
									String ik = constIndexKey(((ArrayIndexing)al2).getIndexExpression());
									if( ik == null || "role".equals(ik) ) hasRoleKey = true;
								}
							}
							if( hasRoleKey ) {
								// proven/undecidable role presence — fall through, sink is kept
							} else if( rhsList0 == null || rhsList0.isEmpty() ) {
								hasRoleKey = true;   // unresolvable construction — keep (FN-free)
							} else {
								for( ASTNode r0 : rhsList0 ) {
									if( hasRoleKey ) break;
									if( r0 instanceof ast.php.expressions.ArrayExpression ) {
										ast.php.expressions.ArrayExpression a0 = (ast.php.expressions.ArrayExpression)r0;
										for( int aj = 0; aj < a0.size() && !hasRoleKey; aj++ ) {
											ast.php.expressions.ArrayElement e0 = a0.getArrayElement(aj);
											if( e0 != null && e0.getKey() instanceof StringExpression
											    && "role".equals(((StringExpression)e0.getKey()).getEscapedCodeStr()) ) {
												if( !PRIV_ESC_ECONOMY
												    || !isConstantRhs(e0.getValue())
												    || !isLowPrivRoleLiteral(e0.getValue())
												    || !targetsCurrentUser(a0) ) hasRoleKey = true;
											}
										}
									} else {
										// non-array RHS (merge/filter/function result) — can't prove absence
										hasRoleKey = true;
									}
								}
							}
						}
					}
					if( hasRoleKey ) cls = "priv_esc";
					// else: array has no 'role' key → not a privilege-escalation sink, skip
				} else {
					// add_role/remove_role/add_cap/remove_cap: role is always the direct arg
					cls = "priv_esc";
				}
			}
			else if( runExtended && OBJ_INJECTION_SINKS.contains(name) ) {
				// PHP 7+ unserialize($data, ['allowed_classes' => false]) (or => []) instantiates no
				// objects, so no POP-chain / object-injection is possible. Prove-safe-before-suppress:
				// only this exact allowlist-empty form is dropped; everything else stays a sink (FN-free).
				if( name.equals("unserialize") && hasAllowedClassesFalse(fc) ) continue;
				cls = "object-injection";
			}
			else if( runExtended && CALLABLE_SINKS.contains(name) ) {
				// Dynamic-callable RCE requires the CALLABLE itself (arg 0) to be attacker-influenced.
				// A literal function name ('foo') or an array with a literal method — array($obj,'render')
				// — names a FIXED target; only the arguments vary, so it is not a callable-injection
				// sink. Mirrors the SSRF literal-URL suppression below. (wordpress-popup batch #8 FP.)
				if( callableTargetIsFixed(fc) ) continue;
				// Finite-target-set (in_array(...) allowlist) bounding is deliberately NOT used to
				// suppress this finding -- see isCallableTargetProvablyBounded's docstring. It IS
				// recorded as evidence alongside the still-active finding: proves
				// "arbitrary_injection=false" without claiming "authorization=true" or
				// "target_safety=true", which are separate, unestablished questions (confirmed via
				// an adversarial fixture pair this session where two structurally identical
				// in_array(...)-bounded dispatches differed entirely in whether the allowlisted
				// targets themselves were sensitive).
				{
					ArgumentList cal = fc.getArgumentList();
					Expression calTarget = null;
					if( cal != null && cal.size() >= 1 ) {
						Expression c0 = cal.getArgument(0);
						if( c0 instanceof ast.php.expressions.ArrayExpression && ((ast.php.expressions.ArrayExpression)c0).size() >= 2 ) {
							ast.php.expressions.ArrayElement me = ((ast.php.expressions.ArrayExpression)c0).getArrayElement(1);
							calTarget = (me != null) ? me.getValue() : null;
						} else {
							calTarget = c0;
						}
					}
					java.util.List<String> bounded = (calTarget != null) ? callableInArrayBoundEvidence(calTarget, fc.getNodeId(), fc.getFuncId()) : null;
					if( bounded != null ) {
						System.out.println("CALLABLE_TARGET_EVIDENCE node=" + fc.getNodeId()
							+ " bounded=true arbitrary_injection=false authorization=UNKNOWN target_safety=UNKNOWN"
							+ " targets=" + bounded);
					}
				}
				cls = "rce-callable";
			}
			else if( runExtended && SSRF_SINKS.contains(name) ) {
				// SSRF target provenance = argument 0 (the URL) only. A literal URL, or a call to
				// a well-known WordPress URL-generator function (admin_url/site_url/...), or a
				// variable traced to either via a single-hop assignment, cannot be SSRF -- this
				// does NOT make the whole call "safe": other arguments (body, cookies, headers)
				// remain irrelevant to THIS sink class by design, not because they were checked
				// and found safe. Confirmed real false-positive shape via Smush 4.2.0.
				ArgumentList al = fc.getArgumentList();
				if( al != null && al.size() >= 1 && isProvablyFixedUrl(al.getArgument(0), fc.getFuncId()) ) continue;
				cls = "ssrf";
			}
			else if( (runExtended || runFileRead) && FILE_READ_SINKS.contains(name) ) cls = "file-read";
			else if( (runExtended || runFileDelete) && FILE_DELETE_SINKS.contains(name) ) cls = "file-delete";
			else if( (runExtended || runPostWrite) && POST_WRITE_SINKS.contains(name) ) cls = "post-write";
			else if( (runExtended || runUserMeta) && USER_META_SINKS.contains(name) ) {
				ArgumentList umal = fc.getArgumentList();
				Expression keyArg = ( umal != null && umal.size() > 1 ) ? umal.getArgument(1) : null;
				if( keyArg != null && !(keyArg instanceof StringExpression) ) {
					// A literal key is the overwhelmingly common, benign call shape and is
					// deliberately never flagged (see USER_META_SINKS comment). Only a non-
					// literal key that is actually TAINTED gets flagged -- a non-literal but
					// safely-constructed key (e.g. a hardcoded loop variable over a fixed list)
					// is correctly left unflagged too, since valueIsTainted() requires an actual
					// traced request-data origin, not merely "not a string literal".
					if( varAssignsByFunc == null ) computeEnumValidated();
					Long encFidUm = enclosingFunctionId(fc.getNodeId());
					if( valueIsTainted(keyArg.getNodeId(), encFidUm, varAssignsByFunc, 0)
					    || foreachKeyTaintedByArrayIndexWrite(keyArg, encFidUm) )
						cls = "user-meta";
				}
			}
			else if( runExtended && FILE_WRITE_SINKS.contains(name) ) cls = "file-write";
			else if( runExtended && name.equals("eval") ) cls = "rce-eval";
			if( cls != null ) {
				sinks.add(fc.getNodeId()); sinkClass.put(fc.getNodeId(), cls); n++;
				System.err.println("WPSINK ["+cls+"] "+name+" node "+fc.getNodeId());
			}
		}
		for( Long id : new ArrayList<Long>(ASTUnderConstruction.idToNode.keySet()) ) {
			ASTNode node = ASTUnderConstruction.idToNode.get(id);
			if( node instanceof IncludeOrEvalExpression ) {
				sinks.add(id); sinkClass.put(id, "include-eval"); n++;
				System.err.println("WPSINK [include-eval] node "+id);
			}
		}
		// Privilege escalation via WP_User method calls: $user->set_role($tainted_value)
		// is the canonical pattern. These are method calls on WP_User instances.
		// We register the method call node itself as the sink, tagged priv_esc.
		if( runPrivEsc ) {
			for( MethodCallExpression mc : nonStaticMethodCalls ) {
				if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
				String mname = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
				if( !PRIV_ESC_METHODS.contains(mname) ) continue;
				if( privEscMethodProvablyNotWpUser(mc) ) {
					System.err.println("WPSINK_SKIP [priv_esc:method] "+mname+" node "+mc.getNodeId()
						+" - resolves to plugin-defined method on a non-WP_User class");
					continue;
				}
				sinks.add(mc.getNodeId()); sinkClass.put(mc.getNodeId(), "priv_esc"); n++;
				System.err.println("WPSINK [priv_esc:method] "+mname+" node "+mc.getNodeId());
			}
		}
		if( runPrivEsc )
			System.err.println("PRIV_ESC_MODE "+(PRIV_ESC_ECONOMY
				? "ECONOMY - constant low-priv self-targeted role assignments SUPPRESSED (known FNs: R5,R6)"
				: "CORRECTNESS-FIRST - every reachable role assignment registered"));
		System.err.println("WPSINK added "+n+" extended sinks (WP_SINKS="+SINK_MODE+")");
	}

	// File-upload (arbitrary-write) source. $_FILES[*]['name'] and ['type'] are attacker-controlled
	// (the uploaded filename and MIME), so a destination path built from them taints the dest arg of
	// move_uploaded_file/file_put_contents/etc. -> arbitrary upload. $_FILES[*]['tmp_name'] is the
	// server-generated temp path and is deliberately NOT tainted: it is always the source arg of
	// move_uploaded_file, so tainting it would flag every upload (the coarse-$_FILES FP). Matching
	// only the ['name']/['type'] dim-fetch keeps this FN-free for real bugs and FP-free on safe
	// uploads. Gated to WP_SINKS=extended so SQLi/XSS runs are unchanged.
	// query_vars user-key sources: $x->query_vars[<key>] for user-controlled keys is a request source.
	// User-controlled WP_Query query-var keys (URL/request params). Structural keys (taxonomy, tax_query,
	// meta_query, date_query, post__in/not_in) are EXCLUDED: they're usually internally constructed and
	// validated (e.g. taxonomy_exists), so tainting them causes structural FPs (ultimate-member class-access).
	private static final java.util.Set<String> QV_USER_KEYS = new java.util.HashSet<String>(java.util.Arrays.asList(
		"s","search","orderby","order","meta_key","meta_value","author_name","name","pagename",
		"category_name","tag","m"));
	private static void seedQueryVarsSources() {
		int n = 0;
		PHPCGFactory.recordScanSite("PCG_3528", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof ast.expressions.ArrayIndexing) ) continue;
			ast.expressions.ArrayIndexing ai = (ast.expressions.ArrayIndexing)node;
			Expression qb = ai.getArrayExpression();
			if( !(qb instanceof PropertyExpression) ) continue;
			Expression qp = ((PropertyExpression)qb).getPropertyExpression();
			String qpn = (qp instanceof StringExpression) ? ((StringExpression)qp).getEscapedCodeStr()
				: (qp instanceof Variable && ((Variable)qp).getNameExpression() instanceof StringExpression)
					? ((StringExpression)((Variable)qp).getNameExpression()).getEscapedCodeStr() : null;
			if( !"query_vars".equals(qpn) ) continue;
			// Restrict to a whitelist of user-controlled keys; a literal key not in the set (structural),
			// or a dynamic key (unknown), is conservatively skipped to avoid structural FPs.
			Expression idx = ai.getIndexExpression();
			if( !(idx instanceof StringExpression) ) continue;
			if( !QV_USER_KEYS.contains(((StringExpression)idx).getEscapedCodeStr()) ) continue;
			PHPCSVEdgeInterpreter.sources.add(node.getNodeId()); n++;
		}
		if( n > 0 ) System.err.println("WPQUERYVARSSRC added "+n+" user-key sources");
	}

	private static void seedFileUploadSources() {
		if( !"extended".equals(SINK_MODE) ) return;
		int n = 0;
		PHPCGFactory.recordScanSite("PCG_3551", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof ast.expressions.ArrayIndexing) ) continue;
			ast.expressions.ArrayIndexing ai = (ast.expressions.ArrayIndexing)node;
			Expression idx = ai.getIndexExpression();
			if( !(idx instanceof StringExpression) ) continue;
			String key = ((StringExpression)idx).getEscapedCodeStr();
			if( !"name".equals(key) && !"type".equals(key) ) continue;
			Expression base = ai.getArrayExpression();
			if( !(base instanceof ast.expressions.ArrayIndexing) ) continue;   // require $_FILES[field][key]
			Expression froot = ((ast.expressions.ArrayIndexing)base).getArrayExpression();
			if( froot instanceof Variable
				&& ((Variable)froot).getNameExpression() instanceof StringExpression
				&& "_FILES".equals(((StringExpression)((Variable)froot).getNameExpression()).getEscapedCodeStr()) ) {
				PHPCSVEdgeInterpreter.sources.add(ai.getNodeId());
				n++;
			}
		}
		System.err.println("WPUPLOADSRC added "+n+" $_FILES[*][name|type] sources");
	}

	// WP_REST_Request getter methods that return attacker-controlled request data.
	private static final java.util.Set<String> REST_SOURCE_METHODS =
		new java.util.HashSet<String>(java.util.Arrays.asList(
			"get_param","get_params","get_json_params","get_body_params",
			"get_query_params","get_url_params","get_file_params","get_default_params","get_body"));

	// Treat $request->get_param(...) and siblings as taint sources (the REST analogue of
	// superglobals). A source only yields a flag when its enclosing function is a seeded
	// entry, so this stays inert outside the REST handlers public-mode seeds.
	// WP_REST_Request implements ArrayAccess, so $request['key'] is equivalent to $request->get_param('key').
	// Within a REST-callback function the FIRST parameter is the WP_REST_Request; treat array-access on it
	// as a request source. Root-caused from CVE-2022-45808 (LearnPress): $request['order_by'] -> ORDER BY.
	// Runs after seedWordPressEntryPoints populates entryPriv (which marks REST callbacks "rest:*").
	private static void seedRestArrayAccess() {
		java.util.HashMap<Long,String> restReqParam = new java.util.HashMap<Long,String>();
		for( java.util.Map.Entry<Long,String> e : entryPriv.entrySet() ) {
			if( e.getValue() == null || !e.getValue().startsWith("rest") ) continue;
			ASTNode n = ASTUnderConstruction.idToNode.get(e.getKey());
			if( !(n instanceof FunctionDef) ) continue;
			ParameterList pl = ((FunctionDef)n).getParameterList();
			if( pl == null || pl.size() < 1 ) continue;
			String pn = ((Parameter)pl.getParameter(0)).getName();
			if( pn != null ) restReqParam.put(e.getKey(), pn);
		}
		if( restReqParam.isEmpty() ) return;
		int added = 0;
		PHPCGFactory.recordScanSite("PCG_3597", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !"AST_DIM".equals(n.getProperty("type")) ) continue;
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			String reqName = restReqParam.get(fid);
			if( reqName == null ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
			if( kids == null ) continue;
			ASTNode base = ASTUnderConstruction.idToNode.get(kids.get(0));
			String baseName = varNameOf(base instanceof Expression ? (Expression)base : null);
			if( reqName.equals(baseName) ) { PHPCSVEdgeInterpreter.sources.add(n.getNodeId()); added++; }
		}
		if( added > 0 ) System.err.println("WPRESTARR added "+added+" $request[...] array-access source(s)");
	}

	// FIX (2026-08-08): the receiver was NOT checked -- ANY object's ->get_param()/->get_body()/
	// etc, regardless of class, was tagged as a request source purely by method name. Confirmed
	// live FP: a plugin-defined MyConfig::get_param() returning a hardcoded constant was reported
	// as a REST source and produced a Vul: finding. Fixed by requiring the SAME evidence
	// seedRestArrayAccess() (above) already requires: the receiver must be the FIRST PARAMETER of
	// a function seedWordPressEntryPoints() has independently confirmed is a REST callback
	// (entryPriv value starting with "rest"). This is positional-convention evidence, the same
	// kind the array-access sibling already relies on -- not a new, unproven mechanism.
	// NOTE: this method's call site was moved (see seedWordPressEntryPoints() call site) to run
	// AFTER seedWordPressEntryPoints(), since entryPriv is empty before that point.
	private static void seedRestRequestSources() {
		java.util.HashMap<Long,String> restReqParam = new java.util.HashMap<Long,String>();
		for( java.util.Map.Entry<Long,String> e : entryPriv.entrySet() ) {
			if( e.getValue() == null || !e.getValue().startsWith("rest") ) continue;
			ASTNode rn = ASTUnderConstruction.idToNode.get(e.getKey());
			if( !(rn instanceof FunctionDef) ) continue;
			ParameterList pl = ((FunctionDef)rn).getParameterList();
			if( pl == null || pl.size() < 1 ) continue;
			String pn = ((Parameter)pl.getParameter(0)).getName();
			if( pn != null ) restReqParam.put(e.getKey(), pn);
		}
		int added = 0, skippedWrongReceiver = 0;
		if( !restReqParam.isEmpty() ) {
			for( Long id : new java.util.ArrayList<Long>(ASTUnderConstruction.idToNode.keySet()) ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(id);
				if( n instanceof MethodCallExpression ) {
					Expression tf = ((MethodCallExpression)n).getTargetFunc();
					if( tf instanceof StringExpression
						&& REST_SOURCE_METHODS.contains(((StringExpression)tf).getEscapedCodeStr()) ) {
						Long fid = n.getFuncId();
						String reqName = (fid != null) ? restReqParam.get(fid) : null;
						if( reqName == null ) { skippedWrongReceiver++; continue; }
						Expression recv = ((MethodCallExpression)n).getTargetObject();
						String recvName = varNameOf(recv);
						if( !reqName.equals(recvName) ) { skippedWrongReceiver++; continue; }
						PHPCSVEdgeInterpreter.sources.add(id); added++;
					}
				}
			}
		}
		System.err.println("WPRESTSRC added "+added+" REST request sources ("+skippedWrongReceiver
			+" method-name matches skipped: receiver was not the REST callback's own first parameter)");
	}

	// Classify a hook string into a privilege tag (null = not an entry-point hook).
	private static String classifyHook(String hook) {
		if( hook.startsWith("wp_ajax_nopriv_") || hook.startsWith("admin_post_nopriv_") ) return "unauth";
		if( hook.startsWith("wp_ajax_") || hook.startsWith("admin_post_") || hook.equals("admin_post") ) return "authed";
		if( hook.equals("admin_init") || hook.startsWith("admin_action_") ) return "authed";
		// Public hooks that fire on every front-end request, including unauthenticated:
		if( hook.equals("init") || hook.equals("wp_loaded") || hook.startsWith("wp_loaded")
			|| hook.equals("template_redirect") || hook.equals("wp") || hook.equals("parse_request")
			|| hook.equals("send_headers") || hook.equals("parse_query") || hook.equals("pre_get_posts")
			// P12: additional unauth-reachable request hooks. plugins_loaded / wp_enqueue_scripts
			// fire on every (including logged-out) page load; template_include routes unauthenticated
			// requests; wc_ajax_* / woocommerce_api_* are WooCommerce's logged-out-capable endpoints;
			// rest_pre_dispatch fires before any REST request including unauthenticated ones.
			|| hook.equals("plugins_loaded") || hook.equals("wp_enqueue_scripts")
			|| hook.equals("template_include") || hook.equals("rest_pre_dispatch")
			|| hook.startsWith("wc_ajax_") || hook.startsWith("woocommerce_api_")
			// FIX (2026-08-08): core WordPress authentication-lifecycle filter hooks. These fire
			// on every request, INCLUDING unauthenticated ones, and run BEFORE any capability
			// check could be meaningful -- determine_current_user establishes who the current
			// user even IS, and rest_authentication_errors gates REST authentication itself.
			// Narrow, deliberate addition: only these two specific, verified hooks -- NOT a
			// generic promotion of every add_filter()/add_action() callback to an entry point,
			// which would explode the reachable state space. Motivated by one real,
			// independently-evaluated CVE (Spreadsheet Price Changer, CVE-2025-10656) dispatching
			// an unauthenticated privilege-escalation path through determine_current_user;
			// confirmed ENTRYPOINT_MISS under the frozen baseline before this change.
			|| hook.equals("determine_current_user") || hook.equals("rest_authentication_errors")
			// FIX (2026-08-08): save_post / save_post_{post_type}. Fires unconditionally whenever
			// wp_insert_post()/wp_update_post() succeeds for a post of that type, REGARDLESS of
			// the calling context (REST API, XML-RPC, an admin form, a programmatic internal
			// call, a cron job, an import script) -- the hook itself establishes no authentication
			// guarantee whatsoever, the same semantic shape as init/determine_current_user, not a
			// capability-gated dispatch point. Deliberately narrow: only the literal hook name
			// "save_post" and the exact "save_post_" prefix -- not a generic promotion of every
			// add_action() callback, which would explode the reachable state space the same way
			// every other extension this session was careful to avoid. Motivated by one real,
			// independently-evaluated CVE (Wholesale for WooCommerce, CVE-2026-12144), whose
			// vulnerable function registers on save_post_wwp_requests and was confirmed to reach
			// only LOCAL_SINK_CANDIDATE / external_reachability=NOT_ESTABLISHED under the frozen
			// baseline before this change -- a real, present, correctly-computed guard fact
			// (nonce, no capability) attached to a witness whose external reachability could not
			// be confirmed, purely because this trigger family was unmodeled.
			|| hook.equals("save_post") || hook.startsWith("save_post_")
			) return "unauth";
		return null;
	}

	// Seed from a hook-registration call's argument list, whether it came from the core
	// add_action()/add_filter() function or a wrapper method (e.g. WP Plugin Boilerplate's
	// $this->loader->add_action(...), or Hook_Registry::add_action(...)). Handles two callback
	// shapes: (hook, callback) core-style, and (hook, $component, 'method') boilerplate-style.
	// Leftmost string-literal of a (possibly nested) BINARY_CONCAT expression, else null.
	// 'wp_ajax_' . static::getAction()  ->  "wp_ajax_"  (concat is left-associative, so the
	// prefix literal is reached by descending getLeft()).
	private static String concatLiteralPrefix(Expression e) {
		while( e instanceof BinaryOperationExpression
		       && "BINARY_CONCAT".equals(((BinaryOperationExpression)e).getFlags()) ) {
			e = ((BinaryOperationExpression)e).getLeft();
		}
		if( e instanceof StringExpression ) return ((StringExpression)e).getEscapedCodeStr();
		return null;
	}

	// Leftmost string-literal prefix of an OPTION-NAME argument, across the three name forms that
	// matter for the privesc test, else null:
	//   'wpfoo_x'                       (StringExpression)            -> "wpfoo_x"
	//   'wpfoo_' . $x                   (BINARY_CONCAT)               -> "wpfoo_"
	//   "wpfoo_{$x}"                    (ENCAPS_LIST, literal first)  -> "wpfoo_"
	//   $name / "{$x}_y" / $_POST['k']  (no leading literal)         -> null
	// A non-empty prefix namespaces the write to the plugin's own option space, so the attacker
	// cannot reach a WP-core option name (default_role / users_can_register): NOT privesc-capable.
	// Literal prefix that NAMESPACES the option name. Resolves variables through their
	// assignments (symmetric with valueIsTainted) so that
	//     $n = 'dgx_donate_' . sanitize_key($_POST['x']) . '_list'; update_option($n, ...)
	// is recognized as prefixed (constrained to dgx_donate_*) and therefore NOT privesc,
	// even though request data influences the suffix. Returns null when the name can be
	// fully attacker-chosen on some reaching path (no constant prefix), which keeps genuine
	// arbitrary-name privesc TPs — update_option($_POST['k']) / update_option(sanitize(...$_POST))
	// — flagged. A variable is prefixed only if EVERY reaching assignment is itself prefixed;
	// one unprefixed assignment means the name could be attacker-chosen on that path.
	// Build the R4 return-name summaries. retSummaryReady is false during the build so the
	// call-return check inside valueIsTainted is inert here (a helper that returns another helper's
	// result is a documented residual; this single pass catches the direct internal-source return,
	// the common case). A return that is namespaced with a constant prefix populates retPrefixFids
	// instead — the coupling that keeps `$n = 'plugin_'.$x`-style helpers out of retArbitraryFids.
	private static void buildReturnNameSummaries(
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va) {
		retArbitraryFids.clear(); retPrefixFids.clear(); retSummaryReady = false;
		java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>> rbf =
			new java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			Long f; try { f = n.getFuncId(); } catch( Exception ex ) { continue; }
			if( f == null ) continue;
			rbf.computeIfAbsent(f, k -> new java.util.ArrayList<ast.statements.jump.ReturnStatement>())
			   .add((ast.statements.jump.ReturnStatement)n);
		}
		for( java.util.Map.Entry<Long,java.util.List<ast.statements.jump.ReturnStatement>> en : rbf.entrySet() ) {
			Long f = en.getKey(); boolean anyArb = false, allPfx = true, sawReturn = false; String common = null;
			for( ast.statements.jump.ReturnStatement r : en.getValue() ) {
				Expression re = r.getReturnExpression();
				if( re == null ) { allPfx = false; continue; }
				sawReturn = true;
				boolean tnt = valueIsTaintedIntrinsic(re.getNodeId(), f, va, 0);
				String pfx = optionNameLiteralPrefix(re, f, va, 0);
				if( pfx == null || pfx.isEmpty() ) { allPfx = false; if( tnt ) anyArb = true; }
				else if( common == null ) common = pfx;
			}
			if( anyArb ) retArbitraryFids.add(f);
			if( sawReturn && allPfx && common != null ) retPrefixFids.put(f, common);
		}
		if( System.getenv("WP_RAF_DIAG") != null ) {
			System.err.println("RAF_DIAG[buildReturnNameSummaries] retArbitraryFids=" + retArbitraryFids);
		}
		retSummaryReady = true;
	}

	// Resolve method `m` starting at class `classId`, walking up the parent chain (inherited methods).
	// Returns the method def node id, or null.
	private static Long resolveMethodInHierarchy(Long classId, String m) {
		if( classId == null || classId == -1 || m == null ) return null;
		java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>();
		java.util.HashSet<Long> seen = new java.util.HashSet<Long>();
		q.add(classId);
		while( !q.isEmpty() ) {
			Long c = q.poll(); if( c == null || !seen.add(c) ) continue;
			java.util.List<Method> ms = nonStaticMethodDefs.get(c + "::" + m);
			if( ms == null || ms.isEmpty() ) ms = staticMethodDefs.get(c + "::" + m);
			if( ms != null && !ms.isEmpty() ) return ms.get(0).getNodeId();
			if( ch2prt.containsKey(c) ) q.addAll(ch2prt.get(c));
		}
		return null;
	}

	// Add the call-graph edges the core builder misses for self:: / parent:: / static:: dispatch, so a
	// sink reached only through one of those enters the handler's closure (and the reverse wrapper map).
	// Resolution is by the call's ENCLOSING class + the class hierarchy: self/static -> enclosing class
	// (and up for inherited methods); parent -> the enclosing class's parent(s). Only MISSING edges are
	// added (deduped), and only these three forms — named-class C::m is left to the core resolver.
	private static void augmentStaticDispatchEdges() {
		for( StaticCallExpression sc : staticMethodCalls ) {
			if( !(sc.getTargetFunc() instanceof StringExpression) || !(sc.getTargetClass() instanceof Identifier) ) continue;
			Identifier cid = (Identifier)sc.getTargetClass();
			if( cid.getNameChild() == null ) continue;
			String cls = cid.getNameChild().getEscapedCodeStr();
			if( !( "self".equals(cls) || "parent".equals(cls) || "static".equals(cls) ) ) continue;
			String m = ((StringExpression)sc.getTargetFunc()).getEscapedCodeStr();
			String ns = cid.getEnclosingNamespace();
			Long encl = getClassId(sc.getEnclosingClass(), sc.getNodeId(), ns);
			if( encl == null || encl == -1 ) continue;
			java.util.List<Long> starts = new java.util.ArrayList<Long>();
			if( "parent".equals(cls) ) { if( ch2prt.containsKey(encl) ) starts.addAll(ch2prt.get(encl)); }
			else starts.add(encl);   // self / static
			for( Long st : starts ) {
				Long fid = resolveMethodInHierarchy(st, m);
				if( fid == null ) continue;
				java.util.List<Long> ex = call2mtd.get(sc.getNodeId());
				if( ex == null || !ex.contains(fid) ) call2mtd.add(sc.getNodeId(), fid);
			}
		}
	}

	// Instance-dispatch analogue of augmentStaticDispatchEdges, for `$this->method()` calls the
	// core / path2callee resolver misses (an instance receiver's runtime type is not in the parser's
	// CALLS edge, so no path2callee entry is produced). `$this` is definitively the ENCLOSING class,
	// so it resolves exactly like `self::` — by enclosing class + hierarchy. This lets the
	// access-control / options-write reachability BFS follow a sink reached one instance-method hop
	// away (handler -> `$this->saveSetting()` -> `update_option()`), which previously dead-ended at the
	// handler because the method edge was absent from call2mtd. Only `$this->` is handled; a typed
	// local (`$obj = new X; $obj->m()`) needs receiver-type inference and is deliberately left
	// unmodeled (FN-safe — it simply remains as today). Only MISSING edges are added (deduped),
	// mirroring augmentStaticDispatchEdges; the !contains guard also keeps the call2mtd value list
	// duplicate-free, so the merge in-degree (Edgesize) is never inflated.
	private static void augmentInstanceDispatchEdges() {
		int added = 0;
		for( MethodCallExpression mc : nonStaticMethodCalls ) {
			if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
			Expression recv = mc.getTargetObject();
			if( !(recv instanceof Variable) || !"this".equals(varNameOf(recv)) ) continue;
			String m = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
			String ns = mc.getEnclosingNamespace();
			Long encl = getClassId(mc.getEnclosingClass(), mc.getNodeId(), ns);
			if( encl == null || encl == -1 ) continue;
			Long fid = resolveMethodInHierarchy(encl, m);
			if( fid != null ) {
				java.util.List<Long> ex = call2mtd.get(mc.getNodeId());
				if( ex == null || !ex.contains(fid) ) { call2mtd.add(mc.getNodeId(), fid); added++; }
			}
			// VIRTUAL DISPATCH DOWNWARD: `$this->m()` inside a BASE class dispatches at runtime to
			// the SUBCLASS override whenever the instance is of that subclass (PHP late binding).
			// Walking only UP the hierarchy left every such override uncalled, so a template-method
			// base (`base_column::__construct` -> `$this->setup_value()`, overridden in
			// `user_column`) produced an entry-unreachable subclass method and taint never entered
			// it. Bind the call to every subclass that defines `m` as well. Over-approximate by
			// design and sound for PHP semantics: any of these CAN be the runtime target.
			try {
				for( Long cld : getAllChild(encl) ) {
					if( cld == null || cld.equals(encl) ) continue;
					java.util.List<? extends FunctionDef> cdefs = nonStaticMethodDefs.get(cld+"::"+m);
					if( cdefs == null || cdefs.isEmpty() ) continue;
					for( FunctionDef cd : cdefs ) {
						java.util.List<Long> ex2 = call2mtd.get(mc.getNodeId());
						if( ex2 == null || !ex2.contains(cd.getNodeId()) ) {
							call2mtd.add(mc.getNodeId(), cd.getNodeId()); added++;
						}
					}
				}
			} catch( Exception e ) {}
		}
		if( System.getenv("WP_INSTDISP_DBG") != null )
			System.err.println("WPINSTDISP added "+added+" $this->method() edges");
	}

	// Walk the wrapper chain for an option-name parameter. `fn`'s parameter `pidx` flows to an option
	// sink; for every call that binds it, evaluate the bound arg in the caller's context. A tainted,
	// unprefixed, non-allowlisted bind makes that caller arbitrary-name privesc; a bind that is itself
	// a bare parameter is climbed another level. A literal prefix at any level stops the climb (the
	// name is namespaced there). visited is keyed by fn:pidx, and depth is bounded, so a recursive or
	// cyclic wrapper terminates.
	private static void resolveWrapperArbitrary(Long fn, int pidx,
			java.util.HashMap<Long,java.util.List<CallExpressionBase>> mtd2calls,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va,
			java.util.HashMap<Long,java.util.List<CallExpressionBase>> memGuardsByFid,
			Set<Long> optArbitraryNameFids, java.util.Set<String> visited, int depth) {
		if( fn == null || depth > 6 ) return;
		if( !visited.add(fn + ":" + pidx) ) return;
		java.util.List<CallExpressionBase> callers = mtd2calls.get(fn);
		if( callers == null ) return;
		for( CallExpressionBase cs : callers ) {
			Long cf = cs.getFuncId();
			ArgumentList cal = cs.getArgumentList();
			if( cf == null || cal == null || cal.size() <= pidx ) continue;
			Expression bound = cal.getArgument(pidx);
			String bpfx = optionNameLiteralPrefix(bound, cf, va, 0);
			if( bpfx != null && !bpfx.isEmpty() ) continue;          // namespaced here -> not arbitrary, don't climb
			if( valueIsTainted(bound.getNodeId(), cf, va, 0) ) {
				if( !nameIsAllowlisted(bound, cf, cs.getNodeId(), va, memGuardsByFid) )
					optArbitraryNameFids.add(cf);                     // this caller binds the arbitrary name
				continue;
			}
			if( bound instanceof Variable ) {                        // bind is itself a parameter -> climb a level
				Integer pidx2 = paramIndexOf(cf, varNameOf(bound));
				if( pidx2 != null )
					resolveWrapperArbitrary(cf, pidx2, mtd2calls, va, memGuardsByFid,
						optArbitraryNameFids, visited, depth+1);
			}
		}
	}

	// Index of the parameter named `name` in function `fid`, or null. Used by the wrapper-sink (R7)
	// resolution: when an option-name argument is a bare parameter, its taint/prefix live at the call
	// sites that bind this index.
	private static Integer paramIndexOf(Long fid, String name) {
		if( fid == null || name == null ) return null;
		ASTNode n = ASTUnderConstruction.idToNode.get(fid);
		if( !(n instanceof FunctionDef) ) return null;
		ParameterList pl = ((FunctionDef)n).getParameterList();
		if( pl == null ) return null;
		for( int i=0; i<pl.size(); i++ ) {
			Parameter p = (Parameter)pl.getParameter(i);
			if( p != null && name.equals(p.getName()) ) return i;
		}
		return null;
	}

	private static String optionNameLiteralPrefix(Expression e, Long fid,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va, int depth) {
		if( e == null || depth > 8 ) return null;
		while( e instanceof BinaryOperationExpression
		       && "BINARY_CONCAT".equals(((BinaryOperationExpression)e).getFlags()) ) {
			e = ((BinaryOperationExpression)e).getLeft();
		}
		if( e instanceof StringExpression ) return ((StringExpression)e).getEscapedCodeStr();
		// #6 constant evaluation: a program-defined constant as the leading concat operand
		// (MY_PREFIX . $name / self::PFX . $name) resolves to its string value -> a fixed prefix.
		if( e instanceof Constant ) {
			Identifier id = ((Constant)e).getIdentifier();
			StringExpression nm = (id != null) ? id.getNameChild() : null;
			String val = (nm != null) ? constValues.get(nm.getEscapedCodeStr()) : null;
			return ( val != null && !val.isEmpty() ) ? val : null;
		}
		if( e instanceof ClassConstantExpression ) {
			StringExpression nm = ((ClassConstantExpression)e).getConstantName();
			String val = (nm != null) ? constValues.get(nm.getEscapedCodeStr()) : null;
			return ( val != null && !val.isEmpty() ) ? val : null;
		}
		if( e instanceof EncapsListExpression ) {
			for( Expression part : (EncapsListExpression)e ) {        // leading part only
				return (part instanceof StringExpression) ? ((StringExpression)part).getEscapedCodeStr() : null;
			}
		}
		// A call to a helper whose every return is namespaced with a constant prefix (R4 coupling):
		// $n = build_key($x) where build_key returns 'plugin_'.$x is a fixed-prefix name.
		if( e instanceof CallExpressionBase ) {
			java.util.List<Long> tg = call2mtd.get(e.getNodeId());
			if( tg != null ) for( Long t : tg ) {
				String p = retPrefixFids.get(t);
				if( p != null && !p.isEmpty() ) return p;
			}
			return null;
		}
		// Variable, array element, or property — resolve the prefix through the assignment map (R5).
		if( ( e instanceof Variable || e instanceof ArrayIndexing || e instanceof PropertyExpression ) && va != null ) {
			java.util.HashMap<String,java.util.List<ASTNode>> m = va.get(fid);
			String vn = lvalKey(e);
			if( m == null || vn == null || !m.containsKey(vn) ) return null;
			String pfx = null;
			for( ASTNode rhs : m.get(vn) ) {
				if( !(rhs instanceof Expression) || rhs.getNodeId().equals(e.getNodeId()) ) return null;
				String p = optionNameLiteralPrefix((Expression)rhs, fid, va, depth+1);
				if( p == null || p.isEmpty() ) return null;
				pfx = p;
			}
			return pfx;
		}
		return null;
	}

	// True if the option-name variable is constrained by a dominating membership ALLOWLIST guard
	// against a plugin-defined (non-request) set, so it can only ever be one of a fixed set of keys
	// and never a core option (default_role / users_can_register) — i.e. NOT privilege escalation.
	// Models the ThemeGrill-SDK dismiss-notice pattern (bundled across many WPEverest/ThemeGrill plugins):
	//   $id = sanitize_text_field($_POST['id']);
	//   $ids = wp_list_pluck(self::$notifications,'id');     // plugin-defined keys
	//   if ( ! in_array($id, $ids, true) ) { return; }       // dominates the write
	//   update_option($id, $confirm);
	// We require (a) the tested value is the name variable, (b) the set is not request-tainted, and
	// (c) the guard call's region dominates the sink (reusing guardedRegion, which covers both the
	// if(in_array){sink} and the if(!in_array)bail; ...; sink forms). A genuine arbitrary-name TP
	// (update_option($_POST['k']) with no such guard) is unaffected.
	private static boolean nameIsAllowlisted(Expression nameArg, Long caller, Long sinkNode,
			java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> va,
			java.util.HashMap<Long,java.util.List<CallExpressionBase>> memGuardsByFid) {
		if( memGuardsByFid == null || !(nameArg instanceof Variable) ) return false;
		String nv = varNameOf((Expression)nameArg);
		if( nv == null ) return false;
		java.util.List<CallExpressionBase> guards = memGuardsByFid.get(caller);
		if( guards == null ) return false;
		for( CallExpressionBase fc : guards ) {
			String gn = callTargetName(fc);
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 2 ) continue;
			Expression tested = al.getArgument(0);   // in_array/array_search needle, array_key_exists key
			Expression set     = al.getArgument(1);
			if( !(tested instanceof Variable) || !nv.equals(varNameOf(tested)) ) continue;
			if( valueIsTainted(set.getNodeId(), caller, va, 0) ) continue;   // set must be plugin-defined
			// in_array/array_search default to LOOSE (==) comparison, which type juggling can slip past,
			// so a loose guard does NOT reliably constrain the name and must NOT clear the finding. Only a
			// STRICT check trusts the allowlist: in_array/array_search with 3rd arg `true`, or
			// array_key_exists (key identity, always strict).
			boolean strict = "array_key_exists".equals(gn)
				|| ( al.size() >= 3 && isTrueLiteral(al.getArgument(2)) );
			if( !strict ) continue;
			if( guardedRegion(fc.getNodeId(), caller).contains(sinkNode) ) return true;  // and dominate the sink
		}
		return false;
	}

	private static void seedFromHookRegistration(ArgumentList args, boolean publicOnly) {
		if( args == null || args.size() < 2 ) return;
		Expression hookArg = args.getArgument(0);
		String hook;
		if( hookArg instanceof StringExpression ) {
			hook = ((StringExpression)hookArg).getEscapedCodeStr();
		} else {
			// Dynamically-named hook: add_action('wp_ajax_'.X, cb). The action SUFFIX is built at
			// runtime (e.g. static::getAction()), but the literal PREFIX still classifies the endpoint
			// (wp_ajax_ / wp_ajax_nopriv_ / admin_post_). OO dispatchers (AbstractAjax::register doing
			// add_action('wp_ajax_'.static::getAction(), [static::class,'execute'])) were silently
			// skipped here, so their handlers were never seeded. Seed by the literal prefix; the
			// callback still resolves by method name below. Truly dynamic (no literal prefix) still bails.
			String pfx = concatLiteralPrefix(hookArg);
			if( pfx == null || classifyHook(pfx) == null ) return;
			hook = pfx;
		}
		// P13: SQL-clause filter hooks (posts_where / posts_join / ...). The callback's
		// RETURN value is spliced verbatim into the WHERE/JOIN/ORDER BY of WP core's own
		// $wpdb query, so any tainted data reaching a `return` inside the callback is a
		// SQL sink even though no $wpdb call appears in the plugin. We mark the callback's
		// return statements as sinks. We deliberately do NOT seed the callback's params as
		// tainted: $where is core-supplied, not attacker-controlled, and tainting it would
		// flag every callback. The existing self-contained-handler pass seeds the callback
		// when it independently reads a superglobal, so an inline `$_GET` in the callback
		// is reported; split/query-var sources need separate source modeling (not here).
		if( isSqlClauseFilter(hook) ) {
			Expression scb = args.getArgument(1);
			if( scb instanceof StringExpression || scb instanceof ArrayExpression || scb instanceof CallExpressionBase )
				addSqlFilterReturnSinks(scb);
			else if( args.size() >= 3 && args.getArgument(2) instanceof StringExpression )
				addSqlFilterReturnSinks(args.getArgument(2));
			return;
		}
		// Curated user-input action hooks (e.g. wp_login_failed) that classifyHook does not rank as
		// ajax/admin entries but which still hand the callback raw request data. Register the callback
		// as an unauthenticated entry and seed the request-carrying parameter as a source, then stop.
		if( HOOK_TAINTED_PARAM.containsKey(hook) ) {
			Expression hcb = args.getArgument(1);
			if( !(hcb instanceof StringExpression || hcb instanceof ArrayExpression || hcb instanceof CallExpressionBase)
				&& args.size() >= 3 && args.getArgument(2) instanceof StringExpression )
				hcb = args.getArgument(2);
			int seeded = 0;
			for( int pos : HOOK_TAINTED_PARAM.get(hook) ) seeded += seedHookParamAsSource(hcb, pos);
			// Only treat the hook specially when a tainted parameter was actually present on this
			// callback (e.g. add_filter('authenticate', cb) with accepted_args=1 declares no
			// $username/$password to seed). Otherwise fall through to normal classification so the
			// analysis surface is unchanged.
			if( seeded > 0 ) { registerCallbackAsEntry(hcb, hook+":unauth"); return; }
		}
		String priv = classifyHook(hook);
		if( priv == null ) return;
		// Dynamically-named hook: we cannot bind the concrete registration (e.g. AbstractAjax::init
		// does `add_action('wp_ajax_'.X, cb)` always but `add_action('wp_ajax_nopriv_'.X, cb)` only
		// `if(static::isPublic())`, and isPublic() is per-subclass). Asserting anonymous reachability
		// here would FP in the ACL pass on non-public dispatchers. Downgrade unauth -> authed: the
		// handler is still seeded and caught by the authed-sensitive passes (OPTIONS_WRITE/CSRF/IDOR),
		// but no unconfirmed "anonymous-reachable" claim is made.
		if( !(hookArg instanceof StringExpression) && "unauth".equals(priv) ) priv = "authed";
		if( publicOnly && priv.equals("authed") ) return;
		Expression cb = args.getArgument(1);
		// core / Hook_Registry style: arg1 is a function name or [obj,'method'] array.
		// CallExpressionBase covers the PHP 8.1 first-class-callable form $this->m(...) / C::m(...) / f(...).
		if( cb instanceof StringExpression || cb instanceof ArrayExpression || cb instanceof CallExpressionBase ) {
			registerCallbackAsEntry(cb, hook+":"+priv);
		}
		// boilerplate loader style: add_action($hook, $component, 'method'[, ...]) — the
		// callback is the method-name string in arg2; resolve it by name.
		else if( args.size() >= 3 && args.getArgument(2) instanceof StringExpression ) {
			registerCallbackAsEntry(args.getArgument(2), hook+":"+priv);
		}
	}

	// P13: WordPress filter hooks whose callback RETURN value is concatenated raw into
	// the SQL that WP core then executes via its own $wpdb query. posts_clauses returns an
	// array (different shape) and is intentionally excluded to avoid mismodeling.
	private static boolean isSqlClauseFilter(String hook) {
		if( hook == null ) return false;
		return hook.equals("posts_where") || hook.equals("posts_join")
			|| hook.equals("posts_where_request") || hook.equals("posts_request")
			|| hook.equals("posts_orderby") || hook.equals("posts_groupby")
			|| hook.equals("posts_fields") || hook.equals("posts_fields_request");
	}

	// Resolve a hook callback (name string / [obj,'method'] array / first-class-callable)
	// to its function definition(s) and mark every `return` statement inside as a SQL sink.
	private static void addSqlFilterReturnSinks(Expression cb) {
		String target = null;
		if( cb instanceof StringExpression ) {
			target = ((StringExpression)cb).getEscapedCodeStr();
		}
		else if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 && arr.getArrayElement(1).getValue() instanceof StringExpression )
				target = ((StringExpression)arr.getArrayElement(1).getValue()).getEscapedCodeStr();
		}
		else if( cb instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf != null ) {
				if( "string".equals(tf.getProperty("type")) ) target = tf.getEscapedCodeStr();
				else if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null )
					target = ((Identifier)tf).getNameChild().getEscapedCodeStr();
			}
		}
		if( target == null ) return;
		Set<Long> fids = new HashSet<Long>();
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(mid);
		}
		for( Long mid : allStaticMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(mid);
		}
		for( Long fid : allFunc ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(fid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(fid);
		}
		if( fids.isEmpty() ) return;
		// SQL-filter-callback root seeding: a SQL-clause filter callback's return is registered as a sink below,
		// but the callback is never called from top-level PHP, so its body is traversed only if it's a
		// traversal root (topFunIds). The existing self-contained-handler pass seeds it only when it reads a
		// source DIRECTLY; when the tainted return value arrives via a callee (helper/summary), the body is
		// never walked and the already-registered sink is unreachable. Seed the callback as a root so its
		// return-sink is reachable regardless of how the taint arrives inside it. Root-caused from wp-ticket
		// (CVE-2026-9848): wp_ticket_com_posts_request returns emd_author_search_results(...)'s tainted value.
		for( Long fid : fids ) { topFunIds.add(fid); reasonSqlFilterCallbackRoot.add(fid); }
		for( java.util.Map.Entry<Long,ASTNode> e : ASTUnderConstruction.idToNode.entrySet() ) {
			ASTNode n = e.getValue();
			if( n instanceof ast.statements.jump.ReturnStatement && n.getFuncId() != null && fids.contains(n.getFuncId()) ) {
				sinks.add(n.getNodeId());
				System.err.println("WPSQLFILTER return-sink node "+n.getNodeId()+" in "+target);
			}
		}
	}

	// Known Elementor base class names — any class that extends one of these (directly or transitively)
	// is a widget/element whose render() output is Contributor+-controlled. Elementor core itself is not
	// in the analysed corpus (it's a dependency), so we match by parent class *name string*, not by ID.
	private static final java.util.Set<String> ELEMENTOR_BASE_CLASSES = new java.util.HashSet<>(java.util.Arrays.asList(
		"Widget_Base", "Element_Base", "Widget_WordPress",
		"Base_Widget", "Base_Element",
		// common intermediate base names found in large addon plugins
		"EAEL_Helper_Trait", "EAEL_Adv_Tabs_Widget"
	));
	// Return methods (get_settings* return Contributor+-supplied values when called from render())
	private static final java.util.Set<String> ELEMENTOR_SETTINGS_GETTERS = new java.util.HashSet<>(java.util.Arrays.asList(
		"get_settings_for_display", "get_settings", "get_active_settings", "get_parsed_dynamic_settings"
	));
	// Method name prefix patterns for Elementor render helpers. Exact names plus any starting with
	// "render_" are treated as render entry points. This covers render_feature_list, render_header,
	// render_price, etc. — methods within Widget_Base subclasses that receive $settings as a parameter
	// from render() and pass it into add_render_attribute() calls.
	private static final java.util.Set<String> ELEMENTOR_RENDER_METHODS = new java.util.HashSet<>(java.util.Arrays.asList(
		"render", "render_content", "render_plain_content", "get_render_attributes_string"
	));
	private static boolean isElementorRenderMethod(String name) {
		return name != null && (ELEMENTOR_RENDER_METHODS.contains(name) || name.startsWith("render_"));
	}

	private static void seedElementorWidgets() {
		// Step 1: identify all class IDs that transitively extend a known Elementor base.
		// Since Elementor core is not in the corpus, we resolve by parent name string.
		// Do a fixpoint: start with classes whose immediate parent name is in ELEMENTOR_BASE_CLASSES,
		// then widen to classes whose parent is already in the Elementor set.
		java.util.Set<Long> elementorClasses = new java.util.HashSet<>();
		boolean changed = true; int rounds = 0;
		while( changed && rounds++ < 8 ) {
			changed = false;
			for( Long clsId : inhe.keySet() ) {
				if( elementorClasses.contains(clsId) ) continue;
				java.util.List<Long> parents = inhe.get(clsId);
				for( Long pNode : parents ) {
					ASTNode pn = ASTUnderConstruction.idToNode.get(pNode);
					if( !(pn instanceof Identifier) ) continue;
					String pName = ((Identifier)pn).getNameChild() == null ? null
						: ((Identifier)pn).getNameChild().getEscapedCodeStr();
					if( pName == null ) continue;
					if( ELEMENTOR_BASE_CLASSES.contains(pName) ) {
						elementorClasses.add(clsId); changed = true; break;
					}
					// Check if the parent class ID is already in our elementor set.
					Long pclsId = getClassId(pName, pNode, ((Identifier)pn).getEnclosingNamespace());
					if( pclsId != null && pclsId != -1 && elementorClasses.contains(pclsId) ) {
						elementorClasses.add(clsId); changed = true; break;
					}
				}
			}
		}
		if( elementorClasses.isEmpty() ) return;

		// Step 2: for each Elementor widget class, find its render() methods and seed them.
		// Also seed any get_settings_for_display()/get_settings() call within those functions as a source.
		int widgetCount = 0, renderCount = 0, sourceCount = 0;
		java.util.Set<Long> renderFids = new java.util.HashSet<>();
		// renderHelperFids: render_*() methods that receive $settings as a parameter (not via get_settings_for_display).
		// Their parameter named $settings should be treated as a source, same as the $settings variable in render().
		java.util.Map<Long,java.util.Set<String>> helperSettingsParams = new java.util.HashMap<>();
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( !(n instanceof FunctionDef) ) continue;
			String mName = ((FunctionDef)n).getName();
			if( !isElementorRenderMethod(mName) ) continue;
			// Check if this method belongs to an Elementor class.
			Long clsId = getClassId(((Method)n).getEnclosingClass(), mid, ((Method)n).getEnclosingNamespace());
			if( clsId == null || clsId == -1 || !elementorClasses.contains(clsId) ) continue;
			// Only seed as a top-level entry point if it's a primary render method (not a helper).
			if( ELEMENTOR_RENDER_METHODS.contains(mName) ) {
				topFunIds.add(mid);
				entryPriv.put(mid, "elementor:contributor");
				renderCount++;
			}
			renderFids.add(mid);
			// For render_*() helpers, collect parameter names that are likely $settings passed from render().
			// Convention: first parameter named "settings" (common across EAEL helpers).
			if( !ELEMENTOR_RENDER_METHODS.contains(mName) ) {
				ParameterList pl = ((FunctionDef)n).getParameterList();
				if( pl != null ) {
					for( int i = 0; i < pl.size(); i++ ) {
						String pname = ((Parameter)pl.getParameter(i)).getName();
						if( "settings".equals(pname) || "atts".equals(pname) || "attrs".equals(pname) )
							helperSettingsParams.computeIfAbsent(mid, k -> new java.util.HashSet<>()).add(pname);
					}
				}
			}
		}
		widgetCount = elementorClasses.size();

		// Step 3: seed get_settings_for_display() / get_settings() call RETURNS as taint sources.
		// Two complementary mechanisms:
		// (a) Seed the method call node itself: catches direct use of the return value.
		// (b) Seed the assigned variable's reads: `$settings = $this->get_settings_for_display()` →
		//     seed all `$settings` Variable reads in the same function. This is the primary mechanism
		//     for detectInlineSourceTaint — it needs a variable-read source node so sanitizedOnPath
		//     can walk upward through esc_attr($settings['key']) and correctly suppress the finding.
		//     Seeding only the method-call node makes sanitizedOnPath unable to find the escaper
		//     (it walks from the call node itself, which is not inside the esc_attr subtree).
		java.util.Map<Long,java.util.Set<String>> settingsVarsByFid = new java.util.HashMap<>();
		PHPCGFactory.recordScanSite("PCG_4252", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof MethodCallExpression) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			MethodCallExpression mc = (MethodCallExpression)n;
			if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
			String mn = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
			if( !ELEMENTOR_SETTINGS_GETTERS.contains(mn) ) continue;
			PHPCSVEdgeInterpreter.sources.add(mc.getNodeId());
			sourceCount++;
			// If this call is in an assignment ($settings = ...), collect the LHS var name.
			ASTNode parent = ASTUnderConstruction.idToNode.get(
				PHPCSVEdgeInterpreter.child2parent.get(mc.getNodeId()));
			if( parent instanceof AssignmentExpression ) {
				String lhsName = varNameOf(((AssignmentExpression)parent).getLeft());
				if( lhsName != null )
					settingsVarsByFid.computeIfAbsent(fid, k -> new java.util.HashSet<>()).add(lhsName);
			}
		}
		// Seed Variable reads of $settings within each render fid (both render() and render_*() helpers).
		PHPCGFactory.recordScanSite("PCG_4272", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof Variable) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			java.util.Set<String> svars = settingsVarsByFid.get(fid);
			// Also seed from helper method $settings parameters.
			java.util.Set<String> hparams = helperSettingsParams.get(fid);
			Expression ne = ((Variable)n).getNameExpression();
			if( ne == null ) continue;
			String vname = ne.getEscapedCodeStr();
			if( (svars != null && svars.contains(vname)) || (hparams != null && hparams.contains(vname)) ) {
				PHPCSVEdgeInterpreter.sources.add(n.getNodeId());
				sourceCount++;
			}
		}
		if( widgetCount > 0 )
			System.err.println("WPELEMENTOR seeded "+widgetCount+" widget class(es), "
				+renderCount+" render entry point(s), "+sourceCount+" settings-getter source(s)");

		// Step 4: add_render_attribute(key, attrs_array) as XSS sinks.
		// Elementor does NOT HTML-escape attribute values internally — it calls print_render_attribute_string()
		// which prints key="value" verbatim. Developers must call esc_attr() on values before passing.
		// Two complementary registration strategies:
		// (a) Pre-screen: use xssOutputProvablySafe on each array value; register the call as a sink only
		//     when at least one value is not provably safe (esc_attr'd etc.). This correctly suppresses
		//     calls like add_render_attribute(id, ['class'=>esc_attr($settings['x'])]).
		// (b) Bypass pre-screening for calls whose subtree CONTAINS a foreach iteration variable ($item):
		//     xssOutputProvablySafe uses parent2child (downward, valid-childnum only) which cannot reach
		//     $item variables nested inside calls with empty-childnum ancestors. For these, register the
		//     call as a sink unconditionally and rely on the taint engine's detectInlineSourceTaint plus
		//     the srcDim entries we plant downward-traversal in Step 5.
		int attrSinkCount = 0;
		java.util.Set<String> ELEMENTOR_ATTR_SINK_METHODS = new java.util.HashSet<>(java.util.Arrays.asList(
			"add_render_attribute", "add_render_attributes"
		));
		// Build item-var name set per fid (needed here before Step 5 computes it fully).
		java.util.Map<Long,java.util.Set<String>> earlyItemVars = new java.util.HashMap<>();
		PHPCGFactory.recordScanSite("PCG_4309", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !"AST_FOREACH".equals(n.getProperty("type")) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
			if( kids == null ) continue;
			Long valueVarId = kids.get(1);
			if( valueVarId == null ) continue;
			ASTNode valueVar = ASTUnderConstruction.idToNode.get(valueVarId);
			String itemName = varNameOf(valueVar instanceof Expression ? (Expression)valueVar : null);
			if( itemName != null )
				earlyItemVars.computeIfAbsent(fid, k -> new java.util.HashSet<>()).add(itemName);
		}
		PHPCGFactory.recordScanSite("PCG_4322", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof MethodCallExpression) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			MethodCallExpression mc = (MethodCallExpression)n;
			if( !(mc.getTargetFunc() instanceof StringExpression) ) continue;
			if( !ELEMENTOR_ATTR_SINK_METHODS.contains(
					((StringExpression)mc.getTargetFunc()).getEscapedCodeStr()) ) continue;
			ArgumentList al = mc.getArgumentList();
			if( al == null || al.size() < 2 ) continue;
			// Check if any argument subtree contains a foreach item variable (bypass pre-screen).
			java.util.Set<String> myItemVars = earlyItemVars.get(fid);
			boolean hasItemVar = false;
			if( myItemVars != null && !myItemVars.isEmpty() ) {
				hasItemVar = subtreeContainsItemVar(mc.getNodeId(), myItemVars);
			}
			if( hasItemVar ) {
				// Bypass: register unconditionally; $item path not visible via parent2child.
				sinks.add(mc.getNodeId()); sinkClass.put(mc.getNodeId(), "xss"); attrSinkCount++;
			} else {
				// Normal pre-screen via xssOutputProvablySafe.
				boolean hasUnsafeValue = false;
				if( al.size() >= 2 && al.getArgument(1) instanceof ArrayExpression ) {
					for( ArrayElement el : (ArrayExpression)al.getArgument(1) ) {
						Expression val = el.getValue();
						if( val != null && !xssOutputProvablySafe(val.getNodeId()) ) {
							hasUnsafeValue = true; break;
						}
					}
				} else if( al.size() >= 3 ) {
					Expression val = al.getArgument(2);
					if( val != null && !xssOutputProvablySafe(val.getNodeId()) ) hasUnsafeValue = true;
				}
				if( hasUnsafeValue ) {
				// Before registering add_render_attribute() itself as the sink, check whether this
				// SAME function later consumes the stored attribute through Elementor's own known
				// escaped rendering chain (get_render_attribute_string() -> Utils::render_html_
				// attributes() -> esc_attr(), or print_render_attribute_string() which delegates to
				// the same). add_render_attribute() only STORES a raw value -- it is not itself a
				// sanitizer and is never credited as one here. The safety property, if it exists,
				// is established downstream at the actual escaped-output boundary, and is only
				// trusted when the RESOLVED target of that downstream call has an already-computed,
				// PROVEN-safe return-taint summary (reusing today's returnTaintPositions/
				// returnTaintAnalyzed machinery, not a new mechanism) -- never by function name
				// alone. An unresolved chain, an alternate raw-output path, or a render_html_
				// attributes()-named function whose actual summary is NOT proven safe (e.g. a
				// locally-overridden broken version, or one where the escaper's result is
				// discarded) all fall through to the original, conservative sink registration.
				if( elementRenderedThroughSafeChain(fid) ) {
					// suppressed -- proven to reach the escaped rendering boundary in this function
				} else {
					sinks.add(mc.getNodeId()); sinkClass.put(mc.getNodeId(), "xss"); attrSinkCount++;
				}
			}
			}
		}
		if( attrSinkCount > 0 )
			System.err.println("WPELEMENTOR registered "+attrSinkCount+" add_render_attribute call sink(s)");

		// Step 5: foreach ($settings[...] as $item) repeater propagation.
		// Elementor repeater fields arrive via get_settings_for_display() as $settings['repeater_key'],
		// which is an array of item arrays. The engine doesn't propagate taint through foreach iteration.
		// We model this by seeding $item-variable reads in the foreach body as sources AND by registering
		// them in srcDim[stmtId] so detectInlineSourceTaint can fire on add_render_attribute sinks.
		//
		// The child2parent / parent2child maps are incomplete for nodes with empty childnum columns in
		// the parsed CSV — which covers most of the AST nodes in these large files. We cannot traverse
		// upward from a $item node to its containing statement. Instead, we traverse DOWNWARD from each
		// sink (add_render_attribute call, which IS a CFG node and IS in sinks) into its argument subtree,
		// using parent2child, to find $item-named variable reads. Then seed srcDim[sinkStmt -> itemNode]
		// directly. For the Pricing_Table CVE: add_render_attribute call (91825) → its args subtree →
		// contains $item (91845) → srcDim[91825] += 91845 → detectInlineSourceTaint fires.
		int foreachSeedCount = 0;
		java.util.Map<Long,java.util.Set<String>> renderFidSettingsVars = new java.util.HashMap<>();
		// Collect which variable names are assigned from settings getters in each render fid.
		PHPCGFactory.recordScanSite("PCG_4397", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			Expression rhs = ((AssignmentExpression)n).getRight();
			if( !(rhs instanceof MethodCallExpression) ) continue;
			MethodCallExpression mc2 = (MethodCallExpression)rhs;
			if( !(mc2.getTargetFunc() instanceof StringExpression) ) continue;
			if( !ELEMENTOR_SETTINGS_GETTERS.contains(
					((StringExpression)mc2.getTargetFunc()).getEscapedCodeStr()) ) continue;
			String lhsName = varNameOf(((AssignmentExpression)n).getLeft());
			if( lhsName != null )
				renderFidSettingsVars.computeIfAbsent(fid, k -> new java.util.HashSet<>()).add(lhsName);
		}

		// Collect foreach iteration variable names per fid (from foreach nodes inside render fids).
		java.util.Map<Long,java.util.Set<String>> renderFidItemVars = new java.util.HashMap<>();
		PHPCGFactory.recordScanSite("PCG_4414", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !"AST_FOREACH".equals(n.getProperty("type")) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
			if( kids == null ) continue;
			Long iterExprId = kids.get(0), valueVarId = kids.get(1);
			if( iterExprId == null || valueVarId == null ) continue;
			// Check that the iterated expression involves a settings variable.
			ASTNode iterExpr = ASTUnderConstruction.idToNode.get(iterExprId);
			if( iterExpr == null ) continue;
			java.util.Set<String> settingsVars = renderFidSettingsVars.get(fid);
			boolean fromSettings = false;
			if( "AST_DIM".equals(iterExpr.getProperty("type")) ) {
				HashMap<Integer,Long> dimKids = PHPCSVEdgeInterpreter.parent2child.get(iterExprId);
				if( dimKids != null && dimKids.get(0) != null ) {
					ASTNode base = ASTUnderConstruction.idToNode.get(dimKids.get(0));
					String baseName = varNameOf(base instanceof Expression ? (Expression)base : null);
					if( baseName != null && settingsVars != null && settingsVars.contains(baseName) )
						fromSettings = true;
				}
			}
			if( !fromSettings && PHPCSVEdgeInterpreter.sources.contains(iterExprId) )
				fromSettings = true;
			if( !fromSettings ) continue;
			// Collect the iteration variable name.
			ASTNode valueVar = ASTUnderConstruction.idToNode.get(valueVarId);
			String itemName = varNameOf(valueVar instanceof Expression ? (Expression)valueVar : null);
			if( itemName != null )
				renderFidItemVars.computeIfAbsent(fid, k -> new java.util.HashSet<>()).add(itemName);
		}

		// For each seeded $item variable read in the function body, seed it as a source.
		// Also look for $item reads inside sink-subtrees (downward traversal via parent2child)
		// and register them in srcDim[sinkNode -> itemVarNode] so detectInlineSourceTaint can fire.
		PHPCGFactory.recordScanSite("PCG_4449", ASTUnderConstruction.idToNode.size());
		for( ASTNode vn : ASTUnderConstruction.idToNode.values() ) {
			if( !(vn instanceof Variable) ) continue;
			Long fid = vn.getFuncId();
			if( fid == null || !renderFids.contains(fid) ) continue;
			java.util.Set<String> itemVars = renderFidItemVars.get(fid);
			if( itemVars == null || itemVars.isEmpty() ) continue;
			Expression ne = ((Variable)vn).getNameExpression();
			if( ne == null ) continue;
			String vName = ne.getEscapedCodeStr();
			if( !itemVars.contains(vName) ) continue;
			PHPCSVEdgeInterpreter.sources.add(vn.getNodeId());
			foreachSeedCount++;
		}

		// Downward traversal from add_render_attribute sinks into their arg subtrees:
		// find $item variable reads and register them in srcDim so the inline check fires.
		PHPCGFactory.recordScanSite("PCG_4465", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof MethodCallExpression) ) continue;
			if( !sinks.contains(n.getNodeId()) ) continue;
			String mn = (((MethodCallExpression)n).getTargetFunc() instanceof StringExpression)
				? ((StringExpression)((MethodCallExpression)n).getTargetFunc()).getEscapedCodeStr() : null;
			if( !ELEMENTOR_ATTR_SINK_METHODS.contains(mn) ) continue;
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			java.util.Set<String> itemVars = renderFidItemVars.get(fid);
			if( itemVars == null || itemVars.isEmpty() ) continue;
			// Collect all variable reads in the subtree of this call's arguments.
			collectItemVarsInSubtree(n.getNodeId(), itemVars, n.getNodeId());
		}

		if( foreachSeedCount > 0 )
			System.err.println("WPELEMENTOR seeded "+foreachSeedCount+" foreach-repeater var source(s)");
	}

	// True if any Variable node whose name is in itemVarNames is reachable via parent2child
	// downward from nodeId. Used to detect $item reads inside add_render_attribute arg subtrees.
	private static boolean subtreeContainsItemVar(Long nodeId, java.util.Set<String> itemVarNames) {
		if( nodeId == null ) return false;
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		if( n instanceof Variable ) {
			Expression ne = ((Variable)n).getNameExpression();
			if( ne != null && itemVarNames.contains(ne.getEscapedCodeStr()) ) return true;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nodeId);
		if( kids == null ) return false;
		for( Long child : kids.values() )
			if( subtreeContainsItemVar(child, itemVarNames) ) return true;
		return false;
	}

	// Elementor add_render_attribute() rendering-chain modeling. add_render_attribute() only
	// STORES a raw value -- it is never credited as a sanitizer anywhere in this file. The safety
	// property, if it exists, is established downstream at Elementor's own escaped rendering
	// boundary: get_render_attribute_string() -> Utils::render_html_attributes() -> esc_attr(), or
	// print_render_attribute_string() which delegates to the same. This checks whether the SAME
	// enclosing function later reaches that boundary, using ONLY the already-computed
	// returnTaintPositions/returnTaintAnalyzed summaries (built during the return-taint fixed
	// point elsewhere in this file) to verify actual proven safety -- never trusting a function by
	// name alone. Deliberately coarse: checks "does this function contain a proven-safe
	// consumption call anywhere", not "is this SPECIFIC element key consumed" -- exact per-key
	// correlation would be more precise but adds real complexity; this stays fail-conservative
	// regardless, since a name match alone is never sufficient to suppress -- only a resolved
	// target with a genuinely safe summary is.
	private static boolean elementRenderedThroughSafeChain(Long fid) {
		if( fid == null ) return false;
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			Long nfid;
			try { nfid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( nfid == null || !nfid.equals(fid) ) continue;
			if( !(n instanceof CallExpressionBase) ) continue;
			String nm = callTargetName((CallExpressionBase)n);
			if( nm == null ) continue;
			if( "get_render_attribute_string".equals(nm) || "render_html_attributes".equals(nm) ) {
				if( callTargetIsProvenSafeReturn(n.getNodeId()) ) return true;
			}
			if( "print_render_attribute_string".equals(nm) ) {
				// Documented, stable WPElementor API (verified directly against real Elementor
				// 4.2.2 source: controls-stack.php's print_render_attribute_string() body is
				// exactly `Utils::print_unescaped_internal_string( $this->get_render_attribute_
				// string( $element ) )`) -- always delegates to get_render_attribute_string(). Not
				// trusted by name alone: resolves the call's OWN target and checks THAT target's
				// body for a nested, independently-proven-safe get_render_attribute_string /
				// render_html_attributes call.
				if( printRenderAttributeStringTargetIsSafe(n.getNodeId()) ) return true;
			}
		}
		return false;
	}

	private static boolean callTargetIsProvenSafeReturn(Long callNodeId) {
		List<Long> targets = call2mtd.get(callNodeId);
		if( targets == null || targets.isEmpty() ) return false;   // unresolved -- stay conservative
		for( Long t : targets ) {
			if( !returnTaintAnalyzed.contains(t) ) return false;   // unanalyzed target -- stay conservative
			Set<Integer> pos = returnTaintPositions.get(t);
			if( pos != null && !pos.isEmpty() ) return false;      // some position propagates unsanitized
		}
		return true;
	}

	private static boolean printRenderAttributeStringTargetIsSafe(Long callNodeId) {
		List<Long> targets = call2mtd.get(callNodeId);
		if( targets == null || targets.isEmpty() ) return false;   // unresolved -- stay conservative
		for( Long t : targets ) {
			// print_render_attribute_string() is void -- no return-taint summary exists for it.
			// Instead, scan ITS OWN body for a nested call to get_render_attribute_string() /
			// render_html_attributes() that is independently proven safe.
			boolean foundSafeNested = false;
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				Long nfid;
				try { nfid = n.getFuncId(); } catch( Exception e ) { continue; }
				if( nfid == null || !nfid.equals(t) ) continue;
				if( !(n instanceof CallExpressionBase) ) continue;
				String nm = callTargetName((CallExpressionBase)n);
				if( nm == null ) continue;
				if( "get_render_attribute_string".equals(nm) || "render_html_attributes".equals(nm) ) {
					if( callTargetIsProvenSafeReturn(n.getNodeId()) ) { foundSafeNested = true; break; }
				}
			}
			if( !foundSafeNested ) return false;   // this target doesn't provably delegate to a safe call
		}
		return true;
	}

	// Recursively walk the subtree rooted at `nodeId` via parent2child, collect any Variable nodes
	// whose name is in `itemVarNames`, and register them in StaticAnalysis.srcDim[sinkStmt].
	private static void collectItemVarsInSubtree(Long nodeId, java.util.Set<String> itemVarNames, Long sinkStmt) {
		if( nodeId == null ) return;
		ASTNode n = ASTUnderConstruction.idToNode.get(nodeId);
		if( n instanceof Variable ) {
			Expression ne = ((Variable)n).getNameExpression();
			if( ne != null && itemVarNames.contains(ne.getEscapedCodeStr()) ) {
				tools.php.ast2cpg.StaticAnalysis.srcDim.add(sinkStmt, nodeId);
			}
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nodeId);
		if( kids == null ) return;
		for( Long child : kids.values() ) collectItemVarsInSubtree(child, itemVarNames, sinkStmt);
	}

	// FIX (2026-08-08): registration-wrapper resolution. Two independent real cases found this
	// session share the same underlying gap: a plugin-defined function/method takes a short
	// action name and a callback, and INTERNALLY calls add_action()/add_filter() -- but every
	// existing seeding path requires the call whose NAME is literally "add_action"/"add_filter",
	// so a wrapper named anything else (register_ajax(), userspn_add_action()) was invisible
	// regardless of how simple its internal forwarding was. WP User Frontend (CVE-2025-14047):
	// register_ajax($action, $callback, $args=[]) internally does
	// add_action('wp_ajax_'.$action, $callback, ...) -- hook built from a literal PREFIX
	// concatenated with the wrapper's OWN parameter, callback forwarded directly. Deliberately
	// narrow: only two shapes recognized (hook argument is either a bare parameter, or a literal-
	// prefix concatenated with a bare parameter; callback argument is a bare parameter, forwarded
	// unchanged) -- not a general call-graph inliner. A wrapper can register more than one
	// hook/callback pattern (register_ajax's priv + nopriv pair, each behind its own add_action
	// call) -- all recognized patterns for a given wrapper identity are collected, not just one.
	private static final class RegWrapperPattern {
		final String hookPrefix;     // literal prefix before the parameter, or "" for a bare param
		final int hookParamIdx;
		final int cbParamIdx;
		RegWrapperPattern(String p, int h, int c) { hookPrefix = p; hookParamIdx = h; cbParamIdx = c; }
	}
	private static java.util.Map<String,java.util.List<RegWrapperPattern>> registrationWrappers = null;

	private static java.util.Map<String,Integer> paramIndexMap(ParameterList pl) {
		java.util.Map<String,Integer> m = new HashMap<String,Integer>();
		if( pl == null ) return m;
		for( int i = 0; i < pl.size(); i++ ) {
			try {
				String pn = ((Parameter)pl.getParameter(i)).getName();
				if( pn != null ) m.put(pn, i);
			} catch( Exception e ) {}
		}
		return m;
	}

	// Returns the wrapper's own parameter index this expression resolves to (a bare parameter, or
	// a literal-prefix concatenated with a bare parameter -- see class doc above), or null if the
	// expression doesn't match either recognized shape.
	private static Integer[] hookArgAsParamPattern(Expression e, java.util.Map<String,Integer> params) {
		// bare $param
		String vn = varNameOf(e);
		if( vn != null && params.containsKey(vn) ) return new Integer[]{ -1, params.get(vn) }; // -1 = no literal prefix marker; caller checks separately
		// 'literal_prefix' . $param
		if( e instanceof BinaryOperationExpression
		    && "BINARY_CONCAT".equals(((BinaryOperationExpression)e).getFlags()) ) {
			Expression left = ((BinaryOperationExpression)e).getLeft();
			Expression right = ((BinaryOperationExpression)e).getRight();
			if( left instanceof StringExpression ) {
				String rvn = varNameOf(right);
				if( rvn != null && params.containsKey(rvn) ) return new Integer[]{ 1, params.get(rvn) }; // 1 = has literal prefix marker
			}
		}
		return null;
	}

	// ---- Deferred-registration-queue resolution (WordPress Plugin Boilerplate Loader pattern) --
	// FIX (2026-08-08): a genuinely different, harder shape than the direct-forwarding wrapper
	// above. Confirmed by reading the real source before designing anything (Users manager - PN):
	// the producer method does NOT call add_action() at all -- it packages its own parameters
	// into a keyed array and appends that array to a `$this->` property; a SEPARATE method later
	// iterates that property and calls add_action() using the array's keys. This is the canonical
	// WordPress Plugin Boilerplate Loader class shape, used by many real plugins beyond this one,
	// so a correct, narrow resolver for it has value beyond the single motivating case. Built as
	// a separate mechanism from oneHopGuardWrapperFunctions()/RegWrapperPattern above rather than
	// unified with it, to avoid destabilizing that already-verified code with this new, larger
	// piece of matching logic.
	private static final class QueuePattern {
		final int hookParamIdx, componentParamIdx, methodParamIdx;
		QueuePattern(int h, int c, int m) { hookParamIdx = h; componentParamIdx = c; methodParamIdx = m; }
	}
	private static java.util.Map<String,QueuePattern> queueRegistrationWrappers = null;

	// Step 1: array-builder methods -- a method that does `$accumulator[] = ['key' => $param,
	// ...]; return $accumulator;` where $accumulator is itself one of the method's own bare
	// parameters (the classic "accumulate into a passed-in array, return it" shape) and every
	// value in the keyed literal is also one of the method's own bare parameters.
	private static java.util.Map<String,java.util.Map<String,Integer>> detectArrayBuilderMethods() {
		java.util.Map<String,java.util.Map<String,Integer>> builders = new HashMap<String,java.util.Map<String,Integer>>();
		PHPCGFactory.recordScanSite("PCG_4666", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof FunctionDef) ) continue;
			ParameterList pl; try { pl = ((FunctionDef)n).getParameterList(); } catch( Exception e ) { continue; }
			java.util.Map<String,Integer> params = paramIndexMap(pl);
			if( params.isEmpty() ) continue;
			java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>(); q.add(n.getNodeId());
			java.util.Set<Long> seen = new HashSet<Long>(); int gg = 0;
			ArrayExpression foundArr = null;
			String accumVar = null;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				ASTNode xn = ASTUnderConstruction.idToNode.get(x);
				if( xn instanceof AssignmentExpression ) {
					Expression lhs = ((AssignmentExpression)xn).getLeft();
					Expression rhs = ((AssignmentExpression)xn).getRight();
					if( lhs instanceof ast.expressions.ArrayIndexing
					    && ((ast.expressions.ArrayIndexing)lhs).getIndexExpression() == null
					    && rhs instanceof ArrayExpression ) {
						String base = varNameOf(((ast.expressions.ArrayIndexing)lhs).getArrayExpression());
						if( base != null && params.containsKey(base) ) {
							foundArr = (ArrayExpression)rhs;
							accumVar = base;
						}
					}
				}
				HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kk != null ) q.addAll(kk.values());
			}
			if( foundArr == null || accumVar == null ) continue;
			// confirm a `return $accumVar;` exists somewhere in the same function
			boolean returnsAccum = false;
			q.clear(); seen.clear(); q.add(n.getNodeId()); gg = 0;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				ASTNode xn = ASTUnderConstruction.idToNode.get(x);
				if( xn != null && "AST_RETURN".equals(xn.getProperty("type")) ) {
					HashMap<Integer,Long> rk = PHPCSVEdgeInterpreter.parent2child.get(x);
					if( rk != null ) for( Long rid : rk.values() ) {
						ASTNode rn = ASTUnderConstruction.idToNode.get(rid);
						if( rn instanceof Expression && accumVar.equals(varNameOf((Expression)rn)) ) returnsAccum = true;
					}
				}
				HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kk != null ) q.addAll(kk.values());
			}
			if( !returnsAccum ) continue;
			java.util.Map<String,Integer> keyToParam = new HashMap<String,Integer>();
			boolean allMatch = foundArr.size() > 0;
			for( int i = 0; i < foundArr.size(); i++ ) {
				ast.php.expressions.ArrayElement el = foundArr.getArrayElement(i);
				Expression key = el.getKey(), val = el.getValue();
				if( !(key instanceof StringExpression) ) { allMatch = false; break; }
				String vn = varNameOf(val);
				if( vn == null || !params.containsKey(vn) ) { allMatch = false; break; }
				keyToParam.put(((StringExpression)key).getEscapedCodeStr(), params.get(vn));
			}
			if( !allMatch || keyToParam.isEmpty() ) continue;
			String id = funcIdentity(n.getNodeId());
			if( id != null && !"anonymous".equals(id) ) builders.put(id, keyToParam);
		}
		return builders;
	}

	private static void detectDeferredQueuePatterns() {
		queueRegistrationWrappers = new HashMap<String,QueuePattern>();
		java.util.Map<String,java.util.Map<String,Integer>> builders = detectArrayBuilderMethods();
		if( builders.isEmpty() ) return;

		// Step 2: producer methods -- call a known builder with (some of) their own bare
		// parameters as arguments, and assign the builder's result to $this->PROPERTY. The
		// builder call is typically $this->builder(...) -- a MethodCallExpression, not in
		// functionCalls at all (confirmed empirically: an earlier version of this only scanned
		// functionCalls and found zero producers on the real motivating shape). Scan all three
		// call-expression collections and resolve each to a comparable builder identity.
		java.util.List<CallExpressionBase> builderCallCandidates = new java.util.ArrayList<CallExpressionBase>();
		builderCallCandidates.addAll(functionCalls);
		builderCallCandidates.addAll(nonStaticMethodCalls);
		builderCallCandidates.addAll(staticMethodCalls);
		java.util.Map<String,String> producerProperty = new HashMap<String,String>();
		java.util.Map<String,java.util.Map<Integer,Integer>> producerArgMap = new HashMap<String,java.util.Map<Integer,Integer>>();
		java.util.Map<String,String> producerBuilder = new HashMap<String,String>();
		for( CallExpressionBase fc : builderCallCandidates ) {
			String callee;
			if( fc instanceof StaticCallExpression ) callee = staticCallTargetName((StaticCallExpression)fc);
			else if( fc instanceof MethodCallExpression ) {
				// $this->builder(...) -- resolve by bare method name only (matching a builder's
				// OWN bare name, since builders detected above are keyed by full "Class::name"
				// but the call site's receiver may be $this rather than a named class).
				callee = ( ((MethodCallExpression)fc).getTargetFunc() instanceof StringExpression )
					? ((StringExpression)((MethodCallExpression)fc).getTargetFunc()).getEscapedCodeStr() : null;
			}
			else callee = callTargetName(fc);
			if( callee == null ) continue;
			for( String builderId : builders.keySet() ) {
				String bareBuilderName = builderId.contains("::") ? builderId.substring(builderId.indexOf("::")+2) : builderId;
				if( !bareBuilderName.equals(callee) ) continue;
				Long fid = null; try { fid = fc.getFuncId(); } catch( Exception e ) {}
				if( fid == null ) continue;
				ASTNode producerNode = ASTUnderConstruction.idToNode.get(fid);
				if( producerNode == null ) continue;
				ParameterList ppl; try { ppl = ((FunctionDef)producerNode).getParameterList(); } catch( Exception e ) { continue; }
				java.util.Map<String,Integer> pparams = paramIndexMap(ppl);
				ArgumentList al = fc.getArgumentList();
				if( al == null ) continue;
				java.util.Map<Integer,Integer> argMap = new HashMap<Integer,Integer>();
				for( int i = 0; i < al.size(); i++ ) {
					String vn = varNameOf(al.getArgument(i));
					if( vn != null && pparams.containsKey(vn) ) argMap.put(i, pparams.get(vn));
				}
				if( argMap.isEmpty() ) continue;
				Long parent = PHPCSVEdgeInterpreter.child2parent.get(fc.getNodeId());
				ASTNode p = ASTUnderConstruction.idToNode.get(parent);
				if( !(p instanceof AssignmentExpression) ) continue;
				Expression lhs = ((AssignmentExpression)p).getLeft();
				String propName = propertyNameOf(lhs);
				if( propName == null ) continue;
				String producerId = funcIdentity(fid);
				if( producerId == null || "anonymous".equals(producerId) ) continue;
				producerProperty.put(producerId, propName);
				producerArgMap.put(producerId, argMap);
				producerBuilder.put(producerId, builderId);
			}
		}

		// Step 3: consumer methods -- foreach ($this->PROP as $lv) { add_action($lv['K1'],
		// [$lv['K2'], $lv['K3']], ...); } -- extract which property, and which array keys feed
		// the hook name / callback component / callback method position.
		java.util.Map<String,String[]> consumerKeys = new HashMap<String,String[]>();
		for( CallExpressionBase fc : functionCalls ) {
			String callee = callTargetName(fc);
			if( !"add_action".equals(callee) && !"add_filter".equals(callee) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 2 ) continue;
			String hookKey = dimKeyOfSameBase(al.getArgument(0));
			if( hookKey == null ) continue;
			String loopVarBase = dimBaseVarName(al.getArgument(0));
			if( !(al.getArgument(1) instanceof ArrayExpression) ) continue;
			ArrayExpression cbArr = (ArrayExpression)al.getArgument(1);
			if( cbArr.size() < 2 ) continue;
			String componentKey = dimKeyIfBase(cbArr.getArrayElement(0).getValue(), loopVarBase);
			String methodKey = dimKeyIfBase(cbArr.getArrayElement(1).getValue(), loopVarBase);
			if( componentKey == null || methodKey == null ) continue;
			Long fid = null; try { fid = fc.getFuncId(); } catch( Exception e ) {}
			String prop = enclosingForeachThisProperty(fc.getNodeId(), loopVarBase);
			if( prop == null || fid == null ) continue;
			ASTNode consumerNode = ASTUnderConstruction.idToNode.get(fid);
			String cls = null;
			try { cls = consumerNode.getEnclosingClass(); } catch( Exception e ) {}
			if( cls == null || cls.isEmpty() ) continue;
			consumerKeys.put(cls+"::"+prop, new String[]{ hookKey, componentKey, methodKey });
		}

		// Step 4: link. For each producer, its OWN class + property must match a consumer.
		for( java.util.Map.Entry<String,String> pe : producerProperty.entrySet() ) {
			String producerId = pe.getKey();
			String prop = pe.getValue();
			String cls = producerId.contains("::") ? producerId.substring(0, producerId.indexOf("::")) : null;
			if( cls == null ) continue;
			String[] keys = consumerKeys.get(cls+"::"+prop);
			if( keys == null ) continue;
			java.util.Map<String,Integer> builderKeyToParam = builders.get(producerBuilder.get(producerId));
			java.util.Map<Integer,Integer> argMap = producerArgMap.get(producerId);
			if( builderKeyToParam == null || argMap == null ) continue;
			Integer hookBP = builderKeyToParam.get(keys[0]);
			Integer compBP = builderKeyToParam.get(keys[1]);
			Integer methBP = builderKeyToParam.get(keys[2]);
			if( hookBP == null || compBP == null || methBP == null ) continue;
			Integer hookPP = argMap.get(hookBP), compPP = argMap.get(compBP), methPP = argMap.get(methBP);
			if( hookPP == null || compPP == null || methPP == null ) continue;
			queueRegistrationWrappers.put(producerId, new QueuePattern(hookPP, compPP, methPP));
		}
	}

	private static String propertyNameOf(Expression e) {
		if( !(e instanceof ast.expressions.PropertyExpression) ) return null;
		ast.expressions.PropertyExpression pe = (ast.expressions.PropertyExpression)e;
		if( !"this".equals(varNameOf(pe.getObjectExpression())) ) return null;
		Expression prop = pe.getPropertyExpression();
		return ( prop instanceof StringExpression ) ? ((StringExpression)prop).getEscapedCodeStr() : null;
	}
	private static String dimKeyOfSameBase(Expression e) {
		if( !(e instanceof ast.expressions.ArrayIndexing) ) return null;
		Expression idx = ((ast.expressions.ArrayIndexing)e).getIndexExpression();
		return ( idx instanceof StringExpression ) ? ((StringExpression)idx).getEscapedCodeStr() : null;
	}
	private static String dimBaseVarName(Expression e) {
		if( !(e instanceof ast.expressions.ArrayIndexing) ) return null;
		return varNameOf(((ast.expressions.ArrayIndexing)e).getArrayExpression());
	}
	// FIX (2026-08-08): array-key-into-later-foreach-key taint propagation. Deliberately isolated
	// from valueIsTainted() itself rather than modified into it -- this is a narrower, coarser,
	// separately-verified addition specifically for the "foreach key variable used as a sink
	// argument" shape, not a general change to the widely-used core taint mechanism every other
	// sink class also depends on. Motivated by the real, confirmed remaining gap in Users manager
	// - PN (CVE-2026-4003), traced to source in an earlier round: the vulnerable key is built via
	// index-assignment in one loop ($arr[$taintedIdx] = $v;) and consumed via a SEPARATE, later
	// foreach's key variable ($k => $v over the same $arr), which plain value-assignment-chain
	// tracing does not connect.
	//
	// Deliberately coarse, not field-sensitive: if the array has ANY tainted-index-write
	// assignment anywhere in the enclosing function, its foreach key variable is treated as
	// tainted -- this does not attempt to prove that EVERY key the array could hold is
	// attacker-chosen, only that at least one demonstrably is. A false trigger here means an
	// extra REVIEW-tier finding requiring semantic disposition, not a confirmed vulnerability
	// claim; this session's architecture already reserves that disposition step for adjudication,
	// so a coarse-but-honest "possibly tainted" signal here is the correct tradeoff, not a
	// shortcut around it.
	private static boolean foreachKeyTaintedByArrayIndexWrite(Expression keyArg, Long fid) {
		try {
			String keyVarName = varNameOf(keyArg);
			if( keyVarName == null || fid == null ) return false;
			String baseArrayName = foreachIteratedArrayForKeyVar(keyArg.getNodeId(), keyVarName, fid);
			if( baseArrayName == null ) return false;
			// scan the enclosing function for $baseArrayName[TAINTED_INDEX] = ...;
			ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
			if( fn == null ) return false;
			java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>(); q.add(fid);
			java.util.Set<Long> seen = new HashSet<Long>(); int gg = 0;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				ASTNode xn = ASTUnderConstruction.idToNode.get(x);
				if( xn instanceof AssignmentExpression ) {
					Expression lhs = ((AssignmentExpression)xn).getLeft();
					if( lhs instanceof ast.expressions.ArrayIndexing ) {
						ast.expressions.ArrayIndexing ai = (ast.expressions.ArrayIndexing)lhs;
						Expression idx = ai.getIndexExpression();
						String base = varNameOf(ai.getArrayExpression());
						if( idx != null && baseArrayName.equals(base) ) {
							if( valueIsTainted(idx.getNodeId(), fid, varAssignsByFunc, 0) ) return true;
						}
					}
				}
				HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kk != null ) q.addAll(kk.values());
			}
			return false;
		} catch( Exception e ) { return false; }
	}

	// Walks up from a node to find the nearest enclosing AST_FOREACH whose KEY variable (not
	// value variable) matches keyVarName, and returns the base array name being iterated, or null.
	private static String foreachIteratedArrayForKeyVar(Long node, String keyVarName, Long fid) {
		try {
			Long cur = node; int g = 0;
			while( cur != null && g++ < 64 ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(cur);
				if( n != null && "AST_FOREACH".equals(n.getProperty("type")) ) {
					HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(cur);
					if( kids != null ) {
						// FIX: HashMap<Integer,Long>.values() does not preserve iteration order by
						// integer key -- must sort by key explicitly to get the correct
						// iter/key/value positional ordering. Caught by this fixture actually
						// failing, not assumed correct.
						java.util.List<Integer> sortedKeys = new java.util.ArrayList<Integer>(kids.keySet());
						java.util.Collections.sort(sortedKeys);
						java.util.List<Long> ordered = new java.util.ArrayList<Long>();
						for( Integer k : sortedKeys ) ordered.add(kids.get(k));
						// foreach ($iter as $key => $value) -- confirmed empirically (not assumed):
						// child order is [iter, VALUE, KEY, body] -- value at index 1, key at
						// index 2, the reverse of source-text order. A 2-child foreach
						// ($iter, $value only, no "as $key =>" form) has no key child at all.
						if( ordered.size() >= 3 ) {
							ASTNode iterN = ASTUnderConstruction.idToNode.get(ordered.get(0));
							ASTNode keyN = ASTUnderConstruction.idToNode.get(ordered.get(2));
							if( iterN instanceof Expression && keyN instanceof Expression
							    && keyVarName.equals(varNameOf((Expression)keyN)) ) {
								String base = varNameOf((Expression)iterN);
								if( base != null ) return base;
							}
						}
					}
				}
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
		} catch( Exception e ) {}
		return null;
	}

	private static String dimKeyIfBase(Expression e, String expectedBase) {
		if( !(e instanceof ast.expressions.ArrayIndexing) || expectedBase == null ) return null;
		if( !expectedBase.equals(varNameOf(((ast.expressions.ArrayIndexing)e).getArrayExpression())) ) return null;
		Expression idx = ((ast.expressions.ArrayIndexing)e).getIndexExpression();
		return ( idx instanceof StringExpression ) ? ((StringExpression)idx).getEscapedCodeStr() : null;
	}
	private static String enclosingForeachThisProperty(Long node, String loopVarName) {
		if( loopVarName == null ) return null;
		try {
			Long cur = node; int g = 0;
			while( cur != null && g++ < 64 ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(cur);
				if( n != null && "AST_FOREACH".equals(n.getProperty("type")) ) {
					HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(cur);
					if( kids != null ) {
						Expression iterExpr = null, valExpr = null;
						// FIX (2026-08-08): same bug as the sibling method foreachIteratedArrayForKeyVar()
						// just above, which already found and fixed this exact pattern with a fixture
						// that confirmed it actually failing, not assumed correct (see that method's
						// own comment). HashMap<Integer,Long>.values() does not preserve iteration
						// order by integer key -- must sort by key explicitly to get the correct
						// iter/value positional ordering. Applying the same, already-validated fix
						// pattern here. Direct adversarial reproduction attempted (a chained
						// producer/consumer fixture matching this method's real call shape) but not
						// achieved -- small, dense Integer keys happened to iterate in ascending
						// order on this JVM, same as the sibling required a specific fixture to
						// expose. Correctness relies on the sibling's own confirmed, documented proof
						// that this exact HashMap-ordering pattern manifests in real CSVs, not on a
						// fresh synthetic demonstration here.
						java.util.List<Integer> sortedKeys = new java.util.ArrayList<Integer>(kids.keySet());
						java.util.Collections.sort(sortedKeys);
						java.util.List<Long> ordered = new java.util.ArrayList<Long>();
						for( Integer k : sortedKeys ) ordered.add(kids.get(k));
						if( ordered.size() >= 2 ) {
							ASTNode a0 = ASTUnderConstruction.idToNode.get(ordered.get(0));
							ASTNode a1 = ASTUnderConstruction.idToNode.get(ordered.get(1));
							if( a0 instanceof Expression ) iterExpr = (Expression)a0;
							if( a1 instanceof Expression ) valExpr = (Expression)a1;
						}
						if( valExpr != null && loopVarName.equals(varNameOf(valExpr))
						    && iterExpr != null ) {
							String p = propertyNameOf(iterExpr);
							if( p != null ) return p;
						}
					}
				}
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
		} catch( Exception e ) {}
		return null;
	}

	private static void seedFromDeferredQueueCallSites(boolean publicOnly) {
		if( queueRegistrationWrappers == null || queueRegistrationWrappers.isEmpty() ) return;
		java.util.List<CallExpressionBase> allCalls = new java.util.ArrayList<CallExpressionBase>();
		allCalls.addAll(functionCalls);
		allCalls.addAll(nonStaticMethodCalls);
		allCalls.addAll(staticMethodCalls);
		for( CallExpressionBase call : allCalls ) {
			String callee = null;
			if( call instanceof StaticCallExpression ) callee = staticCallTargetName((StaticCallExpression)call);
			else if( call instanceof MethodCallExpression ) callee = instanceMethodCalleeName((MethodCallExpression)call);
			else callee = callTargetName(call);
			if( callee == null || !queueRegistrationWrappers.containsKey(callee) ) continue;
			QueuePattern pat = queueRegistrationWrappers.get(callee);
			ArgumentList al = call.getArgumentList();
			if( al == null ) continue;
			int maxIdx = Math.max(pat.hookParamIdx, Math.max(pat.componentParamIdx, pat.methodParamIdx));
			if( al.size() <= maxIdx ) continue;
			Expression hookArg = al.getArgument(pat.hookParamIdx);
			if( !(hookArg instanceof StringExpression) ) continue;
			String hookLiteral = ((StringExpression)hookArg).getEscapedCodeStr();
			String priv = classifyHook(hookLiteral);
			if( priv == null ) continue;
			if( publicOnly && priv.equals("authed") ) continue;
			Expression compArg = al.getArgument(pat.componentParamIdx);
			Expression methArg = al.getArgument(pat.methodParamIdx);
			if( !(methArg instanceof StringExpression) ) continue;
			String methodName = ((StringExpression)methArg).getEscapedCodeStr();
			String pinClass = null;
			if( compArg instanceof StringExpression ) pinClass = simpleClassName(((StringExpression)compArg).getEscapedCodeStr());
			else if( "this".equals(varNameOf(compArg)) ) {
				Long encFid = null; try { encFid = call.getFuncId(); } catch( Exception e ) {}
				ASTNode encFn = encFid == null ? null : ASTUnderConstruction.idToNode.get(encFid);
				if( encFn instanceof Method ) pinClass = simpleClassName(((Method)encFn).getEnclosingClass());
			}
			boolean any = false;
			if( pinClass != null ) {
				for( Long mid : allMtd ) {
					ASTNode n = ASTUnderConstruction.idToNode.get(mid);
					if( n instanceof Method && methodName.equals(((Method)n).getName())
					    && pinClass.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) ) {
						topFunIds.add(mid); entryPriv.put(mid, hookLiteral+":"+priv);
						System.err.println("WPENTRY ["+hookLiteral+":"+priv+"] method "+pinClass+"::"+methodName+" node "+mid+" (deferred-queue)");
						any = true;
					}
				}
			}
			if( !any ) registerCallbackAsEntry(methArg, hookLiteral+":"+priv);
		}
	}

	private static void detectRegistrationWrappers() {
		registrationWrappers = new HashMap<String,java.util.List<RegWrapperPattern>>();
		java.util.Map<Long,ParameterList> paramListByFid = new HashMap<Long,ParameterList>();
		PHPCGFactory.recordScanSite("PCG_5052", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( n instanceof FunctionDef ) {
				try { paramListByFid.put(n.getNodeId(), ((FunctionDef)n).getParameterList()); } catch( Exception e ) {}
			}
		}
		for( CallExpressionBase fc : functionCalls ) {
			if( !(fc.getTargetFunc() instanceof Identifier) ) continue;
			String callName = ((Identifier)fc.getTargetFunc()).getNameChild().getEscapedCodeStr();
			if( !callName.equals("add_action") && !callName.equals("add_filter") ) continue;
			ArgumentList args = fc.getArgumentList();
			if( args == null || args.size() < 2 ) continue;
			Long fid = null; try { fid = fc.getFuncId(); } catch( Exception e ) {}
			if( fid == null || !paramListByFid.containsKey(fid) ) continue;
			ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
			if( fn == null ) continue;
			java.util.Map<String,Integer> params = paramIndexMap(paramListByFid.get(fid));
			if( params.isEmpty() ) continue;
			Integer[] hookMatch = hookArgAsParamPattern(args.getArgument(0), params);
			if( hookMatch == null ) continue;
			int cbIdx = -1;
			String cbVn = varNameOf(args.getArgument(1));
			if( cbVn != null && params.containsKey(cbVn) ) cbIdx = params.get(cbVn);
			else continue;   // callback not forwarded directly -- out of scope for this pass
			String prefix = "";
			if( hookMatch[0] == 1 ) {
				Expression left = ((BinaryOperationExpression)args.getArgument(0)).getLeft();
				prefix = ((StringExpression)left).getEscapedCodeStr();
			}
			String wrapperName = funcIdentity(fid);
			if( wrapperName == null || "anonymous".equals(wrapperName) ) continue;
			if( !registrationWrappers.containsKey(wrapperName) )
				registrationWrappers.put(wrapperName, new java.util.ArrayList<RegWrapperPattern>());
			registrationWrappers.get(wrapperName).add(new RegWrapperPattern(prefix, hookMatch[1], cbIdx));
		}
	}

	// At each call site of a detected registration wrapper, resolve the literal hook-name
	// argument (prefix + the actual literal passed at that parameter position) and the callback
	// argument (the actual expression passed at that parameter position), then feed both directly
	// into the same classifyHook()/registerCallbackAsEntry() logic every other entry-point path
	// already uses -- not a new registration pipeline, the same one, fed from a new source.
	private static void seedFromRegistrationWrapperCallSites(boolean publicOnly) {
		if( registrationWrappers == null || registrationWrappers.isEmpty() ) return;
		java.util.List<CallExpressionBase> allCalls = new java.util.ArrayList<CallExpressionBase>();
		allCalls.addAll(functionCalls);
		allCalls.addAll(nonStaticMethodCalls);
		allCalls.addAll(staticMethodCalls);
		for( CallExpressionBase call : allCalls ) {
			String callee = null;
			if( call instanceof StaticCallExpression ) callee = staticCallTargetName((StaticCallExpression)call);
			else if( call instanceof MethodCallExpression ) callee = instanceMethodCalleeName((MethodCallExpression)call);
			else callee = callTargetName(call);
			if( callee == null || !registrationWrappers.containsKey(callee) ) continue;
			ArgumentList al = call.getArgumentList();
			if( al == null ) continue;
			for( RegWrapperPattern pat : registrationWrappers.get(callee) ) {
				if( al.size() <= pat.hookParamIdx || al.size() <= pat.cbParamIdx ) continue;
				Expression hookArgAtCallsite = al.getArgument(pat.hookParamIdx);
				if( !(hookArgAtCallsite instanceof StringExpression) ) continue;   // needs a literal to resolve
				String hookLiteral = pat.hookPrefix + ((StringExpression)hookArgAtCallsite).getEscapedCodeStr();
				String priv = classifyHook(hookLiteral);
				if( priv == null ) continue;
				if( publicOnly && priv.equals("authed") ) continue;
				Expression cb = al.getArgument(pat.cbParamIdx);
				if( cb instanceof StringExpression || cb instanceof ArrayExpression || cb instanceof CallExpressionBase )
					registerCallbackAsEntry(cb, hookLiteral+":"+priv);
			}
		}
	}

	// Best-effort instance-method call name resolution ($obj->method()) for registration-wrapper
	// matching only -- NOT a general receiver-type resolver. Matches by method name alone when the
	// method name is unique in the codebase (avoiding the harder, separate receiver-identity
	// problem PRIV_ESC_METHODS' own machinery exists for). A non-unique method name is left
	// unresolved rather than guessed at.
	private static java.util.Map<String,Integer> methodNameUniqueness = null;
	private static String instanceMethodCalleeName(MethodCallExpression mc) {
		if( !(mc.getTargetFunc() instanceof StringExpression) ) return null;
		String mname = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
		if( methodNameUniqueness == null ) {
			methodNameUniqueness = new HashMap<String,Integer>();
			for( java.util.Map.Entry<String,java.util.List<Method>> e : nonStaticMethodNameDefs.entrySet() )
				methodNameUniqueness.put(e.getKey(), e.getValue().size());
		}
		Integer count = methodNameUniqueness.get(mname);
		if( count == null || count != 1 ) return null;
		FunctionDef def = nonStaticMethodNameDefs.get(mname).get(0);
		Long fid = def.getNodeId();
		String cls = null;
		try { cls = def.getEnclosingClass(); } catch( Exception e ) {}
		return ( cls == null || cls.isEmpty() ) ? mname : cls + "::" + mname;
	}

	private static void seedWordPressEntryPoints() {
		boolean publicOnly = "public".equals(SEED_MODE);
		detectRegistrationWrappers();
		seedFromRegistrationWrapperCallSites(publicOnly);
		detectDeferredQueuePatterns();
		seedFromDeferredQueueCallSites(publicOnly);
		// (1) core function-call registrations: add_action(...) / add_filter(...) / register_rest_route(...)
		for(CallExpressionBase fc : functionCalls) {
			if( !(fc.getTargetFunc() instanceof Identifier) ) continue;
			String callName = ((Identifier)fc.getTargetFunc()).getNameChild().getEscapedCodeStr();
			ArgumentList args = fc.getArgumentList();
			if( args == null ) continue;
			if( (callName.equals("add_action") || callName.equals("add_filter")) && args.size() >= 2 )
				seedFromHookRegistration(args, publicOnly);
			else if( callName.equals("register_rest_route") && args.size() >= 3 )
				seedRestRoute(args.getArgument(2), publicOnly);
			// add_menu_page(page_title, menu_title, capability, menu_slug, callback, icon, position)
			// add_submenu_page(parent_slug, page_title, menu_title, capability, menu_slug, callback, position)
			// WordPress core's own admin-menu registration -- core never invokes the callback
			// unless the current user holds the given capability. Confirmed real via AIOWM's
			// entire admin UI: add_submenu_page('ai1wm_export', ..., 'ai1wm_import_site',
			// 'ai1wm_backups', 'Ai1wm_Backups_Controller::index'). Only literal-string capability
			// arguments are trusted (a dynamic/computed capability is left unclassified rather than
			// guessed); the callback argument is optional in core's own signature, so a missing or
			// non-literal-resolvable callback is simply not seeded, same as elsewhere in this file.
			else if( callName.equals("add_menu_page") && args.size() >= 5
					&& args.getArgument(2) instanceof StringExpression ) {
				String cap = ((StringExpression)args.getArgument(2)).getEscapedCodeStr();
				if( System.getenv("WP_MENU_TRACE") != null ) System.err.println("WPMENU_REGISTRATION call_node="+fc.getNodeId()+" function=add_menu_page capability_arg="+cap+" callback_kind="+(args.getArgument(4)!=null?args.getArgument(4).getClass().getSimpleName():"null"));
				if( !(publicOnly) ) registerCallbackAsEntry(args.getArgument(4), "authed:capability=" + cap);
			}
			else if( callName.equals("add_submenu_page") && args.size() >= 6
					&& args.getArgument(3) instanceof StringExpression ) {
				String cap = ((StringExpression)args.getArgument(3)).getEscapedCodeStr();
				if( System.getenv("WP_MENU_TRACE") != null ) System.err.println("WPMENU_REGISTRATION call_node="+fc.getNodeId()+" function=add_submenu_page capability_arg="+cap+" callback_kind="+(args.getArgument(5)!=null?args.getArgument(5).getClass().getSimpleName():"null"));
				if( !(publicOnly) ) registerCallbackAsEntry(args.getArgument(5), "authed:capability=" + cap);
			}
			else if( callName.equals("add_submenu_page") && System.getenv("WP_MENU_TRACE") != null ) {
				System.err.println("WPMENU_REGISTRATION call_node="+fc.getNodeId()+" function=add_submenu_page reject_reason=argshape_mismatch args_size="+args.size()
					+ (args.size() > 3 ? " capability_arg_type="+args.getArgument(3).getClass().getSimpleName() : ""));
			}
			// Shortcode callbacks render inside post content authored by contributor-level users,
			// so their attributes and any contributor-set post meta they echo are a stored-XSS
			// vector. Seed the callback as an entry so its source->output flows are analyzed.
			else if( callName.equals("add_shortcode") && args.size() >= 2 ) {
				seedShortcodeCallback(args.getArgument(1));
				addShortcodeReturnSinks(args.getArgument(1));
			}
			// su_add_shortcode($data) — Shortcodes Ultimate's wrapper. $data is an array with
			// 'callback' key holding the handler. Also covers similar wrapper conventions.
			else if( callName.equals("su_add_shortcode") && args.size() >= 1 ) {
				Expression data = args.getArgument(0);
				if( data instanceof ArrayExpression ) {
					for( ArrayElement el : (ArrayExpression)data ) {
						if( !(el.getKey() instanceof StringExpression) ) continue;
						if( !"callback".equals(((StringExpression)el.getKey()).getEscapedCodeStr()) ) continue;
						if( el.getValue() != null ) {
							seedShortcodeCallback(el.getValue());
							addShortcodeReturnSinks(el.getValue());
						}
					}
				}
			}
		}
		// (2) wrapper registrations via instance method: $this->loader->add_action(...) etc.
		for(MethodCallExpression mc : nonStaticMethodCalls) {
			if( mc.getTargetFunc() instanceof StringExpression ) {
				String m = ((StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
				if( m.equals("add_action") || m.equals("add_filter") )
					seedFromHookRegistration(mc.getArgumentList(), publicOnly);
				else if( m.equals("register_rest_route") && mc.getArgumentList()!=null && mc.getArgumentList().size()>=3 )
					seedRestRoute(mc.getArgumentList().getArgument(2), publicOnly);
				else if( m.equals("add_shortcode") && mc.getArgumentList()!=null && mc.getArgumentList().size()>=2 ) {
					seedShortcodeCallback(mc.getArgumentList().getArgument(1));
					addShortcodeReturnSinks(mc.getArgumentList().getArgument(1));
				}
			}
		}
		// (3) wrapper registrations via static method: Hook_Registry::add_action(...) etc.
		for(StaticCallExpression sc : staticMethodCalls) {
			if( sc.getTargetFunc() instanceof StringExpression ) {
				String m = ((StringExpression)sc.getTargetFunc()).getEscapedCodeStr();
				if( m.equals("add_action") || m.equals("add_filter") )
					seedFromHookRegistration(sc.getArgumentList(), publicOnly);
				else if( m.equals("register_rest_route") && sc.getArgumentList()!=null && sc.getArgumentList().size()>=3 )
					seedRestRoute(sc.getArgumentList().getArgument(2), publicOnly);
				else
					seedCustomRouterVerb(sc, m, publicOnly);
			}
		}
		// (4) Hook-registration methods: OOP plugins (WPForms, GiveWP, LearnPress, etc.) put
		// their add_action/add_filter calls inside a method named hooks(), register_hooks(),
		// init_hooks(), setup_hooks(), register(), or boot() that is only invoked after class
		// instantiation. The top-level scanner (passes 1-3) sees those add_action calls in
		// functionCalls but they are scoped to the class method's funcId, so they are silently
		// skipped — the method is never traversed at top level. Fix: find every method whose
		// name matches the hook-registration convention, then process the add_action/add_filter
		// calls scoped to that method's funcId, exactly as if they appeared at file scope.
		java.util.Set<String> HOOK_METHOD_NAMES = new java.util.HashSet<>(java.util.Arrays.asList(
			"hooks", "register_hooks", "init_hooks", "setup_hooks", "add_hooks",
			"define_hooks", "define_public_hooks", "define_admin_hooks",
			"register", "boot", "init", "load", "setup", "configure"
		));
		// FIX (2026-08-08): removed unconditional System.err.println debug output that fired once
		// per matching method name -- unlike every other diagnostic print in this file (WP_STORED_
		// DEBUG, WP_RETURNSINK_DEBUG, etc.), these were not gated behind any env flag, so every
		// production scan printed a line for every method anywhere in the plugin coincidentally
		// named one of these fairly generic names (init, load, setup, configure, register, boot),
		// regardless of whether it was actually a WordPress hook-registration method. The
        // underlying state (hookMethodFids, a deduplicating Set) and the actual seeding behavior
        // built from it were unaffected either way -- this was pure, ungated log volume with no
        // functional consequence, safe to remove outright.
		java.util.Set<Long> hookMethodFids = new java.util.HashSet<>();
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof Method ) {
				String mname = ((Method)n).getName();
				if( mname != null && HOOK_METHOD_NAMES.contains(mname) ) {
					hookMethodFids.add(mid);
				}
			}
		}
		for( Long mid : allStaticMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof Method ) {
				String mname = ((Method)n).getName();
				if( mname != null && HOOK_METHOD_NAMES.contains(mname) ) {
					hookMethodFids.add(mid);
				}
			}
		}
		if( !hookMethodFids.isEmpty() ) {
			int hookMethodCalls = 0;
			for( CallExpressionBase fc : functionCalls ) {
				Long fid = fc.getFuncId();
				if( fid == null || !hookMethodFids.contains(fid) ) continue;
				if( !(fc.getTargetFunc() instanceof Identifier) ) continue;
				String callName = ((Identifier)fc.getTargetFunc()).getNameChild() == null ? null
					: ((Identifier)fc.getTargetFunc()).getNameChild().getEscapedCodeStr();
				if( callName == null ) continue;
				ArgumentList args = fc.getArgumentList();
				if( args == null ) continue;
				if( (callName.equals("add_action") || callName.equals("add_filter")) && args.size() >= 2 ) {
					seedFromHookRegistration(args, publicOnly);
					hookMethodCalls++;
				} else if( callName.equals("register_rest_route") && args.size() >= 3 ) {
					seedRestRoute(args.getArgument(2), publicOnly);
					hookMethodCalls++;
				} else if( callName.equals("add_shortcode") && args.size() >= 2 ) {
					seedShortcodeCallback(args.getArgument(1));
					addShortcodeReturnSinks(args.getArgument(1));
					hookMethodCalls++;
				}
			}
		}
	}

	// Seed self-contained request handlers: any function/method/constructor whose body
	// holds BOTH a superglobal read and a $wpdb sink. WordPress reaches such routines
	// through admin-page routing, top-level `new`, and file includes the hook scanner
	// cannot see (e.g. CVE-2021-24340's pages_page::__construct, invoked by a top-level
	// `new pages_page;`). Seeding surfaces a finding only when the intra-routine
	// source->sink flow is actually unsanitized, so the precision cost is bounded.
	private static void seedSelfContainedHandlers() {
		// In public-only mode we must not seed privilege-agnostic handlers: a self-contained
		// routine (superglobal + sink) is typically reached via admin-page routing, so seeding
		// it would let an admin-only flow masquerade as publicly reachable.
		if( "public".equals(SEED_MODE) ) return;
		java.util.Set<Long> funcsWithSink = new java.util.HashSet<Long>();
		for( Long sinkId : sinks ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(sinkId);
			if( n != null ) funcsWithSink.add(n.getFuncId());
		}
		for( Long srcId : PHPCSVEdgeInterpreter.sources ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(srcId);
			if( n == null ) continue;
			Long fid = n.getFuncId();
			if( fid == null || topFunIds.contains(fid) ) continue;
			if( funcsWithSink.contains(fid)
				&& (allMtd.contains(fid) || allFunc.contains(fid) || allConstructor.contains(fid)) ) {
				topFunIds.add(fid);
				reasonSelfContainedHandler.add(fid);
				System.err.println("WPENTRY self-contained handler node "+fid);
			}
		}
	}

	// ---- Query-wrapper sink modeling (thin DB wrappers) -----------------------
	// Forward taint into a callee is recognized when a parameter is used in an expression
	// at the sink, but NOT when the parameter is passed BARE as the sink argument — the
	// common wrapper shape  function q($sql){ $wpdb->query($sql); }. We model such wrappers
	// as sinks: a function that passes a parameter (or a param-derived local — covering
	// $p=(object)['sql'=>$sql]; $wpdb->query($p->sql) ) into a $wpdb sink WITHOUT an
	// intervening sanitizer is a wrapper, and CALLS to it become sinks so a tainted argument
	// is reported at the call site. Method wrappers are class-qualified to avoid matching
	// unrelated methods that happen to share a common name (e.g. query/get_results).

	// Variable names in a subtree, NOT descending into sanitizer calls (prepare/esc_sql/...),
	// whose arguments are already neutralized and therefore do not make a function a wrapper.
	private static void collectUnsanitizedVarNames(ASTNode n, Set<String> out) {
		if( n == null ) return;
		if( System.getenv("WP_CUVN_DIAG") != null && n instanceof CallExpressionBase ) {
			String dcn = callTargetName((CallExpressionBase)n);
			System.err.println("CUVN_DIAG call cn=" + dcn + " node=" + n.getNodeId());
		}
		if( n instanceof MethodCallExpression ) {
			Expression tf = ((MethodCallExpression)n).getTargetFunc();
			if( tf instanceof StringExpression && "prepare".equals(((StringExpression)tf).getEscapedCodeStr()) ) return;
		}
		// NOTE: deliberately NOT "else if" -- MethodCallExpression extends CallExpressionBase, so a
		// method/static call (self::markup(...), $this->get_output(...), Breadcrumbs::get()->x(...))
		// matches BOTH checks. It must fall through into this block too, or none of the logic below
		// (repairs/escaper recognition, apply_filters scoping, interprocedural summary consultation)
		// ever applies to method calls -- which is most of what real plugin code actually uses. This
        // was caught by direct instrumentation before it shipped: RankMath's four flagged findings
        // are ALL method/static calls (self::markup, $this->get_output, Breadcrumbs::get()->...).
		if( n instanceof CallExpressionBase ) {
			String cn = callTargetName((CallExpressionBase)n);
			// repairs = SQL/type-coercion sanitizers (esc_sql, intval, absint, ...). isXssOutputEscaper
			// = WP HTML/output escapers (esc_html, wp_kses_post, ...), already defined and used
			// elsewhere in this file (line 6613) for exactly this purpose, but never previously
			// consulted here. Without this second check, a value wrapped in a real, recognized
			// output escaper (e.g. wp_kses_post(join("\n", $out))) still had its inner raw
			// variable ($out) walked into and collected as "unsanitized" -- the SQL-only repairs
			// check let SQL-sanitized values through but not XSS-sanitized ones, so this function's
			// notion of "sanitized" was systematically narrower than the engine's own recognized
			// escaper vocabulary. This was the actual blocker on RankMath's Block_FAQ::markup()
			// finding surviving the apply_filters argument-scoping fix above: that fix correctly
			// isolated argument index 1, but argument index 1 itself was still being walked into.
			if( cn != null && (PHPCSVEdgeInterpreter.repairs.contains(cn) || isXssOutputEscaper(cn)) ) return;
			// apply_filters(tag, value, ...extra_context) -- only argument index 1 is what the
			// function actually returns (absent a filter callback overriding it); args 2+ are
			// WordPress's own convention for passing extra context to registered filter
			// callbacks, never part of the return value. Mirrors the identical, already-proven
			// precedent in capArgIsManagement() (lines 567-573, used for capability-check
			// guard-pass-through detection) -- ported here for return-taint-summary purposes.
			if( "apply_filters".equals(cn) || "apply_filters_deprecated".equals(cn) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() >= 2 ) { collectUnsanitizedVarNames(al.getArgument(1), out); return; }
			}
			// apply_filters_ref_array(tag, array(value, ...extra_context)) -- the array-taking
			// sibling of apply_filters, real WordPress core API, same "only the first value
			// matters" semantics but the value sits at element 0 of the SECOND argument's array,
			// not at argument index 1 directly. Only handles a literal array expression -- a
			// non-literal args expression (e.g. built via array_merge(), as plugin-specific
			// do_filter()-style wrappers commonly do) can't have "element 0" picked out
			// statically without evaluating it, so that case falls through to the existing
			// conservative generic recursion below, unchanged.
			if( "apply_filters_ref_array".equals(cn) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() >= 2 && al.getArgument(1) instanceof ArrayExpression ) {
					ArrayExpression ae = (ArrayExpression) al.getArgument(1);
					if( ae.size() == 0 ) return;   // empty array -- no value at all to be unsanitized
					collectUnsanitizedVarNames(ae.getArrayElement(0).getValue(), out);
					return;
				}
			}
			// do_filter(tag_suffix, value, ...extra_context): a plugin-specific (RankMath) wrapper
			// observed delegating to apply_filters_ref_array(), but with the EXACT SAME
			// caller-facing calling convention as apply_filters() itself -- argument index 1 is
			// the value, the rest is context. Confirmed by reading its own implementation
			// (includes/traits/class-hooker.php): do_filter($suffix, $value, ...$context) unsets
			// arg 0 and forwards the rest to apply_filters_ref_array() positionally, preserving
			// order, so the caller-side shape matches apply_filters's exactly even though the
			// callee-side plumbing (variadic capture + unset + array_merge) is too
			// PHP-mechanics-heavy to trace generically. This is the same noise class already
			// documented for security-check wrappers (GiveWP/WPForms) -- a custom wrapper hiding
			// a recognized WordPress calling convention -- just against apply_filters-argument
			// scoping instead. Named narrowly (this exact method name) rather than attempting a
			// general "trace any wrapper's body" mechanism, matching this codebase's existing
			// convention of specific, real-plugin-motivated special cases (wp-optimize,
			// ultimate-member, rsvpmaker are all named directly elsewhere in this file).
			if( "do_filter".equals(cn) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() >= 2 ) { collectUnsanitizedVarNames(al.getArgument(1), out); return; }
			}
			// Interprocedural return-summary consultation: if this call resolves (via the already-
			// built call graph, call2mtd) to first-party function(s) whose OWN return-taint summary
			// has already been computed, use that summary to decide which argument POSITIONS can
			// actually contribute to what this call returns, instead of walking every argument
			// indiscriminately. Fail-closed on every ambiguity, matching the existing philosophy
			// throughout this function: unresolved call, no resolved target, any resolved target not
			// yet analyzed, or an untraceable argument list -- all fall through to the pre-existing
			// generic recursion below, which is always at least as conservative as this branch.
			List<Long> targets = call2mtd.get(n.getNodeId());
			if( targets != null && !targets.isEmpty() ) {
				boolean allAnalyzed = true;
				Set<Integer> unionPositions = new HashSet<Integer>();
				for( Long t : targets ) {
					if( !returnTaintConsultAnalyzed.contains(t) ) { allAnalyzed = false; break; }
					Set<Integer> p = returnTaintConsultPositions.get(t);
					if( p != null ) unionPositions.addAll(p);
				}
				if( allAnalyzed ) {
					ArgumentList al = ((CallExpressionBase)n).getArgumentList();
					if( al == null ) return;   // no arguments at all -- nothing to walk, and a
					                            // resolved+analyzed callee with no positions means safe
					if( unionPositions.isEmpty() ) return;   // analyzed: return never depends on any arg
					for( Integer pidx : unionPositions ) {
						if( pidx >= 0 && pidx < al.size() ) collectUnsanitizedVarNames(al.getArgument(pidx), out);
					}
					return;
				}
				// else: at least one resolved target isn't analyzed yet (or never will be) -- fall
				// through to the generic recursion below, exactly as before this change.
			}
		}
		if( n instanceof ast.expressions.ConditionalExpression ) {
			// Conditional value = its arms, not its condition (control-dependence, not data flow).
			// A ternary whose arms are constant literals (cond($_GET) ? 'DESC' : 'ASC') is a constant
			// regardless of how tainted the condition is. Short ternary (a ?: c) keeps the condition,
			// which is the value when truthy.
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
			Expression t = ce.getTrueExpression();
			if( t != null ) collectUnsanitizedVarNames(t, out);
			else collectUnsanitizedVarNames(ce.getCondition(), out);
			collectUnsanitizedVarNames(ce.getFalseExpression(), out);
			return;
		}
		if( n instanceof Variable && ((Variable)n).getNameExpression() instanceof StringExpression ) {
			out.add(((StringExpression)((Variable)n).getNameExpression()).getEscapedCodeStr());
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() ) collectUnsanitizedVarNames(ASTUnderConstruction.idToNode.get(c), out);
	}

	// --- placeholder-string recognition (prepare() format-safety refinement) ---------------------
	// The "$ph = implode(',', array_fill(0, count($x), '%d'))" IN-clause idiom builds a string that
	// is ONLY printf placeholders ("%d,%d,%d") — a parameterization template, never attacker data.
	// Interpolating such a var into a prepare() FORMAT must NOT make the format "unsafe" (it was the
	// dominant false positive: well-written plugins use this for IN clauses). We collect the names of
	// such locals PER ENCLOSING FUNCTION so a same-named tainted var elsewhere is never suppressed.
	private static Long enclosingFunctionId(Long node) {
		Long cur = node; int g = 0;
		while( cur != null && g++ < 8192 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			if( n instanceof FunctionDefBase ) return cur;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return null;
	}
	private static boolean isPlaceholderLiteral(String s) {
		if( s == null ) return false;
		String t = s.replaceAll("['\"]", "").trim();
		return t.matches("(%[dsifFxXeEgGbcu],?\\s*)+");   // "%d" / "%d," / "%s,%s" / ...
	}
	private static boolean subtreeHasPlaceholderFill(ASTNode n) {
		if( n == null ) return false;
		if( n instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)n).getTargetFunc();
			String nm = (tf instanceof Identifier && ((Identifier)tf).getNameChild()!=null)
					? ((Identifier)tf).getNameChild().getEscapedCodeStr() : null;
			if( "array_fill".equals(nm) || "str_repeat".equals(nm) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null ) for( int i=0; i<al.size(); i++ ) {
					Expression a = al.getArgument(i);
					if( a instanceof StringExpression && isPlaceholderLiteral(((StringExpression)a).getEscapedCodeStr()) )
						return true;
				}
			}
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() )
			if( subtreeHasPlaceholderFill(ASTUnderConstruction.idToNode.get(c)) ) return true;
		return false;
	}
	private static void collectPlaceholderVars(Long funcNode, Set<String> out) {
		if( funcNode == null ) return;
		java.util.ArrayDeque<Long> stack = new java.util.ArrayDeque<Long>();
		stack.push(funcNode);
		int guard = 0;
		while( !stack.isEmpty() && guard++ < 400000 ) {
			Long id = stack.pop();
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( n == null ) continue;
			if( n instanceof AssignmentExpression ) {
				AssignmentExpression as = (AssignmentExpression)n;
				if( as.getLeft() instanceof Variable
						&& ((Variable)as.getLeft()).getNameExpression() instanceof StringExpression
						&& subtreeHasPlaceholderFill(as.getRight()) ) {
					out.add(((StringExpression)((Variable)as.getLeft()).getNameExpression()).getEscapedCodeStr());
				}
			}
			if( id.equals(funcNode) || !(n instanceof FunctionDefBase) ) {   // stay within this function
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
				if( kids != null ) for( Long c : kids.values() ) stack.push(c);
			}
		}
	}

	// SAFE-ARGUMENT SUPPRESSOR. A $wpdb / mysql_query SQL sink whose query string
	// interpolates NOTHING that can carry attacker data is not a vulnerability and
	// should not be a sink (it otherwise produces false positives that drown the real
	// signal). collectUnsanitizedVarNames already skips into prepare()/esc_sql/intval/
	// absint (the SQL "repairs") subtrees, so the variable set it returns for a provably
	// safe query is at most {"wpdb"} — i.e. the only interpolated things are $wpdb->prefix
	// / $wpdb->postmeta style table-name properties, string literals, and sanitizer-wrapped
	// casts. Anything else (a request var, a plain local like $where/$quiz_id, a function
	// param) leaves a non-"wpdb" name in the set and keeps the sink. This is deliberately
	// one-directional: we suppress ONLY when we can prove every component safe, so it can
	// never introduce a false negative (e.g. $wpdb->query("... '$id'") with $id=intval(...)
	// is conservatively KEPT, because $id is a non-wpdb name). DB-originated values are
	// intentionally NOT treated as safe here: blanket-trusting prior DB reads would defeat
	// stored / second-order taint detection.
	// Enum/whitelist validation: a variable that is BOTH compared against a string literal
	// (==, !=, ===, !==, or in_array($v, ...)) AND assigned a constant (string literal or a
	// bare const like FALSE/NULL) within the same function is constrained to a constant set on
	// the path a developer guards — the "validate against an allow-list, else default" idiom
	// (e.g. ORDER BY restricted to ASC/DESC, or a table-name whitelist with a FALSE fallback).
	// Such a value cannot carry SQL injection, so it is treated as safe at the suppressor.
	// Conservative by construction: neither a bare comparison nor a bare constant assignment
	// qualifies alone — only their conjunction, which matches the guard idiom while leaving
	// genuinely unguarded uses (no comparison at all) flagged.
	private static HashMap<Long, Set<String>> enumValidatedByFunc = null;
	// Per-function variable -> list of RHS expressions assigned to it. Lets the suppressor follow
	// an indirect chain ($query = $query_base.'...'; $query_base = "...{$table}") back to a root
	// that is enum/whitelist-validated, instead of only inspecting the sink's direct argument.
	private static HashMap<Long, HashMap<String, java.util.List<ASTNode>>> varAssignsByFunc = null;

	// Defect 3 fix: property-to-request-origin map built by buildPropRequestOrigins().
	// Maps property identity string (e.g. "ClassId::sql_order") to the set of request-superglobal
	// source nodes ($_POST/$_GET/...) that can reach that property through local variable chains.
	// Populated once before the taint analysis runs; consulted at vulSources.add time in
	// StaticAnalysis to emit the superglobal as an ADDITIONAL Vul Source alongside the AST_PROP.
	public static HashMap<String, Set<Long>> propRequestOrigins = new HashMap<String, Set<Long>>();

	// Defect 2 fix: property identities that are ONLY ever written from $wpdb->prepare()
	// return values. Such properties carry parameterized/escaped SQL — the stored value is
	// safe to use in further queries. Populated in buildPropRequestOrigins().
	// StaticAnalysis excludes these from srcPropSet so they are never seeded as stored-taint sources.
	public static Set<String> safePrepareProps = new HashSet<String>();

	// Build the propRequestOrigins map:
	// For each property write in dstProp, follow the RHS variables through varAssignsByFunc
	// (up to MAX_HOP hops) to find if any upstream assignment reads a request superglobal.
	// A "request superglobal" is any node in srcGlobalVar or srcDim that appears in the
	// same function's varAssignsByFunc chain.
	public static void buildPropRequestOrigins() {
		if( varAssignsByFunc == null ) computeEnumValidated();   // ensure varAssignsByFunc is ready
		propRequestOrigins.clear();
		// Skip on very large plugins: the property backtracking is O(dstProp × varAssignsByFunc).
		// With 2500+ dstProp entries the map-build itself times out. Stored-taint findings on
		// large plugins are caught by the taint analysis directly; the adjudicator's text-scan
		// fallback (_trace_property_construction) covers the chain display side.
		if( ASTUnderConstruction.idToNode.size() > 750_000 ) {
			System.err.println("PROP_ORIGIN_SKIP large AST ("+ASTUnderConstruction.idToNode.size()+" nodes)");
			return;
		}
		final int MAX_HOP = 5;
		// Build: funcId → varName → Set<Long> (request source nodes that reach that var)
		// Derived from srcGlobalVar (srcGlobal in StaticAnalysis is the raw superglobal node;
		// here we use the already-computed per-stmt srcGlobal data in StaticAnalysis).
		// srcGlobal maps stmt → [superglobal_expr_nodes]; stmt is the stmt where $_POST is READ.
		// We need: for each local var assigned from a superglobal, which source node is it?
		// Use StaticAnalysis.srcGlobal + StaticAnalysis.srcStmt to find request origins by var.
		// Simpler: build funcId → varName → [request_nodes] by scanning varAssignsByFunc
		// for vars whose RHS contains a superglobal ArrayIndexing node.
		HashMap<Long, HashMap<String, Set<Long>>> funcVarRequestOrigins = new HashMap<>();
		for( java.util.Map.Entry<Long, HashMap<String, java.util.List<ASTNode>>> fe : varAssignsByFunc.entrySet() ) {
			Long fid = fe.getKey();
			for( java.util.Map.Entry<String, java.util.List<ASTNode>> ve : fe.getValue().entrySet() ) {
				String varName = ve.getKey();
				for( ASTNode rhs : ve.getValue() ) {
					Set<Long> reqNodes = new HashSet<Long>();
					collectRequestNodes(rhs, reqNodes);
						if( !reqNodes.isEmpty() ) {
						funcVarRequestOrigins.computeIfAbsent(fid, k -> new HashMap<>())
							.computeIfAbsent(varName, k -> new HashSet<>()).addAll(reqNodes);
					}
				}
			}
		}
		// Now: for each property write in dstProp, follow the RHS var chain to request nodes.
		int debugCnt=0;
		for( java.util.Map.Entry<Long, List<Long>> dpE : tools.php.ast2cpg.StaticAnalysis.dstProp.entrySet() ) {
			Long wstmt = dpE.getKey();
			Long fid = null;
			try { ASTNode wn = ASTUnderConstruction.idToNode.get(wstmt); if(wn!=null) fid = wn.getFuncId(); } catch(Exception e) {}
			HashMap<String, Set<Long>> funcVarMap = (fid != null) ? funcVarRequestOrigins.get(fid) : null;
			// Get the assignment RHS for this write stmt — use parent2child to find the AST_ASSIGN's RHS
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(wstmt);
			ASTNode rhs = null;
			if( kids != null ) { Long rk = kids.get(1); if(rk!=null) rhs = ASTUnderConstruction.idToNode.get(rk); }
			if( rhs == null ) continue;
			// Defect 2 fix: if the RHS is $wpdb->prepare(...), the stored value is parameterized/safe.
			// Record those property identities in safePrepareProps so StaticAnalysis won't seed them
			// as stored-taint sources (preventing the false-positive path: value → prepare → stored prop → sink).
			if( rhs instanceof MethodCallExpression ) {
				Expression tf = ((MethodCallExpression)rhs).getTargetFunc();
				if( tf instanceof StringExpression && "prepare".equals(((StringExpression)tf).getEscapedCodeStr()) ) {
					for( Long wprop : dpE.getValue() ) {
						ASTNode wnode = ASTUnderConstruction.idToNode.get(wprop);
						if( wnode == null ) continue;
						String iden = getPropIdenForPHPCG(wnode);
						if( iden != null && !iden.startsWith("-1::") ) {
							safePrepareProps.add(iden);
							System.err.println("SAFE_PREPARE_PROP "+iden);
						}
					}
					continue;  // skip request-origin tracking for prepare() writes
				}
			}
			if( funcVarMap == null ) continue;
			// Collect vars used in the RHS (what's interpolated into the property write's RHS)
			Set<String> rhsVars = new HashSet<String>();
			collectSqlRiskNames(rhs, rhsVars);   // reuse collectSqlRiskNames for var extraction
			// BFS through rhsVars → funcVarMap to find request origins
			Set<Long> origins = new HashSet<Long>();
			java.util.ArrayDeque<String> work = new java.util.ArrayDeque<>(rhsVars);
			Set<String> seen = new HashSet<>();
			int guard = 0;
			while( !work.isEmpty() && guard++ < MAX_HOP * 5 ) {
				String v = work.poll();
				if( v == null || !seen.add(v) ) continue;
				Set<Long> ro = funcVarMap.get(v);
				if( ro != null ) { origins.addAll(ro); continue; }
				// Follow further: if v is assigned from other vars, recurse
				HashMap<String, java.util.List<ASTNode>> assigns = varAssignsByFunc.get(fid);
				if( assigns == null || !assigns.containsKey(v) ) continue;
				for( ASTNode r2 : assigns.get(v) ) {
					Set<String> sub = new HashSet<>();
					collectSqlRiskNames(r2, sub);
					work.addAll(sub);
				}
			}
			if( origins.isEmpty() ) continue;
			// Associate found origins with each property written at this stmt
			for( Long wprop : dpE.getValue() ) {
				ASTNode wnode = ASTUnderConstruction.idToNode.get(wprop);
				if( wnode == null ) continue;
				String iden = getPropIdenForPHPCG(wnode);
				if( iden == null || iden.startsWith("-1::") ) continue;
				propRequestOrigins.computeIfAbsent(iden, k -> new HashSet<>()).addAll(origins);
				System.err.println("PROP_ORIGIN "+iden+" <- "+origins.size()+" request nodes");
			}
		}
		System.err.println("PROP_ORIGIN_MAP built: "+propRequestOrigins.size()+" entries (funcVarRequestOrigins="+funcVarRequestOrigins.size()+" dstProp="+tools.php.ast2cpg.StaticAnalysis.dstProp.size()+")");
		// Second pass: catch array-push writes ($this->prop[] = $wpdb->prepare(...)) that are
		// mis-classified into srcProp (not dstProp) because the LHS is AST_DIM(prop, null)
		// rather than AST_PROP directly. Iterate srcProp to find stmts whose RHS is prepare()
		// and whose stmt is an AssignmentExpression — those are really writes, not reads.
		for( java.util.Map.Entry<Long, List<Long>> spE : tools.php.ast2cpg.StaticAnalysis.srcProp.entrySet() ) {
			Long sstmt = spE.getKey();
			ASTNode sn = ASTUnderConstruction.idToNode.get(sstmt);
			if( !(sn instanceof AssignmentExpression) ) continue;
			HashMap<Integer,Long> sk = PHPCSVEdgeInterpreter.parent2child.get(sstmt);
			if( sk == null ) continue;
			Long rk = sk.get(1); if( rk == null ) continue;
			ASTNode srhs = ASTUnderConstruction.idToNode.get(rk);
			if( !(srhs instanceof MethodCallExpression) ) continue;
			Expression stf = ((MethodCallExpression)srhs).getTargetFunc();
			if( !(stf instanceof StringExpression) || !"prepare".equals(((StringExpression)stf).getEscapedCodeStr()) ) continue;
			// RHS is prepare() and stmt is an assignment — prop on srcProp side is actually a write
			for( Long sprop : spE.getValue() ) {
				ASTNode spnode = ASTUnderConstruction.idToNode.get(sprop);
				if( spnode == null ) continue;
				String siden = getPropIdenForPHPCG(spnode);
				if( siden != null && !siden.startsWith("-1::") ) {
					safePrepareProps.add(siden);
					System.err.println("SAFE_PREPARE_PROP_SRCSIDE "+siden);
				}
			}
		}

	}
	// Collect all ArrayIndexing nodes whose base is a superglobal ($_POST/$_GET/etc.)
	// and return their node IDs. These are the "request origin" nodes for a given expression.
	private static void collectRequestNodes(ASTNode n, Set<Long> out) {
		if( n == null ) return;
		if( n instanceof ArrayIndexing ) {
			Expression base = ((ArrayIndexing)n).getArrayExpression();
			if( base instanceof Variable ) {
				String bn = varNameOf(base);
				if( bn != null && (bn.equals("_POST") || bn.equals("_GET") ||
				    bn.equals("_REQUEST") || bn.equals("_COOKIE") || bn.equals("_SERVER")) ) {
					out.add(n.getNodeId());
					return;
				}
			}
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() ) {
			ASTNode cn = ASTUnderConstruction.idToNode.get(c);
			if( cn != null ) collectRequestNodes(cn, out);
		}
	}

	// Simplified property identity extractor for use within PHPCGFactory.
	// StaticAnalysis.getPropIdentity is a non-static instance method — not callable here.
	// Returns "classname::propName" from an AST_PROP node's metadata.

	// True if `clsId`'s declared ancestor chain mentions WP_User (by NAME, so it works even though
	// WP_User is WordPress core and therefore absent from the analysed AST). Used to keep priv_esc
	// method sinks on plugin classes that subclass WP_User and override set_role/add_cap.
	private static boolean classChainMentionsWpUser(Long clsId, java.util.Set<Long> seen, int depth) {
		if( clsId == null || clsId == -1L || depth > 8 ) return false;
		if( seen == null ) seen = new HashSet<Long>();
		if( !seen.add(clsId) ) return false;
		java.util.List<Long> prtNodes = inhe.get(clsId);
		if( prtNodes == null ) return false;
		for( Long prt : prtNodes ) {
			try {
				ASTNode pn = ASTUnderConstruction.idToNode.get(prt);
				if( !(pn instanceof Identifier) ) continue;
				String pname = ((Identifier)pn).getNameChild().getEscapedCodeStr();
				if( pname == null ) continue;
				String bare = pname.substring(pname.lastIndexOf('\\')+1);
				if( "WP_User".equalsIgnoreCase(bare) || "WP_Role".equalsIgnoreCase(bare)
				    || "WP_Roles".equalsIgnoreCase(bare) ) return true;
				ASTNode cn = ASTUnderConstruction.idToNode.get(clsId);
				String ns = (cn != null) ? cn.getEnclosingNamespace() : null;
				Long pid = getClassId(bare, prt, ns);
				if( pid != null && pid != -1L && classChainMentionsWpUser(pid, seen, depth+1) ) return true;
			} catch( Exception e ) { /* unresolvable parent -> treat as not-proven, caller keeps sink */ }
		}
		return false;
	}

	// A priv_esc METHOD sink (set_role/add_cap/...) is only suppressible when we can PROVE the call
	// targets a plugin-defined method on a class unrelated to WP_User. WP_User is core and never in
	// the AST, so a genuine $user->set_role() never resolves through call2mtd — an unresolved call
	// is therefore kept. This is suppress-on-proof-only: every uncertain case stays a sink (FN-free).
	// Motivating FP: import-users-from-csv-with-meta 2.4.9 `$exporter->set_role($_POST['role'])`,
	// which is a CSV export query filter, not a privilege assignment.
	private static boolean privEscMethodProvablyNotWpUser(MethodCallExpression mc) {
		java.util.List<Long> targets = call2mtd.get(mc.getNodeId());
		if( targets == null || targets.isEmpty() ) return false;   // unresolved -> keep (core WP_User)
		for( Long t : targets ) {
			ASTNode tn = ASTUnderConstruction.idToNode.get(t);
			if( tn == null ) return false;                          // can't inspect -> keep
			String cname = tn.getEnclosingClass();
			if( cname == null || cname.isEmpty() ) return false;    // no class -> keep
			if( "WP_User".equalsIgnoreCase(cname) || "WP_Role".equalsIgnoreCase(cname) ) return false;
			Long cid = getClassId(cname, mc.getNodeId(), tn.getEnclosingNamespace());
			if( cid == null || cid == -1L ) return false;           // untypable -> keep
			if( classChainMentionsWpUser(cid, null, 0) ) return false;  // subclasses WP_User -> keep
		}
		return true;   // every target is a plugin-defined method on a non-WP_User class
	}


	// Roles that confer no elevated capability. Assigning one of these is not escalation on its own.
	private static final Set<String> LOW_PRIV_ROLES =
		new HashSet<String>(Arrays.asList("subscriber","customer","'subscriber'","'customer'",
			"\"subscriber\"","\"customer\""));
	private static boolean isLowPrivRoleLiteral(Expression v) {
		if( !(v instanceof StringExpression) ) return false;
		String r = ((StringExpression)v).getEscapedCodeStr();
		if( r == null ) return false;
		return LOW_PRIV_ROLES.contains(r.trim().toLowerCase());
	}
	// True only when the user array explicitly targets the CURRENT user, e.g.
	// 'ID' => get_current_user_id(). An attacker-chosen ID (or no ID at all, as in wp_insert_user)
	// is NOT self-targeting, so those keep the sink.
	private static boolean targetsCurrentUser(ast.php.expressions.ArrayExpression arr) {
		if( arr == null ) return false;
		for( int i = 0; i < arr.size(); i++ ) {
			ast.php.expressions.ArrayElement el = arr.getArrayElement(i);
			if( el == null || !(el.getKey() instanceof StringExpression) ) continue;
			String k = ((StringExpression)el.getKey()).getEscapedCodeStr();
			if( k == null ) continue;
			k = k.replace("\"","").replace("'","").trim();
			if( !("ID".equalsIgnoreCase(k) || "user_id".equalsIgnoreCase(k)) ) continue;
			Expression v = el.getValue();
			if( v instanceof CallExpressionBase ) {
				String cn = callTargetName((CallExpressionBase)v);
				if( "get_current_user_id".equals(cn) ) return true;
			}
			return false;   // an ID element that is not get_current_user_id() -> not self-targeting
		}
		return false;       // no ID element at all (wp_insert_user creating a new account) -> not self
	}

	private static String getPropIdenForPHPCG(ASTNode node) {
		if( node == null ) return null;
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(node.getNodeId());
		if( kids == null ) return null;
		Long nameChild = kids.get(1);
		if( nameChild == null ) return null;
		ASTNode nameNode = ASTUnderConstruction.idToNode.get(nameChild);
		if( !(nameNode instanceof StringExpression) ) return null;
		String propName = ((StringExpression)nameNode).getEscapedCodeStr();
		// Use same identity format as StaticAnalysis.getPropIdentity: numericClassId::propName.
		// Get class from enclosing method (which has setEnclosingClass called on it).
		// Use node.getNodeId() as callSiteId — same file as the lookup side, same alias map.
		String clsId = "-1";
		try {
			Long fid = node.getFuncId();
			if( fid != null ) {
				ASTNode methNode = ASTUnderConstruction.idToNode.get(fid);
				if( methNode != null ) {
					String clsName = methNode.getEnclosingClass();
					String ns = methNode.getEnclosingNamespace();
					if( clsName != null && !clsName.isEmpty() ) {
						Long cid = getClassId(clsName, node.getNodeId(), ns);
						if( cid != null && cid != -1L ) clsId = cid.toString();
					}
				}
			}
		} catch(Exception e) {}
		return clsId + "::" + propName;
	}

	// Base array names that are EVER written with a dynamic (non-literal) key
	// anywhere in the program. Such a base cannot be safely tracked per-element: a dynamic-keyed
	// write could alias any literal element, so a later read of $a['k'] is not provably the value
	// last written to 'k'. Array elements are keyed (below) ONLY when their base is NOT in this set,
	// which removes the aliasing path and keeps element-keying false-negative-free.
	private static Set<String> dynKeyedWriteBases = null;

	// Keyed lvalue name for a literal-indexed array element whose base is a plain $var never written
	// with a dynamic key — e.g. $lz_env['cur_page'] -> "lz_env[cur_page]". Returns null for dynamic
	// indices, non-simple bases, or bases with any dynamic-keyed write (which fall back to the coarse
	// base name, i.e. unchanged behaviour). This is what lets the chain resolver follow an element
	// back to its assignment instead of treating the whole base array as one opaque risk.
	private static String keyableArrayLval(Expression e) {
		if( !(e instanceof ArrayIndexing) ) return null;
		Expression base = ((ArrayIndexing)e).getArrayExpression();
		String bn = varNameOf(base);                       // simple-$var base only
		if( bn == null ) return null;
		if( dynKeyedWriteBases != null && dynKeyedWriteBases.contains(bn) ) return null;
		if( constIndexKey(((ArrayIndexing)e).getIndexExpression()) == null ) return null;
		return lvalKey(e);                                 // "base[key]"
	}

	private static String varNameOf(ASTNode n) {
		if( n instanceof Variable && ((Variable)n).getNameExpression() instanceof StringExpression )
			return ((StringExpression)((Variable)n).getNameExpression()).getEscapedCodeStr();
		return null;
	}

	private static boolean isConstantRhs(ASTNode n) {
		return n instanceof StringExpression || n instanceof ast.expressions.Constant;
	}

	private static void addByFunc(HashMap<Long,Set<String>> m, Long fid, String v) {
		if( !m.containsKey(fid) ) m.put(fid, new HashSet<String>());
		m.get(fid).add(v);
	}

	private static void computeEnumValidated() {
		enumValidatedByFunc = new HashMap<Long, Set<String>>();
		enumDefaultNodesByFunc = new java.util.HashMap<Long,java.util.HashMap<String,java.util.List<Long>>>();
		HashMap<Long, HashMap<String, java.util.List<Long>>> defaultedNodes = new HashMap<Long, HashMap<String, java.util.List<Long>>>();
		varAssignsByFunc = new HashMap<Long, HashMap<String, java.util.List<ASTNode>>>();
		dynKeyedWriteBases = new HashSet<String>();
		// Pass 0: any base array written with a dynamic or append key is excluded from element keying
		// (its literal elements could be aliased by the dynamic write). Must run before keyableArrayLval.
		PHPCGFactory.recordScanSite("PCG_5893", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			Expression l = ((AssignmentExpression)n).getLeft();
			if( l instanceof ArrayIndexing ) {
				String bn = varNameOf(((ArrayIndexing)l).getArrayExpression());
				if( bn != null && constIndexKey(((ArrayIndexing)l).getIndexExpression()) == null ) dynKeyedWriteBases.add(bn);
			}
		}
		HashMap<Long, Set<String>> compared = new HashMap<Long, Set<String>>();
		HashMap<Long, Set<String>> defaulted = new HashMap<Long, Set<String>>();
		PHPCGFactory.recordScanSite("PCG_5903", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			Long fid; try { fid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( fid == null ) continue;
			if( n instanceof BinaryOperationExpression ) {
				String op = n.getFlags();
				if( op != null && (op.equals("BINARY_IS_EQUAL") || op.equals("BINARY_IS_NOT_EQUAL")
						|| op.equals("BINARY_IS_IDENTICAL") || op.equals("BINARY_IS_NOT_IDENTICAL")) ) {
					Expression l = ((BinaryOperationExpression)n).getLeft();
					Expression r = ((BinaryOperationExpression)n).getRight();
					String v = null;
					if( l instanceof StringExpression ) v = varNameOf(r);
					else if( r instanceof StringExpression ) v = varNameOf(l);
					if( v != null ) addByFunc(compared, fid, v);
				}
			}
			else if( n instanceof CallExpressionBase ) {
				String tn = callTargetName((CallExpressionBase)n);
				if( "in_array".equals(tn) ) {
					ArgumentList al = ((CallExpressionBase)n).getArgumentList();
					if( al != null && al.size() >= 1 ) {
						String v = varNameOf(al.getArgument(0));
						if( v != null ) addByFunc(compared, fid, v);
					}
				}
			}
			else if( n instanceof AssignmentExpression ) {
				Expression left = ((AssignmentExpression)n).getLeft();
				String v = varNameOf(left);
				if( v == null ) v = keyableArrayLval(left);   // literal-keyed element of a non-dyn-keyed base
				if( v != null ) {
					ASTNode rhs = ((AssignmentExpression)n).getRight();
					if( isConstantRhs(rhs) ) {
						addByFunc(defaulted, fid, v);
						if( !defaultedNodes.containsKey(fid) ) defaultedNodes.put(fid, new HashMap<String,java.util.List<Long>>());
						HashMap<String,java.util.List<Long>> dm = defaultedNodes.get(fid);
						if( !dm.containsKey(v) ) dm.put(v, new java.util.ArrayList<Long>());
						dm.get(v).add(n.getNodeId());
					}
					if( rhs != null ) {
						if( !varAssignsByFunc.containsKey(fid) ) varAssignsByFunc.put(fid, new HashMap<String, java.util.List<ASTNode>>());
						HashMap<String, java.util.List<ASTNode>> m = varAssignsByFunc.get(fid);
						if( !m.containsKey(v) ) m.put(v, new java.util.ArrayList<ASTNode>());
						m.get(v).add(rhs);
					}
				}
			}
		}
		for( Long fid : compared.keySet() ) {
			if( !defaulted.containsKey(fid) ) continue;
			Set<String> both = new HashSet<String>(compared.get(fid));
			both.retainAll(defaulted.get(fid));
			if( !both.isEmpty() ) {
				enumValidatedByFunc.put(fid, both);
				// carry over only the defaulting-assignment nodes for names that made the cut
				HashMap<String,java.util.List<Long>> allDn = defaultedNodes.get(fid);
				if( allDn != null ) {
					HashMap<String,java.util.List<Long>> kept = new HashMap<String,java.util.List<Long>>();
					for( String name : both ) if( allDn.containsKey(name) ) kept.put(name, allDn.get(name));
					enumDefaultNodesByFunc.put(fid, kept);
				}
			}
		}
	}

	// True if an assignment RHS contains a function/method call that is not one of the known
	// value-narrowing sanitizers (intval/absint/$wpdb->prepare). Such a call may be a request
	// source (e.g. get_query_var()) or any tainting helper, so a variable assigned from it cannot
	// be proven safe by chaining and must stay a terminal risk. Without this, a chain would follow
	// $x = get_query_var('k') back to a call with no variable operands and wrongly clear it.
	private static boolean rhsHasUnresolvableCall(ASTNode n) {
		if( n == null ) return false;
		if( n instanceof ast.expressions.ConditionalExpression ) {
			// Only the arms become the value; a call in the (discarded) condition does not taint it.
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
			Expression t = ce.getTrueExpression();
			if( t != null ) { if( rhsHasUnresolvableCall(t) ) return true; }
			else { if( rhsHasUnresolvableCall(ce.getCondition()) ) return true; }
			return rhsHasUnresolvableCall(ce.getFalseExpression());
		}
		if( n instanceof MethodCallExpression ) {
			Expression tf = ((MethodCallExpression)n).getTargetFunc();
			if( tf instanceof StringExpression && "prepare".equals(((StringExpression)tf).getEscapedCodeStr()) ) return false;
			return true;
		}
		if( n instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)n).getTargetFunc();
			if( tf instanceof Identifier && ((Identifier)tf).getNameChild()!=null ) {
				String nm = ((Identifier)tf).getNameChild().getEscapedCodeStr();
				if( "intval".equals(nm) || "absint".equals(nm) || inferredIntSanitizers.contains(nm) ) return false;
			}
			return true;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() )
			if( rhsHasUnresolvableCall(ASTUnderConstruction.idToNode.get(c)) ) return true;
		return false;
	}

	// Transitively resolve the risk variables of a SQL sink argument within its function: follow
	// each variable back through its in-function assignments, stopping (as safe) at enum/whitelist-
	// validated variables and at $wpdb. A variable with no in-function assignment (a parameter,
	// superglobal, or otherwise unresolved) is a terminal risk. Empty result => the argument is
	// constrained to provably-safe values. Stays FN-free for real bugs: a value escaped only for a
	// quoted context (sanitize_text_field/esc_sql, which collectSqlRiskNames descends into) chains
	// back to its superglobal/parameter root, which is terminal and risky.
	// FIX (2026-08-08): the enum-validation suppressor is genuinely flow-insensitive as originally
	// written -- "compared against a literal somewhere" and "assigned a constant somewhere" in the
	// SAME function, with no requirement that either occurrence actually precedes the SQL sink in
	// control flow, let alone that it dominates it. Confirmed via direct trace: a vulnerable use
	// followed later in the same function by an unrelated comparison and an unrelated defaulting
	// assignment would satisfy the original check and get silently suppressed. This feeds
	// sqlSinkProvablySafe(), which drops findings from `sinks` entirely -- the same "auto-clear on
	// a plausible-but-unproven signal" pattern this engine's own authorization-sufficiency work
	// explicitly rejected for a different mechanism, so this was worth the additional cost to fix
	// properly rather than leaving as a known gap.
	//
	// Reuses guardedRegion() -- the existing, already-verified dominance primitive built for the
	// nonce/CSRF clearing logic -- rather than building new dominance machinery. Deliberately
	// conservative in what it accepts: a variable is only treated as safe AT A GIVEN SINK if at
	// least one of its "defaulted to a constant" assignments has that specific sink inside its
	// guardedRegion(). This correctly handles the common, simple case (a top-level defaulting
	// assignment preceding the sink in the same block) and the bail-form case (an if(!valid){...
	// default...; return;} whose region extends past the if). It does NOT recognize the
	// positive-form case (if(!valid){$v='default';} with no halt, followed by the sink after the
	// whole if-statement) -- guardedRegion()'s positive-form handling only guards the if-BODY
	// itself, not statements after it, and proving safety there would require reasoning about
	// both branches of the conditional jointly, not just one guard node's dominated region. This
	// is an accepted, deliberate false-negative for sanitizer recognition (an extra REVIEW-tier
	// finding on code that may be genuinely safe), not a false claim of safety -- the same
	// direction this engine already favors elsewhere when a choice has to be made.
	private static java.util.HashMap<Long,java.util.HashMap<String,java.util.List<Long>>> enumDefaultNodesByFunc = null;

	private static Set<String> transitiveRiskVars(Long fid, Set<String> direct) {
		return transitiveRiskVars(fid, direct, null);
	}
	private static Set<String> transitiveRiskVars(Long fid, Set<String> direct, Long sinkNode) {
		Set<String> result = new HashSet<String>();
		Set<String> enumv = (fid != null && enumValidatedByFunc.containsKey(fid)) ? enumValidatedByFunc.get(fid) : java.util.Collections.<String>emptySet();
		java.util.HashMap<String,java.util.List<Long>> defaultNodes =
			(fid != null && enumDefaultNodesByFunc != null && enumDefaultNodesByFunc.containsKey(fid))
				? enumDefaultNodesByFunc.get(fid) : null;
		HashMap<String, java.util.List<ASTNode>> assigns = (fid != null && varAssignsByFunc.containsKey(fid)) ? varAssignsByFunc.get(fid) : null;
		java.util.ArrayDeque<String> work = new java.util.ArrayDeque<String>(direct);
		Set<String> visited = new HashSet<String>();
		int guard = 0;
		while( !work.isEmpty() && guard++ < 2000 ) {
			String v = work.poll();
			if( v == null || !visited.add(v) ) continue;
			if( v.equals("wpdb") ) continue;                                // provably-safe root
			if( enumv.contains(v) ) {
				boolean dominatesSink = false;
				if( sinkNode == null ) {
					dominatesSink = true;   // no sink context available -- preserve old behavior for other callers
				} else if( defaultNodes != null && defaultNodes.containsKey(v) ) {
					for( Long dn : defaultNodes.get(v) ) {
						if( guardedRegion(dn, fid).contains(sinkNode) ) { dominatesSink = true; break; }
					}
				}
				if( dominatesSink ) continue;   // provably-safe root, AND dominates this specific sink
				// falls through to normal risk resolution below -- enum-listed but not proven to
				// dominate THIS sink, so treated the same as any other unresolved variable
			}
			java.util.List<ASTNode> rhsList = (assigns != null) ? assigns.get(v) : null;
			if( rhsList == null || rhsList.isEmpty() ) { result.add(v); continue; }   // terminal risk
			boolean unresolvable = false;
			for( ASTNode rhs : rhsList ) if( rhsHasUnresolvableCall(rhs) ) { unresolvable = true; break; }
			if( unresolvable ) { result.add(v); continue; }   // assigned from a call/source -> keep risky
			for( ASTNode rhs : rhsList ) {
				Set<String> rv = new HashSet<String>();
				collectSqlRiskNames(rhs, rv);
				work.addAll(rv);
			}
		}
		return result;
	}

	public static boolean sqlSinkProvablySafe(CallExpressionBase call) {
		ArgumentList al = call.getArgumentList();
		if( al == null || al.size() < 1 ) return false;            // no SQL arg to reason about -> keep
		ASTNode sqlArg = al.getArgument(0);
		if( sqlArg == null ) return false;
		if( enumValidatedByFunc == null ) computeEnumValidated();
		Set<String> vars = new HashSet<String>();
		collectSqlRiskNames(sqlArg, vars);
		Long fid = null; try { fid = call.getFuncId(); } catch( Exception e ) {}
		// Follow indirect chains ($query = $query_base.'...'; $query_base = "...{$table}") back to
		// their roots; suppress only when every root is enum-validated (and dominance-proven at
		// THIS sink), $wpdb, or a constant.
		return transitiveRiskVars(fid, vars, call.getNodeId()).isEmpty();
	}

	// Collect names of interpolated variables in a SQL argument that could carry attacker
	// data. Unlike collectUnsanitizedVarNames (which skips ALL "repairs", including the
	// context-sensitive esc_sql/addslashes), this skips ONLY unconditionally-safe wrappers:
	// $wpdb->prepare(...) and the integer-cast calls intval()/absint(). It DESCENDS into
	// esc_sql/addslashes/*_real_escape_string/etc. so a value escaped only for quoted
	// contexts still leaves its variable name here and keeps the sink — deferring to the
	// context-sensitive esc_sql demotion at the sink check (e.g. unquoted ORDER BY / numeric
	// context stays injectable). That keeps the suppressor strictly (a) prefix/table-name,
	// (b) prepare-fragment, (c) intval/absint cast — and provably FN-free.
	private static void collectSqlRiskNames(ASTNode n, Set<String> out) {
		if( n == null ) return;
		if( n instanceof MethodCallExpression ) {
			Expression tf = ((MethodCallExpression)n).getTargetFunc();
			if( tf instanceof StringExpression && "prepare".equals(((StringExpression)tf).getEscapedCodeStr()) ) return;
		}
		else if( n instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)n).getTargetFunc();
			if( tf instanceof Identifier && ((Identifier)tf).getNameChild()!=null ) {
				String nm = ((Identifier)tf).getNameChild().getEscapedCodeStr();
				if( "intval".equals(nm) || "absint".equals(nm) || inferredIntSanitizers.contains(nm) ) return;   // integer -> safe in any context
			}
		}
		if( n instanceof ast.expressions.ConditionalExpression ) {
			// A conditional's VALUE comes from its arms, not its condition. The condition only selects
			// which arm — control-dependence, not data flow — so a ternary whose arms are constant
			// literals (e.g. cond($_GET) ? 'DESC' : 'ASC') carries no taint regardless of the
			// condition. Descend into the arms only. Short ternary (a ?: c) is the exception: the
			// condition IS the value when truthy, so it is included.
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
			Expression t = ce.getTrueExpression();
			if( t != null ) collectSqlRiskNames(t, out);
			else collectSqlRiskNames(ce.getCondition(), out);
			collectSqlRiskNames(ce.getFalseExpression(), out);
			return;
		}
		if( n instanceof ArrayIndexing ) {
			String kl = keyableArrayLval((Expression)n);   // $a['k'] of a non-dyn-keyed base -> "a[k]"
			if( kl != null ) { out.add(kl); return; }       // tracked by element; don't fall through to base
		}
		if( n instanceof Variable && ((Variable)n).getNameExpression() instanceof StringExpression ) {
			out.add(((StringExpression)((Variable)n).getNameExpression()).getEscapedCodeStr());
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() ) collectSqlRiskNames(ASTUnderConstruction.idToNode.get(c), out);
	}

	private static String callTargetName(CallExpressionBase c) {
		Expression tf = c.getTargetFunc();
		if( tf instanceof Identifier && ((Identifier)tf).getNameChild()!=null )
			return ((Identifier)tf).getNameChild().getEscapedCodeStr();
		if( tf instanceof StringExpression )
			return ((StringExpression)tf).getEscapedCodeStr();
		return null;
	}

	// Returns true if argument at position `argPos` (0-based) of the call is an empty array
	// literal — i.e. array() or [] with zero elements. Used to detect wp_kses($x, array())
	// which strips ALL HTML (equivalent to strip_tags) and is unconditionally XSS-safe.
	private static boolean isEmptyArrayArg(CallExpressionBase c, int argPos) {
		ArgumentList args = c.getArgumentList();
		if(args != null && args.size() > argPos) {
			Expression arg = args.getArgument(argPos);
			if(arg != null && "AST_ARRAY".equals(arg.getProperty("type"))) {
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(arg.getNodeId());
				return (kids == null || kids.isEmpty());
			}
			return false;
		}
		// Fallback: parent2child may lack entries if childnum parsing failed for the array node.
		// Find the AST_ARG_LIST child of this call, then look for an AST_ARRAY grandchild with no children.
		HashMap<Integer,Long> callKids = PHPCSVEdgeInterpreter.parent2child.get(c.getNodeId());
		if(callKids == null) return false;
		for(Long kid : callKids.values()) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(kid);
			if(kn == null || !"AST_ARG_LIST".equals(kn.getProperty("type"))) continue;
			// Scan child2parent inverse for any AST_ARRAY that has this arg-list as parent
			for(java.util.Map.Entry<Long,Long> e : PHPCSVEdgeInterpreter.child2parent.entrySet()) {
				if(!e.getValue().equals(kid)) continue;
				ASTNode maybe = ASTUnderConstruction.idToNode.get(e.getKey());
				if(maybe != null && "AST_ARRAY".equals(maybe.getProperty("type"))) {
					HashMap<Integer,Long> arrKids = PHPCSVEdgeInterpreter.parent2child.get(e.getKey());
					if(arrKids == null || arrKids.isEmpty()) return true;
				}
			}
			break;
		}
		return false;
	}

	private static String exprClassName(Expression e) {
		if( e instanceof Identifier && ((Identifier)e).getNameChild()!=null )
			return ((Identifier)e).getNameChild().getEscapedCodeStr();
		if( e instanceof StringExpression )
			return ((StringExpression)e).getEscapedCodeStr();
		return null;
	}

	// True if call n targets a currently-known wrapper (free function, Class::method, or
	// self/static/parent::method). Instance dispatch ($obj->m) is not resolved here.
	private static boolean isKnownWrapperCall(CallExpressionBase n, Set<String> fnNames,
	                                          Set<String> staticKeys, Set<String> methodNames) {
		if( n instanceof StaticCallExpression ) {
			StaticCallExpression sc = (StaticCallExpression)n;
			String cls = exprClassName(sc.getTargetClass());
			String m   = callTargetName(sc);
			if( m == null ) return false;
			if( cls != null && staticKeys.contains(cls+"::"+m) ) return true;
			if( cls != null && (cls.equals("self")||cls.equals("static")||cls.equals("parent"))
				&& methodNames.contains(m) ) return true;
			return false;
		}
		if( n instanceof MethodCallExpression ) {
			// $this->/self::/static::/parent:: calls are already handled by the dataflow
			// traversal path (it resolves the enclosing class), so we only need wrapper
			// matching for EXTERNAL instance calls — e.g. $r->getAll($_GET['x']) on a
			// constructed object, which traversal misses because the receiver's class is
			// not tracked. Restricting to non-$this receivers also avoids re-flagging
			// intra-class calls where a different, safe param carries the only non-constant
			// argument (the array_map-sanitizer false-positive class, case 08).
			String recv = receiverName(((MethodCallExpression)n).getTargetObject());
			if( recv.equals("this") || recv.equals("self") || recv.equals("static") || recv.equals("parent") )
				return false;
			// Receiver class unknown, but if the method name is globally unique (defined in
			// exactly one class) the target is unambiguous — the same assumption the
			// name-based call resolver already makes (nonStaticMethodNameDefs size==1).
			String m = callTargetName(n);
			if( m == null ) return false;
			if( methodNames.contains(m)
					&& nonStaticMethodNameDefs.containsKey(m)
					&& nonStaticMethodNameDefs.get(m).size() == 1 ) return true;
			return false;
		}
		String tn = callTargetName(n);
		return tn != null && fnNames.contains(tn);
	}

	private static void detectQueryWrappers() {
		computeHookParamFuncNames();   // hook-entry funcs with seeded source params are not wrappers
		// index assignments, calls, and $wpdb sinks by enclosing function
		HashMap<Long,List<AssignmentExpression>> assignsByFunc = new HashMap<Long,List<AssignmentExpression>>();
		HashMap<Long,List<CallExpressionBase>> callsByFunc = new HashMap<Long,List<CallExpressionBase>>();
		PHPCGFactory.recordScanSite("PCG_6235", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) && !(n instanceof CallExpressionBase) ) continue;
			Long fid; try { fid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( fid == null ) continue;
			if( n instanceof AssignmentExpression ) {
				if( !assignsByFunc.containsKey(fid) ) assignsByFunc.put(fid, new ArrayList<AssignmentExpression>());
				assignsByFunc.get(fid).add((AssignmentExpression)n);
			} else if( n instanceof CallExpressionBase ) {
				if( !callsByFunc.containsKey(fid) ) callsByFunc.put(fid, new ArrayList<CallExpressionBase>());
				callsByFunc.get(fid).add((CallExpressionBase)n);
			}
		}
		HashMap<Long,List<Long>> sinksByFunc = new HashMap<Long,List<Long>>();
		for( Long s : sinks ) {
			ASTNode sn = ASTUnderConstruction.idToNode.get(s);
			if( sn == null ) continue;
			Long fid; try { fid = sn.getFuncId(); } catch( Exception e ) { continue; }
			if( fid == null ) continue;
			if( !sinksByFunc.containsKey(fid) ) sinksByFunc.put(fid, new ArrayList<Long>());
			sinksByFunc.get(fid).add(s);
		}
		// per-function "derived" set: params + locals assigned (transitively) from a param,
		// not counting values that pass through a sanitizer.
		HashMap<Long,Set<String>> funcDerived = new HashMap<Long,Set<String>>();
		HashMap<Long,FunctionDef> funcNode = new HashMap<Long,FunctionDef>();
		PHPCGFactory.recordScanSite("PCG_6260", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof FunctionDef) ) continue;
			FunctionDef fd = (FunctionDef)n;
			ParameterList pl = fd.getParameterList();
			if( pl == null || pl.size() == 0 ) continue;
			Long fid = n.getNodeId();
			Set<String> derived = new HashSet<String>();
			for( int i=0;i<pl.size();i++ ) derived.add(((Parameter)pl.getParameter(i)).getName());
			List<AssignmentExpression> assigns = assignsByFunc.containsKey(fid) ? assignsByFunc.get(fid) : Collections.<AssignmentExpression>emptyList();
			boolean changed = true; int guard = 0;
			while( changed && guard++ < 50 ) {
				changed = false;
				for( AssignmentExpression a : assigns ) {
					if( a.getRight()==null || a.getLeft()==null ) continue;
					Set<String> rhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getRight(), rhs);
					rhs.retainAll(derived);
					if( !rhs.isEmpty() ) {
						Set<String> lhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getLeft(), lhs);
						for( String v : lhs ) if( derived.add(v) ) changed = true;
					}
				}
			}
			funcDerived.put(fid, derived);
			funcNode.put(fid, fd);
		}
		// ---- Return-taint summary: param positions whose value flows (unsanitized) into a
		// `return`. Used so a caller's `$v = f($_GET['x'])` can taint $v (interproc return), AND
		// (new) so collectUnsanitizedVarNames() can consult a callee's own summary instead of
		// walking every argument of every call indiscriminately -- see the interprocedural
		// consultation block added inside collectUnsanitizedVarNames() above.
		//
		// That consultation creates a genuine interprocedural dependency (render()'s summary needs
		// markup()'s summary to already be computed), so this is now a fixed-point computation, not
		// a single pass: each pass reads the PREVIOUS pass's stable, fully-written results (via
		// returnTaintConsultPositions/Analyzed) and writes a fresh result; passes repeat until
		// nothing changes or a bounded guard is hit. Writing into fresh maps each pass (rather than
		// mutating returnTaintPositions live during iteration) guarantees a single pass's results
		// don't depend on HashMap iteration order -- exactly the class of bug this rewrite exists to
		// avoid elsewhere in this codebase (see triage_v3.py's history for the same lesson learned
		// the hard way on a different tool).
		HashMap<Long,List<ASTNode>> returnsByFunc = new HashMap<Long,List<ASTNode>>();
		PHPCGFactory.recordScanSite("PCG_6301", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			Long rfid; try { rfid = n.getFuncId(); } catch( Exception e ) { continue; }
			if( rfid == null ) continue;
			if( !returnsByFunc.containsKey(rfid) ) returnsByFunc.put(rfid, new ArrayList<ASTNode>());
			returnsByFunc.get(rfid).add(n);
		}
		HashMap<Long, Set<Integer>> fpPositions = new HashMap<Long, Set<Integer>>();
		Set<Long> fpAnalyzed = new HashSet<Long>();
		boolean fpChanged = true; int fpGuard = 0;
		final int FP_MAX_PASSES = 12;   // generous for real call-chain depths; guards against any
		                                 // unforeseen non-convergence rather than looping forever
		while( fpChanged && fpGuard++ < FP_MAX_PASSES ) {
			fpChanged = false;
			// This pass reads whatever the PREVIOUS pass produced (empty on pass 1, matching the
			// old single-pass behavior exactly -- so pass 1 alone is a strict no-op change from
			// the pre-fixed-point code, and only pass 2+ can add precision).
			returnTaintConsultPositions = fpPositions;
			returnTaintConsultAnalyzed = fpAnalyzed;
			HashMap<Long, Set<Integer>> newPositions = new HashMap<Long, Set<Integer>>();
			Set<Long> newAnalyzed = new HashSet<Long>();
			for( Long fid : returnsByFunc.keySet() ) {
				FunctionDef fd = funcNode.get(fid);
				if( fd == null ) continue;   // unresolved definition -- never marked analyzed, stays conservative
				ParameterList pl = fd.getParameterList();
				if( pl == null || pl.size() == 0 ) {
					// No parameters at all: the return CANNOT depend on any caller-supplied argument
					// position, vacuously. Safe to mark analyzed with empty positions -- this is a
					// distinct, legitimate fact, not "unknown". (A zero-arg function that internally
					// reads a request source is handled separately, by retArbitraryFids below -- this
					// consultation is only about caller-argument-to-return flow.)
					newAnalyzed.add(fid);
					continue;
				}
				Set<String> returnVars = new HashSet<String>();
				for( ASTNode r : returnsByFunc.get(fid) ) {
					ASTNode re = ((ast.statements.jump.ReturnStatement)r).getReturnExpression();
					if( re != null ) collectUnsanitizedVarNames(re, returnVars);
				}
				if( System.getenv("WP_GATE8_DIAG") != null ) System.err.println("G8 fid="+fid+" pass="+fpGuard+" returnVars="+returnVars);
				if( returnVars.isEmpty() ) {
					// Successfully proved no unsanitized name reaches any return in this function --
					// a real, useful "safe" fact (this is exactly what lets RankMath's markup(), once
					// its own apply_filters/escaper handling is correct, actually help its callers).
					newAnalyzed.add(fid);
					continue;
				}
				List<AssignmentExpression> assigns = assignsByFunc.containsKey(fid) ? assignsByFunc.get(fid) : Collections.<AssignmentExpression>emptyList();
				Set<Integer> positions = new HashSet<Integer>();
				for( int i=0;i<pl.size();i++ ) {
					String pname = ((Parameter)pl.getParameter(i)).getName();
					// transitive closure of locals derived (unsanitized) from this single param
					Set<String> derived = new HashSet<String>(); derived.add(pname);
					boolean changed = true; int guard = 0;
					while( changed && guard++ < 50 ) {
						changed = false;
						for( AssignmentExpression a : assigns ) {
							if( a.getRight()==null || a.getLeft()==null ) continue;
							Set<String> rhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getRight(), rhs);
							rhs.retainAll(derived);
							if( !rhs.isEmpty() ) {
								Set<String> lhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getLeft(), lhs);
								for( String v : lhs ) if( derived.add(v) ) changed = true;
							}
						}
					}
					derived.retainAll(returnVars);
					if( System.getenv("WP_GATE8_DIAG") != null && (fid==119L || fid==69L || fid==13L) ) System.err.println("G8PARAM fid="+fid+" pass="+fpGuard+" i="+i+" pname="+pname+" hit="+derived);
					if( !derived.isEmpty() ) positions.add(i);
				}
				newAnalyzed.add(fid);
				if( !positions.isEmpty() ) newPositions.put(fid, positions);
			}
			applyFrontendStateReturnSummaries(newPositions,newAnalyzed); // Gate 11: participate in fixed point
			applyFrontendClosureReturnSummaries(newPositions,newAnalyzed); // Gate 23: exact lexical-closure summaries
			if( !newPositions.equals(fpPositions) || !newAnalyzed.equals(fpAnalyzed) ) fpChanged = true;
			fpPositions = newPositions;
			fpAnalyzed = newAnalyzed;
		}
		returnTaintPositions.clear();
		returnTaintPositions.putAll(fpPositions);
		returnTaintAnalyzed = fpAnalyzed;
		// Consult fields now reflect the FINAL, fully-converged summary, so every other call site of
		// collectUnsanitizedVarNames() elsewhere in this file (SQL-argument summaries, etc.) gets the
		// same precision for free, not just this specific return-summary computation.
		returnTaintConsultPositions = returnTaintPositions;
		returnTaintConsultAnalyzed = returnTaintAnalyzed;
		buildReturnMayTaintSummaries(); // Gate 14: preserve uncertain provenance through direct return wrappers
		if( System.getenv("WP_RTP_DIAG") != null ) {
			System.err.println("RTP_DIAG fixed point converged after " + fpGuard + " pass(es)");
			System.err.println("RTP_DIAG analyzed=" + returnTaintAnalyzed.size() + " positions_nonempty=" + returnTaintPositions.size());
			for( Long fid : returnTaintAnalyzed ) {
				FunctionDef fd = funcNode.get(fid);
				String nm = fd == null ? "?" : fd.getName();
				System.err.println("RTP_DIAG fid=" + fid + " name=" + nm + " positions=" + returnTaintPositions.get(fid));
			}
		}
		// ---- retArbitraryFids: user functions that read a request source internally and return it.
		// e.g. function get_name() { return $_GET['name']; }  -> caller's $x = get_name() is tainted.
		// Build this here (alongside returnTaintPositions) so it's available for XSS-mode taint prop.
		// Return-summary local tracing: trace LOCALS in the return expression via the existing valueIsTainted +
		// assignment map (so `$x=$_GET; return $x` and transitive chains are recognized), instead of the
		// inline-only subtree walk. The inline-only form was a deliberate PERFORMANCE restriction (assignment
		// -chain blow-up); valueIsTainted is now memoized (O(nodes x depth)), so it is plausibly affordable —
		// gated + validated for runtime on large plugins before any promotion.
		retArbitraryFids.clear();
		java.util.HashMap<Long,java.util.HashMap<String,java.util.List<ASTNode>>> retVa = buildVarAssigns();
		// Return-summary fixpoint: a function whose return is `other_helper()` only resolves once other_helper
		// is already in retArbitraryFids (R4 in valueIsTainted). Iterate to a fixpoint so cross-function
		// return chains (wrapper() { return build(); }) converge regardless of processing order.
		boolean retChanged = true; int retRounds = 0;
		while( retChanged && retRounds++ < 12 ) {
			retChanged = false;
			boolean prevReady = retSummaryReady; if( retVa != null ) retSummaryReady = true;
			PHPCGFactory.recordScanSite("PCG_6410", ASTUnderConstruction.idToNode.size());
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
				Long rfid; try { rfid = n.getFuncId(); } catch( Exception e ) { continue; }
				if( rfid == null || retArbitraryFids.contains(rfid) ) continue;
				Expression re = ((ast.statements.jump.ReturnStatement)n).getReturnExpression();
				if( re == null ) continue;
				boolean tainted = false;
				if( retVa != null ) {
					// Uses the intrinsic-only variant (see valueIsTaintedIntrinsic's doc comment) --
					// retArbitraryFids means "this function can independently manufacture attacker
					// data", which a synthetically-forwarded parameter does NOT establish; that case
					// is exactly what returnTaintPositions (computed separately, above) is for.
					tainted = valueIsTaintedIntrinsic(re.getNodeId(), rfid, retVa, 0);
				} else {
					java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
					java.util.Set<Long> seen = new java.util.HashSet<Long>();
					work.add(re.getNodeId());
					while( !work.isEmpty() ) {
						Long id = work.poll();
						if( id == null || !seen.add(id) ) continue;
						if( PHPCSVEdgeInterpreter.sources.contains(id) && !forwardedParamSources.contains(id) ) { tainted = true; break; }
						HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
						if( kids != null ) work.addAll(kids.values());
					}
				}
				retSummaryReady = prevReady;
				if( tainted && retArbitraryFids.add(rfid) ) retChanged = true;
				if( retVa != null ) retSummaryReady = true;
			}
			retSummaryReady = prevReady;
			if( retVa == null ) break;   // inline-only path is order-independent; one pass suffices
		}
		if( System.getenv("WP_RAF_DIAG") != null ) {
			System.err.println("RAF_DIAG[fixed-point retArbitraryFids] final=" + retArbitraryFids);
		}
		// ---- Typed-local instance dispatch: $var = new ClassName(); $var->method()
		// augmentInstanceDispatchEdges only handles $this->m() calls. For typed-local variables
		// ($w = new Widget(); $w->method()), we scan for new-expression assignments and add call2mtd
		// edges for method calls on those variables, enabling inter-method taint tracking.
		// Scope: same function, MethodCallExpression whose receiver is a Variable matching a $var
		// assigned from new ClassName() in the same function.
		{
			// Build per-function: varName -> classId from $var = new ClassName() assignments
			java.util.HashMap<Long, java.util.HashMap<String,Long>> funcLocalTypes =
				new java.util.HashMap<Long, java.util.HashMap<String,Long>>();
			PHPCGFactory.recordScanSite("PCG_6455", ASTUnderConstruction.idToNode.size());
			for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
				if( !(n instanceof AssignmentExpression) ) continue;
				Expression lhs = ((AssignmentExpression)n).getLeft();
				Expression rhs = ((AssignmentExpression)n).getRight();
				if( lhs == null || rhs == null ) continue;
				if( !(lhs instanceof Variable) ) continue;
				if( !(rhs instanceof ast.expressions.NewExpression) ) continue;
				String vn = varNameOf(lhs);
				if( vn == null || "this".equals(vn) ) continue;
				Expression cn = ((ast.expressions.NewExpression)rhs).getTargetClass();
				if( cn == null || !"AST_NAME".equals(cn.getProperty("type")) ) continue;
				ast.expressions.StringExpression cnChild = ((ast.expressions.Identifier)cn).getNameChild();
				if( cnChild == null ) continue;
				String cls = cnChild.getEscapedCodeStr();
				if( cls == null ) continue;
				if( "static".equals(cls) || "self".equals(cls) ) cls = rhs.getEnclosingClass();
				Long cid = getClassId(cls, cn.getNodeId(), rhs.getEnclosingNamespace());
				if( cid == null || cid == -1L ) continue;
				Long fid = n.getFuncId();
				if( fid == null ) continue;
				funcLocalTypes.computeIfAbsent(fid, k -> new java.util.HashMap<String,Long>()).put(vn, cid);
			}
			// Now for each method call $var->method(), look up the class and resolve the method
			int addedInst = 0;
			for( MethodCallExpression mc : nonStaticMethodCalls ) {
				if( !(mc.getTargetFunc() instanceof ast.expressions.StringExpression) ) continue;
				Expression recv = mc.getTargetObject();
				if( !(recv instanceof Variable) ) continue;
				String recvName = varNameOf(recv);
				if( recvName == null || "this".equals(recvName) ) continue;
				Long fid = mc.getFuncId();
				if( fid == null ) continue;
				java.util.HashMap<String,Long> localTypes = funcLocalTypes.get(fid);
				if( localTypes == null ) continue;
				Long cid = localTypes.get(recvName);
				if( cid == null ) continue;
				String methodName = ((ast.expressions.StringExpression)mc.getTargetFunc()).getEscapedCodeStr();
				if( methodName == null ) continue;
				Long targetFid = resolveMethodInHierarchy(cid, methodName);
				if( targetFid == null ) continue;
				java.util.List<Long> ex = call2mtd.get(mc.getNodeId());
				if( ex == null || !ex.contains(targetFid) ) {
					call2mtd.add(mc.getNodeId(), targetFid);
					addedInst++;
				}
			}
			if( addedInst > 0 )
				System.err.println("WPINSTLOCAL added "+addedInst+" typed-local $var->method() dispatch edges");
		}
		Set<String> wrapperFuncNames = new HashSet<String>();   // free functions
		Set<String> wrapperStaticKeys = new HashSet<String>();  // Class::method
		Set<String> wrapperMethodNames = new HashSet<String>(); // method names (self/static/parent)
		Set<Long> wrapperFids = new HashSet<Long>();
		// seed: functions that pass a derived var straight into a $wpdb sink
		for( Long fid : sinksByFunc.keySet() ) {
			if( !funcDerived.containsKey(fid) ) continue;
			FunctionDef __hf = funcNode.get(fid);
			if( __hf != null && hookParamFuncNames.contains(__hf.getName()) ) continue;  // hook entry w/ seeded source param — not a wrapper
			Set<String> derived = funcDerived.get(fid);
			boolean isWrapper = false;
			for( Long s : sinksByFunc.get(fid) ) {
				ASTNode sn = ASTUnderConstruction.idToNode.get(s);
				if( !(sn instanceof MethodCallExpression) ) continue;
				ArgumentList al = ((MethodCallExpression)sn).getArgumentList();
				if( al == null || al.size() < 1 ) continue;
				Set<String> argVars = new HashSet<String>(); collectUnsanitizedVarNames(al.getArgument(0), argVars);
				argVars.retainAll(derived);
				if( !argVars.isEmpty() ) { isWrapper = true; break; }
			}
			if( isWrapper ) markWrapper(fid, funcNode.get(fid), wrapperFids, wrapperFuncNames, wrapperStaticKeys, wrapperMethodNames);
		}
		// Per-wrapper risky positions: for each wrapper, which param positions reach a $wpdb sink
		// UNSANITIZED. Mirrors the returnTaintPositions closure but targets the sink's SQL argument
		// instead of a return expression. A position is risky iff the param-derived (unsanitized)
		// closure of that single param intersects the sink's risk-variable set. Positions a wrapper
		// sanitizes internally (esc_sql/intval/absint/prepare break the unsanitized chain) or that
		// never reach the sink are therefore NOT risky. FN-safe: if the closure is uncertain it
		// over-includes (keeps the position risky), never under-includes.
		wrapperRiskyPositions.clear();
		for( Long fid : wrapperFids ) {
			FunctionDef fd = funcNode.get(fid);
			if( fd == null ) continue;
			ParameterList pl = fd.getParameterList();
			if( pl == null || pl.size() == 0 ) continue;
			if( !sinksByFunc.containsKey(fid) ) continue;
			Set<String> sinkVars = new HashSet<String>();
			for( Long s : sinksByFunc.get(fid) ) {
				ASTNode sn = ASTUnderConstruction.idToNode.get(s);
				if( !(sn instanceof MethodCallExpression) ) continue;
				ArgumentList al = ((MethodCallExpression)sn).getArgumentList();
				if( al == null || al.size() < 1 ) continue;
				collectUnsanitizedVarNames(al.getArgument(0), sinkVars);
			}
			if( sinkVars.isEmpty() ) continue;
			List<AssignmentExpression> assigns = assignsByFunc.containsKey(fid) ? assignsByFunc.get(fid) : Collections.<AssignmentExpression>emptyList();
			Set<Integer> risky = new HashSet<Integer>();
			for( int i=0;i<pl.size();i++ ) {
				String pname = ((Parameter)pl.getParameter(i)).getName();
				Set<String> derived = new HashSet<String>(); derived.add(pname);
				boolean changed = true; int guard = 0;
				while( changed && guard++ < 50 ) {
					changed = false;
					for( AssignmentExpression a : assigns ) {
						if( a.getRight()==null || a.getLeft()==null ) continue;
						Set<String> rhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getRight(), rhs);
						rhs.retainAll(derived);
						if( !rhs.isEmpty() ) {
							Set<String> lhs = new HashSet<String>(); collectUnsanitizedVarNames(a.getLeft(), lhs);
							for( String v : lhs ) if( derived.add(v) ) changed = true;
						}
					}
				}
				Set<String> hit = new HashSet<String>(derived); hit.retainAll(sinkVars);
				if( !hit.isEmpty() ) risky.add(i);
			}
			wrapperRiskyPositions.put(fid, risky);
			System.err.println("WPWRAPRISKY fid "+fid+" "+fd.getName()+" risky "+risky+" of "+pl.size());
		}
		// NOTE: a transitive closure (mark a function that forwards a param into a known
		// wrapper as itself a wrapper) was evaluated and deliberately NOT shipped: on
		// config-driven query builders (e.g. Pods, where high-level API methods thread a
		// pod-definition array down many layers before a table name is interpolated) it
		// conflates "param influences the query" with "param is raw SQL", which — combined
		// with entry-point seeding treating those methods' structured params as user input —
		// produced false positives on constant and config-derived queries. Direct wrappers
		// (a param, or an intra-function param-derived local, reaching a $wpdb sink) are
		// precise; multi-hop and instance-dispatch wrappers are left unmodeled.
		if( wrapperFuncNames.isEmpty() && wrapperStaticKeys.isEmpty() ) return;
		// name -> wrapper fid, so a call site can recover the risky positions of its target.
		// Free-function and unique-method names map directly; ambiguous names are dropped (the
		// sink check then leaves such calls in the default whole-call behavior — FN-safe).
		HashMap<String,Long> wrapperFidByName = new HashMap<String,Long>();
		Set<String> ambiguousWrapperNames = new HashSet<String>();
		for( Long wfid : wrapperFids ) {
			FunctionDef wf = funcNode.get(wfid);
			if( wf == null || wf.getName() == null ) continue;
			String nm = wf.getName();
			if( wrapperFidByName.containsKey(nm) && !wrapperFidByName.get(nm).equals(wfid) ) ambiguousWrapperNames.add(nm);
			wrapperFidByName.put(nm, wfid);
		}
		wrapperCallRiskyArgs.clear();
		for( String fn : wrapperFuncNames ) System.err.println("WPWRAPPERNAME func "+fn);
		for( String sk : wrapperStaticKeys ) System.err.println("WPWRAPPERNAME static "+sk);
		// mark every call to a wrapper as a sink (taint analysis decides which are tainted)
		PHPCGFactory.recordScanSite("PCG_6599", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof CallExpressionBase) ) continue;
			if( sinks.contains(n.getNodeId()) ) continue;
			if( isKnownWrapperCall((CallExpressionBase)n, wrapperFuncNames, wrapperStaticKeys, wrapperMethodNames) ) {
				// A wrapper call with only constant arguments cannot carry tainted SQL; skip it
				// (avoids flagging e.g. pods_query('DROP TABLE @wp_pods')).
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				Set<String> av = new HashSet<String>();
				if( al != null ) collectUnsanitizedVarNames(al, av);
				if( av.isEmpty() ) continue;
				sinks.add(n.getNodeId());
				System.err.println("WPWRAPPER sink node "+n.getNodeId());
				// Record the risky-position argument nodes for this call, when the target wrapper
				// is resolvable to a single fid with a computed risky-position set. Unresolvable or
				// ambiguous targets are left unrecorded -> default whole-call behavior (FN-safe).
				String tnm = callTargetName((CallExpressionBase)n);
				if( tnm != null && !ambiguousWrapperNames.contains(tnm) && wrapperFidByName.containsKey(tnm) ) {
					Long wfid = wrapperFidByName.get(tnm);
					Set<Integer> risky = wrapperRiskyPositions.get(wfid);
					if( risky != null ) {
						Set<Long> riskyArgNodes = new HashSet<Long>();
						if( al != null ) for( Integer p : risky ) if( p < al.size() ) riskyArgNodes.add(al.getArgument(p).getNodeId());
						wrapperCallRiskyArgs.put(n.getNodeId(), riskyArgNodes);
					}
				}
			}
		}
	}

	private static void markWrapper(Long fid, FunctionDef fnode, Set<Long> wrapperFids,
	                                Set<String> fnNames, Set<String> staticKeys, Set<String> methodNames) {
		if( fnode == null ) return;
		String fname = fnode.getName();
		if( fname == null || fname.isEmpty() ) return;
		wrapperFids.add(fid);
		if( fnode instanceof Method ) {
			String cls = ((Method)fnode).getEnclosingClass();
			if( cls != null && !cls.isEmpty() ) staticKeys.add(cls+"::"+fname);
			methodNames.add(fname);
		} else {
			fnNames.add(fname);
		}
	}

	// Simple (unqualified) class name: strip surrounding quotes, namespace, and leading backslash,
	// so `\Foo\Bar`, `'Bar'`, and `Bar` all compare equal. Used to pin array($this/'Class','m')
	// callbacks to one class instead of every class that happens to share the method name.
	private static String simpleClassName(String s) {
		if( s == null ) return null;
		s = s.trim();
		if( s.length() >= 2 ) { char a = s.charAt(0), b = s.charAt(s.length()-1);
			if( (a=='"' || a=='\'') && a==b ) s = s.substring(1, s.length()-1); }
		int bs = s.lastIndexOf('\\');
		if( bs >= 0 ) s = s.substring(bs+1);
		return s;
	}

	// ITEM42 FIX: side-effect-free extraction of registerCallbackAsEntry's own callable-name
	// resolution (string / array-callable / first-class-callable forms), returning the matched
	// function/method node id(s) instead of seeding them as entry points. Used to resolve a
	// register_rest_route() 'permission_callback' argument to the same function id(s) that
	// objectAuthorizationFacts() can then search -- reusing the exact resolution logic already
	// verified for 'callback' rather than duplicating it with a second, potentially-diverging
	// implementation. Returns an empty set for anything unresolvable, including opaque inline
	// closures (phpjoern extracts those as disconnected units with no linkable name -- same
	// documented limitation as classifyRestPermission()), which is the correct conservative
	// behavior: no evidence is invented for a callback this function cannot actually read.
	private static java.util.Set<Long> resolveCallableFuncIds(Expression cb) {
		java.util.Set<Long> out = new HashSet<Long>();
		// ITEM42 FIX (closure case) -- CONFIRMED NON-FUNCTIONAL, kept for documentation and
		// forward-compatibility only. An inline `function(){...}` permission_callback parses as
		// an AST_CLOSURE node that IS correctly linked to its array-literal use site in the raw
		// parser CSV output (verified directly: rels.csv contains the PARENT_OF edge from the
		// array-element node to the closure node). However, that specific edge is never delivered
		// to PHPCSVEdgeInterpreter.handle() at all -- traced empirically via targeted logging,
		// not assumed -- because closures are parsed through a separate, function-like CSVAST
		// sub-conversion pipeline (the same one used for top-level functions/methods, since
		// Closure extends FunctionDef), and the edge connecting a closure back to its use site is
		// dropped somewhere before reaching the generic edge interpreter this detector's logic
		// depends on. The result: ArrayElement.getValue() returns null for a closure value,
		// exactly as classifyRestPermission()'s pre-existing comment already warned, though the
		// mechanism is a dropped parser edge, not merely an unimplemented lookup. Fixing this
		// would require changes to the underlying php2ast/joern-php CSV-to-AST construction layer,
		// not this detector -- out of scope here. The branch below is unreachable via this path
		// today (perm is null before resolveCallableFuncIds is ever called on a closure), but is
		// left in so a future parser-level fix does not silently need this half rewritten too.
		if( cb instanceof ast.php.expressions.ClosureExpression ) {
			ast.php.functionDef.Closure cl = ((ast.php.expressions.ClosureExpression)cb).getClosure();
			if( cl != null ) { Long id = cl.getNodeId(); if( id != null ) out.add(id); }
			return out;
		}
		String target = null;
		if( cb instanceof StringExpression ) {
			String s = ((StringExpression)cb).getEscapedCodeStr();
			int sep = s.indexOf("::");
			target = (sep > 0) ? s.substring(sep + 2) : s;
		}
		else if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 && arr.getArrayElement(1).getValue() instanceof StringExpression ) {
				target = ((StringExpression)arr.getArrayElement(1).getValue()).getEscapedCodeStr();
			}
		}
		else if( cb instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf != null ) {
				if( "string".equals(tf.getProperty("type")) ) target = tf.getEscapedCodeStr();
				else if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null )
					target = ((Identifier)tf).getNameChild().getEscapedCodeStr();
			}
		}
		if( target == null ) return out;
		String pinClass = null;
		if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 ) {
				Expression recv = arr.getArrayElement(0).getValue();
				if( recv instanceof StringExpression ) {
					pinClass = simpleClassName(((StringExpression)recv).getEscapedCodeStr());
				} else if( recv instanceof Variable && "this".equals(varNameOf((Expression)recv)) ) {
					Long encFid = cb.getFuncId();
					ASTNode encFn = encFid == null ? null : ASTUnderConstruction.idToNode.get(encFid);
					if( encFn instanceof Method ) pinClass = simpleClassName(((Method)encFn).getEnclosingClass());
				}
			}
		} else if( cb instanceof StringExpression ) {
			String s = ((StringExpression)cb).getEscapedCodeStr();
			int sep = s.indexOf("::");
			if( sep > 0 ) pinClass = simpleClassName(s.substring(0, sep));
		}
		if( pinClass != null ) {
			for( Long mid : allMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pinClass.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) ) out.add(mid);
			}
			for( Long mid : allStaticMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pinClass.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) ) out.add(mid);
			}
			if( !out.isEmpty() ) return out;
			// fall through to name-global scan if pinning found nothing, same FN-safety
			// discipline as registerCallbackAsEntry.
		}
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof Method && target.equals(((Method)n).getName()) ) out.add(mid);
		}
		for( Long mid : allStaticMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof Method && target.equals(((Method)n).getName()) ) out.add(mid);
		}
		for( Long fid : allFunc ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(fid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) out.add(fid);
		}
		return out;
	}

	private static void registerCallbackAsEntry(Expression cb, String priv) {
		// Resolve the callback to a function/method name, then find the matching
		// definition by scanning allMtd (methods) and allFunc (functions) — these
		// node-id sets are always populated and independent of class-id resolution.
		String target = null;
		if( cb instanceof StringExpression ) {
			// "ClassName::method" static-callable string -- same fix as resolveCallbackName()
			// earlier this session (confirmed real via AIOWM's add_submenu_page registrations,
			// which use exactly this string form). Without splitting on "::", `target` stayed the
			// full qualified string and NEVER matched a bare method name below -- this callback
			// silently failed to seed at all for any plugin using this completely standard PHP
			// callable syntax, not just add_action/add_filter.
			String s = ((StringExpression)cb).getEscapedCodeStr();
			int sep = s.indexOf("::");
			target = (sep > 0) ? s.substring(sep + 2) : s;
		}
		else if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 && arr.getArrayElement(1).getValue() instanceof StringExpression ) {
				target = ((StringExpression)arr.getArrayElement(1).getValue()).getEscapedCodeStr();
			}
		}
		else if( cb instanceof CallExpressionBase ) {
			// PHP 8.1 first-class-callable used as a callback, e.g.
			//   add_action('wp_ajax_nopriv_x', $this->handler(...))
			//   register_rest_route(..., array('callback' => Class::method(...)))
			//   add_filter('posts_join', filter_fn(...))
			// The args are the (...) placeholder; we only need the referenced name so the
			// existing name-based seeding below can register the handler as an entry point.
			// Without this, modern plugins that register callbacks via f(...) never get their
			// handlers seeded, so the handler's request-data reads are never analyzed.
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf != null ) {
				if( "string".equals(tf.getProperty("type")) ) {
					target = tf.getEscapedCodeStr();                          // $this->m(...) / Class::m(...)
				}
				else if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null ) {
					target = ((Identifier)tf).getNameChild().getEscapedCodeStr();  // func(...)
				}
			}
		}
		if( target == null ) return;
		// Pin a target CLASS for instance/class array callbacks so a method name shared across classes
		// (process/init/save/handle) is not seeded onto every one of them. array($this,'m') -> the class
		// enclosing the registration site ($this's class); array('Class','m') -> the named class. If the
		// class is pinned AND it has the method, seed ONLY that method; otherwise fall through to the
		// name-global scan below so no handler that used to seed is lost (FN-safe).
		String pinClass = null;
		if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 ) {
				Expression recv = arr.getArrayElement(0).getValue();
				if( recv instanceof StringExpression ) {
					pinClass = simpleClassName(((StringExpression)recv).getEscapedCodeStr());
				} else if( recv instanceof Variable && "this".equals(varNameOf((Expression)recv)) ) {
					Long encFid = cb.getFuncId();
					ASTNode encFn = encFid == null ? null : ASTUnderConstruction.idToNode.get(encFid);
					if( encFn instanceof Method ) pinClass = simpleClassName(((Method)encFn).getEnclosingClass());
				}
			}
		} else if( cb instanceof StringExpression ) {
			// "ClassName::method" string form -- mirrors the array('ClassName','method') case
			// immediately above.
			String s = ((StringExpression)cb).getEscapedCodeStr();
			int sep = s.indexOf("::");
			if( sep > 0 ) pinClass = simpleClassName(s.substring(0, sep));
		}
		if( pinClass != null ) {
			boolean any = false;
			for( Long mid : allMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pinClass.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) ) {
					topFunIds.add(mid); entryPriv.put(mid, priv);
					System.err.println("WPENTRY ["+priv+"] method "+pinClass+"::"+target+" node "+mid);
					any = true;
				}
			}
			for( Long mid : allStaticMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pinClass.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) ) {
					topFunIds.add(mid); entryPriv.put(mid, priv);
					System.err.println("WPENTRY ["+priv+"] static-method "+pinClass+"::"+target+" node "+mid);
					any = true;
				}
			}
			if( any ) return;   // class pinned and seeded — do NOT also name-global match other classes
		}
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) {
				topFunIds.add(mid);
				entryPriv.put(mid, priv);
				System.err.println("WPENTRY ["+priv+"] method "+target+" node "+mid);
			}
		}
		// Static methods used as callbacks (array($this,'static_method') / 'Class::method')
		// live in a separate set; resolve them too, or wrapper-registered static handlers
		// (very common — e.g. Hook_Registry::add_action(..., array($this,'tracker_parser')))
		// are silently never seeded.
		for( Long mid : allStaticMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) {
				topFunIds.add(mid);
				entryPriv.put(mid, priv);
				System.err.println("WPENTRY ["+priv+"] static-method "+target+" node "+mid);
			}
		}
		for( Long fid : allFunc ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(fid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) {
				topFunIds.add(fid);
				entryPriv.put(fid, priv);
				System.err.println("WPENTRY ["+priv+"] function "+target+" node "+fid);
			}
		}
	}

	// Resolve a callback expression (string literal / array-callable ['obj','method'] or [$this,'method'] /
	// first-class-callable) to its declared function/method NAME only (not which class it belongs to) —
	// mirrors the existing precedent in seedShortcodeCallback / addSqlFilterReturnSinks exactly.
	private static String resolveCallbackName(Expression cb) {
		if( cb instanceof StringExpression ) {
			String s = ((StringExpression)cb).getEscapedCodeStr();
			// "ClassName::method" static-callable string syntax -- a completely standard PHP
			// callable form (e.g. add_filter($tag, 'MyClass::my_method')), distinct from the
			// array('MyClass','my_method') form already handled below. Without this split, the
			// WHOLE "ClassName::method" string was being compared directly against bare method
			// names (which are never a full qualified string), so resolution silently always
			// failed. Confirmed real via AIOWM 9.x: every add_filter('ai1wm_import', ...)
			// registration uses this exact string form, so callback resolution -- for BOTH the
			// pre-existing resolveHookDispatch() and this session's new indirect-dispatch
			// extension -- never worked for this plugin's own hook system at all.
			int sep = s.indexOf("::");
			if( sep > 0 ) return s.substring(sep + 2);
			return s;
		}
		if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 && arr.getArrayElement(1).getValue() instanceof StringExpression )
				return ((StringExpression)arr.getArrayElement(1).getValue()).getEscapedCodeStr();
			return null;
		}
		if( cb instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf == null ) return null;
			if( "string".equals(tf.getProperty("type")) ) return tf.getEscapedCodeStr();
			if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null )
				return ((Identifier)tf).getNameChild().getEscapedCodeStr();
		}
		return null;
	}

	private static Set<Long> resolveCallbackFids(String target) {
		Set<Long> fids = new HashSet<Long>();
		if( target == null ) return fids;
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(mid);
		}
		for( Long mid : allStaticMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(mid);
		}
		for( Long fid : allFunc ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(fid);
			if( n instanceof FunctionDef && target.equals(((FunctionDef)n).getName()) ) fids.add(fid);
		}
		return fids;
	}

	// Class-aware variant: when the callback is array($this,'method') or array('Class','method'),
	// resolve only the method belonging to the pinned class. This matches the class-pinning logic in
	// registerCallbackAsEntry so shortcode/block seeding doesn't seed every class that has a method
	// named 'handle_shortcode' or 'render_css' — a common problem with page-builders.
	private static Set<Long> resolveCallbackFidsPinned(Expression cb) {
		String target = resolveCallbackName(cb);
		if( target == null ) return java.util.Collections.emptySet();
		String pinClass = null;
		if( cb instanceof ArrayExpression ) {
			ArrayExpression arr = (ArrayExpression)cb;
			if( arr.size() >= 2 ) {
				Expression recv = arr.getArrayElement(0).getValue();
				if( recv instanceof StringExpression ) {
					pinClass = simpleClassName(((StringExpression)recv).getEscapedCodeStr());
				} else if( recv instanceof Variable && "this".equals(varNameOf((Expression)recv)) ) {
					Long encFid = cb.getFuncId();
					ASTNode encFn = encFid == null ? null : ASTUnderConstruction.idToNode.get(encFid);
					if( encFn instanceof Method )
						pinClass = simpleClassName(((Method)encFn).getEnclosingClass());
				}
			}
		} else if( cb instanceof StringExpression ) {
			// "ClassName::method" string form -- mirrors the array('ClassName','method') case
			// immediately above. resolveCallbackName() already stripped the class prefix off of
			// `target`; recover it here to pin the class the same way.
			String s = ((StringExpression)cb).getEscapedCodeStr();
			int sep = s.indexOf("::");
			if( sep > 0 ) pinClass = simpleClassName(s.substring(0, sep));
		}
		if( pinClass != null ) {
			Set<Long> fids = new HashSet<Long>();
			String pc = pinClass;
			for( Long mid : allMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pc.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) )
					fids.add(mid);
			}
			for( Long mid : allStaticMtd ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(mid);
				if( n instanceof Method && target.equals(((Method)n).getName())
						&& pc.equalsIgnoreCase(simpleClassName(((Method)n).getEnclosingClass())) )
					fids.add(mid);
			}
			if( !fids.isEmpty() ) return fids;
			// Class pinned but no method found under that exact class — fall through to name-global.
		}
		return resolveCallbackFids(target);
	}

	// Mark every `return` statement inside the given function/method definitions as an XSS output sink.
	// WP core echoes the return value of a shortcode/block render callback directly into page HTML, so a
	// tainted return is exactly as dangerous as an unescaped echo — this makes the existing echo/print
	// dataflow AND escaper-suppression machinery (xssOutputProvablySafe, consulted for every `sinks`
	// entry tagged sinkClass=="xss") apply to it unchanged, with no new dataflow code. Mirrors the
	// precedent in addSqlFilterReturnSinks (SQL-clause filter-hook returns spliced into $wpdb queries).
	// This runs from seedWordPressEntryPoints(), which is AFTER the one-time filterProvablySafeXssSinks()
	// suppression sweep — so these newly-added sinks would never get escaper credit if just added
	// unconditionally; apply the same xssOutputProvablySafe check inline instead (the escaper-adequacy
	// classification it depends on, markContextInadequateXssEscapers(), already ran and is still valid).
	private static void markReturnsAsXssSink(Set<Long> fids, String label) {
		if( fids.isEmpty() ) return;
		int n = 0, safe = 0;
		boolean dbg = System.getenv("WP_RETURNSINK_DEBUG") != null;
		PHPCGFactory.recordScanSite("PCG_6995", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof ast.statements.jump.ReturnStatement) ) continue;
			Long f = node.getFuncId();
			if( f == null || !fids.contains(f) ) continue;
			if( xssOutputProvablySafe(node.getNodeId()) ) { safe++; continue; }
			sinks.add(node.getNodeId()); sinkClass.put(node.getNodeId(), "xss"); n++;
			if( dbg ) System.err.println("WPRETURNSINKID "+node.getNodeId()+" fid="+f+" "+label);
		}
		if( n > 0 || safe > 0 ) System.err.println("WPRETURNSINK marked "+n+" "+label
			+" return-statement xss sink(s) ("+safe+" provably-safe, skipped)");
	}

	// Shortcode callback return value: WP core's do_shortcode() splices it verbatim into the post content
	// output, unescaped. seedShortcodeCallback() already sources the callback's $atts parameter; this
	// marks its return statements as the matching sink, closing the loop for direct `$atts['x']` XSS —
	// and, independently, for cases where the source is a stored read rather than $atts (e.g. a
	// shortcode that does `return get_post_meta($id,'k')`), where the ONLY missing piece was this sink.
	private static void addShortcodeReturnSinks(Expression cb) {
		markReturnsAsXssSink(resolveCallbackFidsPinned(cb), "shortcode");
	}

	// Gutenberg block render_callback: core's render_block()/do_blocks() echoes the return value directly
	// into page HTML exactly like a shortcode callback. The first parameter ($attributes, from the saved
	// block's attributes in post content) is attacker-controlled by the same Contributor+ threat model as
	// shortcode $atts. Source the parameter and sink the returns, mirroring seedShortcodeCallback exactly
	// (collectShortcodeAttsParam is already generic — first-parameter-by-name — so it is reused as-is).
	private static void seedBlockRenderCallback(Expression cb) {
		registerCallbackAsEntry(cb, "block:contributor");
		Set<Long> fids = resolveCallbackFidsPinned(cb);
		String target = resolveCallbackName(cb);
		if( fids.isEmpty() ) return;
		java.util.HashSet<Long> attsFids = new java.util.HashSet<Long>();
		java.util.HashMap<Long,String> attsName = new java.util.HashMap<Long,String>();
		for( Long fid : fids ) collectShortcodeAttsParam(fid, target, attsFids, attsName);
		PHPCGFactory.recordScanSite("PCG_7029", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null || !attsFids.contains(f) ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne != null && attsName.get(f) != null && attsName.get(f).equals(ne.getEscapedCodeStr()) )
				PHPCSVEdgeInterpreter.sources.add(node.getNodeId());
		}
		markReturnsAsXssSink(fids, "block-render");
	}

	// register_block_type( $name, $args ) where $args is an inline array literal containing
	// 'render_callback'. Modern block.json-based registration (render_callback referenced only via
	// block.json / a file-naming convention, not an inline array) is NOT covered — deliberately scoped
	// to the common inline-array form, matching how other additions this session stayed narrow.
	private static void seedBlockRegistrations() {
		for( CallExpressionBase fc : functionCalls ) {
			String name = callTargetName(fc);
			if( !"register_block_type".equals(name) && !"register_block_type_from_metadata".equals(name) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null ) continue;
			// register_block_type has two call forms:
			// (A) register_block_type(path_to_block_json, ['render_callback'=>...]) — path string first, array second.
			// (B) register_block_type(['render_callback'=>...]) — inline array only (original implementation).
			// Scan all arguments for the options array containing 'render_callback'.
			for( int i = 0; i < al.size(); i++ ) {
				Expression a = al.getArgument(i);
				if( !(a instanceof ArrayExpression) ) continue;
				for( ArrayElement el : (ArrayExpression)a ) {
					if( !(el.getKey() instanceof StringExpression) ) continue;
					if( !"render_callback".equals(((StringExpression)el.getKey()).getEscapedCodeStr()) ) continue;
					if( el.getValue() != null ) seedBlockRenderCallback(el.getValue());
				}
			}
		}
	}

	// Seed a shortcode render callback as an analysis entry AND source its first parameter ($atts).
	// Shortcodes execute inside post content authored by contributor-level users, so (a) contributor-
	// set post meta the callback echoes and (b) the shortcode ATTRIBUTES themselves ($atts['x'], from
	// `[tag x="..."]` in the post) are stored-XSS vectors once an admin/visitor renders the post. The
	// attribute array is the callback's first parameter; every use of it is marked a source so
	// `echo $atts['x']` (unescaped) flags while `echo esc_html($atts['x'])` stays clean. The
	// "shortcode:contributor" tag is inert for the ACL audit (which filters on "unauth").
	// Also handles extract(shortcode_atts(defaults, $atts)): when the function body calls extract()
	// on the result of shortcode_atts, the variable names created by extract() (= the keys of the
	// defaults array) become sources. This covers `extract(shortcode_atts(['class'=>''],  $atts));
	// echo '<div class="'.$class.'">'` — page-list's actual XSS vector.
	private static void seedShortcodeCallback(Expression cb) {
		registerCallbackAsEntry(cb, "shortcode:contributor");
		String target = null;
		if( cb instanceof StringExpression ) target = ((StringExpression)cb).getEscapedCodeStr();
		else if( cb instanceof ArrayExpression ) {
			ArrayExpression a = (ArrayExpression)cb;
			if( a.size() >= 2 && a.getArrayElement(1).getValue() instanceof StringExpression )
				target = ((StringExpression)a.getArrayElement(1).getValue()).getEscapedCodeStr();
		}
		if( target == null ) return;
		// Use class-pinned resolution: for array($this,'method') callbacks, only seed the method
		// belonging to the enclosing class. Falls back to name-global if class is unavailable.
		java.util.Set<Long> pinnedFids = resolveCallbackFidsPinned(cb);
		java.util.HashSet<Long> attsFids = new java.util.HashSet<Long>();
		java.util.HashMap<Long,String> attsName = new java.util.HashMap<Long,String>();
		if( !pinnedFids.isEmpty() ) {
			for( Long fid : pinnedFids ) collectShortcodeAttsParam(fid, target, attsFids, attsName);
		} else {
			for( Long fid : allFunc ) collectShortcodeAttsParam(fid, target, attsFids, attsName);
			for( Long fid : allMtd ) collectShortcodeAttsParam(fid, target, attsFids, attsName);
			for( Long fid : allStaticMtd ) collectShortcodeAttsParam(fid, target, attsFids, attsName);
		}
		// Also collect any fids whose name matches (for the extract path below) even if no $atts param.
		java.util.Set<Long> targetFids = new java.util.HashSet<Long>(attsFids);
		if( !pinnedFids.isEmpty() ) {
			targetFids.addAll(pinnedFids);
		} else {
			for( Long fid : allFunc ) { ASTNode n=ASTUnderConstruction.idToNode.get(fid); if(n instanceof FunctionDef && target.equals(((FunctionDef)n).getName())) targetFids.add(fid); }
			for( Long fid : allMtd ) { ASTNode n=ASTUnderConstruction.idToNode.get(fid); if(n instanceof FunctionDef && target.equals(((FunctionDef)n).getName())) targetFids.add(fid); }
			for( Long fid : allStaticMtd ) { ASTNode n=ASTUnderConstruction.idToNode.get(fid); if(n instanceof FunctionDef && target.equals(((FunctionDef)n).getName())) targetFids.add(fid); }
		}
		// Collect extract(shortcode_atts(defaults, ...)) var names per fid.
		java.util.Map<Long,java.util.Set<String>> extractedNames = collectExtractedShortcodeAttsNames(targetFids);
		if( attsFids.isEmpty() && extractedNames.isEmpty() ) return;
		int seededExtract = 0;
		PHPCGFactory.recordScanSite("PCG_7112", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null || !targetFids.contains(f) ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne == null ) continue;
			String vn = ne.getEscapedCodeStr();
			// Standard $atts parameter sourcing.
			if( attsFids.contains(f) && attsName.get(f) != null && attsName.get(f).equals(vn) )
				PHPCSVEdgeInterpreter.sources.add(node.getNodeId());
			// extract(shortcode_atts) sourcing: variables whose names match extracted keys.
			else if( extractedNames.containsKey(f) && extractedNames.get(f).contains(vn) ) {
				PHPCSVEdgeInterpreter.sources.add(node.getNodeId()); seededExtract++;
			}
		}
		if( seededExtract > 0 )
			System.err.println("WPEXTRACT seeded "+seededExtract+" extract(shortcode_atts) var sources for "+target);
	}

	// Find functions/methods in `targetFids` that contain `extract(shortcode_atts(defaults, ...))` and
	// return the defaults array keys (the variable names extract() will create) per function.
	// Limited to 24 keys per function to avoid seeding huge arrays from complex page-builders.
	private static java.util.Map<Long,java.util.Set<String>> collectExtractedShortcodeAttsNames(
			java.util.Set<Long> targetFids) {
		java.util.Map<Long,java.util.Set<String>> result = new java.util.HashMap<Long,java.util.Set<String>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof CallExpressionBase) ) continue;
			String name = callTargetName((CallExpressionBase)n);
			if( !"extract".equals(name) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !targetFids.contains(fid) ) continue;
			ArgumentList al = ((CallExpressionBase)n).getArgumentList();
			if( al == null || al.size() < 1 ) continue;
			Expression arg0 = al.getArgument(0);
			// Arg must be a shortcode_atts(...) call or a call wrapping it (apply_filters wrapping is common).
			String keys = extractShortcodeAttsKeys(arg0);
			if( keys == null ) continue;
			java.util.Set<String> names = result.computeIfAbsent(fid, k -> new java.util.HashSet<String>());
			for( String k : keys.split(",") ) if( !k.isEmpty() ) names.add(k);
		}
		return result;
	}

	// Given an expression that is (or wraps) a shortcode_atts call, return the comma-joined keys of its
	// defaults array, or null if not recognized. Handles the bare form and the apply_filters-wrapped form
	// common in page-builders: `apply_filters('tag_atts', array('class'=>''), $atts)`.
	private static String extractShortcodeAttsKeys(Expression e) {
		if( !(e instanceof CallExpressionBase) ) return null;
		String nm = callTargetName((CallExpressionBase)e);
		ArgumentList al = ((CallExpressionBase)e).getArgumentList();
		if( al == null ) return null;
		if( "shortcode_atts".equals(nm) && al.size() >= 1 )
			return arrayKeysFromExpression(al.getArgument(0));
		// apply_filters('tag', defaults_array, $atts): shortcode_atts is sometimes not called but the
		// same defaults-then-atts shape appears as an apply_filters. Also: the nested form
		// shortcode_atts(apply_filters('tag_atts', array(...),...), $atts).
		if( "apply_filters".equals(nm) && al.size() >= 2 ) {
			String inner = extractShortcodeAttsKeys(al.getArgument(1));
			if( inner != null ) return inner;
			if( al.size() >= 2 ) return arrayKeysFromExpression(al.getArgument(1));
		}
		return null;
	}

	// Extract the string keys from an AST_ARRAY expression, returning them comma-joined or null.
	private static String arrayKeysFromExpression(Expression e) {
		if( !(e instanceof ArrayExpression) ) return null;
		StringBuilder sb = new StringBuilder();
		int count = 0;
		for( ArrayElement el : (ArrayExpression)e ) {
			if( count >= 24 ) break;   // cap to avoid flooding from huge page-builder defaults arrays
			Expression k = el.getKey();
			if( !(k instanceof StringExpression) ) continue;
			String kv = ((StringExpression)k).getEscapedCodeStr();
			if( kv == null || kv.isEmpty() ) continue;
			if( sb.length() > 0 ) sb.append(',');
			sb.append(kv);
			count++;
		}
		return sb.length() > 0 ? sb.toString() : null;
	}

	private static void collectShortcodeAttsParam(Long fid, String target,
			java.util.HashSet<Long> attsFids, java.util.HashMap<Long,String> attsName) {
		ASTNode n = ASTUnderConstruction.idToNode.get(fid);
		if( !(n instanceof FunctionDef) || !target.equals(((FunctionDef)n).getName()) ) return;
		ParameterList pl = ((FunctionDef)n).getParameterList();
		if( pl == null || pl.size() < 1 ) return;
		String pname = ((Parameter)pl.getParameter(0)).getName();
		if( pname != null ) { attsFids.add(fid); attsName.put(fid, pname); }
	}

	// Action hooks whose callback is handed attacker-controlled data in a known parameter position.
	// This is the deliberate, curated counterpart to the choice NOT to taint filter-hook params
	// (posts_where etc., which are core-supplied): these hooks pass raw request data, so the named
	// parameter must be seeded as a source or the bug is invisible. Conservative by design — only
	// hooks with a well-known unauthenticated user-input argument belong here.
	//   wp_login_failed($username): $username is the submitted login name ($_POST['log']) on a failed
	//   login — unauthenticated, unsanitized; the CVE-2020-27615 (loginizer) SQLi vector. Without this
	//   the tool never seeds $username and misses the real injection.
	private static final java.util.HashMap<String,int[]> HOOK_TAINTED_PARAM = new java.util.HashMap<String,int[]>();
	static {
		HOOK_TAINTED_PARAM.put("wp_login_failed", new int[]{0});   // $username (submitted login name)
		HOOK_TAINTED_PARAM.put("authenticate",    new int[]{1,2}); // filter ($user,$username,$password)
		HOOK_TAINTED_PARAM.put("wp_authenticate", new int[]{0,1}); // action (&$username,&$password)
	}

	// Seed the callback's parameter at position `pos` as a taint source: every use of that parameter
	// variable inside the callback body is marked a request source. Mirrors seedShortcodeCallback
	// (which does this for a shortcode's $atts at position 0) but for an arbitrary position.
	private static int seedHookParamAsSource(Expression cb, int pos) {
		String target = null;
		if( cb instanceof StringExpression ) target = ((StringExpression)cb).getEscapedCodeStr();
		else if( cb instanceof ArrayExpression ) {
			ArrayExpression a = (ArrayExpression)cb;
			if( a.size() >= 2 && a.getArrayElement(1).getValue() instanceof StringExpression )
				target = ((StringExpression)a.getArrayElement(1).getValue()).getEscapedCodeStr();
		}
		else if( cb instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf != null ) {
				if( "string".equals(tf.getProperty("type")) ) target = tf.getEscapedCodeStr();
				else if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null )
					target = ((Identifier)tf).getNameChild().getEscapedCodeStr();
			}
		}
		if( target == null ) return 0;
		java.util.HashSet<Long> pFids = new java.util.HashSet<Long>();
		java.util.HashMap<Long,String> pName = new java.util.HashMap<Long,String>();
		for( Long fid : allFunc ) collectHookParam(fid, target, pos, pFids, pName);
		for( Long fid : allMtd ) collectHookParam(fid, target, pos, pFids, pName);
		for( Long fid : allStaticMtd ) collectHookParam(fid, target, pos, pFids, pName);
		if( pFids.isEmpty() ) return 0;
		int added = 0;
		PHPCGFactory.recordScanSite("PCG_7246", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null || !pFids.contains(f) ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne != null && pName.get(f) != null && pName.get(f).equals(ne.getEscapedCodeStr()) )
				{ PHPCSVEdgeInterpreter.sources.add(node.getNodeId()); hookParamSourceNodes.add(node.getNodeId()); added++; }
		}
		return added;
	}

	private static void collectHookParam(Long fid, String target, int pos,
			java.util.HashSet<Long> pFids, java.util.HashMap<Long,String> pName) {
		ASTNode n = ASTUnderConstruction.idToNode.get(fid);
		if( !(n instanceof FunctionDef) || !target.equals(((FunctionDef)n).getName()) ) return;
		ParameterList pl = ((FunctionDef)n).getParameterList();
		if( pl == null || pl.size() <= pos ) return;
		String pname = ((Parameter)pl.getParameter(pos)).getName();
		if( pname != null ) { pFids.add(fid); pName.put(fid, pname); }
	}

	// Function names registered as callbacks for a HOOK_TAINTED_PARAM hook. Such a function is an
	// ENTRY POINT whose request-carrying parameter is seeded as a source, so it must NOT be modeled
	// as an internal query-wrapper — otherwise its own $wpdb sink is shifted to its call sites and
	// the seeded-param taint never reaches a sink. Computed before detectQueryWrappers consumes it.
	private static Set<String> hookParamFuncNames = new HashSet<String>();

	// Seeded hook-parameter source nodes (e.g. $username uses in a wp_login_failed callback). Unlike a
	// superglobal read, these appear INLINE inside a concat/sink argument rather than as an assignment
	// right-value, so StaticAnalysis.isSource (which expects an assignment-RHS or direct call-arg) would
	// otherwise reject them. isSource consults this set to accept them directly.
	public static Set<Long> hookParamSourceNodes = new HashSet<Long>();
	// Distinguishes WHY a node is in PHPCSVEdgeInterpreter.sources: hookParamSourceNodes covers
	// both genuine WordPress hook-callback parameters AND forwardInlineSourceArgs()'s synthetic
	// forwarding (a caller passed a source as an argument, so the callee's corresponding parameter
	// use gets seeded "tainted by fiat" so taint reaching a SINK inside a non-sink callee isn't
	// missed -- see forwardInlineSourceArgs()'s own doc comment). That forwarding is deliberately
	// blunt: it doesn't know whether the callee's RETURN actually depends on that parameter, only
	// that the parameter MAY carry attacker data at this call site -- exactly what
	// returnTaintPositions is for. Before this set existed, retArbitraryFids's own source-detection
	// (valueIsTaintedIntrinsic) couldn't tell "this function reads $_GET itself" from "this
	// function merely received a source as an argument", so ANY function called with a source
	// argument got marked as if it could independently manufacture attacker-controlled data,
	// bypassing the position-aware returnTaintPositions machinery entirely. See
	// valueIsTaintedIntrinsic() below for the one consumer that cares about this distinction --
	// every OTHER consumer of `sources` is deliberately left untouched.
	public static Set<Long> forwardedParamSources = new HashSet<Long>();

	/** One PROMOTION EVENT: a specific caller argument caused a specific callee parameter to be
	 *  seeded as a source. forwardInlineSourceArgs had all of this in scope but stored only
	 *  parameter-node membership, so two callers promoting the same parameter became one fact. */
	public static final class PromotedParameterEvidence {
		public final Long parameterNodeId, calleeFunction, callsiteAstId, callerSourceNodeId;
		public final String parameterName; public final int argumentIndex;
		public PromotedParameterEvidence(Long pn, Long callee, String pname, int argIdx,
		                                 Long callsite, Long callerSrc) {
			parameterNodeId=pn; calleeFunction=callee; parameterName=pname;
			argumentIndex=argIdx; callsiteAstId=callsite; callerSourceNodeId=callerSrc;
		}
		/** Canonical promotion tuple — dedupe on ALL of it, never on parameter or source alone. */
		public String key() { return parameterNodeId+"|"+calleeFunction+"|"+parameterName+"|"
			+argumentIndex+"|"+callsiteAstId+"|"+callerSourceNodeId; }
	}
	public static final HashMap<Long, java.util.LinkedHashMap<String,PromotedParameterEvidence>>
		promotedParamEvidence = new HashMap<Long, java.util.LinkedHashMap<String,PromotedParameterEvidence>>();
	/** (calleeFunc, paramName) -> promotion inputs observed in the first loop. */
	private static final HashMap<String, java.util.List<long[]>> pendingPromotions =
		new HashMap<String, java.util.List<long[]>>();

	// ITEM78 (WP_EXPERIMENTAL_VALUE_PROVENANCE): parameters seeded ONLY by reaching-definition
	// evidence. `derivedProvenanceKeys` is keyed "funcId|paramName" during resolution;
	// `derivedProvenanceNodes` holds the resolved Variable nodes. These deliberately do NOT enter
	// PHPCSVEdgeInterpreter.sources: membership there carries statement-level semantics
	// (srcStmt / source-statement branch) far broader than "this value derives from a source",
	// which is what caused the ARG_REACHDEF 88 -> 51 regression. The taint layer consumes these
	// for propagation only (sourceFunc), never for statement reclassification.
	public static final java.util.Set<String> derivedProvenanceKeys = new java.util.HashSet<String>();
	public static final java.util.Set<Long> derivedProvenanceNodes = new java.util.HashSet<Long>();

	private static String callbackNameOf(Expression cb) {
		if( cb instanceof StringExpression ) return ((StringExpression)cb).getEscapedCodeStr();
		if( cb instanceof ArrayExpression ) {
			ArrayExpression a = (ArrayExpression)cb;
			if( a.size() >= 2 && a.getArrayElement(1).getValue() instanceof StringExpression )
				return ((StringExpression)a.getArrayElement(1).getValue()).getEscapedCodeStr();
		}
		if( cb instanceof CallExpressionBase ) {
			Expression tf = ((CallExpressionBase)cb).getTargetFunc();
			if( tf != null ) {
				if( "string".equals(tf.getProperty("type")) ) return tf.getEscapedCodeStr();
				if( tf instanceof Identifier && ((Identifier)tf).getNameChild() != null )
					return ((Identifier)tf).getNameChild().getEscapedCodeStr();
			}
		}
		return null;
	}

	private static void computeHookParamFuncNames() {
		hookParamFuncNames.clear();
		for( CallExpressionBase fc : functionCalls ) {
			if( !(fc.getTargetFunc() instanceof Identifier) ) continue;
			String callName = ((Identifier)fc.getTargetFunc()).getNameChild().getEscapedCodeStr();
			if( !(callName.equals("add_action") || callName.equals("add_filter")) ) continue;
			ArgumentList args = fc.getArgumentList();
			if( args == null || args.size() < 2 || !(args.getArgument(0) instanceof StringExpression) ) continue;
			String hook = ((StringExpression)args.getArgument(0)).getEscapedCodeStr();
			if( !HOOK_TAINTED_PARAM.containsKey(hook) ) continue;
			String nm = callbackNameOf(args.getArgument(1));
			if( nm == null && args.size() >= 3 ) nm = callbackNameOf(args.getArgument(2));
			if( nm != null ) hookParamFuncNames.add(nm);
		}
	}

	// Variables that, within a given function scope, are assigned ONLY string/scalar literals (and are
	// not parameters). Such a variable provably holds a constant, so echoing it is safe even though it
	// is syntactically a $var. Lets the XSS suppressor drop sinks like
	//   $cls=' active'; echo $tab==='x' ? $cls : '';   (the ternary arms are constant)
	// Sound: a variable with ANY non-literal assignment, or that is a parameter, is excluded, so a
	// tainted value can never be mistaken for a constant.
	private static HashMap<Long, Set<String>> literalOnlyVarsByFunc = null;

	private static boolean subtreeHasNoDynamicValue(ASTNode n) {
		if( n == null ) return true;
		if( n instanceof Variable || n instanceof CallExpressionBase || n instanceof MethodCallExpression
			|| n instanceof StaticCallExpression || n instanceof ArrayIndexing ) return false;
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() )
			if( !subtreeHasNoDynamicValue(ASTUnderConstruction.idToNode.get(c)) ) return false;
		return true;
	}

	private static void computeLiteralOnlyVars() {
		literalOnlyVarsByFunc = new HashMap<Long, Set<String>>();
		HashMap<Long, Set<String>> nonLiteral = new HashMap<Long, Set<String>>();
		PHPCGFactory.recordScanSite("PCG_7370", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression a = (AssignmentExpression)n;
			if( a.getLeft()==null || a.getRight()==null ) continue;
			String lv = varNameOf(a.getLeft());
			if( lv == null ) continue;                         // simple $var lvalues only
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			Set<String> bucket = (subtreeHasNoDynamicValue(a.getRight()) ? literalOnlyVarsByFunc : nonLiteral)
				.computeIfAbsent(fid, k -> new HashSet<String>());
			bucket.add(lv);
		}
		// FIX (2026-08-08): a foreach loop's value (and key) variable is implicitly reassigned on
		// every iteration from whatever is being iterated -- this binding is a separate
		// AST_FOREACH construct, not an AssignmentExpression node, so it was completely invisible
		// to the scan above. A variable that also happens to receive an explicit literal
		// assignment elsewhere in the same function (e.g. `$x = 'lit'; foreach($tainted as $x) {
		// echo $x; }`) was therefore incorrectly credited as literal-only, since the only
		// AssignmentExpression the scan above ever saw for it was the literal one -- silently
		// suppressing what should be a genuine XSS finding. Fixed by unconditionally treating
		// every foreach value/key variable name as non-literal, regardless of what the iterated
		// expression itself is (conservative in the safe direction: even a foreach over a
		// genuinely all-literal array now loses the credit it would technically deserve, rather
		// than risk crediting a tainted one).
		PHPCGFactory.recordScanSite("PCG_7394", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( n == null || !"AST_FOREACH".equals(n.getProperty("type")) ) continue;
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
			if( kids == null ) continue;
			java.util.List<Integer> sortedKeys = new java.util.ArrayList<Integer>(kids.keySet());
			java.util.Collections.sort(sortedKeys);
			Set<String> bucket = nonLiteral.computeIfAbsent(fid, k -> new HashSet<String>());
			for( Integer k : sortedKeys ) {
				ASTNode child = ASTUnderConstruction.idToNode.get(kids.get(k));
				if( child instanceof Expression ) {
					String vn = varNameOf((Expression)child);
					if( vn != null ) bucket.add(vn);
				}
			}
		}
		for( Long fid : nonLiteral.keySet() )                  // any non-literal assignment disqualifies
			if( literalOnlyVarsByFunc.containsKey(fid) ) literalOnlyVarsByFunc.get(fid).removeAll(nonLiteral.get(fid));
		for( Long fid : new HashSet<Long>(literalOnlyVarsByFunc.keySet()) ) {   // parameters are not constants
			ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
			if( fn instanceof FunctionDef ) {
				ParameterList pl = ((FunctionDef)fn).getParameterList();
				if( pl != null ) for( int i=0;i<pl.size();i++ ) {
					String pn = ((Parameter)pl.getParameter(i)).getName();
					if( pn != null ) literalOnlyVarsByFunc.get(fid).remove(pn);
				}
			}
		}
	}

	// XSS OUTPUT-SINK SUPPRESSOR (context-sensitive, runs in ALL modes). An echo/print sink whose
	// every interpolated value is either a constant or wrapped AT THE OUTPUT in an XSS sanitizer
	// (esc_html/esc_attr/esc_url/wp_kses*/selected/checked/htmlspecialchars/intval/...) cannot reflect
	// attacker markup and is not an XSS vulnerability. This is the XSS analogue of the $wpdb WPSAFE
	// suppressor and is what lets the multi-class hunt credit XSS escapers WITHOUT crediting them for
	// SQL (echo sinks only; $wpdb sinks are untouched, so no SQL false negative). One-directional and
	// FN-free for XSS: a bare tainted variable ($x, $_GET[...], $this->prop) leaves a name in the set
	// and KEEPS the sink, so only output that is provably escaped-at-sink is dropped.
	// HTML/attribute output escapers that neutralize reflected/stored markup AT THE OUTPUT. The
	// XSS suppressor below credits these (its comment always claimed to, but the code only checked
	// the numeric xssSanitizers list — so every `echo esc_html($x)` was a false positive; this was
	// the dominant XSS FP across the plugin batches). Includes the translation+escape variants
	// (esc_html__/esc_attr__/..._e/..._x) and the kses allowlist wrappers. Deliberately EXCLUDES
	// sanitize_text_field (leaves quotes intact -> attribute-context breakout) which stays taint-
	// preserving. Context caveat (esc_url for URLs, esc_js for JS) accepted: crediting esc_html/
	// esc_html/esc_attr for the standard text/quoted-attribute case matches WP's own model and the residual
	// FN (unquoted attr / javascript: URL) is narrow versus the FP flood of not crediting them.
	// DELIBERATELY OMITS htmlspecialchars/htmlentities: those escape quotes but NOT a javascript: URL
	// scheme, so htmlspecialchars($url,ENT_QUOTES) in an href stays vulnerable — that is exactly
	// CVE-2022-0653 (Profile Builder), which its regression oracle requires to remain flagged. The
	// WP esc_* family is credited; the raw-PHP context-weak pair is not.
	static final Set<String> htmlEscapers = new HashSet<String>(Arrays.asList(
		"esc_html","esc_attr","esc_url","esc_url_raw","esc_js","esc_textarea","esc_xml",
		"esc_html__","esc_attr__","esc_html_e","esc_attr_e","esc_html_x","esc_attr_x",
		"wp_kses","wp_kses_post","wp_kses_data","tag_escape","sanitize_key"));

	public static boolean isXssOutputEscaper( String nm ) {
		return nm != null && ( htmlEscapers.contains(nm) || PHPCSVEdgeInterpreter.xssSanitizers.contains(nm) );
	}

	// Numeric-coercion functions: their output cannot contain HTML/JS metacharacters in any context,
	// so a sink fully wrapped in one of these is genuinely safe. Delete (not tag) those sinks.
	// Everything else in htmlEscapers/xssSanitizers is a name-only match — correct in common cases
	// but wrong in context-mismatch or shadowing situations — so those get tagged for downstream review.
	public static final java.util.Set<String> NUMERIC_COERCERS = new java.util.HashSet<>(
		java.util.Arrays.asList("intval","absint","floatval","intdiv","ceil","floor","round","abs",
			"number_format","sprintf_int_only"));  // last two only if format is purely numeric

	// sink node id -> name of the escaper whose name matched (for reporting; never re-suppresses).
	// Populated by filterProvablySafeXssSinks() for sinks that are suppressed by name-match only.
	public static java.util.HashMap<Long, String> xssEscaperMatched = new java.util.HashMap<>();

	// Like xssOutputProvablySafe, but returns the matched escaper name (or null if sink is genuinely
	// risky). Used to record which escaper triggered suppression so downstream can audit the match.
	public static String xssOutputEscaperName(Long sinkId) {
		ASTNode n = ASTUnderConstruction.idToNode.get(sinkId);
		if( n == null ) return null;
		String[] matched = {null};
		boolean[] risk = {false};
		collectXssEscaperName(n, matched, risk);
		// FIX (2026-08-08): out[0] previously doubled as both "nothing examined yet" and "a bare,
		// unescaped variable was found" (both represented as null), with the escaper-name branch
		// only conditionally overwriting it (if(out[0]==null)) while the risk branch overwrote it
		// UNCONDITIONALLY. For a concatenation with more than one child (e.g. echo esc_html($a) .
		// $tainted;), which child's effect "won" depended on HashMap.values() iteration order over
		// parent2child -- confirmed genuinely reproducible, not merely theoretical, by testing the
		// same expression with operands in each order: one order kept the finding, the other
		// silently deleted it. A separate, sticky risk[0] flag now tracks whether ANY unescaped
		// leaf was found anywhere in the subtree, independent of traversal order and independent of
		// whatever escaper names were also seen; the final answer is null (unsafe -- do not
		// suppress) whenever risk[0] is true, regardless of what the escaper-name tracking recorded.
		if( risk[0] ) return null;
		return matched[0];   // non-null ↔ all leaves were covered by escapers; value = last escaper seen
	}

	// Variant of collectXssRiskNames that records the matched escaper name instead of risky var names.
	// Returns (via out[0]) the name of the escaper that covered this subtree, and (via risk[0]) a
	// sticky flag set true if any unescaped, risky leaf was found anywhere in the subtree -- risk[0]
	// is authoritative over out[0] for the final safety decision (see xssOutputEscaperName above).
	private static void collectXssEscaperName(ASTNode n, String[] out, boolean[] risk) {
		if( n == null ) return;
		if( n instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)n);
			if( isXssOutputEscaper(nm) && !xssInadequateEscaperNodes.contains(n.getNodeId()) ) {
				if( out[0] == null ) out[0] = nm;   // record first escaper seen
				return;   // subtree covered
			}
			if( STORED_TAINT && nm != null && STORED_SOURCE_FUNCS.contains(nm) ) { risk[0] = true; return; }
			if( STORED_TAINT && storedWrapperTargetOf((CallExpressionBase)n) != null ) { risk[0] = true; return; }
		}
		if( n instanceof MethodCallExpression ) {
			Expression tf = ((MethodCallExpression)n).getTargetFunc();
			if( tf instanceof StringExpression ) {
				String mnm = ((StringExpression)tf).getEscapedCodeStr();
				if( isXssOutputEscaper(mnm) ) { if( out[0] == null ) out[0] = mnm; return; }
			}
		}
		if( n instanceof ast.expressions.ConditionalExpression ) {
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
			Expression t = ce.getTrueExpression();
			if( t != null ) collectXssEscaperName(t, out, risk); else collectXssEscaperName(ce.getCondition(), out, risk);
			collectXssEscaperName(ce.getFalseExpression(), out, risk);
			return;
		}
		if( n instanceof Variable && ((Variable)n).getNameExpression() instanceof StringExpression ) {
			// A bare variable: risky — escaper did not cover it.
			risk[0] = true; return;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() ) collectXssEscaperName(ASTUnderConstruction.idToNode.get(c), out, risk);
	}

	// CONTEXT-AWARE ESCAPER CREDITING (recall fix for the dominant modern-XSS class: escaping that is
	// wrong for the output context). An escaper only neutralizes reflected markup in the context it was
	// designed for — esc_html/esc_attr do NOT strip a javascript: scheme in an href (needs esc_url), and
	// NO html escaper escapes the space that breaks out of an UNQUOTED attribute. The output context is
	// inferred from the string literal immediately preceding the escaped value in the concat, exactly as
	// demoteAllUnquotedEscSql does for esc_sql. Escapers landing in a context they don't cover are
	// recorded here so collectXssRiskNames stops crediting them (the escaped value becomes a risk again,
	// keeping the sink). BODY / quoted-non-URL-attribute contexts are unchanged, so the common safe case
	// (echo esc_html($x) in text) is still suppressed and the oracles' FP-suppression is preserved.
	private static final int XCTX_BODY = 0, XCTX_URL = 1, XCTX_UNQUOTED_ATTR = 2, XCTX_JS = 3;
	public static final Set<Long> xssInadequateEscaperNodes = new HashSet<Long>();
	// URL-bearing attribute (value is a URL -> only esc_url family is adequate).
	private static final java.util.regex.Pattern XSS_URL_ATTR = java.util.regex.Pattern.compile(
		"(?is).*\\b(href|src|action|formaction|poster|background|cite|longdesc|manifest|xlink:href)\\s*=\\s*[\"']?\\s*$");
	// An open <script ...> not yet closed, or an inline event handler on*= (JS context -> esc_js only).
	private static final java.util.regex.Pattern XSS_JS_CTX = java.util.regex.Pattern.compile(
		"(?is).*(<script\\b[^>]*>[^<]*$|\\bon[a-z]+\\s*=\\s*[\"']?\\s*$)");
	// An attribute name= with NO opening quote (unquoted attribute -> space/> breakout; only esc_url or a
	// numeric narrower is adequate).
	private static final java.util.regex.Pattern XSS_UNQUOTED_ATTR = java.util.regex.Pattern.compile(
		"(?is).*<[^>]*\\s[\\w:-]+\\s*=\\s*$");

	private static int xssContextOf( String pre ) {
		if( pre == null ) return XCTX_BODY;   // unknown left context -> body (current default behavior)
		if( XSS_URL_ATTR.matcher(pre).matches() ) return XCTX_URL;
		if( XSS_JS_CTX.matcher(pre).matches() ) return XCTX_JS;
		if( XSS_UNQUOTED_ATTR.matcher(pre).matches() ) return XCTX_UNQUOTED_ATTR;
		return XCTX_BODY;
	}
	private static boolean xssEscaperAdequate( String nm, int ctx ) {
		if( nm == null ) return false;
		// Numeric / fixed-token narrowers (intval/absint/selected/checked/…) emit no markup-significant
		// characters in ANY context, so they are adequate everywhere.
		if( PHPCSVEdgeInterpreter.xssSanitizers.contains(nm) ) return true;
		switch( ctx ) {
			case XCTX_URL:           return nm.equals("esc_url") || nm.equals("esc_url_raw");
			case XCTX_UNQUOTED_ATTR: return nm.equals("esc_url") || nm.equals("esc_url_raw");
			case XCTX_JS:            return nm.equals("esc_js");
			default:                 return htmlEscapers.contains(nm);   // BODY / quoted non-URL attr
		}
	}
	// The escaper call at the START of a (possibly nested-concat) right operand — i.e. the one that
	// immediately follows the preceding literal.
	private static Long leadingXssEscaperNode( Expression e ) {
		if( e == null ) return null;
		if( e instanceof BinaryOperationExpression
			&& "BINARY_CONCAT".equals(((BinaryOperationExpression)e).getFlags()) )
			return leadingXssEscaperNode(((BinaryOperationExpression)e).getLeft());
		if( e instanceof CallExpressionBase && isXssOutputEscaper(callTargetName((CallExpressionBase)e)) )
			return e.getNodeId();
		return null;
	}
	private static String xssCallName( ASTNode n ) {
		if( n instanceof CallExpressionBase ) return callTargetName((CallExpressionBase)n);
		return null;
	}
	// Global pass: for every string concatenation, if its right side begins with an XSS escaper, judge
	// that escaper against the context implied by the rightmost literal of the left side; record it as
	// inadequate if it does not cover that context. Mirrors demoteAllUnquotedEscSql.
	private static void markContextInadequateXssEscapers() {
		xssInadequateEscaperNodes.clear();
		int marked = 0;
		PHPCGFactory.recordScanSite("PCG_7589", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof BinaryOperationExpression) ) continue;
			BinaryOperationExpression bin = (BinaryOperationExpression) n;
			if( !"BINARY_CONCAT".equals(bin.getFlags()) ) continue;
			Long esc = leadingXssEscaperNode(bin.getRight());
			if( esc == null ) continue;
			String escName = xssCallName(ASTUnderConstruction.idToNode.get(esc));
			int ctx = xssContextOf(rightmostLiteral(bin.getLeft()));
			if( ctx != XCTX_BODY && !xssEscaperAdequate(escName, ctx) ) {
				xssInadequateEscaperNodes.add(esc); marked++;
			}
		}
		if( marked > 0 ) System.err.println("WPXSSCTX "+marked+" context-inadequate escaper(s) not credited"
			+ " (URL/JS/unquoted-attribute output)");
	}

	private static void collectXssRiskNames(ASTNode n, Set<String> out) {
		if( n == null ) return;
		if( n instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)n);
			// Credit the escaper only if it is adequate for its output context. A context-inadequate
			// escaper (esc_html in an href/unquoted-attr, esc_attr in an href, …) is NOT crediting — fall
			// through so the escaped value is walked and its tainted var keeps the sink.
			if( isXssOutputEscaper(nm) && !xssInadequateEscaperNodes.contains(n.getNodeId()) ) return;   // escaped-at-output -> whole subtree safe
			// wp_kses($x, array()) — empty allowlist strips ALL HTML tags and is unconditionally safe.
			// The non-empty case is already handled above by isXssOutputEscaper (wp_kses is in htmlEscapers).
			if( "wp_kses".equals(nm) && isEmptyArrayArg((CallExpressionBase)n, 1) ) return;
			// XSS input sanitizers: strip HTML/JS metacharacters even though they leave SQL quotes.
			// sanitize_url strips javascript: scheme; sanitize_text_field/strip_tags strip markup.
			// When any of these wraps the tainted value, the subtree cannot carry XSS payloads to output.
			if( nm != null && PHPCSVEdgeInterpreter.xssInputSanitizers.contains(nm) ) return;
			// preg_replace($pattern, '', $input) where $pattern is a character class stripping
			// both < and > is an effective XSS sanitizer — the output cannot contain HTML tags.
			// Detects the common WordPress admin pattern:
			//   preg_replace('/[ <>\'"...]/', '', $input)
			// We require the pattern to contain both '<' and '>' to be conservative.
			if( "preg_replace".equals(nm) && isPregReplaceXssSanitizer((CallExpressionBase)n) ) return;
			// A stored-read source (get_post_meta/get_option/…) return value is itself a risk when
			// stored-taint is active: the value is attacker-controllable via a prior write, but being a
			// call-return rather than a bare variable it would otherwise slip past the risk-name walk and
			// let the sink be suppressed as "provably safe" (e.g. echo get_post_meta(intval($_POST['id']),
			// 'k') — the only variable is neutralised by intval, so nothing was flagged). Escaped stored
			// reads stay safe: the outer escaper check above returns before reaching here.
			if( STORED_TAINT && nm != null && STORED_SOURCE_FUNCS.contains(nm) ) { out.add(nm); return; }
			// A call to a resolved setting-getter wrapper is itself a stored read (its return value is the
			// attacker-controllable stored value), so it is a risk that keeps the output sink alive.
			if( STORED_TAINT && storedWrapperTargetOf((CallExpressionBase)n) != null ) { out.add("__storedwrap__"); return; }
		}
		if( n instanceof MethodCallExpression ) {
			Expression tf = ((MethodCallExpression)n).getTargetFunc();
			if( tf instanceof StringExpression && isXssOutputEscaper(((StringExpression)tf).getEscapedCodeStr()) ) return;
		}
		if( n instanceof ast.expressions.ConditionalExpression ) {
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)n;
			Expression t = ce.getTrueExpression();
			if( t != null ) collectXssRiskNames(t, out); else collectXssRiskNames(ce.getCondition(), out);
			collectXssRiskNames(ce.getFalseExpression(), out);
			return;
		}
		if( n instanceof Variable && ((Variable)n).getNameExpression() instanceof StringExpression ) {
			String vn = ((StringExpression)((Variable)n).getNameExpression()).getEscapedCodeStr();
			Long fid = n.getFuncId();
			if( literalOnlyVarsByFunc != null && fid != null
				&& literalOnlyVarsByFunc.containsKey(fid) && literalOnlyVarsByFunc.get(fid).contains(vn) )
				return;   // provably holds only literals in this scope -> constant, safe to output
			out.add(vn);
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
		if( kids != null ) for( Long c : kids.values() ) collectXssRiskNames(ASTUnderConstruction.idToNode.get(c), out);
	}

	private static boolean xssOutputProvablySafe(Long sinkId) {
		ASTNode n = ASTUnderConstruction.idToNode.get(sinkId);
		if( n == null ) return false;
		Set<String> risk = new HashSet<String>();
		collectXssRiskNames(n, risk);
		return risk.isEmpty();
	}

	/** Public accessor for StaticAnalysis to call at the interprocedural sink-check point. */
	public static boolean xssOutputProvablySafePublic(Long sinkId) {
		return xssOutputProvablySafe(sinkId);
	}

	/** Public wrapper for isXssOutputEscaper for use in StaticAnalysis. */
	public static boolean isXssOutputEscaperPublic(String nm) {
		return isXssOutputEscaper(nm);
	}

	/**
	 * True if this preg_replace call is a character-class sanitizer that strips both
	 * '<' and '>' from its input, making XSS impossible in the result.
	 * Pattern: preg_replace('/[...<...>...]/', '', $input)
	 * We require: (a) pattern arg is a string literal, (b) pattern contains both '<' and '>',
	 * (c) replacement arg is an empty string ''.
	 */
	static boolean isPregReplaceXssSanitizer(CallExpressionBase c) {
		ArgumentList args = c.getArgumentList();
		if( args == null || args.size() < 2 ) return false;
		// Check arg 0: regex pattern — must be a string literal containing < and >
		Expression patArg = args.getArgument(0);
		if( patArg == null ) return false;
		String pat = null;
		if( patArg instanceof StringExpression ) pat = ((StringExpression)patArg).getEscapedCodeStr();
		if( pat == null ) return false;
		// Strip surrounding quotes if present
		if( pat.length() >= 2 ) {
			char f = pat.charAt(0), l = pat.charAt(pat.length()-1);
			if( (f=='\'' || f=='"') && f==l ) pat = pat.substring(1, pat.length()-1);
		}
		// Must contain both < and > (or their hex/unicode escapes are too rare to worry about)
		if( !pat.contains("<") || !pat.contains(">") ) return false;
		// FIX (2026-08-08): reject any pattern containing a negated character class ([^...]).
		// Confirmed as a genuine gap: this check previously only looked for the literal
		// characters '<' and '>' appearing ANYWHERE in the pattern text, which a pattern like
		// '/[^<>]/' (matching -- and stripping -- everything EXCEPT '<' and '>', the OPPOSITE of
		// what this function claims to prove) also satisfies. Deliberately conservative rather
		// than attempting to fully parse the regex to determine what it actually matches: a
		// pattern like '/<[^>]*>/' (a genuine, common HTML-tag-stripping idiom) also contains
		// "[^" and will now also be rejected as unproven -- a false negative for sanitizer
		// recognition (an extra REVIEW-tier finding on code that may be genuinely safe), not a
		// false claim of safety. This is the same "when uncertain, don't silently clear" tradeoff
		// applied elsewhere in this engine, not a new principle introduced here.
		if( pat.contains("[^") ) return false;
		// Check arg 1: replacement — must be empty string '' or ""
		Expression replArg = args.getArgument(1);
		if( replArg == null ) return false;
		String repl = null;
		if( replArg instanceof StringExpression ) repl = ((StringExpression)replArg).getEscapedCodeStr();
		if( repl == null ) return false;
		if( repl.length() >= 2 ) {
			char f = repl.charAt(0), l = repl.charAt(repl.length()-1);
			if( (f=='\'' || f=='"') && f==l ) repl = repl.substring(1, repl.length()-1);
		}
		return repl.isEmpty();
	}

	/** Public wrapper for isPregReplaceXssSanitizer, for StaticAnalysis. */
	public static boolean isPregReplaceXssSanitizerPublic(CallExpressionBase c) {
		return isPregReplaceXssSanitizer(c);
	}

	private static void filterProvablySafeXssSinks() {
		markContextInadequateXssEscapers();   // decide which escapers are context-adequate first
		// echo/print sinks (xsssinks): split into three buckets —
		//   NUMERIC COERCERS: output cannot carry metacharacters in any context → delete (safe to suppress)
		//   NAMED ESCAPERS:   name-only match; wrong in context-mismatch or shadowing cases → tag-and-keep
		//   NOT SAFE:         risky variables remain in subtree → keep untouched (will produce a finding)
		java.util.List<Long> toDelete = new java.util.ArrayList<>();
		int tagged = 0;
		for( Long sinkId : tools.php.ast2cpg.PHPCSVNodeInterpreter.xsssinks ) {
			String escaperName = xssOutputEscaperName(sinkId);
			if( escaperName == null ) continue;   // not provably safe — leave as-is
			if( NUMERIC_COERCERS.contains(escaperName) ) {
				toDelete.add(sinkId);             // numeric coercer: deletion is sound
			} else {
				xssEscaperMatched.put(sinkId, escaperName);   // named escaper: tag for review
				tagged++;
			}
		}
		tools.php.ast2cpg.PHPCSVNodeInterpreter.xsssinks.removeAll(toDelete);
		if( !toDelete.isEmpty() ) System.err.println("WPXSSSAFE deleted "+toDelete.size()
			+" echo/print sinks suppressed by numeric coercer (intval/absint/floatval) — output cannot carry XSS payload");
		if( tagged > 0 ) System.err.println("WPXSSESCAPED tagged "+tagged
			+" echo/print sinks matched by escaper name only — KEPT for review (name match is not context-checked)");
		// XSS-class FUNCTION-CALL output sinks (printf/vprintf/print_r/die output) live in `sinks`, not
		// xsssinks, and otherwise never credit an html escaper — so printf('...%s...', esc_html($x)) was a
		// false positive. Credit escapers context-awarely: for printf/vprintf the %s position's context is
		// read from the format string (so esc_html in a "<a href=%s>" is still KEPT, no false negative);
		// print_r/print/die output a single value judged by the generic escaped-at-output check.
		java.util.List<Long> safeCall = new java.util.ArrayList<Long>();
		for( Long s : sinks ) {
			if( !"xss".equals(sinkClass.get(s)) ) continue;
			ASTNode sn = ASTUnderConstruction.idToNode.get(s);
			String cn = (sn instanceof CallExpressionBase) ? callTargetName((CallExpressionBase)sn) : null;
			boolean safe = ("printf".equals(cn) || "vprintf".equals(cn))
				? printfFormatSafe((CallExpressionBase)sn)
				: xssOutputProvablySafe(s);
			if( safe ) {
				// Same split: numeric coercers → delete; named escapers → tag
				String en = xssOutputEscaperName(s);
				if( en != null && !NUMERIC_COERCERS.contains(en) ) {
					xssEscaperMatched.put(s, en);   // tag, do NOT add to safeCall
				} else {
					safeCall.add(s);
				}
			}
		}
		for( Long s : safeCall ) { sinks.remove(s); sinkClass.remove(s); }
		if( !safeCall.isEmpty() ) System.err.println("WPXSSSAFE suppressed "+safeCall.size()
			+" provably-safe function-call output sink(s) (printf/print_r/die)");
	}

	// True if a value handed to a printf-style conversion is provably safe in the given output context:
	// a constant literal, or an escaper call adequate for that context (esc_url for URL, esc_js for JS,
	// any html escaper for body/quoted-attr, numeric narrowers everywhere). A bare/tainted value is not.
	private static boolean argEscapedAdequately( Expression arg, int ctx ) {
		if( arg == null ) return false;
		if( arg instanceof StringExpression ) return true;                 // constant
		if( arg instanceof CallExpressionBase ) {
			String nm = callTargetName((CallExpressionBase)arg);
			if( isXssOutputEscaper(nm) ) return xssEscaperAdequate(nm, ctx);
		}
		return false;                                                       // bare var / unrecognized -> risk
	}
	// printf/vprintf provably safe: format arg is a literal AND every %s/%S conversion's data argument is
	// safe for the context implied by the format text preceding that conversion. Numeric/char conversions
	// are inherently safe. A dynamic (non-literal) format is not provably safe -> keep the sink.
	private static boolean printfFormatSafe( CallExpressionBase call ) {
		ArgumentList al = call.getArgumentList();
		if( al == null || al.size() < 1 ) return false;
		Expression fmtArg = al.getArgument(0);
		if( !(fmtArg instanceof StringExpression) ) return false;           // dynamic format -> conservative keep
		String fmt = ((StringExpression)fmtArg).getEscapedCodeStr();
		if( fmt == null ) return false;
		int i = 0, n = fmt.length(), argPos = 1;
		StringBuilder pre = new StringBuilder();
		while( i < n ) {
			char c = fmt.charAt(i);
			if( c != '%' ) { pre.append(c); i++; continue; }
			int j = i + 1;
			if( j < n && fmt.charAt(j) == '%' ) { pre.append('%'); i = j + 1; continue; }  // %%
			int explicitArg = -1, k = j;
			while( k < n && Character.isDigit(fmt.charAt(k)) ) k++;
			if( k < n && k > j && fmt.charAt(k) == '$' ) { explicitArg = Integer.parseInt(fmt.substring(j,k)); j = k + 1; }
			// FIX (2026-08-08): PHP's custom pad-character flag is %'X -- the single quote is
			// itself a flag character, but the very NEXT character is an arbitrary, unconstrained
			// pad character, not a second flag to be matched against the flag set. Confirmed
			// against real PHP output: printf("%'s10d", 5) pads with literal "s" characters, using
			// "s" purely as a pad char with no relation to the %s string conversion. The original
			// loop below only consumed a following character if it also happened to be IN the flag
			// set, so a pad char outside that set (e.g. "s") was left unconsumed and misidentified
			// as the conversion specifier itself, silently skipping past the format string's real,
			// later specifier -- risking a genuinely tainted %s argument being missed and the
			// printf call incorrectly cleared as provably safe.
			while( j < n && "+-# 0'".indexOf(fmt.charAt(j)) >= 0 ) {
				boolean wasQuote = fmt.charAt(j) == '\'';
				j++;
				if( wasQuote && j < n ) j++;     // consume the pad character unconditionally
			}
			while( j < n && Character.isDigit(fmt.charAt(j)) ) j++;         // width
			if( j < n && fmt.charAt(j) == '.' ) { j++; while( j < n && Character.isDigit(fmt.charAt(j)) ) j++; } // precision
			if( j >= n ) return false;                                      // malformed -> keep
			char spec = fmt.charAt(j);
			int dataIdx = (explicitArg > 0) ? explicitArg : argPos++;
			if( spec == 's' || spec == 'S' ) {
				int ctx = xssContextOf(pre.toString());
				Expression dataArg = (al.size() > dataIdx) ? al.getArgument(dataIdx) : null;
				if( !argEscapedAdequately(dataArg, ctx) ) return false;     // tainted/inadequate string -> KEEP
			}
			// numeric/char conversions (d,i,u,f,g,e,x,o,b,c,...) are inherently markup-safe
			i = j + 1;
		}
		return true;
	}

	// PHP CALLABLE DISPATCH (recall fix). Stock TChecker resolves $obj->$m() but NOT the
	// call_user_func / array-callable indirection, so taint passed through the very common AJAX-router
	// pattern  call_user_func(array($this->commands, $this->subaction), $this->data)  never reaches the
	// callee — every command method reads as unanalyzed. We resolve the target function/method(s) into
	// call2mtd (so the dataflow enters them) and record the call site in callableArgOffset (so the
	// dataflow maps arg[i+1] -> param[i], skipping the leading callable argument).
	public static Set<Long> callableArgOffset = new HashSet<Long>();
	// call_user_func_array('fn', array($a,$b)): the real args are the ELEMENTS of arg[1]'s array
	// literal (element[i] -> param[i]), not positional trailing args. Tracked separately so the
	// arg-forwarding unpacks the array instead of applying the +1 positional shift.
	public static Set<Long> cufaArrayArg = new HashSet<Long>();

	// Collect class names constructed anywhere in an expression: a direct  new X()  or one buried as an
	// argument to a wrapper call, e.g.  apply_filters('hook', new X())  /  new X($args). Used as a
	// fallback when ParseVar can't infer a call_user_func receiver's type because the constructor is
	// hidden inside such a wrapper (wp-optimize: $this->commands = apply_filters(_, new WP_Optimize_Commands())).
	private static void collectNewClassNames(Expression e, Set<String> out, int depth) {
		if( e == null || depth > 4 ) return;
		if( e instanceof NewExpression && ((NewExpression)e).getTargetClass() instanceof Identifier ) {
			Identifier id = (Identifier)((NewExpression)e).getTargetClass();
			if( id.getNameChild() != null ) out.add(id.getNameChild().getEscapedCodeStr());
		} else if( e instanceof CallExpressionBase ) {
			ArgumentList a = ((CallExpressionBase)e).getArgumentList();
			if( a != null ) for( int i=0; i<a.size(); i++ ) collectNewClassNames(a.getArgument(i), out, depth+1);
		}
	}


	// RECALL: inline request source used directly as a call argument (e.g. f($_GET['x']) or
	// call_user_func('f',$_GET['x'])). Both inline-source mechanisms in the taint pass gate on the
	// source sitting inside a SINK statement, so a source passed to a NON-sink callee is dropped and
	// the callee reads as untainted. Forward it: for each call with a resolved user-function target
	// and an inline-source argument, seed the corresponding callee PARAMETER as a source
	// (sources + hookParamSourceNodes = "tainted by fiat", the mechanism hook params already use), so
	// the existing interprocedural analysis carries it from the param through the callee to its sinks.

	// Export the resolved interprocedural call graph (call2mtd: callsite -> target function nodes)
	// so the adjudicator can walk the SAME edges the analyzer resolved — including call_user_func[_array],
	// variable-function, and method dispatch that a source-text regex can't follow. Emits caller-function
	// node -> target-function node pairs; the adjudicator maps nodes to bodies via nodes.csv.
	private static void dumpSetterStats() {
		if( System.getenv("WP_SETTER_STATS") == null ) return;
		// Full funnel: field written-from-a-var (setter) whose SAME field name is later read inside a
		// function that contains a sink. Upper bound on setter->sink findings (receiver-insensitive
		// name match, matching the engine's own property model). Answers whether the setter fix pays off.
		java.util.Set<Long> sinkFids = new java.util.HashSet<Long>();
		for( Long s : sinks ) { ASTNode sn = ASTUnderConstruction.idToNode.get(s); if( sn != null && sn.getFuncId() != null ) sinkFids.add(sn.getFuncId()); }
		java.util.Set<String> setterFields = new java.util.HashSet<String>();
		java.util.Set<Long> writeNodes = new java.util.HashSet<Long>();
		int propWrites = 0, propWriteFromVar = 0;
		PHPCGFactory.recordScanSite("PCG_7895", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			Expression lhs = ((AssignmentExpression)n).getLeft();
			if( !(lhs instanceof PropertyExpression) ) continue;
			propWrites++; writeNodes.add(lhs.getNodeId());
			if( ((AssignmentExpression)n).getRight() instanceof Variable ) {
				propWriteFromVar++;
				Expression prop = ((PropertyExpression)lhs).getPropertyExpression();
				if( prop instanceof StringExpression ) setterFields.add(((StringExpression)prop).getEscapedCodeStr());
			}
		}
		java.util.Set<String> sinkReadFields = new java.util.HashSet<String>();
		PHPCGFactory.recordScanSite("PCG_7907", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof PropertyExpression) || writeNodes.contains(n.getNodeId()) ) continue;
			Long fid = n.getFuncId();
			if( fid == null || !sinkFids.contains(fid) ) continue;
			Expression prop = ((PropertyExpression)n).getPropertyExpression();
			if( prop instanceof StringExpression ) sinkReadFields.add(((StringExpression)prop).getEscapedCodeStr());
		}
		int inter = 0;
		for( String f : setterFields ) if( sinkReadFields.contains(f) ) inter++;
		System.err.println("SETTERSTATS propertyWrites="+propWrites+" RHSisVar="+propWriteFromVar
			+" | setterFieldNames="+setterFields.size()+" fieldsReadInSinkFn="+sinkReadFields.size()
			+" setter->sink(upperBound)="+inter+" [totalSinks="+sinks.size()+"]");
	}

	private static void dumpPropertyReceiverStats() {
		if( System.getenv("WP_PROP_STATS") == null ) return;
		// Quantifies the cross-object over-taint SURFACE of the receiver-insensitive property abstraction
		// (tainting $a->name taints $b->name). $this-> access is within-method self-access; the visible
		// cross-object risk is a property NAME reached through 2+ distinct NAMED receiver variables.
		int total=0, thisRecv=0, namedRecv=0, dynamic=0;
		java.util.HashMap<String, java.util.Set<String>> propToRecv = new java.util.HashMap<String, java.util.Set<String>>();
		PHPCGFactory.recordScanSite("PCG_7928", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof PropertyExpression) ) continue;
			total++;
			Expression prop = ((PropertyExpression)n).getPropertyExpression();
			String pn = (prop instanceof StringExpression) ? ((StringExpression)prop).getEscapedCodeStr() : null;
			String recv = lvalKey(((PropertyExpression)n).getObjectExpression());
			if( pn == null || recv == null ) { dynamic++; continue; }
			if( "this".equals(recv) ) thisRecv++; else namedRecv++;
			propToRecv.computeIfAbsent(pn, k -> new java.util.HashSet<String>()).add(recv);
		}
		int multiNamed = 0;
		for( java.util.Set<String> recvs : propToRecv.values() ) {
			int named = 0; for( String r : recvs ) if( !"this".equals(r) ) named++;
			if( named >= 2 ) multiNamed++;
		}
		System.err.println("PROPSTATS total="+total+" this="+thisRecv+" named="+namedRecv+" dynamic="+dynamic
			+" | distinctPropNames="+propToRecv.size()+" propsWith2+NamedReceivers="+multiNamed);
	}

	private static void dumpCallResolutionStats() {
		if( System.getenv("WP_CALL_RESOLUTION_STATS") == null ) return;
		// Separates CALL-GRAPH quality (does call2mtd resolve the call to a target?) from PROPAGATION
		// quality (does taint flow through it?). Supports the claim that the remaining method-call
		// limitation is propagation, not resolution: if method M/N is high, the edges exist and only the
		// forward's failure to iterate method calls loses the taint.
		int mN = nonStaticMethodCalls.size(), mM = 0, mGapInternal = 0, mExternal = 0, mDynamic = 0;
		for( MethodCallExpression mc : nonStaticMethodCalls ) {
			java.util.List<Long> t = call2mtd.get(mc.getNodeId());
			if( t != null && !t.isEmpty() ) { mM++; continue; }
			// unresolved: classify. A literal name defined in-plugin but unresolved is a REAL call-graph
			// gap; a name with no in-plugin definition is an external/core call (correctly unresolved);
			// a variable name is dynamic dispatch.
			Expression tf = mc.getTargetFunc();
			if( tf instanceof StringExpression ) {
				String nm = ((StringExpression)tf).getEscapedCodeStr();
				if( !resolveCallbackFids(nm).isEmpty() ) mGapInternal++; else mExternal++;
			} else mDynamic++;
		}
		System.err.println("CALLRESOLUTION method: resolved="+mM+"/"+mN
			+" internalGap="+mGapInternal+" external="+mExternal+" dynamic="+mDynamic);
		// FUNNEL: of RESOLVED method calls, how many even carry a tainted arg? Caps the method-forwarding
		// payoff — if few resolved calls have tainted args, a propagation engine buys little here.
		int mResolvedTainted = 0;
		for( MethodCallExpression mc : nonStaticMethodCalls ) {
			java.util.List<Long> t = call2mtd.get(mc.getNodeId());
			if( t == null || t.isEmpty() ) continue;
			ArgumentList al = mc.getArgumentList();
			if( al == null ) continue;
			for( int i = 0; i < al.size(); i++ ) {
				Expression a = al.getArgument(i);
				if( a != null && subtreeHasSourceIn(a.getNodeId(), PHPCSVEdgeInterpreter.sources, 0) ) { mResolvedTainted++; break; }
			}
		}
		System.err.println("CALLRESOLUTION method-funnel: resolved="+mM+" with-tainted-arg="+mResolvedTainted);
	}

	// Branch-reconciliation export (WP_DUMP_SUMMARIES=1): emit the engine's already-computed Layer-1B
	// summaries as TSV so the layer1_fact_check.py diagnostic can read them. Pure export — reads
	// retArbitraryFids / sinks / topFunIds, changes NO detector behavior.
	private static void dumpSummaries() {
		if( System.getenv("WP_DUMP_SUMMARIES") == null ) return;
		Set<Long> allDefs = new HashSet<Long>();
		allDefs.addAll(allFunc); allDefs.addAll(allMtd); allDefs.addAll(allStaticMtd);
		// return_summaries.csv : function name -> returns a source-derived value (retArbitraryFids)
		try {
			java.util.LinkedHashMap<String,Boolean> rmap = new java.util.LinkedHashMap<String,Boolean>();
			for( Long fid : allDefs ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(fid);
				if( !(n instanceof FunctionDef) ) continue;
				String nm = ((FunctionDef)n).getName();
				if( nm == null ) continue;
				boolean rs = retArbitraryFids.contains(fid);
				Boolean prev = rmap.get(nm);
				rmap.put(nm, prev == null ? rs : (prev || rs));
			}
			java.io.PrintWriter w = new java.io.PrintWriter(new java.io.FileWriter("return_summaries.csv"));
			w.println("name\treturns_source");
			for( java.util.Map.Entry<String,Boolean> e : rmap.entrySet() )
				w.println(e.getKey() + "\t" + (e.getValue() ? "true" : "false"));
			w.close();
		} catch( Exception e ) { System.err.println("SUMMARIES return dump failed: " + e); }
		// hook_summaries.csv : (hook, callback) -> return_sink_registered, seeded_as_root, seed_reason
		try {
			java.io.PrintWriter hw = new java.io.PrintWriter(new java.io.FileWriter("hook_summaries.csv"));
			hw.println("hook\tcallback\treturn_sink_registered\tseeded_as_root\tseed_reason");
			java.util.LinkedHashSet<String> emitted = new java.util.LinkedHashSet<String>();
			for( CallExpressionBase fc : functionCalls ) {
				if( !(fc.getTargetFunc() instanceof Identifier) ) continue;
				Identifier tid = (Identifier)fc.getTargetFunc();
				if( tid.getNameChild() == null ) continue;
				String callName = tid.getNameChild().getEscapedCodeStr();
				ArgumentList args = fc.getArgumentList();
				if( args == null ) continue;
				String hook = null, cbName = null;
				if( (callName.equals("add_action") || callName.equals("add_filter")) && args.size() >= 2 ) {
					Expression tagE = args.getArgument(0);
					if( tagE instanceof StringExpression ) hook = ((StringExpression)tagE).getEscapedCodeStr();
					cbName = resolveCallbackName(args.getArgument(1));
				} else if( callName.equals("register_rest_route") && args.size() >= 3 ) {
					Expression routeE = args.getArgument(1);
					if( routeE instanceof StringExpression ) hook = "rest:" + ((StringExpression)routeE).getEscapedCodeStr();
					Expression cfg = args.getArgument(2);
					if( cfg instanceof ArrayExpression )
						for( ArrayElement el : (ArrayExpression)cfg )
							if( el.getKey() instanceof StringExpression
									&& "callback".equals(((StringExpression)el.getKey()).getEscapedCodeStr()) )
								cbName = resolveCallbackName(el.getValue());
				}
				if( hook == null || cbName == null ) continue;
				Set<Long> cbFids = new HashSet<Long>();
				for( Long fid : allDefs ) {
					ASTNode n = ASTUnderConstruction.idToNode.get(fid);
					if( n instanceof FunctionDef && cbName.equals(((FunctionDef)n).getName()) ) cbFids.add(fid);
				}
				boolean seeded = false;
				for( Long fid : cbFids ) if( topFunIds.contains(fid) ) { seeded = true; break; }
				boolean retSink = false;
				PHPCGFactory.recordScanSite("PCG_8045", ASTUnderConstruction.idToNode.size());
				for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
					if( node instanceof ast.statements.jump.ReturnStatement && node.getFuncId() != null
							&& cbFids.contains(node.getFuncId()) && sinks.contains(node.getNodeId()) ) { retSink = true; break; }
				}
				String reason = isSqlClauseFilter(hook) ? "sql_filter_return_sink"
						: (seeded ? "entry_hook" : "not_seeded");
				String rowKey = hook + "\t" + cbName;
				if( emitted.add(rowKey) )
					hw.println(hook + "\t" + cbName + "\t" + retSink + "\t" + seeded + "\t" + reason);
			}
			hw.close();
		} catch( Exception e ) { System.err.println("SUMMARIES hook dump failed: " + e); }
	}


	// ==================================================================================
	// ControlReachabilityAnalysis — GENERIC, vulnerability-class independent.
	//
	//     ENTRY  --resolved call path-->  SECURITY-SENSITIVE OPERATION
	//
	// Value flow asks "does attacker DATA reach a sink argument?". This asks the orthogonal
	// question "can an attacker cause the operation to EXECUTE at all?" — the shape where every
	// argument is constant yet any visitor can trigger the effect.
	//
	// Path discovery, witness construction, accounting and coverage disclosure live HERE and are
	// class-independent. Everything framework-specific (which hooks are entries, what an entry's
	// access level means, which calls are guards and what KIND of guard they are) is supplied by
	// a SecurityShape + adapter below, so adding a class is a data change, not a new pass.
	// ==================================================================================

	/** Guard semantics are categorised, never conflated. Request integrity is NOT authorization. */
	enum GuardKind { AUTHORIZATION, REQUEST_INTEGRITY, OWNERSHIP, INPUT_ALLOWLIST }

	static final class SecurityShape {
		final String name;                        // evidence class tag
		final String sinkClassPrefix;             // which sinkClass tags belong to this shape
		final java.util.Map<String,GuardKind> guards;   // guard fn name -> semantic category
		SecurityShape(String n, String p, java.util.Map<String,GuardKind> g) {
			name=n; sinkClassPrefix=p; guards=g;
		}
	}

	/** Accounting shared by every analysis pass. A zero result is only meaningful beside this. */
	public static final class PassResult {
		public String shapeName = "";
		public int entriesConsidered, entriesUnclassifiedTraversed, entriesDroppedNotReachable;
		public int sinksConsidered, pathsFound, pathsEmitted, traversalsTruncated;
		// Truncation is decomposed by REASON and DEDUPLICATED by frontier state. A raw event count
		// is uninterpretable: 2150 events over 40 repeated frontier states means the bound is not
		// the constraint, while 2150 DISTINCT states hitting a shallow cap means it is.
		public final java.util.Map<String,Integer> truncByReason = new java.util.LinkedHashMap<String,Integer>();
		public final java.util.Set<String> truncStates = new HashSet<String>();
		public final java.util.Set<Long> truncEntries = new HashSet<Long>();
		void truncate(String reason, Long entry, Long frontier, int depth) {
			traversalsTruncated++;
			Integer c = truncByReason.get(reason);
			truncByReason.put(reason, c == null ? 1 : c + 1);
			truncStates.add(reason + ":" + frontier + ":" + depth);
			truncEntries.add(entry);
		}
		String terminalReason = "";
		String render(String pass) {
			return pass+" ACCOUNTING entries_considered="+entriesConsidered
				+" entries_unclassified_TRAVERSED_as_unknown="+entriesUnclassifiedTraversed
				+" entries_dropped="+entriesDroppedNotReachable
				+" sinks_considered="+sinksConsidered
				+" entry_sink_paths_found="+pathsFound
				+" paths_emitted="+pathsEmitted
				+" truncation_events="+traversalsTruncated
				+" truncation_unique_states="+truncStates.size()
				+" truncation_entries_affected="+truncEntries.size()
				+" truncation_by_reason="+truncByReason
				+(terminalReason.isEmpty()?"":" reason="+terminalReason)+" (pass EXECUTED)";
		}
	}

	// ---- WordPress ADAPTER: the only place framework semantics are encoded -------------------
	// FIX (2026-08-08): resolve simple, unambiguous, first-party define() constants used as a
	// guard call's argument -- current_user_can(NF_USER_LEVEL) where
	// define('NF_USER_LEVEL', 'manage_options') appears exactly once, both arguments literal
	// strings. Motivated by a real, confirmed precision gap found on NEX-Forms
	// (CVE-2026-15450): the CAPABILITY check itself was already correctly detected and credited
	// (controls_sink=true, any_capability_check_controls_sink=true -- this was NOT a missing-
	// check bug, confirmed by re-reading the actual evidence before starting this work), but
	// argument_raw/argument_normalized stayed "UNKNOWN" for a constant argument instead of
	// showing the actual capability string, which matters for evidence completeness and any
	// future work that needs the real capability name (e.g. an eventual sufficiency check).
	// Deliberately narrow -- this is a lookup table for ONE call shape, not a constant-
	// propagation engine:
	//   - resolves ONLY define('LITERAL_NAME', 'LITERAL_VALUE') -- both arguments literal
	//     strings, checked structurally, no evaluation of any kind
	//   - a name defined more than once (even with the same value) is treated as ambiguous and
	//     left unresolved, rather than guessing which definition applies at any given call site
	//   - a bare Identifier argument at a guard call site is looked up in this table; anything
	//     else (a variable, a class constant, a computed expression) is untouched and stays
	//     whatever the existing resolution already produces
	//   - does not change checkKind()/GuardKind classification, controls_sink, or credit toward
	//     any_capability_check_controls_sink in any way -- those were already correct and are
	//     computed entirely independently of this resolution
	private static java.util.Map<String,String> resolveDefineConstants() {
		java.util.Map<String,String> resolved = new HashMap<String,String>();
		java.util.Set<String> ambiguous = new HashSet<String>();
		for( CallExpressionBase fc : functionCalls ) {
			String name = callTargetName(fc);
			if( !"define".equals(name) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 2 ) continue;
			Expression nameArg = al.getArgument(0), valArg = al.getArgument(1);
			if( !(nameArg instanceof StringExpression) || !(valArg instanceof StringExpression) ) continue;
			String cname = ((StringExpression)nameArg).getEscapedCodeStr();
			String cval  = ((StringExpression)valArg).getEscapedCodeStr();
			if( ambiguous.contains(cname) ) continue;
			if( resolved.containsKey(cname) ) {
				resolved.remove(cname);
				ambiguous.add(cname);          // second definition seen -> unresolved, not a guess
				continue;
			}
			resolved.put(cname, cval);
		}
		return resolved;
	}
	// Lazily computed once, reused across every collectCheckFacts() call (one per witness/shape)
	// rather than rescanning functionCalls each time.
	private static java.util.Map<String,String> _defineConstantsCache = null;
	private static java.util.Map<String,String> DEFINE_CONSTANTS() {
		if( _defineConstantsCache == null ) _defineConstantsCache = resolveDefineConstants();
		return _defineConstantsCache;
	}

	private static java.util.Map<String,GuardKind> wpGuards() {
		java.util.Map<String,GuardKind> g = new HashMap<String,GuardKind>();
		g.put("current_user_can", GuardKind.AUTHORIZATION);
		g.put("user_can", GuardKind.AUTHORIZATION);
		g.put("current_user_can_for_blog", GuardKind.AUTHORIZATION);
		g.put("check_ajax_referer", GuardKind.REQUEST_INTEGRITY);
		g.put("wp_verify_nonce", GuardKind.REQUEST_INTEGRITY);
		g.put("check_admin_referer", GuardKind.REQUEST_INTEGRITY);
		g.put("current_user_owns", GuardKind.OWNERSHIP);
		g.putAll(oneHopGuardWrapperFunctions(g));
		return g;
	}

	// FIX (2026-08-08): one-hop guard-wrapper resolution. Motivated by a real, verified case found
	// scanning Really Simple SSL (5M+ installs, no known CVE): rsssl_admin::init() opens with
	// `if (!rsssl_user_can_manage()) return;`, and rsssl_user_can_manage() itself directly wraps
	// `current_user_can('manage_security')`. The guard genuinely exists and genuinely controls the
	// sink -- but was invisible to collectCheckFacts(), which only matches shape.guards against the
	// LITERAL function name at each candidate guard call site, with no interprocedural step to see
	// that a called function is itself, one level down, wrapping a recognized guard. Wrapping a
	// recognized guard in a small, named, project-specific helper (`rsssl_user_can_manage`,
	// `current_user_can_wrapper`, etc.) is a common, unremarkable WordPress coding convention, not
	// specific to this one plugin -- this is a real false-negative class, not a labeling artifact.
	//
	// DELIBERATELY NARROW, matching this session's discipline for every prior extension:
	//  - top-level functions only (no methods) for this first pass -- methods are a separate,
	//    later extension if warranted, not silently folded in here.
	//  - exactly ONE hop: a wrapper's body may call a *directly recognized* guard (from the base
	//    wpGuards() map, not from a wrapper found in this same pass) -- no transitive chains of
	//    wrappers wrapping wrappers. A function that only reaches a guard through another wrapper
	//    is NOT recognized by this pass, by design, to keep the recognized shape small and
	//    auditable rather than open-ended interprocedural resolution.
	//  - exactly two recognized shapes, both confirmed against the real motivating case and
	//    directly reusing guardRelation()'s own AST_IF/AST_RETURN primitives rather than a new,
	//    separately-verified traversal:
	//      (a) `return <guardcall>(...);` -- the guard call is the direct, immediate argument of
	//          a return statement.
	//      (b) `if (<guardcall>(...)) { ... return <truthy>; ... }` -- the guard call is an
	//          AST_IF/AST_IF_ELEM condition whose consequent subtree contains an AST_RETURN.
	//  - a function must contain ONLY ONE recognized-guard call across its whole body to qualify.
	//    A function calling a guard alongside unrelated guard-adjacent logic (multiple different
	//    checks, complex branching) is deliberately left unrecognized rather than guessed at --
	//    this keeps the detector's claim narrow ("this function's behavior IS this one guard call")
	//    rather than broad ("this function probably does something guard-like").
	private static java.util.Map<String,GuardKind> oneHopGuardWrapperFunctions(
			java.util.Map<String,GuardKind> baseGuards) {
		java.util.Map<String,GuardKind> wrappers = new HashMap<String,GuardKind>();
		// group recognized-guard calls by their enclosing top-level function id
		java.util.Map<Long,java.util.List<CallExpressionBase>> byFunc = new HashMap<Long,java.util.List<CallExpressionBase>>();
		for( CallExpressionBase gc : functionCalls ) {
			String gn = callTargetName(gc);
			if( gn == null || !baseGuards.containsKey(gn) ) continue;
			Long fid = null; try { fid = gc.getFuncId(); } catch( Exception e ) {}
			if( fid == null ) continue;
			if( !byFunc.containsKey(fid) ) byFunc.put(fid, new java.util.ArrayList<CallExpressionBase>());
			byFunc.get(fid).add(gc);
		}
		for( java.util.Map.Entry<Long,java.util.List<CallExpressionBase>> e : byFunc.entrySet() ) {
			if( e.getValue().size() != 1 ) continue;               // exactly one guard call, no more
			Long fid = e.getKey();
			CallExpressionBase gc = e.getValue().get(0);
			ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
			if( fn == null ) continue;
			String cls = null;
			try { cls = fn.getEnclosingClass(); } catch( Exception ex ) {}
			// FIX (2026-08-08): static-method wrapper resolution. Was: methods excluded entirely
			// this pass. Motivated by a real, confirmed case found cold-scanning UpdraftPlus
			// (3M+ installs, no known CVE): UpdraftPlus_Options::user_can_manage() -- a public
			// static method directly wrapping current_user_can('manage_options') -- gates the
			// plugin's backup-file-spooling functions, and was invisible to guard detection for
			// exactly the reason the earlier top-level-function-only version of this fix
			// documented as its own known boundary. Deliberately still narrow: STATIC methods
			// only, not instance methods (`$this->guard()`) -- resolving an instance call's
			// actual receiver class reliably is a materially different, harder problem (the same
			// kind of receiver-identity question PRIV_ESC_METHODS' own
			// privEscMethodProvablyNotWpUser() exists to handle for SINKS), left for a separate,
			// later extension rather than folded in here. Every other constraint from the
			// original fix is unchanged: exactly one hop, exactly one recognized-guard-call per
			// candidate wrapper, no shadowing a real guard name.
			boolean isStaticMethodCandidate = ( cls != null && !cls.isEmpty()
				&& fn instanceof ast.php.functionDef.Method
				&& fn.getFlags().contains(PHPCSVNodeTypes.FLAG_MODIFIER_STATIC) );
			if( cls != null && !cls.isEmpty() && !isStaticMethodCandidate ) continue;  // instance methods excluded this pass
			String wrapperName = funcIdentity(fid);
			if( wrapperName == null || "anonymous".equals(wrapperName) ) continue;
			if( baseGuards.containsKey(wrapperName) ) continue;      // don't shadow a real guard name
			GuardKind k = baseGuards.get(callTargetName(gc));
			if( isDirectlyReturned(gc) || isGuardedByIfWithReturn(gc)
			    || isAssignedThenReturnedPossiblyFiltered(gc) ) {
				wrappers.put(wrapperName, k);
			}
		}
		return wrappers;
	}

	// Shape (a): return <guardcall>(...);  -- the call's immediate parent is an AST_RETURN.
	private static boolean isDirectlyReturned(CallExpressionBase gc) {
		try {
			Long parent = PHPCSVEdgeInterpreter.child2parent.get(gc.getNodeId());
			ASTNode p = ASTUnderConstruction.idToNode.get(parent);
			return p != null && "AST_RETURN".equals(p.getProperty("type"));
		} catch( Exception ex ) { return false; }
	}

	// Shape (b): if (<guardcall>(...)) { ... return ...; ... }  -- reuses guardRelation()'s own
	// walk-to-enclosing-if and subtree-search primitives rather than a new, separately-verified
	// traversal. Deliberately does not require the return's value be a literal `true` -- ANY
	// return inside the guard's own consequent branch is accepted (matching the verified case,
	// which has two such branches: a literal `true` and a WP_CLI escape hatch), since requiring a
	// specific literal would be a narrower, more brittle check than the actual risk (an
	// unconditional early exit gated by the guard) that this shape is verifying.
	private static boolean isGuardedByIfWithReturn(CallExpressionBase gc) {
		try {
			Long cur = gc.getNodeId(); Long condNode = null; int g = 0;
			while( cur != null && g++ < 64 ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(cur);
				if( n != null && ("AST_IF".equals(n.getProperty("type"))
				    || "AST_IF_ELEM".equals(n.getProperty("type"))) ) { condNode = cur; break; }
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
			if( condNode == null ) return false;
			java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>(); q.add(condNode);
			java.util.Set<Long> seen = new HashSet<Long>(); int gg = 0;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				ASTNode xn = ASTUnderConstruction.idToNode.get(x);
				if( xn != null && "AST_RETURN".equals(xn.getProperty("type")) ) return true;
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kids != null ) q.addAll(kids.values());
			}
			return false;
		} catch( Exception ex ) { return false; }
	}

	// Shape (c): $var = <guardcall>(...); ... return apply_filters($tag, $var, ...);  -- the
	// guard call's result is assigned to a variable, then that variable is returned either
	// directly or as an argument to apply_filters() -- WordPress's canonical "pass this value
	// through, possibly modified by a registered filter" idiom. Motivated by a real, confirmed
	// case (UpdraftPlus_Options::user_can_manage(), verified against source): `$user_can_manage
	// = current_user_can(...); return apply_filters('updraft_user_can_manage', $user_can_manage,
	// false);`. Deliberately narrow: only apply_filters() specifically (not any arbitrary
	// function call taking the variable as an argument) -- apply_filters is a genuine,
	// well-understood WordPress semantic (returns the value unchanged when no filter is
	// registered for the tag, which is the overwhelming common case), not a general claim that
	// "any function touching this variable preserves its truthiness." A registered filter could
	// theoretically override the guard's decision -- this is not a stronger claim than that a
	// direct current_user_can() call could itself be overridden via WordPress's own
	// 'user_has_cap' filter, which this engine has never attempted to model either; both are
	// syntactic-guard facts with authorization_sufficiency already, separately, always
	// NOT_ESTABLISHED, not a claim of airtight enforcement.
	private static boolean isAssignedThenReturnedPossiblyFiltered(CallExpressionBase gc) {
		try {
			Long parent = PHPCSVEdgeInterpreter.child2parent.get(gc.getNodeId());
			ASTNode p = ASTUnderConstruction.idToNode.get(parent);
			if( !(p instanceof AssignmentExpression) ) return false;
			Expression lhs = ((AssignmentExpression)p).getLeft();
			String varName = varNameOf(lhs);
			if( varName == null ) return false;
			Long fid = enclosingFunctionId(gc.getNodeId());
			if( fid == null ) return false;
			java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>(); q.add(fid);
			java.util.Set<Long> seen = new HashSet<Long>(); int gg = 0;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				ASTNode xn = ASTUnderConstruction.idToNode.get(x);
				if( xn != null && "AST_RETURN".equals(xn.getProperty("type")) ) {
					HashMap<Integer,Long> rkids = PHPCSVEdgeInterpreter.parent2child.get(x);
					if( rkids != null ) for( Long rk : rkids.values() ) {
						ASTNode rn = ASTUnderConstruction.idToNode.get(rk);
						if( rn == null ) continue;
						// return $var; directly
						if( varName.equals(varNameOf(rn)) ) return true;
						// return apply_filters($tag, $var, ...); -- $var among its arguments
						if( rn instanceof CallExpressionBase
						    && "apply_filters".equals(callTargetName((CallExpressionBase)rn)) ) {
							ArgumentList al = ((CallExpressionBase)rn).getArgumentList();
							if( al != null ) for( int i = 0; i < al.size(); i++ )
								if( varName.equals(varNameOf(al.getArgument(i))) ) return true;
						}
					}
				}
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kids != null ) q.addAll(kids.values());
			}
			return false;
		} catch( Exception ex ) { return false; }
	}

	/** WordPress entry-access semantics. Authentication is NOT authorization. */
	// ITEM18 entry-access UNKNOWN reason buckets: which of several distinct mechanisms produced
	// an entry that ends up with no resolvable priv/access classification. Populated at each
	// seeding site that adds to topFunIds WITHOUT also setting entryPriv (the root cause of
	// priv==null -> "unknown-not-classified" in wpEntryAccess()), plus a catch-all for entries
	// that DO have a priv string but one wpEntryAccess()'s substring matching doesn't recognize.
	public static java.util.Set<Long> reasonSqlFilterCallbackRoot = new HashSet<Long>();
	public static java.util.Set<Long> reasonSelfContainedHandler = new HashSet<Long>();
	public static java.util.Set<Long> reasonTopLevelFileScope = new HashSet<Long>();

	// Aggregates ACROSS all CTRLREACH shape passes (a per-entry fact, not per-shape, so the
	// natural Set union here avoids double counting the same entry once per shape).
	public static java.util.Map<String,java.util.Set<Long>> unknownReasonBuckets = new java.util.LinkedHashMap<String,java.util.Set<Long>>();

	// ITEM18 Part 2: include-chain access inheritance for FILE_SCOPE_EXECUTABLE entries. Kept
	// deliberately separate from ordinary function-call propagation (entryPriv/call2mtd) -- an
	// include relationship is a FILE-LOAD edge, a different kind of evidence than a function call,
	// and conflating them would make this harder to audit later.
	//
	// fileIncludeAccessEvidence: resolved file path -> "PUBLICLY_REACHABLE" or
	// "AUTHORIZATION_ESTABLISHED:<capability>". Absence means unresolved (stays UNKNOWN).
	private static java.util.Map<String,String> fileIncludeAccessEvidence = new java.util.HashMap<String,String>();

	private static final java.util.Set<String> CAPABILITY_CHECK_FNS = new java.util.HashSet<String>(
		java.util.Arrays.asList("current_user_can", "user_can", "current_user_can_for_blog")
	);

	// Best-effort target-file resolution for an include/require expression: collects every
	// string-literal fragment in the expression's subtree (handles both a bare literal and a
	// CONST . 'literal/path.php' concatenation, WordPress's dominant idiom), and looks for a
	// UNIQUE analyzed file whose path ends with the longest such fragment. Multiple or zero
	// matches -> null (unresolved) rather than guess -- an ambiguous match is worse than none.
	// Interprocedural include-target resolution through a template-loader wrapper, e.g.:
	//   function render($name) { require AI1WM_TEMPLATES_PATH . '/' . $name . '.php'; }
	//   Ai1wm_Template::render('backups/index');
	// The require's own target is a runtime variable ($name), so resolveIncludeTargetFile() alone
	// can never resolve it -- but at a CALL SITE with a literal argument, substituting that
	// literal for the parameter recovers a concrete candidate path. Conservative by construction:
	// only ONE parameter reference is tolerated in the require's target expression (multiple, or
	// a reference to some OTHER local variable instead of a genuine parameter, disqualifies the
	// whole function as "not a recognized template-loader shape" rather than guessing); only a
	// call-site argument that resolves to a PURE literal-concatenation (no variables, no calls)
	// is substituted -- a dynamic argument (`$_GET['view']`, `build_template_name(...)`) is
	// correctly left unresolved, staying UNKNOWN downstream exactly as it should.
	private static final class TemplateLoaderShape {
		String paramName;
		int paramIndex;    // -1 = fixed (ignore call arguments entirely), >=0 = templated by this
			// reader's own parameter at this index
		String prefixFragment = "";
		String suffixFragment = "";
		String fixedCandidate;   // only meaningful when paramIndex == -1
	}

	// A single write's RHS decomposed into an ORDERED sequence of pieces -- each either a literal
	// string fragment or a reference (by index) to one of the WRITER method's own parameters.
	// Order matters: P2-D (`$prefix . $name . '.php'` with args reordered at different call
	// sites) needs the pieces kept in their original left-to-right sequence, not just collected
	// into separate "params" and "literals" bags the way Phase 1's single-parameter shape did.
	private static final class PropertyWriteShape {
		Long writerMethodId;
		java.util.List<Object> pieces;   // element: String (literal) or Integer (writer's own param index)
		boolean ambiguous = false;   // true if the RHS wasn't cleanly decomposable into the above at all
	}

	private static void collectOrderedTemplatePieces(Long id, java.util.Map<String,Integer> paramIdxByName,
			java.util.List<Object> pieces, boolean[] bad) {
		if( bad[0] ) return;
		ASTNode n = ASTUnderConstruction.idToNode.get(id);
		if( n instanceof StringExpression ) { pieces.add(((StringExpression)n).getEscapedCodeStr()); return; }
		if( n instanceof ast.expressions.BinaryExpression ) {
			ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)n;
			if( be.getLeft() != null ) collectOrderedTemplatePieces(be.getLeft().getNodeId(), paramIdxByName, pieces, bad);
			if( be.getRight() != null ) collectOrderedTemplatePieces(be.getRight().getNodeId(), paramIdxByName, pieces, bad);
			return;
		}
		if( n instanceof Variable ) {
			String vn = varNameOf((Expression)n);
			if( vn != null && paramIdxByName.containsKey(vn) ) { pieces.add(paramIdxByName.get(vn)); return; }
			bad[0] = true;   // a variable that isn't a recognized WRITER parameter -- too ambiguous
			return;
		}
		// realpath($x) unwrapped to $x's own pieces -- same narrow, provenance-not-exact-value
		// justification as tryResolvePureLiteralConcat's identical exception above. Deliberately
		// NOT generalized to any other single-argument call.
		if( n instanceof CallExpressionBase && "realpath".equals(callTargetName((CallExpressionBase)n)) ) {
			ArgumentList al = ((CallExpressionBase)n).getArgumentList();
			if( al != null && al.size() == 1 ) {
				collectOrderedTemplatePieces(al.getArgument(0).getNodeId(), paramIdxByName, pieces, bad);
				return;
			}
		}
		bad[0] = true;   // anything else (a call, a constant, ...) -- too ambiguous to trust
	}

	private static java.util.Map<String,Integer> paramIndexMap(ASTNode fn) {
		java.util.Map<String,Integer> m = new java.util.HashMap<String,Integer>();
		if( !(fn instanceof FunctionDef) ) return m;
		ParameterList pl = ((FunctionDef)fn).getParameterList();
		if( pl == null ) return m;
		for( int i = 0; i < pl.size(); i++ ) {
			ast.functionDef.ParameterBase p = pl.getParameter(i);
			if( p instanceof ast.php.functionDef.Parameter && ((ast.php.functionDef.Parameter)p).getNameChild() != null )
				m.put(((ast.php.functionDef.Parameter)p).getName(), i);
		}
		return m;
	}

	// Marker for "this resolved piece came from the READER's own parameter at this index" --
	// distinct from a plain Integer (which, in PropertyWriteShape.pieces, means a WRITER-side
	// parameter index instead). Kept as its own tiny type specifically to avoid the two meanings
	// of "Integer" in this pipeline being confused with each other.
	private static final class ReaderParamRef { final int idx; ReaderParamRef(int i){ idx = i; } }

	// className|propName -> resolved shape, or explicitly recorded as unresolvable (value == null
	// in the map but key present) once more than one write, or any disqualifying write, is found.
	private static java.util.Map<String,PropertyWriteShape> staticPropertyWriteCache = new java.util.HashMap<String,PropertyWriteShape>();
	private static java.util.Set<String> staticPropertyUnresolvable = new HashSet<String>();
	private static boolean staticPropertyWritesCollected = false;

	// Resolves expression `e` (used at a point inside `funcId`) into an ordered list of template
	// pieces, walking BACKWARD through preceding local reassignments when a leaf Variable doesn't
	// map directly to a function parameter. This is the core of the fix for setTemplate()-style
	// methods that reassign their own parameter through several local steps before the final
	// property write:
	//   $template = '/views/' . $template;
	//   $template = realpath($template . '.php');
	//   self::$template = $template;
	// Examining only the FINAL assignment's direct RHS (a bare $template) would incorrectly treat
	// it as the raw, unmodified parameter -- this walks back through the reassignment chain first.
	//
	// "Nearest PRECEDING assignment" is resolved by node id, which is monotonic with parse/statement
	// order in this AST (confirmed structurally throughout this session's other work) -- strictly
	// LESS THAN the reference point's own node id, never "any assignment anywhere in the function"
	// (which would risk laundering a LATER assignment backward across the read site, the exact
	// mistake already caught and avoided elsewhere in this pipeline). If ANY assignment reaching a
	// given variable at a given point is inside a conditional block (an ancestor IfElement between
	// it and the function boundary), the whole resolution bails to unresolved UNLESS the branch's
	// feasibility can be proven via provenParamValue/evaluateConditionTruthValue below (OPEN A) --
	// deliberately not attempting any OTHER kind of CFG-level branch reasoning; failing to `null`
	// (unresolved) remains the safe default whenever that specific proof doesn't apply.

	// OPEN A: interprocedural default-argument propagation / branch refinement. Narrow, bounded,
	// conservative by construction -- only proves a parameter's value when EVERY call site is
	// consistent with the same literal (either explicitly passing it, or omitting the argument
	// and relying on the SAME declared default), recursing through pure pass-through call chains
	// up to a bounded depth. Any ambiguity anywhere in the chain -> null (stays UNKNOWN downstream,
	// same fail-closed discipline as everywhere else in this pipeline).

	// Normalizes a simple literal expression (used for both declared parameter defaults and
	// explicit call-site arguments) into a comparable string form, or null if not a simple literal
	// this mechanism recognizes. Deliberately narrow: false/true/null, integer literals, and
	// string literals only -- anything else (an expression, a constant reference, a call) is left
	// unresolved rather than guessed at.
	private static String literalDefaultValue(Expression e) {
		if( e == null ) return null;
		if( e instanceof StringExpression ) return "STR:" + ((StringExpression)e).getEscapedCodeStr();
		if( e instanceof ast.expressions.IntegerExpression ) return "NUM:" + ((ast.expressions.IntegerExpression)e).getValue();
		if( e instanceof ast.expressions.Constant ) {
			ast.expressions.Identifier id = ((ast.expressions.Constant)e).getIdentifier();
			if( id != null && id.getNameChild() != null ) {
				String n = id.getNameChild().getEscapedCodeStr();
				if( n != null ) {
					String ln = n.toLowerCase();
					if( ln.equals("false") || ln.equals("true") || ln.equals("null") ) return ln;
				}
			}
		}
		return null;
	}

	private static boolean isLiteralFalsy(String normalized) {
		return normalized == null || normalized.equals("false") || normalized.equals("null")
			|| normalized.equals("NUM:0") || normalized.equals("STR:");
	}

	private static String paramDeclaredDefault(Long funcId, int paramIdx) {
		ASTNode fn = ASTUnderConstruction.idToNode.get(funcId);
		if( !(fn instanceof FunctionDef) ) return null;
		ParameterList pl = ((FunctionDef)fn).getParameterList();
		if( pl == null || pl.size() <= paramIdx ) return null;
		ast.functionDef.ParameterBase p = pl.getParameter(paramIdx);
		if( !(p instanceof ast.php.functionDef.Parameter) ) return null;
		ast.php.functionDef.Parameter param = (ast.php.functionDef.Parameter)p;
		Expression def = param.getDefault();
		String result = literalDefaultValue(def);
		if( System.getenv("WP_PROPWRITE_TRACE") != null ) {
			String rawText = null;
			try { if( def instanceof StringExpression ) rawText = ((StringExpression)def).getEscapedCodeStr(); } catch( Exception e ) {}
			System.err.println("PPV_DEFAULT funcId="+funcId+" paramIndex="+paramIdx+" paramName="+param.getName()
				+" rawDefaultAstType="+(def==null?"null":def.getClass().getSimpleName())
				+" rawDefaultText="+rawText+" extractedDefault="+result);
		}
		return result;
	}

	// Does parameter `paramIdx` of `funcId` PROVABLY hold the same literal value at every call
	// site that reaches it? Bounded recursion through pure pass-through chains (a caller passing
	// its OWN same-position parameter straight through, the exact shape render()->setTemplate()
	// uses for $path). Returns the normalized literal (see literalDefaultValue) or null if
	// unprovable -- an omitted argument at a call site is only accepted if a declared default
	// exists to fall back on; any inconsistency across call sites, or a call site passing
	// something other than a literal or a clean pass-through, disqualifies the whole proof.
	private static String provenParamValue(Long funcId, int paramIdx, int depth) {
		if( depth > 12 ) return null;
		boolean trace = System.getenv("WP_PROPWRITE_TRACE") != null;
		String declaredDefault = paramDeclaredDefault(funcId, paramIdx);
		if( trace ) System.err.println("PPV["+depth+"] funcId="+funcId+" paramIdx="+paramIdx+" declaredDefault="+declaredDefault);
		String baseline = null;
		boolean sawAnyCallSite = false;
		for( CallExpressionBase call : allCallSites() ) {
			java.util.List<Long> targets = call2mtd.get(call.getNodeId());
			boolean matched = targets != null && targets.contains(funcId);
			if( trace && targets != null && !targets.isEmpty() ) System.err.println("PPV_CALL targetFuncId="+funcId+" callNode="+call.getNodeId()
				+" resolvedTargets="+targets+" matchedThisFunc="+matched);
			if( !matched ) continue;
			sawAnyCallSite = true;
			ArgumentList al = call.getArgumentList();
			String thisCallValue;
			if( al == null || al.size() <= paramIdx ) {
				if( trace ) System.err.println("PPV_CALL   callNode="+call.getNodeId()+" suppliedArgCount="+(al==null?0:al.size())
					+" paramIndex="+paramIdx+" argSupplied=false effectiveValue(declaredDefault)="+declaredDefault);
				if( declaredDefault == null ) { if(trace) System.err.println("PPV["+depth+"]   omitted, no default -> null"); return null; }
				thisCallValue = declaredDefault;
			} else {
				Expression arg = al.getArgument(paramIdx);
				String lit = literalDefaultValue(arg);
				if( lit == null ) lit = tryResolvePureLiteralConcat(arg);   // covers string concat too
				if( lit != null ) {
					thisCallValue = lit;
				} else if( arg instanceof Variable ) {
					// Only a clean pass-through (the caller's OWN same-position parameter) is
					// followed; anything else is too ambiguous to trust.
					String argVarName = varNameOf(arg);
					Long callerFuncId = null;
					try { callerFuncId = call.getFuncId(); } catch( Exception e ) {}
					Integer callerParamIdx = null;
					if( callerFuncId != null && argVarName != null ) {
						java.util.Map<String,Integer> callerParams = paramIndexMap(ASTUnderConstruction.idToNode.get(callerFuncId));
						callerParamIdx = callerParams.get(argVarName);
					}
					if( trace ) System.err.println("PPV["+depth+"]   call="+call.getNodeId()+" arg is var '"+argVarName+"' callerFuncId="+callerFuncId+" callerParamIdx="+callerParamIdx);
					if( callerFuncId == null || callerParamIdx == null ) return null;
					String recursed = provenParamValue(callerFuncId, callerParamIdx, depth + 1);
					if( recursed == null ) return null;
					thisCallValue = recursed;
				} else {
					if( trace ) System.err.println("PPV["+depth+"]   call="+call.getNodeId()+" arg is neither literal nor variable -> null");
					return null;   // an expression/call argument -- too ambiguous to trust
				}
			}
			if( baseline == null ) baseline = thisCallValue;
			else if( !baseline.equals(thisCallValue) ) {
				if( trace ) System.err.println("PPV_CALL   INCONSISTENT callNode="+call.getNodeId()+" thisCallValue="+thisCallValue+" baseline="+baseline+" -> null");
				return null;   // inconsistent across call sites
			}
		}
		if( trace ) System.err.println("PPV["+depth+"] funcId="+funcId+" paramIdx="+paramIdx+" sawAnyCallSite="+sawAnyCallSite+" baseline="+baseline+" -> returning "+(sawAnyCallSite?baseline:declaredDefault));
		if( !sawAnyCallSite ) return declaredDefault;   // never called -- fall back to the declared
			// default (this code path being dead makes the exact value moot either way)
		return baseline;
	}

	// Evaluates a condition's truth value when it's a simple truthiness/negation/equality check on
	// EXACTLY ONE parameter of the enclosing function, and that parameter's value is provable via
	// provenParamValue. Returns Boolean.TRUE/FALSE, or null if the shape isn't recognized or the
	// value isn't provable -- null must always fall back to the existing conservative behavior.
	private static Boolean evaluateConditionTruthValue(Long condId, Long funcId, java.util.Map<String,Integer> paramIdxByName) {
		ASTNode n = ASTUnderConstruction.idToNode.get(condId);
		if( System.getenv("WP_PROPWRITE_TRACE") != null ) System.err.println("ECTV condId="+condId+" nodeClass="+(n==null?"null":n.getClass().getSimpleName())+" flags="+(n==null?"null":n.getFlags()));
		if( n instanceof Variable ) {
			String vn = varNameOf((Expression)n);
			Integer idx = (vn != null) ? paramIdxByName.get(vn) : null;
			if( idx == null ) return null;
			String val = provenParamValue(funcId, idx, 0);
			if( val == null ) return null;
			return !isLiteralFalsy(val);
		}
		if( n instanceof ast.expressions.UnaryExpression && "UNARY_BOOL_NOT".equals(n.getFlags()) ) {
			Boolean inner = evaluateConditionTruthValue(((ast.expressions.UnaryExpression)n).getExpression().getNodeId(), funcId, paramIdxByName);
			return (inner == null) ? null : !inner;
		}
		if( n instanceof ast.php.expressions.EmptyExpression ) {
			// empty($x) is true iff $x's value is falsy -- reuse the same provenParamValue proof
			// used for bare truthiness checks above. Confirmed real via Smush's own
			// View::get_template_content($fname, $args=[], $dir='views'), whose
			// `if (!empty($dir))` guard was previously unprovable -- but the actual root cause was
			// deeper than a missing CallExpressionBase check: empty() is a PHP language construct,
			// not an ordinary function call, and this parser represents it with its OWN dedicated
			// EmptyExpression node type (EmptyExpression extends UnaryExpression directly), never
			// a CallExpressionBase at all. The original `n instanceof CallExpressionBase &&
			// "empty".equals(callTargetName(...))` check could never match, so provenParamValue was
			// never even invoked for this case -- confirmed via direct trace
			// (ECTV condId=... nodeClass=EmptyExpression).
			Expression inner = ((ast.php.expressions.EmptyExpression)n).getExpression();
			if( !(inner instanceof Variable) ) return null;
			String vn = varNameOf(inner);
			Integer idx = (vn != null) ? paramIdxByName.get(vn) : null;
			if( idx == null ) return null;
			String val = provenParamValue(funcId, idx, 0);
			if( val == null ) return null;
			return isLiteralFalsy(val);
		}
		if( n instanceof CallExpressionBase && "empty".equals(callTargetName((CallExpressionBase)n)) ) {
			// empty($x) is true iff $x's value is falsy -- reuse the same provenParamValue proof
			// used for bare truthiness checks above. Confirmed real via Smush's own
			// View::get_template_content($fname, $args=[], $dir='views'), whose
			// `if (!empty($dir))` guard was previously unprovable (no CallExpressionBase handling
			// existed at all), causing the "{$dir}/" prefix segment to be silently skipped even
			// though $dir provably always holds its non-empty default.
			ArgumentList al = ((CallExpressionBase)n).getArgumentList();
			if( al == null || al.size() != 1 || !(al.getArgument(0) instanceof Variable) ) return null;
			String vn = varNameOf(al.getArgument(0));
			Integer idx = (vn != null) ? paramIdxByName.get(vn) : null;
			if( idx == null ) return null;
			String val = provenParamValue(funcId, idx, 0);
			if( System.getenv("WP_PROPWRITE_TRACE") != null ) System.err.println("ECTV_EMPTY funcId="+funcId+" var="+vn+" idx="+idx+" provenVal="+val);
			if( val == null ) return null;
			return isLiteralFalsy(val);
		}
		if( n instanceof ast.expressions.BinaryExpression ) {
			ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)n;
			String flags = n.getFlags();
			boolean isEq = flags != null && (flags.contains("IDENTICAL") || (flags.contains("EQUAL") && !flags.contains("NOT")
				&& !flags.contains("GREATER") && !flags.contains("SMALLER")));
			boolean isNeq = flags != null && (flags.contains("NOT_EQUAL") || flags.contains("NOT_IDENTICAL"));
			if( !isEq && !isNeq ) return null;
			Variable var = null; Expression other = null;
			if( be.getLeft() instanceof Variable ) { var = (Variable)be.getLeft(); other = be.getRight(); }
			else if( be.getRight() instanceof Variable ) { var = (Variable)be.getRight(); other = be.getLeft(); }
			if( var == null || other == null ) return null;
			String vn = varNameOf(var);
			Integer idx = (vn != null) ? paramIdxByName.get(vn) : null;
			if( idx == null ) return null;
			String paramVal = provenParamValue(funcId, idx, 0);
			String otherVal = literalDefaultValue(other);
			if( paramVal == null || otherVal == null ) return null;
			boolean equal = paramVal.equals(otherVal);
			return isEq ? equal : !equal;
		}
		return null;
	}

	// Is `nodeId` inside the TRUE-branch (condition present) or the ELSE-branch (condition null)
	// of its nearest enclosing AST_IF_ELEM? Returns null if not inside any IfElem at all.
	private static Boolean isInTrueBranch(Long nodeId, Long funcId) {
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(nodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) {
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(cur);
				if( kids != null ) for( Long k : kids.values() ) {
					ASTNode kn = ASTUnderConstruction.idToNode.get(k);
					if( kn instanceof CallExpressionBase || kn instanceof ast.expressions.UnaryExpression
							|| kn instanceof ast.expressions.BinaryExpression || kn instanceof Variable ) return true;
				}
				return false;   // no condition child found -- this is the else-arm
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return null;
	}

	// Finds the condition that governs `nodeId`'s enclosing branch, PLUS whether that condition
	// needs to be read directly (nodeId is in the if-arm) or negated (nodeId is in the else-arm,
	// which has no condition of its own -- it's governed by the SIBLING if-arm's condition, false).
	// Returns {conditionNodeId, needsNegation ? 1L : 0L}, or null if not inside any IfElem, or if
	// the enclosing AST_IF doesn't have a simple if/else shape this can confidently read (e.g. an
	// elseif chain with more than two arms -- left unhandled rather than guessed at).
	private static long[] findGoverningCondition(Long nodeId, Long funcId) {
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(nodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) {
				Long ownCond = findConditionChild(cur);
				if( ownCond != null ) return new long[]{ ownCond, 0 };   // if-arm: read directly
				// else-arm: find the AST_IF parent, then its OTHER child (the if-arm) for the
				// shared condition, negated.
				Long ifParent = PHPCSVEdgeInterpreter.child2parent.get(cur);
				ASTNode ifNode = (ifParent != null) ? ASTUnderConstruction.idToNode.get(ifParent) : null;
				if( !(ifNode instanceof ast.php.statements.blockstarters.IfStatement) ) return null;
				HashMap<Integer,Long> siblings = PHPCSVEdgeInterpreter.parent2child.get(ifParent);
				if( siblings == null || siblings.size() != 2 ) return null;   // only a simple
					// if/else shape is handled -- an elseif chain (more than 2 arms) is left alone
				for( Long sib : siblings.values() ) {
					if( sib.equals(cur) ) continue;
					Long sibCond = findConditionChild(sib);
					if( sibCond != null ) return new long[]{ sibCond, 1 };   // else-arm: negate
				}
				return null;
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return null;
	}

	private static Long findConditionChild(Long ifElemId) {
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(ifElemId);
		if( kids == null ) return null;
		for( Long k : kids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn instanceof CallExpressionBase || kn instanceof ast.expressions.UnaryExpression
					|| kn instanceof ast.expressions.BinaryExpression || kn instanceof Variable ) return k;
		}
		return null;
	}

	// OPEN B: return-provenance summaries for deterministic path helpers. A function's return
	// value is "proven safe" (not attacker-influenced, though its EXACT string value may remain
	// unknown -- e.g. a defined() constant whose value isn't statically readable) only if EVERY
	// return statement in its body returns an expression built ENTIRELY from: string/number/
	// boolean/null literals, bare constant references (AI1WM_PATH, DIRECTORY_SEPARATOR, etc. --
	// server-defined, never attacker-controlled regardless of exact name), concatenations of safe
	// pieces, realpath()-wrapped safe expressions, or calls to OTHER functions themselves
	// recursively proven safe (bounded depth). Deliberately PARAMETER-BLIND, unlike
	// resolveExprToPieces (which tracks a SPECIFIC call site's literal argument): this is a
	// context-free summary meant to hold for ANY caller, so a bare variable reference (including
	// a parameter) always disqualifies the function, even one that happens to be unused elsewhere
	// (B5's exact adversarial case) -- the function could be called with anything.
	private static java.util.Map<Long,Boolean> returnProvenanceSafeCache = new java.util.HashMap<Long,Boolean>();

	private static boolean isReturnProvenanceSafe(Long funcId, int depth) {
		if( depth > 8 ) return false;
		boolean trace = System.getenv("WP_PROPWRITE_TRACE") != null;
		Boolean cached = returnProvenanceSafeCache.get(funcId);
		if( cached != null ) { if(trace) System.err.println("IRPS["+depth+"] funcId="+funcId+" cached="+cached); return cached; }
		ASTNode fn = ASTUnderConstruction.idToNode.get(funcId);
		if( !(fn instanceof FunctionDef) ) { returnProvenanceSafeCache.put(funcId, false); return false; }
		returnProvenanceSafeCache.put(funcId, false);   // cycle guard: assume unsafe while computing
		boolean allSafe = true;
		int returnsSeen = 0;
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			Long rfid = null;
			try { rfid = n.getFuncId(); } catch( Exception e ) {}
			if( rfid == null || !rfid.equals(funcId) ) continue;
			returnsSeen++;
			Expression retExpr = ((ast.statements.jump.ReturnStatement)n).getReturnExpression();
			if( retExpr == null ) continue;   // bare `return;` -- no value, trivially safe
			boolean thisSafe = isExpressionProvenSafe(retExpr, depth);
			if( trace ) System.err.println("IRPS["+depth+"] funcId="+funcId+" return node="+n.getNodeId()+" exprClass="+retExpr.getClass().getSimpleName()+" safe="+thisSafe);
			if( !thisSafe ) { allSafe = false; break; }
		}
		if( trace ) System.err.println("IRPS["+depth+"] funcId="+funcId+" returnsSeen="+returnsSeen+" allSafe="+allSafe);
		returnProvenanceSafeCache.put(funcId, allSafe);
		return allSafe;
	}

	private static boolean isExpressionProvenSafe(Expression e, int depth) {
		if( e == null ) return true;
		if( e instanceof StringExpression ) return true;
		if( e instanceof ast.expressions.IntegerExpression ) return true;
		if( e instanceof ast.expressions.Constant ) return true;   // any bare constant reference --
			// server-defined, never attacker-controlled, regardless of which specific name
		if( e instanceof ast.expressions.BinaryExpression ) {
			ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)e;
			return isExpressionProvenSafe(be.getLeft(), depth) && isExpressionProvenSafe(be.getRight(), depth);
		}
		if( e instanceof CallExpressionBase ) {
			String cn = callTargetName((CallExpressionBase)e);
			if( "realpath".equals(cn) ) {
				ArgumentList al = ((CallExpressionBase)e).getArgumentList();
				return al != null && al.size() == 1 && isExpressionProvenSafe(al.getArgument(0), depth);
			}
			java.util.List<Long> targets = call2mtd.get(e.getNodeId());
			if( targets == null || targets.isEmpty() ) return false;   // unresolved call -- not safe
			for( Long t : targets ) if( !isReturnProvenanceSafe(t, depth + 1) ) return false;
			return true;
		}
		return false;   // a variable (including a parameter), or anything else unrecognized -- NOT safe
	}

	// Marker for "this piece is proven safe (not attacker-influenced) but its exact string value
	// is unknown" -- a bare constant reference, or a call proven safe via isReturnProvenanceSafe.
	// Distinct from a literal String piece: it must never be used to build a candidate suffix for
	// matching (we don't know its value), but its presence must NOT disqualify the surrounding
	// piece decomposition either -- it's simply skipped when building the candidate string.
	private static final Object OPAQUE_SAFE_PIECE = new Object();



	// Resolves a CALLER's own argument expression to a concrete literal string, reusing the SAME
	// backward local-assignment resolver (resolveExprToPieces/resolveViaPrecedingAssignment)
	// already built and validated for template-internal computation -- NOT a new, separate
	// lineage mechanism. Handles the case where a caller passes a local variable rather than a
	// direct literal (e.g. `$temp_file_name = 'email/index'; ...->get_template_content($temp_file_name);`),
	// tracing backward through the caller's OWN preceding assignments, including the existing
	// branch-feasibility discipline: an unprovable conditional reassignment (the condition doesn't
	// resolve to a literal truth value) correctly stays unresolved here too, exactly as it already
	// does for template-internal `$file` computation -- this is the same conservative behavior,
	// just applied one call-site earlier than before. Requires the FULLY resolved value to consist
	// entirely of literal string pieces; any remaining parameter reference (Integer) or opaque
	// piece (a safe-but-unknown-value constant/call) means this isn't a concrete literal the
	// caller-argument-substitution logic can use, so it correctly returns null rather than
	// guessing.
	private static String resolveCallerArgAsLiteral(Expression argExpr, Long callerFuncId, Long boundaryNodeId) {
		String direct = tryResolvePureLiteralConcat(argExpr);
		if( direct != null ) return direct;
		if( callerFuncId == null || boundaryNodeId == null ) return null;
		java.util.Map<String,Integer> callerParams = paramIndexMap(ASTUnderConstruction.idToNode.get(callerFuncId));
		java.util.List<Object> pieces = resolveExprToPieces(argExpr, callerFuncId, callerParams, 0, boundaryNodeId);
		if( pieces == null ) return null;
		StringBuilder sb = new StringBuilder();
		for( Object p : pieces ) {
			if( !(p instanceof String) ) return null;   // an Integer (caller's own param) or an
				// OPAQUE_SAFE_PIECE isn't a concrete literal -- can't use it here
			sb.append((String)p);
		}
		return sb.toString();
	}

	private static java.util.List<Object> resolveExprToPieces(Expression e, Long funcId,
			java.util.Map<String,Integer> paramIdxByName, int depth, Long boundaryNodeId) {
		if( e == null || depth > 64 ) return null;   // depth is a pure defensive backstop, not the
			// primary termination argument -- see the note below on why one isn't strictly needed.
		if( e instanceof StringExpression ) {
			java.util.List<Object> l = new java.util.ArrayList<Object>();
			l.add(((StringExpression)e).getEscapedCodeStr());
			return l;
		}
		if( e instanceof ast.expressions.BinaryExpression ) {
			ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)e;
			java.util.List<Object> l = resolveExprToPieces(be.getLeft(), funcId, paramIdxByName, depth+1, boundaryNodeId);
			if( l == null ) return null;
			java.util.List<Object> r = resolveExprToPieces(be.getRight(), funcId, paramIdxByName, depth+1, boundaryNodeId);
			if( r == null ) return null;
			java.util.List<Object> combined = new java.util.ArrayList<Object>(l);
			combined.addAll(r);
			return combined;
		}
		if( e instanceof ast.php.expressions.EncapsListExpression ) {
			// Double-quoted string interpolation ("{$dir}/{$file}") -- semantically a concatenation
			// of its parts, same as the `.` operator, just different PHP syntax. Confirmed real via
			// Smush's own View::get_template_content(), which builds its path this way rather than
			// with `.`. Each element resolved and concatenated in order, same discipline as the
			// BinaryExpression case above: any one unresolved element fails the whole expression.
			ast.php.expressions.EncapsListExpression enc = (ast.php.expressions.EncapsListExpression)e;
			java.util.List<Object> combined = new java.util.ArrayList<Object>();
			for( int i = 0; i < enc.size(); i++ ) {
				java.util.List<Object> part = resolveExprToPieces(enc.getElement(i), funcId, paramIdxByName, depth+1, boundaryNodeId);
				if( part == null ) return null;
				combined.addAll(part);
			}
			return combined;
		}
		if( e instanceof CallExpressionBase && "realpath".equals(callTargetName((CallExpressionBase)e)) ) {
			ArgumentList al = ((CallExpressionBase)e).getArgumentList();
			if( al != null && al.size() == 1 ) return resolveExprToPieces(al.getArgument(0), funcId, paramIdxByName, depth+1, boundaryNodeId);
			return null;
		}
		if( e instanceof CallExpressionBase && "trailingslashit".equals(callTargetName((CallExpressionBase)e)) ) {
			// WordPress core's trailingslashit($x) -- a pure string transformation (strips any
			// existing trailing slash(es), appends exactly one), no filesystem access, no side
			// effects. Confirmed real via Smush's own View::get_template_content(), which wraps
			// $this->get_template_dir() in it. Same narrow, provenance-transparent treatment as
			// realpath() above -- and simpler to justify, since it never touches the filesystem at all.
			ArgumentList al = ((CallExpressionBase)e).getArgumentList();
			if( al != null && al.size() == 1 ) return resolveExprToPieces(al.getArgument(0), funcId, paramIdxByName, depth+1, boundaryNodeId);
			return null;
		}
		if( e instanceof ast.expressions.Constant ) {
			// A bare constant reference (AI1WM_PATH, DIRECTORY_SEPARATOR, etc.) -- server-defined,
			// never attacker-controlled. Its exact value isn't known, but it's safe to treat as an
			// opaque, non-disqualifying piece (OPEN B).
			java.util.List<Object> l = new java.util.ArrayList<Object>();
			l.add(OPAQUE_SAFE_PIECE);
			return l;
		}
		if( e instanceof PropertyExpression && currentThisPropSubstitutions != null ) {
			// Instance-field-mediated template provenance (receiver-sensitive instance-property
			// substitution): a $this->prop reference is resolved to an ALREADY-ESTABLISHED
			// substitution value ONLY when currentThisPropSubstitutions is active (set up by
			// resolveInstanceFieldMediatedInclude for the SPECIFIC (class, field) anchor currently
			// being analyzed) and the receiver is genuinely $this. Never active by default, so this
			// branch is a no-op for every other caller of resolveExprToPieces.
			Expression obj = ((PropertyExpression)e).getObjectExpression();
			if( obj instanceof Variable && "this".equals(varNameOf(obj)) ) {
				String propName = receiverName(e);
				java.util.List<Object> sub = currentThisPropSubstitutions.get(propName);
				if( sub != null ) return sub;
			}
		}
		if( e instanceof MethodCallExpression && currentThisPropSubstitutions != null ) {
			// A $this->someMethod() call whose target is a TRIVIAL getter (its body is exactly
			// `return $this->prop;`, e.g. View::get_template_dir()) -- resolve through it the same
			// way a direct $this->prop read resolves, since it's semantically identical. Does NOT
			// attempt to handle any getter with additional logic; a non-trivial getter body
			// correctly falls through to unresolved.
			MethodCallExpression mce = (MethodCallExpression)e;
			if( mce.getTargetObject() instanceof Variable && "this".equals(varNameOf(mce.getTargetObject())) ) {
				java.util.List<Long> targets = call2mtd.get(e.getNodeId());
				if( targets != null && targets.size() == 1 ) {
					String propName = findTrivialThisPropGetterProp(targets.get(0));
					if( propName != null ) {
						java.util.List<Object> sub = currentThisPropSubstitutions.get(propName);
						if( sub != null ) return sub;
					}
				}
			}
		}
		if( e instanceof CallExpressionBase ) {
			// A call to some OTHER function -- OPEN B: if that function's return value is proven
			// safe (context-free, for any caller -- see isReturnProvenanceSafe), treat this as an
			// opaque-but-safe piece the same way a bare constant is. An unresolved call, or one
			// whose target isn't provably safe, correctly falls through to "return null" below.
			java.util.List<Long> targets = call2mtd.get(e.getNodeId());
			if( targets != null && !targets.isEmpty() ) {
				boolean allSafe = true;
				for( Long t : targets ) if( !isReturnProvenanceSafe(t, 0) ) { allSafe = false; break; }
				if( allSafe ) {
					java.util.List<Object> l = new java.util.ArrayList<Object>();
					l.add(OPAQUE_SAFE_PIECE);
					return l;
				}
			}
		}
		if( e instanceof Variable ) {
			String vn = varNameOf(e);
			if( vn == null ) return null;
			// The search boundary is the ENCLOSING STATEMENT's own node id (boundaryNodeId),
			// never this leaf variable-reference's own node id -- a leaf sitting inside the RHS of
			// its OWN reassignment (`$template = realpath($template.'.php')`) always has a HIGHER
			// node id than that same assignment (it's a descendant, parsed after), which would
			// otherwise make the assignment look like it "precedes" its own RHS read.
			//
			// No name-based "visiting" guard is used here (an earlier version had one, and it was
			// a real bug: it blocked $template's own legitimate multi-step reassignment chain,
			// since the SAME variable name recurs at each hop). None is needed: each hop's search
			// boundary is STRICTLY LESS than the previous one by construction (candidates must
			// satisfy nodeId < beforeNodeId, and the recursive call passes that found nodeId
			// onward as the new boundary) -- node ids are finite, so this terminates on its own.
			// The `depth` cap above is pure defensive backstop, not the actual termination argument.
			java.util.List<Object> viaAssignment = resolveViaPrecedingAssignment(vn, boundaryNodeId, funcId, paramIdxByName, depth);
			if( viaAssignment == UNRESOLVED_BUT_REASSIGNED ) return null;   // a reassignment DOES
				// exist before this point, but couldn't be resolved -- must NOT fall through to
				// treating this as the raw parameter (that would be a genuine semantic error: the
				// variable's real value is something else, just not something provable here).
			if( viaAssignment != null ) return viaAssignment;
			Integer pidx = paramIdxByName.get(vn);   // GENUINELY no preceding reassignment found --
				// safe to fall back to treating it as the raw function parameter
			if( pidx != null ) {
				java.util.List<Object> l = new java.util.ArrayList<Object>();
				l.add(pidx);
				return l;
			}
			return null;
		}
		return null;
	}

	// Sentinel distinct from `null`: returned by resolveViaPrecedingAssignment when a preceding
	// reassignment WAS found but couldn't be resolved (branch-unprovable, or its own RHS didn't
	// resolve) -- as opposed to plain `null`, meaning no reassignment exists at all. This
	// distinction is critical: only the latter may fall back to treating the variable as the raw,
	// unmodified function parameter. Conflating the two was a real, confirmed bug -- a variable
	// that IS reassigned (just to an unprovable value) was being silently treated as if it still
	// held its original parameter value, producing a candidate that could coincidentally
	// suffix-match the wrong reasoning even when it happened to match the right file. Caught via
	// the OPEN A/B combined fixture (openA_and_B), which resolved when it should have stayed
	// UNKNOWN, tracing back to this exact fallback.
	private static final java.util.List<Object> UNRESOLVED_BUT_REASSIGNED = java.util.Collections.emptyList();

	// Walks up from nodeId to funcId, collecting every enclosing AST_IF_ELEM's node id.
	private static java.util.Set<Long> ancestorIfElems(Long nodeId, Long funcId) {
		java.util.Set<Long> result = new HashSet<Long>();
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(nodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) result.add(cur);
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return result;
	}

	private static boolean isAncestorOrSelf(Long ancestorCandidate, Long nodeId, Long funcId) {
		if( ancestorCandidate.equals(nodeId) ) return true;
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(nodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			if( cur.equals(ancestorCandidate) ) return true;
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	// True only if referenceId is specifically inside a SIBLING arm of some IfElem that encloses
	// candidateId -- meaning candidateId's branch and referenceId's position are provably mutually
	// exclusive (they can never both be on the same execution path). This is narrower, and
	// correct, compared to a first attempt that excluded whenever the candidate's IfElem simply
	// wasn't ALSO an ancestor of the reference point -- that broke the (already-working) case where
	// the reference point sits AFTER the if/else merges back (e.g. a property write following the
	// branch), which is NOT mutually exclusive with either arm and must remain a valid candidate
	// subject to the existing branch-feasibility proof. Confirmed via direct trace: the first
	// version incorrectly started excluding both branches even for that merged-after case.
	private static boolean isCandidateExcludedBySiblingBranch(Long candidateId, Long referenceId, Long funcId) {
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(candidateId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) {
				Long ifParent = PHPCSVEdgeInterpreter.child2parent.get(cur);
				ASTNode ifNode = (ifParent != null) ? ASTUnderConstruction.idToNode.get(ifParent) : null;
				if( ifNode instanceof ast.php.statements.blockstarters.IfStatement ) {
					HashMap<Integer,Long> siblings = PHPCSVEdgeInterpreter.parent2child.get(ifParent);
					if( siblings != null ) for( Long sib : siblings.values() ) {
						if( sib.equals(cur) ) continue;
						if( isAncestorOrSelf(sib, referenceId, funcId) ) return true;
					}
				}
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	private static java.util.List<Object> resolveViaPrecedingAssignment(String varName, Long beforeNodeId, Long funcId,
			java.util.Map<String,Integer> paramIdxByName, int depth) {
		java.util.List<Long> candidates = new java.util.ArrayList<Long>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression ae = (AssignmentExpression)n;
			if( !(ae.getLeft() instanceof Variable) ) continue;
			String lhsName = varNameOf(ae.getLeft());
			if( lhsName == null || !lhsName.equals(varName) ) continue;
			Long afid = null;
			try { afid = n.getFuncId(); } catch( Exception e2 ) {}
			if( afid == null || !afid.equals(funcId) ) continue;
			if( n.getNodeId() >= beforeNodeId ) continue;   // must strictly precede the reference point
			if( isCandidateExcludedBySiblingBranch(n.getNodeId(), beforeNodeId, funcId) ) continue;   // on
				// a mutually exclusive control path -- never a valid preceding assignment regardless
				// of node-id ordering
			candidates.add(n.getNodeId());
		}
		if( candidates.isEmpty() ) return null;   // GENUINELY no preceding assignment -- caller may
			// fall back to treating this as the raw, unmodified parameter.
		boolean trace = System.getenv("WP_PROPWRITE_TRACE") != null;
		if( trace ) System.err.println("RVPA var="+varName+" before="+beforeNodeId+" candidates="+candidates);
		java.util.List<Long> feasible = new java.util.ArrayList<Long>();
		Long maxUnprovableId = null;
		for( Long cid : candidates ) {
			Boolean inTrue = isInTrueBranch(cid, funcId);
			if( inTrue == null ) { feasible.add(cid); continue; }   // unconditional -- always feasible
			long[] governing = findGoverningCondition(cid, funcId);
			Boolean proven = null;
			if( governing != null ) {
				Boolean rawTruth = evaluateConditionTruthValue(governing[0], funcId, paramIdxByName);
				if( rawTruth != null ) proven = (governing[1] == 1) ? !rawTruth : rawTruth;
			}
			if( trace ) System.err.println("RVPA   cid="+cid+" inTrue="+inTrue+" governing="+java.util.Arrays.toString(governing)+" proven="+proven);
			// An individually-unprovable candidate is not immediately fatal to the whole
			// resolution -- a sibling candidate elsewhere (same condition, opposite branch) may
			// still be provably the one taken (this was the openA_pos/openA_and_B fix). But it
			// MUST still be tracked: if it sits LATER (a higher node id) than whichever candidate
			// we end up trusting as "nearest", that later, unprovable reassignment might have
			// executed and overwritten the value we'd otherwise use -- reaching-definitions
			// correctness requires ruling that out, not just finding SOME provably-feasible
			// candidate earlier in the function. Caught by the localarg_branch fixture: an
			// unconditional `$template = 'header';` followed by an unprovable
			// `if ($x) { $template = $_GET[...]; }` was incorrectly resolving to 'header', when
			// the correct answer is UNKNOWN (the conditional reassignment can't be ruled out).
			if( proven == null ) { if( maxUnprovableId == null || cid > maxUnprovableId ) maxUnprovableId = cid; continue; }
			if( proven ) feasible.add(cid);
		}
		if( trace ) System.err.println("RVPA   feasible="+feasible+" maxUnprovableId="+maxUnprovableId);
		if( feasible.isEmpty() ) return UNRESOLVED_BUT_REASSIGNED;   // no candidate provably feasible
			// -- a reassignment exists, its value just isn't determinable
		Long nearest = java.util.Collections.max(feasible);
		if( maxUnprovableId != null && maxUnprovableId > nearest ) return UNRESOLVED_BUT_REASSIGNED;   // a
			// LATER, unprovable reassignment exists that could have overwritten our chosen value --
			// cannot rule it out, so the whole resolution must stay unresolved
		AssignmentExpression nearestAe = (AssignmentExpression) ASTUnderConstruction.idToNode.get(nearest);
		// The NEW boundary for resolving nearestAe's own RHS is nearestAe's OWN node id (strictly
		// less than beforeNodeId) -- NOT wherever the original leaf reference happened to sit --
		// so any variable read inside THIS assignment's RHS correctly searches for assignments
		// preceding THIS one, and each hop's boundary is guaranteed smaller than the last.
		java.util.List<Object> result = resolveExprToPieces(nearestAe.getRight(), funcId, paramIdxByName, depth+1, nearest);
		return (result == null) ? UNRESOLVED_BUT_REASSIGNED : result;   // the reassignment's own RHS
			// didn't resolve -- still must NOT fall back to the raw parameter; the value IS
			// something else, just not something this analysis can determine.
	}

	private static boolean isNodeInsideConditional(Long nodeId, Long funcId) {
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(nodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) break;
			if( n instanceof ast.php.statements.blockstarters.IfElement ) return true;
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	private static void collectAllStaticPropertyWrites() {
		if( staticPropertyWritesCollected ) return;
		staticPropertyWritesCollected = true;
		java.util.Map<String,java.util.List<PropertyWriteShape>> byKey = new java.util.HashMap<String,java.util.List<PropertyWriteShape>>();
		PHPCGFactory.recordScanSite("PCG_9181", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression ae = (AssignmentExpression)n;
			if( !(ae.getLeft() instanceof StaticPropertyExpression) ) continue;
			StaticPropertyExpression lhs = (StaticPropertyExpression)ae.getLeft();
			String propName = receiverName(lhs);
			if( propName == null || propName.isEmpty() ) continue;
			String className = enclosingClassName(n);
			if( className == null ) continue;   // a write outside any method -- too unusual to model, skip
			String key = simpleClassName(className) + "|" + propName;
			Long writerMethodId = null;
			try { writerMethodId = n.getFuncId(); } catch( Exception e ) {}
			PropertyWriteShape shape = new PropertyWriteShape();
			shape.writerMethodId = writerMethodId;
			Expression rhs = ae.getRight();
			String pureLit = tryResolvePureLiteralConcat(rhs);
			if( pureLit != null ) {
				shape.pieces = java.util.Collections.singletonList((Object)pureLit);
			} else if( writerMethodId != null ) {
				ASTNode wfn = ASTUnderConstruction.idToNode.get(writerMethodId);
				java.util.Map<String,Integer> paramIdx = paramIndexMap(wfn);
				java.util.List<Object> pieces = resolveExprToPieces(rhs, writerMethodId, paramIdx, 0, n.getNodeId());
				if( System.getenv("WP_PROPWRITE_TRACE") != null ) System.err.println("PROPWRITE key="+key+" writeNode="+n.getNodeId()+" pieces="+pieces);
				if( pieces != null && !pieces.isEmpty() ) shape.pieces = pieces;
				else shape.ambiguous = true;
			} else {
				shape.ambiguous = true;
			}
			byKey.computeIfAbsent(key, k -> new java.util.ArrayList<PropertyWriteShape>()).add(shape);
		}
		for( java.util.Map.Entry<String,java.util.List<PropertyWriteShape>> e : byKey.entrySet() ) {
			java.util.List<PropertyWriteShape> writes = e.getValue();
			if( writes.size() == 1 && !writes.get(0).ambiguous ) {
				staticPropertyWriteCache.put(e.getKey(), writes.get(0));
			} else {
				staticPropertyUnresolvable.add(e.getKey());   // multiple writes, or an ambiguous one --
					// one known-safe write must never launder a sibling dynamic/unresolved write.
			}
		}
	}

	// Does methodId contain `include self::$PROP;` (target is DIRECTLY a static property access,
	// not wrapped in any concatenation), where $PROP resolves to a single, confidently-resolvable
	// write elsewhere in the same class? Resolves each piece of that write AGAINST THIS SPECIFIC
	// call to the writer, found within methodId's own body:
	//   - a literal piece stays as-is
	//   - a writer-parameter piece is resolved using STRICT POSITIONAL argument mapping (the
	//     writer's own parameter index against THIS call's argument list) -- never by matching
	//     variable names across unrelated scopes, exactly the discipline the CUFA index fix
	//     established earlier this session
	//   - if that positional argument is itself a pure literal, it substitutes directly
	//   - if it's a Variable matching one of METHODID's OWN parameters, at most ONE such
	//     pass-through piece is tolerated; a second one, or any other unresolved piece, disqualifies
	//     the whole shape
	// Two outcomes: every piece resolved to a literal -> methodId is a FIXED loader (ignores its
	// own call-site arguments entirely); exactly one pass-through piece -> methodId becomes
	// parameter-templated by ITS OWN matching parameter, with the surrounding literals preserved
	// as prefix/suffix in their original order.
	private static TemplateLoaderShape findPropertyMediatedLoaderShape(Long methodId) {
		collectAllStaticPropertyWrites();
		ASTNode mn = ASTUnderConstruction.idToNode.get(methodId);
		if( !(mn instanceof Method) ) return null;
		String className = simpleClassName(((Method)mn).getEnclosingClass());
		if( className == null ) return null;
		java.util.Map<String,Integer> myParamIdx = paramIndexMap(mn);
		for( ASTNode n : includeOrEvalNodesInFunc(methodId) ) {
			if( !(n instanceof IncludeOrEvalExpression) ) continue;
			Long nfid = null;
			try { nfid = n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(methodId) ) continue;
			Expression target = ((IncludeOrEvalExpression)n).getIncludeOrEvalExpression();
			if( !(target instanceof StaticPropertyExpression) ) continue;
			String propName = receiverName((Expression)target);
			String key = className + "|" + propName;
			if( staticPropertyUnresolvable.contains(key) ) continue;
			PropertyWriteShape wshape = staticPropertyWriteCache.get(key);
			if( wshape == null || wshape.pieces == null ) continue;
			for( CallExpressionBase call : callSitesInFunc(methodId) ) {
				Long cfid = null;
				try { cfid = call.getFuncId(); } catch( Exception e ) {}
				if( cfid == null || !cfid.equals(methodId) ) continue;
				java.util.List<Long> callTargets = call2mtd.get(call.getNodeId());
				if( callTargets == null || !callTargets.contains(wshape.writerMethodId) ) continue;
				ArgumentList al = call.getArgumentList();
				java.util.List<Object> resolved = new java.util.ArrayList<Object>();
				boolean ok = true;
				boolean sawPassThrough = false;
				for( Object piece : wshape.pieces ) {
					if( piece instanceof String ) { resolved.add(piece); continue; }
					if( piece == OPAQUE_SAFE_PIECE ) { resolved.add(piece); continue; }   // OPEN B:
						// already resolved as "safe, value unknown" -- no call-site substitution needed
					int writerParamIdx = (Integer)piece;
					if( al == null || al.size() <= writerParamIdx ) {
						// This call site omits the writer's parameter at this position -- fall back
						// to the writer's OWN declared default for it, if one exists and is a
						// simple literal. Confirmed as a real, separate gap (distinct from the
						// provenParamValue/empty() fix): a piece reaching here as a raw parameter
						// index means resolveExprToPieces already correctly identified "this IS the
						// writer's own parameter" (e.g. $dir in setTemplate($fname, $dir='views')),
						// but omitting it at a specific call site doesn't mean "unresolvable" -- it
						// means "takes its declared default", exactly as provenParamValue already
						// models for the SEPARATE branch-feasibility question. Without this
						// fallback, a call site that omits an argument was being disqualified
						// outright even when the omitted parameter's default was already proven.
						String def = paramDeclaredDefault(wshape.writerMethodId, writerParamIdx);
						if( def != null && def.startsWith("STR:") ) { resolved.add(def.substring(4)); continue; }
						ok = false; break;
					}
					Expression argExpr = al.getArgument(writerParamIdx);
					Long callerFuncIdForArg = null;
					try { callerFuncIdForArg = call.getFuncId(); } catch( Exception e2 ) {}
					String lit = resolveCallerArgAsLiteral(argExpr, callerFuncIdForArg, call.getNodeId());
					if( lit != null ) { resolved.add(lit); continue; }
					if( argExpr instanceof Variable && !sawPassThrough ) {
						String argVarName = varNameOf(argExpr);
						Integer myIdx = (argVarName != null) ? myParamIdx.get(argVarName) : null;
						if( myIdx != null ) { resolved.add(new ReaderParamRef(myIdx)); sawPassThrough = true; continue; }
					}
					ok = false; break;   // unresolved piece (dynamic, not a recognized pass-through,
						// or a second pass-through candidate) -- disqualify this call site entirely
				}
				if( !ok ) continue;   // try other call sites to the writer, if any exist
				TemplateLoaderShape shape = new TemplateLoaderShape();
				if( !sawPassThrough ) {
					StringBuilder sb = new StringBuilder();
					for( Object p : resolved ) if( p instanceof String ) sb.append((String)p);   // OPAQUE
						// pieces contribute nothing to the candidate string (their value is unknown
						// by design) but were already confirmed not to disqualify this resolution
					shape.paramIndex = -1;
					shape.fixedCandidate = sb.toString();
				} else {
					StringBuilder prefix = new StringBuilder(), suffix = new StringBuilder();
					boolean afterParam = false;
					int readerParamIdx = -1;
					for( Object p : resolved ) {
						if( p instanceof ReaderParamRef ) { readerParamIdx = ((ReaderParamRef)p).idx; afterParam = true; }
						else if( p instanceof String ) (afterParam ? suffix : prefix).append((String)p);
						// OPAQUE_SAFE_PIECE: contributes nothing to prefix/suffix, same reasoning as above
					}
					shape.paramIndex = readerParamIdx;
					shape.prefixFragment = prefix.toString();
					shape.suffixFragment = suffix.toString();
				}
				return shape;
			}
		}
		return null;
	}

	private static TemplateLoaderShape findTemplateLoaderShape(Long funcId) {
		ASTNode fn = ASTUnderConstruction.idToNode.get(funcId);
		if( !(fn instanceof FunctionDef) ) return null;
		ParameterList params = ((FunctionDef)fn).getParameterList();
		// The direct-include detection below genuinely needs at least one parameter to template
		// from -- but the property-mediated fallback does NOT (a zero-parameter function can still
		// be a valid "fixed" loader if all of its templating happens via literal arguments passed
		// to an internal setter call, e.g. P2-D's `render(){ setTemplate('/views/','backups/index');
		// include self::$template; }`). Skipping straight to the fallback for a zero-parameter
		// function, rather than returning null immediately, was a real bug this exact case caught.
		if( params == null || params.size() == 0 ) return findPropertyMediatedLoaderShape(funcId);
		java.util.Map<String,Integer> paramIndex = new java.util.HashMap<String,Integer>();
		for( int i = 0; i < params.size(); i++ ) {
			ast.functionDef.ParameterBase p = params.getParameter(i);
			if( p instanceof ast.php.functionDef.Parameter && ((ast.php.functionDef.Parameter)p).getNameChild() != null )
				paramIndex.put(((ast.php.functionDef.Parameter)p).getName(), i);
		}
		if( paramIndex.isEmpty() ) return null;
		for( ASTNode n : includeOrEvalNodesInFunc(funcId) ) {
			if( !(n instanceof IncludeOrEvalExpression) ) continue;
			Long nfid = null;
			try { nfid = n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(funcId) ) continue;
			Expression target = ((IncludeOrEvalExpression)n).getIncludeOrEvalExpression();
			if( target == null ) continue;
			java.util.List<String> paramRefs = new java.util.ArrayList<String>();
			java.util.List<String> literalFragments = new java.util.ArrayList<String>();
			boolean[] hasOtherVar = {false};
			collectTemplateFragments(target.getNodeId(), paramIndex.keySet(), paramRefs, literalFragments, hasOtherVar);
			if( hasOtherVar[0] || paramRefs.size() != 1 ) continue;   // ambiguous -- not this shape
			TemplateLoaderShape shape = new TemplateLoaderShape();
			shape.paramName = paramRefs.get(0);
			shape.paramIndex = paramIndex.get(shape.paramName);
			shape.suffixFragment = literalFragments.isEmpty() ? "" : literalFragments.get(literalFragments.size()-1);
			return shape;
		}
		return findPropertyMediatedLoaderShape(funcId);   // direct-include shape not found -- try
			// the static-property-mediated shape before giving up entirely.
	}

	private static void collectTemplateFragments(Long id, java.util.Set<String> paramNames,
			java.util.List<String> paramRefs, java.util.List<String> literalFragments, boolean[] hasOtherVar) {
		ASTNode n = ASTUnderConstruction.idToNode.get(id);
		if( n instanceof StringExpression ) { literalFragments.add(((StringExpression)n).getEscapedCodeStr()); return; }
		if( n instanceof Variable ) {
			String vn = varNameOf((Expression)n);
			if( vn != null && paramNames.contains(vn) ) paramRefs.add(vn);
			else hasOtherVar[0] = true;   // a variable that ISN'T a recognized parameter -- too
				// ambiguous to trust (could be a local derived from anything); disqualify.
			return;
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
		if( kids != null ) for( Long k : kids.values() )
			collectTemplateFragments(k, paramNames, paramRefs, literalFragments, hasOtherVar);
	}

	// Does `e` resolve to a PURE literal string with no variables or calls involved (a bare
	// literal, or a concatenation composed entirely of literals, e.g. 'backups/' . 'index')?
	// Returns null (unresolved) the moment anything non-literal is found anywhere in the tree --
	// deliberately strict, since this feeds a call-site substitution, not a display heuristic.
	//
	// ONE deliberate, narrow exception: realpath($x) is unwrapped to $x's own resolution. This is
	// NOT a claim that the exact runtime canonical path is known -- realpath() depends on live
	// filesystem state (symlinks, working directory, whether the target exists at all) that a
	// static analyzer has no way to see. What's preserved here is PROVENANCE, not the exact
	// runtime value: "this candidate path derives from literal fragments X" survives through
	// realpath() for the purpose of matching it against a known analyzed file by suffix, the same
	// approximate heuristic already used everywhere else in this pipeline (matchFileBySuffix never
	// claims to know a canonical runtime path either). Deliberately NOT generalized to other
	// single-argument wrappers (basename(), sanitize_file_name(), an arbitrary custom_transform())
	// -- each of those would need its own separately-justified semantics, not inherited by
	// pattern-matching "one argument, therefore transparent".
	private static String tryResolvePureLiteralConcat(Expression e) {
		if( e instanceof StringExpression ) return ((StringExpression)e).getEscapedCodeStr();
		if( e instanceof ast.expressions.BinaryExpression ) {
			ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)e;
			String l = tryResolvePureLiteralConcat(be.getLeft());
			if( l == null ) return null;
			String r = tryResolvePureLiteralConcat(be.getRight());
			if( r == null ) return null;
			return l + r;
		}
		if( e instanceof CallExpressionBase && "realpath".equals(callTargetName((CallExpressionBase)e)) ) {
			ArgumentList al = ((CallExpressionBase)e).getArgumentList();
			if( al != null && al.size() == 1 ) return tryResolvePureLiteralConcat(al.getArgument(0));
		}
		return null;
	}

	// Instance-field-mediated template provenance (receiver-sensitive instance-property
	// provenance across method calls). Scoped narrowly to allocation-site/field identity, NOT
	// full points-to analysis: the anchor is (readerClassName, fieldName) -- a field is only ever
	// resolved from within the class that owns it, never across two different fields or two
	// different local variables, even if both happen to hold instances of the same class. This is
	// deliberately conservative by construction, matching gates I1-I6:
	//   I1 same field, literal setter -> RESOLVE
	//   I2 different object fields -> DO NOT CROSS (only $this->{fieldName} itself is ever examined)
	//   I3 setter value attacker-controlled -> UNKNOWN (resolveExprToPieces returning null)
	//   I4 multiple conflicting setter calls -> UNKNOWN
	//   I5 setter on unresolved receiver -> UNKNOWN (ambiguous/missing call2mtd target)
	//   I6 known static prefix + literal template name -> RESOLVE
	private static java.util.Map<String,java.util.List<Object>> currentThisPropSubstitutions = null;

	// Is `e` a `$this->fieldName` PropertyExpression? Returns the field name, or null.
	private static String thisFieldName(Expression e) {
		if( !(e instanceof PropertyExpression) ) return null;
		Expression obj = ((PropertyExpression)e).getObjectExpression();
		if( !(obj instanceof Variable) || !"this".equals(varNameOf(obj)) ) return null;
		String name = receiverName(e);
		return name.isEmpty() ? null : name;
	}

	// A method whose ENTIRE body is exactly `return $this->prop;` -- a trivial getter. Resolving
	// THROUGH such a call (e.g. View::get_template_dir() wrapping $this->template_dir) is safe:
	// it's semantically identical to reading the property directly. A getter with any additional
	// logic correctly does NOT match, and falls through to unresolved elsewhere.
	private static String findTrivialThisPropGetterProp(Long methodId) {
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(methodId);
		if( kids == null ) return null;
		Long stmtListId = null;
		for( Long k : kids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn != null && "AST_STMT_LIST".equals(kn.getProperty("type")) ) { stmtListId = k; break; }
		}
		if( stmtListId == null ) return null;
		HashMap<Integer,Long> stmts = PHPCSVEdgeInterpreter.parent2child.get(stmtListId);
		if( stmts == null || stmts.size() != 1 ) return null;   // must be EXACTLY one statement
		ASTNode only = ASTUnderConstruction.idToNode.get(stmts.values().iterator().next());
		if( !(only instanceof ast.statements.jump.ReturnStatement) ) return null;
		Expression retExpr = ((ast.statements.jump.ReturnStatement)only).getReturnExpression();
		if( !(retExpr instanceof PropertyExpression) ) return null;
		Expression obj = ((PropertyExpression)retExpr).getObjectExpression();
		if( !(obj instanceof Variable) || !"this".equals(varNameOf(obj)) ) return null;
		String propName = receiverName(retExpr);
		return propName.isEmpty() ? null : propName;
	}

	// A method whose body includes `$this->prop = <its own first parameter>;` -- the standard
	// setter shape (e.g. View::set_template_dir($d) { $this->template_dir = $d; return $this; },
	// a fluent setter -- the trailing `return $this;` is fine, only the assignment matters).
	// Narrow and specific: only matches when the RHS is EXACTLY the setter's own param 0, not any
	// other expression, and returns null (ambiguous, fail closed) if more than one DIFFERENT
	// property is written this way within the same method.
	private static String findSingleParamPropertyWrite(Long methodId) {
		java.util.Map<String,Integer> params = paramIndexMap(ASTUnderConstruction.idToNode.get(methodId));
		if( params.isEmpty() ) return null;
		String foundProp = null;
		PHPCGFactory.recordScanSite("PCG_9477", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression ae = (AssignmentExpression)n;
			Long afid = null;
			try { afid = n.getFuncId(); } catch( Exception e ) {}
			if( afid == null || !afid.equals(methodId) ) continue;
			if( !(ae.getLeft() instanceof PropertyExpression) ) continue;
			PropertyExpression lhs = (PropertyExpression)ae.getLeft();
			Expression obj = lhs.getObjectExpression();
			if( !(obj instanceof Variable) || !"this".equals(varNameOf(obj)) ) continue;
			if( !(ae.getRight() instanceof Variable) ) continue;
			String rvn = varNameOf(ae.getRight());
			Integer idx = (rvn != null) ? params.get(rvn) : null;
			if( idx == null || idx != 0 ) continue;   // must come from the setter's OWN first
				// parameter specifically -- narrow, matches the observed shape
			String propName = receiverName(lhs);
			if( propName.isEmpty() ) continue;
			if( foundProp != null && !foundProp.equals(propName) ) return null;   // ambiguous
			foundProp = propName;
		}
		return foundProp;
	}

	// All `$this->{fieldName}->someMethod(args)` call sites found within methods belonging to
	// `className` specifically (I2: never crosses into a different class's own field of the same
	// name, or a different field on the same class).
	private static java.util.List<MethodCallExpression> collectFieldMethodCalls(String className, String fieldName) {
		java.util.List<MethodCallExpression> result = new java.util.ArrayList<MethodCallExpression>();
		PHPCGFactory.recordScanSite("PCG_9505", ((java.util.List<?>)allCallSites()).size());
		for( CallExpressionBase call : allCallSites() ) {
			if( !(call instanceof MethodCallExpression) ) continue;
			MethodCallExpression mc = (MethodCallExpression)call;
			String fn = thisFieldName(mc.getTargetObject());
			if( fn == null || !fn.equals(fieldName) ) continue;
			String encClass = enclosingClassName(mc);
			if( encClass == null || !simpleClassName(encClass).equalsIgnoreCase(simpleClassName(className)) ) continue;
			result.add(mc);
		}
		return result;
	}

	// ITEM53 FIX: findSingleIncludeInMethod() previously scanned ASTUnderConstruction.idToNode.
	// values() -- the entire corpus -- on every call, filtered afterward by methodId. Confirmed
	// as a genuine, high-confidence hot path via three independent, convergent signals (ITEM51):
	// static shape (per-item Long methodId parameter, loop-nested call site), live jstack
	// sampling (caught executing at 113s elapsed in a real GiveWP run), and direct instrumentation
	// (540 calls x ~913,957 nodes visited per call in one run -- essentially the full corpus, on
	// every single call). Reuses ITEM43's EXISTING includeOrEvalByFunc index rather than building
	// a new one -- that index's own build-pass filter (instanceof IncludeOrEvalExpression, then a
	// null-safe getFuncId() via the identical try/catch pattern, grouped by fid) is byte-for-byte
	// the same per-node filter this function applied inline, just pre-grouped instead of scanned
	// fresh each call. Every node includeOrEvalNodesInFunc(methodId) returns is therefore, by
	// construction of that index, already funcId-matched -- no re-check needed in the hot path.
	public static long FSIM_calls = 0, FSIM_fallbackScans = 0;

	private static Long legacyFindSingleIncludeInMethod(Long methodId) {
		// Byte-for-byte the original pre-ITEM53 scan logic, kept ONLY as a verification oracle
		// for WP_VERIFY_INCLUDE_INDEX=1 -- never called in normal operation.
		Long found = null;
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof IncludeOrEvalExpression) ) continue;
			Long fid = null;
			try { fid = n.getFuncId(); } catch( Exception e ) {}
			if( fid == null || !fid.equals(methodId) ) continue;
			if( found != null ) return null;
			found = n.getNodeId();
		}
		return found;
	}

	// A single, unambiguous include/eval statement within `methodId`'s own body, or null if zero
	// or more than one exist (multiple includes in one method is too ambiguous to trust which one
	// this analysis is meant to be resolving).
	private static Long findSingleIncludeInMethod(Long methodId) {
		FSIM_calls++;
		java.util.List<IncludeOrEvalExpression> candidates = includeOrEvalNodesInFunc(methodId);
		PHPCGFactory.recordScanSite("PCG_9522", candidates.size());
		Long found = null;
		for( IncludeOrEvalExpression n : candidates ) {
			if( found != null ) { found = null; break; }
			found = n.getNodeId();
		}
		if( System.getenv("WP_VERIFY_INCLUDE_INDEX") != null ) {
			Long legacy = legacyFindSingleIncludeInMethod(methodId);
			boolean same = (found == null && legacy == null) || (found != null && found.equals(legacy));
			if( !same ) {
				FSIM_fallbackScans++;
				System.err.println("FIND_SINGLE_INCLUDE_MISMATCH methodId=" + methodId
					+ " indexed=" + found + " legacy=" + legacy);
				found = legacy; // trust the verified-correct legacy path if they disagree
			}
		}
		return found;
	}

	// Establishes the resolved substitution map for `readerClassName`'s own `$this->{fieldName}`,
	// applying gates I3-I5, or returns null (unresolved) if any gate fails. Requires EXACTLY one
	// setter-shaped call on the field within the class (I4), that call's own target method
	// resolving unambiguously (I5), and its argument value resolving to something not
	// attacker-influenced (I3, via the same resolveExprToPieces machinery used throughout this
	// session's other template-provenance work).
	private static java.util.Map<String,java.util.List<Object>> establishFieldSubstitutions(String readerClassName, String fieldName) {
		boolean trace = System.getenv("WP_INCLUDE_TRACE") != null;
		java.util.List<MethodCallExpression> fieldCalls = collectFieldMethodCalls(readerClassName, fieldName);
		java.util.List<MethodCallExpression> setterCalls = new java.util.ArrayList<MethodCallExpression>();
		for( MethodCallExpression mc : fieldCalls ) {
			java.util.List<Long> targets = call2mtd.get(mc.getNodeId());
			if( targets == null || targets.size() != 1 ) continue;
			if( findSingleParamPropertyWrite(targets.get(0)) != null ) setterCalls.add(mc);
		}
		if( trace ) System.err.println("IFT_ESTABLISH class="+readerClassName+" field="+fieldName
			+" fieldCalls="+fieldCalls.size()+" setterCalls="+setterCalls.size());
		if( setterCalls.size() != 1 ) return null;   // I4
		MethodCallExpression setterCall = setterCalls.get(0);
		ArgumentList setterArgs = setterCall.getArgumentList();
		if( setterArgs == null || setterArgs.size() < 1 ) return null;
		Long setterCallerFuncId = null;
		try { setterCallerFuncId = setterCall.getFuncId(); } catch( Exception e ) {}
		if( setterCallerFuncId == null ) return null;   // I5
		java.util.Map<String,Integer> setterCallerParams = paramIndexMap(ASTUnderConstruction.idToNode.get(setterCallerFuncId));
		java.util.List<Object> setterValuePieces = resolveExprToPieces(setterArgs.getArgument(0), setterCallerFuncId, setterCallerParams, 0, setterCall.getNodeId());
		if( trace ) System.err.println("IFT_ESTABLISH   setterValuePieces="+setterValuePieces);
		if( setterValuePieces == null ) return null;   // I3
		java.util.List<Long> setterTargets = call2mtd.get(setterCall.getNodeId());
		if( setterTargets == null || setterTargets.size() != 1 ) return null;   // I5
		String writtenProp = findSingleParamPropertyWrite(setterTargets.get(0));
		if( trace ) System.err.println("IFT_ESTABLISH   writtenProp="+writtenProp);
		if( writtenProp == null ) return null;
		java.util.Map<String,java.util.List<Object>> result = new java.util.HashMap<String,java.util.List<Object>>();
		result.put(writtenProp, setterValuePieces);
		return result;
	}

	// Driver: for every `$this->{field}->getterMethod(args)` call site anywhere in the codebase,
	// checks whether the getter's own target method contains a single include statement mediated
	// by an instance property (I1/I6), and if so, resolves that field's state within the CALLING
	// class specifically (never crossing into another class's or another field's state -- I2),
	// then substitutes both the field value and this specific call's own arguments to build a
	// final candidate path. A per-(class,field) cache avoids re-deriving the same field's state
	// for every call site that reads it.
	private static void resolveInstanceFieldMediatedTemplates(java.util.Map<String,java.util.List<Long>> targetFileToIncludeNodes) {
		boolean trace = System.getenv("WP_INCLUDE_TRACE") != null;
		int resolved = 0;
		java.util.Map<String,java.util.Map<String,java.util.List<Object>>> fieldStateCache = new java.util.HashMap<String,java.util.Map<String,java.util.List<Object>>>();
		PHPCGFactory.recordScanSite("PCG_9582", ((java.util.List<?>)allCallSites()).size());
		for( CallExpressionBase call : allCallSites() ) {
			if( !(call instanceof MethodCallExpression) ) continue;
			MethodCallExpression mc = (MethodCallExpression)call;
			String fieldName = thisFieldName(mc.getTargetObject());
			if( fieldName == null ) continue;
			String readerClassName = enclosingClassName(mc);
			if( readerClassName == null ) continue;
			java.util.List<Long> getterTargets = call2mtd.get(mc.getNodeId());
			if( getterTargets == null || getterTargets.size() != 1 ) continue;
			Long getterMethodId = getterTargets.get(0);
			Long includeNodeId = findSingleIncludeInMethod(getterMethodId);
			if( trace && "view".equalsIgnoreCase(fieldName) ) System.err.println("IFT_SCAN call="+mc.getNodeId()+" class="+readerClassName
				+" field="+fieldName+" getterMethodId="+getterMethodId+" includeNodeId="+includeNodeId);
			if( includeNodeId == null ) continue;
			String cacheKey = simpleClassName(readerClassName) + "|" + fieldName;
			java.util.Map<String,java.util.List<Object>> substitutions;
			if( fieldStateCache.containsKey(cacheKey) ) {
				substitutions = fieldStateCache.get(cacheKey);
			} else {
				substitutions = establishFieldSubstitutions(readerClassName, fieldName);
				fieldStateCache.put(cacheKey, substitutions);
			}
			if( substitutions == null ) continue;
			currentThisPropSubstitutions = substitutions;
			try {
				ASTNode getterFn = ASTUnderConstruction.idToNode.get(getterMethodId);
				java.util.Map<String,Integer> getterParams = paramIndexMap(getterFn);
				ASTNode includeNode = ASTUnderConstruction.idToNode.get(includeNodeId);
				if( !(includeNode instanceof IncludeOrEvalExpression) ) continue;
				Expression target = ((IncludeOrEvalExpression)includeNode).getIncludeOrEvalExpression();
				java.util.List<Object> pieces = resolveExprToPieces(target, getterMethodId, getterParams, 0, includeNodeId);
				if( trace && "view".equalsIgnoreCase(fieldName) ) System.err.println("IFT_RESOLVE call="+mc.getNodeId()+" pieces="+pieces);
				if( pieces == null ) continue;
				ArgumentList callerArgs = mc.getArgumentList();
				StringBuilder sb = new StringBuilder();
				boolean ok = true;
				for( Object p : pieces ) {
					if( p instanceof String ) { sb.append((String)p); continue; }
					if( p == OPAQUE_SAFE_PIECE ) continue;   // contributes nothing, doesn't disqualify
					if( p instanceof Integer ) {
						int idx = (Integer)p;
						if( callerArgs == null || callerArgs.size() <= idx ) {
							// This call site omits the getter's own parameter at this position --
							// same fix as findPropertyMediatedLoaderShape's identical gap: fall back
							// to the getter's OWN declared default, if a simple literal one exists,
							// rather than disqualifying outright.
							String def = paramDeclaredDefault(getterMethodId, idx);
							if( def != null && def.startsWith("STR:") ) { sb.append(def.substring(4)); continue; }
							ok = false; break;
						}
						String lit = resolveCallerArgAsLiteral(callerArgs.getArgument(idx), mc.getFuncId(), mc.getNodeId());
						if( lit == null ) { ok = false; break; }
						sb.append(lit);
						continue;
					}
					ok = false; break;
				}
				if( trace && "view".equalsIgnoreCase(fieldName) ) System.err.println("IFT_SUBSTITUTE call="+mc.getNodeId()+" ok="+ok+" candidate="+(ok?sb.toString():"n/a"));
				if( !ok ) continue;
				String candidate = sb.toString();
				String resolvedFile = matchFileBySuffix(candidate);
				if( resolvedFile == null ) continue;
				targetFileToIncludeNodes.computeIfAbsent(resolvedFile, k -> new java.util.ArrayList<Long>()).add(mc.getNodeId());
				resolved++;
				if( trace ) System.err.println("INSTANCEFIELDTEMPLATE site="+mc.getNodeId()+" field="+fieldName
					+" candidate='"+candidate+"' resolvedFile="+resolvedFile);
			} finally {
				currentThisPropSubstitutions = null;
			}
		}
		if( resolved > 0 ) System.err.println("INSTANCE_FIELD_TEMPLATE_INDIRECTION resolved "+resolved+" call site(s) to a file target");
	}

	private static void resolveTemplateLoaderIndirection(java.util.Map<String,java.util.List<Long>> targetFileToIncludeNodes) {
		java.util.Map<Long,TemplateLoaderShape> loaders = new java.util.HashMap<Long,TemplateLoaderShape>();
		for( Long fid : allFunc ) { TemplateLoaderShape s = findTemplateLoaderShape(fid); if( s != null ) loaders.put(fid, s); }
		for( Long mid : allMtd ) { TemplateLoaderShape s = findTemplateLoaderShape(mid); if( s != null ) loaders.put(mid, s); }
		for( Long mid : allStaticMtd ) { TemplateLoaderShape s = findTemplateLoaderShape(mid); if( s != null ) loaders.put(mid, s); }
		if( loaders.isEmpty() ) return;
		boolean trace = System.getenv("WP_INCLUDE_TRACE") != null;
		int resolved = 0;
		PHPCGFactory.recordScanSite("PCG_9663", ((java.util.List<?>)allCallSites()).size());
		for( CallExpressionBase fc : allCallSites() ) {
			java.util.List<Long> targets = call2mtd.get(fc.getNodeId());
			if( targets == null || targets.isEmpty() ) continue;
			for( Long tfid : targets ) {
				TemplateLoaderShape shape = loaders.get(tfid);
				if( shape == null ) continue;
				String candidate;
				String literalArgForTrace = null;
				if( shape.paramIndex == -1 ) {
					// Fixed loader: the target doesn't depend on THIS call's own arguments at all
					// (every piece of the underlying write resolved to a literal already) -- every
					// call site to this loader resolves to the same candidate, including a
					// zero-argument call.
					candidate = shape.fixedCandidate;
				} else {
					ArgumentList al = fc.getArgumentList();
					if( al == null || al.size() <= shape.paramIndex ) continue;
					String literalArg = tryResolvePureLiteralConcat(al.getArgument(shape.paramIndex));
					if( literalArg == null ) continue;   // dynamic/unresolved argument -- correctly skip
					literalArgForTrace = literalArg;
					candidate = shape.prefixFragment + literalArg + shape.suffixFragment;
				}
				if( candidate == null ) continue;
				String resolvedFile = matchFileBySuffix(candidate);
				if( resolvedFile == null ) continue;
				targetFileToIncludeNodes.computeIfAbsent(resolvedFile, k -> new java.util.ArrayList<Long>()).add(fc.getNodeId());
				resolved++;
				if( trace ) System.err.println("TEMPLATELOADER site="+fc.getNodeId()
					+(literalArgForTrace != null ? " arg='"+literalArgForTrace+"'" : " (fixed, no arg needed)")
					+" candidate='"+candidate+"' resolvedFile="+resolvedFile);
			}
		}
		if( resolved > 0 ) System.err.println("TEMPLATELOADER_INDIRECTION resolved "+resolved+" call site(s) to a file target");
	}

	// Every call-expression instance this file already tracks separately by call shape (plain
	// function calls, instance-method calls, static-method calls), combined into one iterable.
	private static Iterable<CallExpressionBase> allCallSites() {
		java.util.List<CallExpressionBase> all = new java.util.ArrayList<CallExpressionBase>();
		all.addAll(functionCalls);
		all.addAll(nonStaticMethodCalls);
		all.addAll(staticMethodCalls);
		return all;
	}

	// Traces a bare local variable used directly as an include target back to a SINGLE,
	// unambiguous assignment within the same enclosing scope (function/method/file), then
	// resolves through that assignment's RHS. Mirrors the same "one write cannot launder another"
	// discipline used for static properties: more than one assignment to the same variable name
	// in the same scope, or none found, leaves it unresolved rather than guessing which one
	// reaches the include. A conditional wrapping the include itself (`if ($p !== false) {
	// include $p; }`) does not matter here -- getFuncId() is function-level, not block-level, so
	// the assignment and the include are found in the same scope regardless of nesting, and no
	// claim is made about which branch runs; only the STRING LINEAGE is traced, exactly as
	// intended (a boolean failure check on realpath()'s result doesn't change what $p derives from).
	private static Expression resolveLocalVariableAssignment(Expression varExpr) {
		if( !(varExpr instanceof Variable) ) return null;
		String varName = varNameOf(varExpr);
		if( varName == null ) return null;
		Long scopeId = null;
		try { scopeId = varExpr.getFuncId(); } catch( Exception e ) {}
		if( scopeId == null ) return null;
		Expression found = null;
		int count = 0;
		PHPCGFactory.recordScanSite("PCG_9727", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			AssignmentExpression ae = (AssignmentExpression)n;
			if( !(ae.getLeft() instanceof Variable) ) continue;
			String lhsName = varNameOf(ae.getLeft());
			if( lhsName == null || !lhsName.equals(varName) ) continue;
			Long afid = null;
			try { afid = n.getFuncId(); } catch( Exception e ) {}
			if( afid == null || !afid.equals(scopeId) ) continue;
			count++;
			found = ae.getRight();
			if( count > 1 ) return null;   // more than one assignment -- ambiguous, stay unresolved
		}
		return (count == 1) ? found : null;
	}

	private static String resolveIncludeTargetFile(Expression target) {
		if( target == null ) return null;
		if( target instanceof Variable ) {
			Expression assigned = resolveLocalVariableAssignment(target);
			return (assigned == null) ? null : resolveIncludeTargetFile(assigned);
		}
		java.util.List<String> fragments = new java.util.ArrayList<String>();
		collectStringLiteralFragments(target.getNodeId(), fragments);
		if( fragments.isEmpty() ) { if( System.getenv("WP_INCLUDE_TRACE") != null ) System.err.println("RITF node="+target.getNodeId()+" NO fragments found"); return null; }
		String longest = null;
		for( String f : fragments ) if( longest == null || f.length() > longest.length() ) longest = f;
		String result = matchFileBySuffix(longest);
		if( System.getenv("WP_INCLUDE_TRACE") != null ) System.err.println("RITF node="+target.getNodeId()+" fragments="+fragments+" longest="+longest+" result="+result);
		return result;
	}

	// Shared suffix-match: does exactly one analyzed file's path end with `fragment`? Used both by
	// the direct include-resolution above and by the template-loader indirection below, so both
	// paths apply the identical "ambiguous match -> give up" discipline.
	private static String matchFileBySuffix(String fragment) {
		if( fragment == null || fragment.length() < 4 || !fragment.contains(".php") ) return null;
		String match = null;
		for( String path : topLevelFunctionDefs.keySet() ) {
			if( path.endsWith(fragment) ) {
				if( match != null && !match.equals(path) ) return null;   // ambiguous -- give up
				match = path;
			}
		}
		return match;
	}

	// Phase 3 fix: previously recursed BLINDLY into every child regardless of node type, which
	// meant a literal fragment sitting inside an UNRELATED wrapping call's argument (e.g.
	// `unknown_transform('/views/backups/index.php')`) would still be found and treated as a
	// candidate -- silently ignoring the fact that the wrapping call could do anything to that
	// string. Now stops (does not recurse) at any CallExpressionBase except realpath(), which is
	// unwrapped -- the same single, narrow, separately-justified exception as everywhere else in
	// this pipeline (see tryResolvePureLiteralConcat's docstring). Confirmed via a dedicated
	// fixture (R3-C) that this was a real gap, not a hypothetical one.
	private static void collectStringLiteralFragments(Long id, java.util.List<String> out) {
		ASTNode n = ASTUnderConstruction.idToNode.get(id);
		if( n instanceof StringExpression ) { out.add(((StringExpression)n).getEscapedCodeStr()); return; }
		if( n instanceof CallExpressionBase ) {
			if( "realpath".equals(callTargetName((CallExpressionBase)n)) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() == 1 ) collectStringLiteralFragments(al.getArgument(0).getNodeId(), out);
			}
			return;   // any other call: stop here, don't recurse into its arguments
		}
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
		if( kids != null ) for( Long k : kids.values() ) collectStringLiteralFragments(k, out);
	}

	// Classification of a single include/require site reaching a target file.
	private static final class IncludeSiteClass {
		boolean isPublic = false;
		String capability = null;   // non-null iff gated by a recognized capability check
		boolean unresolved = false;
	}

	// Walk up from the include node to find its NEAREST ancestor IfElement within the same
	// enclosing function. If none: the include is unconditional in its own function -- if that
	// function itself has no established access gate (priv==null or "unauthenticated"), the
	// include site is PUBLIC (reachable with no local gate). If an IfElement IS found: check
	// whether its condition is (a call to) a recognized capability check with a literal
	// capability argument -- if so, CAPABILITY_GATED with that capability; otherwise UNRESOLVED.
	// Deliberately does NOT treat the ABSPATH direct-access guard as authorization (it never
	// reaches this path anyway -- isAbspathGuard's shape requires an exit-only body, and this
	// checks the CONDITION for a capability call specifically, not the include's own guard).
	// Recursion guard for resolveFileScopeAccess() below -- prevents infinite recursion on a
	// circular include chain (shouldn't normally occur, but must not hang if it does).
	private static java.util.Set<String> fileScopeResolutionInProgress = new HashSet<String>();

	// Resolves the access level of a FILE-SCOPE wrapper by recursively following its OWN include
	// provenance when it has no entryPriv of its own -- the fix for the bug classifyIncludeSite()
	// had: "enclosingPriv==null" was being treated as "therefore public", but for a file-scope
	// wrapper specifically, null just means THIS wrapper's own reachability hasn't been resolved
	// yet, not that it has none. Confirmed via direct trace on AIOWM's real sidebar-right.php ->
	// backups/index.php chain: backups/index.php has no entryPriv (it's a file, not a registered
	// callback), so the old code called it "public" without ever checking THAT file's own include
	// sites, which are in fact gated via add_submenu_page(..., 'ai1wm_import_site', ...) three
	// hops up. Bounded by fileScopeResolutionInProgress (cycle guard) and an explicit depth cap.
	private static String resolveFileScopeAccess(String filePath, java.util.Map<String,java.util.List<Long>> targetFileToIncludeNodes, int depth) {
		if( filePath == null || depth > 8 || !fileScopeResolutionInProgress.add(filePath) ) return "unknown-not-classified";
		try {
			String cached = fileIncludeAccessEvidence.get(filePath);
			if( cached != null ) {
				return cached.startsWith("AUTHORIZATION_ESTABLISHED") ? "authenticated-min-privilege-not-established"
					: "PUBLICLY_REACHABLE".equals(cached) ? "unauthenticated" : "unknown-not-classified";
			}
			java.util.List<Long> sites = targetFileToIncludeNodes.get(filePath);
			if( System.getenv("WP_INCLUDE_TRACE") != null && (filePath.contains("header.php") || filePath.contains("footer.php")) )
				System.err.println("RFSA filePath='"+filePath+"' sites="+sites+" depth="+depth);
			if( sites == null || sites.isEmpty() ) return "unknown-not-classified";
			boolean anyPublic = false, anyUnresolved = false;
			String establishedCap = null;
			for( Long siteId : sites ) {
				IncludeSiteClass cls = classifyIncludeSite(siteId, targetFileToIncludeNodes, depth + 1);
				if( cls.isPublic ) anyPublic = true;
				else if( cls.capability != null ) establishedCap = cls.capability;
				else anyUnresolved = true;
			}
			if( anyPublic ) return "unauthenticated";
			if( !anyUnresolved && establishedCap != null ) return "authenticated-min-privilege-not-established";
			return "unknown-not-classified";
		} finally { fileScopeResolutionInProgress.remove(filePath); }
	}

	// Is `condId` PURELY a check on `varName` itself (e.g. `$p !== false`, `!$p`, `$p === null`) --
	// no other variable, no function call anywhere in the condition? If so this is a
	// failure/null check on the include's OWN target, not an access-control decision, and should
	// be transparent to classifyIncludeSite's walk rather than treated as an unresolved gate.
	// Deliberately requires the target variable to actually appear (so a condition that happens
	// to contain no variables at all doesn't vacuously qualify) and disqualifies on ANY other
	// variable or call found anywhere in the subtree -- narrow by design, since getting this wrong
	// in the permissive direction would let a genuine access check slip past unexamined.
	private static boolean isPureFailureCheckOnVariable(Long condId, String varName) {
		boolean[] sawOtherVar = {false};
		boolean[] sawCall = {false};
		boolean[] sawTargetVar = {false};
		collectVarAndCallUsage(condId, varName, sawOtherVar, sawCall, sawTargetVar);
		return sawTargetVar[0] && !sawOtherVar[0] && !sawCall[0];
	}

	private static void collectVarAndCallUsage(Long id, String varName, boolean[] sawOtherVar, boolean[] sawCall, boolean[] sawTargetVar) {
		ASTNode n = ASTUnderConstruction.idToNode.get(id);
		if( n instanceof Variable ) {
			String vn = varNameOf((Expression)n);
			if( varName.equals(vn) ) sawTargetVar[0] = true; else sawOtherVar[0] = true;
			return;
		}
		if( n instanceof CallExpressionBase ) { sawCall[0] = true; return; }
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
		if( kids != null ) for( Long k : kids.values() ) collectVarAndCallUsage(k, varName, sawOtherVar, sawCall, sawTargetVar);
	}

	private static IncludeSiteClass classifyIncludeSite(Long includeNodeId, java.util.Map<String,java.util.List<Long>> targetFileToIncludeNodes, int depth) {
		IncludeSiteClass result = new IncludeSiteClass();
		Long fid = null;
		ASTNode incNode = ASTUnderConstruction.idToNode.get(includeNodeId);
		try { fid = incNode == null ? null : incNode.getFuncId(); } catch( Exception e ) {}
		String includeTargetVarName = null;
		if( incNode instanceof IncludeOrEvalExpression ) {
			Expression t = ((IncludeOrEvalExpression)incNode).getIncludeOrEvalExpression();
			if( t instanceof Variable ) includeTargetVarName = varNameOf(t);
		}
		boolean trace = System.getenv("WP_INCLUDE_TRACE") != null;
		if( trace ) System.err.println("INCTRACE site="+includeNodeId+" file="+getDir(includeNodeId)+" enclosingFid="+fid+" depth="+depth);
		Long cur = PHPCSVEdgeInterpreter.child2parent.get(includeNodeId);
		int guard = 0;
		while( cur != null && guard++ < 300 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			Long nfid = null;
			try { nfid = (n == null) ? null : n.getFuncId(); } catch( Exception e ) {}
			if( nfid == null || !nfid.equals(fid) ) break;   // left the enclosing function/file scope
			if( n instanceof ast.php.statements.blockstarters.IfElement ) {
				if( includeTargetVarName != null ) {
					HashMap<Integer,Long> elemKids = PHPCSVEdgeInterpreter.parent2child.get(cur);
					Long condId = null;
					if( elemKids != null ) for( Long k : elemKids.values() ) {
						ASTNode kn = ASTUnderConstruction.idToNode.get(k);
						if( kn instanceof CallExpressionBase || kn instanceof ast.expressions.UnaryExpression
								|| kn instanceof ast.expressions.BinaryExpression || kn instanceof Variable ) { condId = k; break; }
					}
					if( condId != null && isPureFailureCheckOnVariable(condId, includeTargetVarName) ) {
						if( trace ) System.err.println("INCTRACE   ancestor IfElement is a pure failure-check on the include's own target var ("+includeTargetVarName+") -- transparent, continuing walk");
						cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
						continue;
					}
				}
				String cap = capabilityGuardingIfElem(cur);
				if( trace ) System.err.println("INCTRACE   found ancestor IfElement -> capability="+cap);
				if( cap != null ) { result.capability = cap; return result; }
				result.unresolved = true;
				return result;
			}
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		// No ancestor IfElement found within the enclosing scope -- unconditional. If the
		// enclosing scope is ITSELF an unresolved file-scope wrapper, recursively resolve ITS
		// access instead of assuming public -- this is the actual fix (see resolveFileScopeAccess
		// docstring). Only a NON-file-scope enclosing context (an ordinary function/method with no
		// known registration) still falls back to "no established gate -> public reach", since
		// there's no further include-provenance chain to trace for an ordinary function call.
		boolean enclosingIsFileScope = fid != null && reasonTopLevelFileScope.contains(fid);
		String enclosingAccess;
		if( enclosingIsFileScope ) {
			enclosingAccess = resolveFileScopeAccess(getDir(fid), targetFileToIncludeNodes, depth);
		} else {
			String enclosingPriv = (fid != null) ? entryPriv.get(fid) : null;
			enclosingAccess = wpEntryAccess(enclosingPriv);
			if( enclosingPriv == null ) enclosingAccess = "unauthenticated";   // ordinary function, no
				// known registration at all -- treated as reachable with no established local gate
				// (matches the incB adversarial fixture's intent: an unregistered method reaching an
				// unconditional include IS the "no protection proven" case for that narrower shape).
		}
		if( trace ) System.err.println("INCTRACE   unconditional, enclosingIsFileScope="+enclosingIsFileScope
			+" enclosingAccess="+enclosingAccess+" enclosingFile="+(fid!=null?getDir(fid):null));
		if( "unauthenticated".equals(enclosingAccess) ) {
			result.isPublic = true;
		} else if( "authenticated-min-privilege-not-established".equals(enclosingAccess) ) {
			// The enclosing file-scope wrapper resolved to a genuine established gate (recursively,
			// via resolveFileScopeAccess) -- inherit it. The specific capability string isn't
			// threaded back through this return value; resolveFileScopeIncludeProvenance()
			// re-derives the exact capability directly when persisting the final evidence. This
			// placeholder just needs to be non-null so the combination logic (ALL paths gated, none
			// unresolved) correctly credits this path as gated rather than unresolved.
			result.capability = "inherited-from-file-scope-chain";
		} else {
			result.unresolved = true;
		}
		if( trace ) System.err.println("INCTRACE   -> isPublic="+result.isPublic+" unresolved="+result.unresolved+" capability="+result.capability);
		return result;
	}

	// Does IfElement `elemId`'s condition consist of (contain) a call to a recognized capability
	// check with a literal capability-string argument? Narrow, whole-subtree check (not precise
	// condition-vs-body separation) -- deliberately conservative in the SAME direction as the
	// rest of this predicate: a false "not gated" (missing a real guard) just leaves the entry
	// UNKNOWN, never wrongly clears it, so a slightly coarse match here is safe.
	private static String capabilityGuardingIfElem(Long elemId) {
		HashMap<Integer,Long> elemKids = PHPCSVEdgeInterpreter.parent2child.get(elemId);
		if( elemKids == null ) return null;
		Long condId = null;
		for( Long k : elemKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn instanceof CallExpressionBase || kn instanceof ast.expressions.UnaryExpression
					|| kn instanceof ast.expressions.BinaryExpression ) { condId = k; break; }
		}
		if( condId == null ) return null;
		return findCapabilityCallInSubtree(condId);
	}

	private static String findCapabilityCallInSubtree(Long root) {
		java.util.ArrayDeque<Long> work = new java.util.ArrayDeque<Long>();
		java.util.Set<Long> seen = new HashSet<Long>();
		work.add(root);
		while( !work.isEmpty() ) {
			Long id = work.poll();
			if( id == null || !seen.add(id) ) continue;
			ASTNode n = ASTUnderConstruction.idToNode.get(id);
			if( n instanceof CallExpressionBase ) {
				String nm = callTargetName((CallExpressionBase)n);
				if( CAPABILITY_CHECK_FNS.contains(nm) ) {
					ArgumentList al = ((CallExpressionBase)n).getArgumentList();
					if( al != null && al.size() >= 1 && al.getArgument(0) instanceof StringExpression ) {
						return ((StringExpression)al.getArgument(0)).getEscapedCodeStr();
					}
				}
			}
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(id);
			if( kids != null ) work.addAll(kids.values());
		}
		return null;
	}

	// Main orchestrator: for every FILE_SCOPE_EXECUTABLE entry, find all include sites that
	// target its file, classify each, and combine per the strict policy: any PUBLIC path wins
	// (dominates); otherwise ALL paths must be capability-gated with none unresolved; anything
	// else (a mix, or no include sites at all) stays UNKNOWN. Never optimizes toward zero UNKNOWN.
	private static void resolveFileScopeIncludeProvenance() {
		java.util.Map<String,java.util.List<Long>> targetFileToIncludeNodes = new java.util.HashMap<String,java.util.List<Long>>();
		PHPCGFactory.recordScanSite("PCG_10005", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof IncludeOrEvalExpression) ) continue;
			String resolved = resolveIncludeTargetFile(((IncludeOrEvalExpression)n).getIncludeOrEvalExpression());
			if( resolved == null ) continue;
			targetFileToIncludeNodes.computeIfAbsent(resolved, k -> new java.util.ArrayList<Long>()).add(n.getNodeId());
		}
		resolveTemplateLoaderIndirection(targetFileToIncludeNodes);
		resolveInstanceFieldMediatedTemplates(targetFileToIncludeNodes);
		if( targetFileToIncludeNodes.isEmpty() ) return;
		int resolvedCount = 0;
		for( Long entry : reasonTopLevelFileScope ) {
			if( isFileScopeDeclarationOnly(entry) ) continue;   // Part 1 already excludes these
			String myFile = getDir(entry);
			if( myFile == null || fileIncludeAccessEvidence.containsKey(myFile) ) continue;
			String resolvedAccess = resolveFileScopeAccess(myFile, targetFileToIncludeNodes, 0);
			if( "unauthenticated".equals(resolvedAccess) ) {
				fileIncludeAccessEvidence.put(myFile, "PUBLICLY_REACHABLE"); resolvedCount++;
			} else if( "authenticated-min-privilege-not-established".equals(resolvedAccess) ) {
				// establishedCap isn't threaded back through resolveFileScopeAccess's string return
				// (it collapses to the same access bucket wpEntryAccess() already uses) -- re-derive
				// it directly here so the stored evidence still records which capability applied.
				java.util.List<Long> sites = targetFileToIncludeNodes.get(myFile);
				String cap = null;
				if( sites != null ) for( Long siteId : sites ) {
					IncludeSiteClass cls = classifyIncludeSite(siteId, targetFileToIncludeNodes, 0);
					if( cls.capability != null ) { cap = cls.capability; break; }
				}
				fileIncludeAccessEvidence.put(myFile, "AUTHORIZATION_ESTABLISHED:" + (cap != null ? cap : "unknown"));
				resolvedCount++;
			}
			// else: stays UNKNOWN -- nothing written, matches the strict combination policy
		}
		if( resolvedCount > 0 ) System.err.println("FILESCOPE_INCLUDE_PROVENANCE resolved "+resolvedCount+" file(s) via include-chain evidence");
	}

	private static String wpEntryAccess(String priv) {
		// Absence of a classification is NOT evidence of inaccessibility. Returning null here used
		// to DROP the entry, which made the mechanism a recall policy dependent on complete
		// WordPress entry modelling: 307 of 351 entries on participants-database were discarded
		// this way. Unknown access must REDUCE CONFIDENCE, not remove the path. The generic core
		// can still report a witness when the adapter cannot classify the entry.
		if( priv == null ) return "unknown-not-classified";
		if( priv.contains("unauth") || priv.contains("nopriv") ) return "unauthenticated";
		if( priv.contains("authed") || priv.contains("wp_ajax") || priv.contains("subscriber")
		    || priv.contains("contributor") || priv.startsWith("rest:") ) return "authenticated-min-privilege-not-established";
			// "contributor" covers three deliberate, pre-existing seeding tags this function had
			// never been taught to recognize: "elementor:contributor" (widget render() methods,
			// since a contributor-authored post's widget settings are attacker-controllable),
			// "block:contributor", and "shortcode:contributor" (same rationale -- content authored
			// by a low-privilege, but genuinely authenticated, WordPress role). All three represent
			// a real, known privilege level, not an unclassifiable one; they were incorrectly
			// falling into unknown-not-classified / registered_unrecognized_priv_format purely
			// because no substring matched, not because the access was actually unknown. Confirmed
			// via the Elementor cross-plugin pass: 47 "registered_unrecognized_priv_format:
			// elementor:contributor" entries, none of which needed a new mechanism -- just this
			// classification to be wired up. This does not change which findings are emitted (an
			// unknown-access path was never dropped, only under-labeled), only the accuracy of the
			// entry_access/coverage-summary bucketing.
		return "unknown-not-classified";
	}

	// Bucket name for an UNKNOWN-classified entry, for the coverage summary's reason breakdown.
	// Distinguishes "never got a priv registration at all" (broken down by WHICH seeding
	// mechanism produced it) from "got a priv string, but its format wasn't recognized".
	private static String wpEntryAccessUnknownReason(Long entry, String priv) {
		if( priv != null ) {
			return "registered_unrecognized_priv_format:" + priv;
		}
		if( reasonTopLevelFileScope.contains(entry) ) {
			if( isFileScopeDeclarationOnly(entry) ) return "top_level_file_scope_declaration_only";
			if( isConfigDataFile(entry) ) return "top_level_file_scope_config_data";
			return "top_level_file_scope_executable";
		}
		if( reasonSelfContainedHandler.contains(entry) ) return "self_contained_handler_no_registration_traced";
		if( reasonSqlFilterCallbackRoot.contains(entry) ) return "sql_filter_callback_root_seeding";
		return "no_registration_model_other";
	}

	// FILE_SCOPE_DECLARATION_ONLY predicate (see design note above unknownReasonBuckets).
	// Conservative BY DESIGN: a file's top-level statement list must consist ENTIRELY of
	// class/function/namespace/use/const declarations, or the standard WordPress direct-access
	// guard (`if(!defined('ABSPATH')){die/exit;}`), or a bare `define('LITERAL', ...)` constant
	// call, for the wrapper to be excluded from entry-access statistics. Any statement not
	// confidently matched -- output, any OTHER call, assignment, require/include, other control
	// flow -- fails CLOSED (keeps the wrapper as executable), per explicit instruction: this
	// changes ACCOUNTING (removes noise from the UNKNOWN denominator), never SUPPRESSES a
	// genuine finding, since a declaration-only file trivially has no source->sink flow of its
	// own to suppress in the first place.
	private static final java.util.Set<String> FILE_SCOPE_SAFE_TYPES = new java.util.HashSet<String>(java.util.Arrays.asList(
		"AST_CLASS", "AST_FUNC_DECL", "AST_USE", "AST_USE_TRAIT", "AST_NAMESPACE", "AST_GROUP_USE",
		"AST_CONST_DECL", "AST_CONST_ELEM", "AST_DECLARE",
		// AST_DECLARE ("declare(strict_types=1);" and similar) is a purely inert compile-time
		// directive with zero security-relevant effect -- confirmed real via Smush's own
		// scoper.inc.php (a PHP-Scoper-generated vendor config file), which opens with exactly
		// this statement before its data. Same spirit as namespace/use.
		// A class/interface/trait body is itself represented as its own AST_TOPLEVEL
		// (TOPLEVEL_CLASS) wrapper by this parser, distinct from the file-level wrapper --
		// confirmed directly (dofC fixture: node 2 = TOPLEVEL_FILE, node 9 = TOPLEVEL_CLASS for
		// an empty `class Foo {}`). Declaring a method/property/class-constant is never itself
		// an executable statement (only CALLING a method executes anything), so these are safe
		// within a class body's own statement list the same way AST_FUNC_DECL is at file scope.
		"AST_METHOD", "AST_PROP_DECL", "AST_PROP_ELEM", "AST_CLASS_CONST_DECL", "AST_CLASS_CONST_GROUP"
	));

	// WordPress's own plugin handbook documents uninstall.php (at a plugin's ROOT directory,
	// exactly that filename) as one of two supported uninstall mechanisms (the other being
	// register_uninstall_hook()). WordPress core's uninstall_plugin() specifically looks for this
	// file by name/location as part of the admin-triggered uninstall workflow -- it is NOT an
	// ordinary web request entry point, and its access gate is the WordPress uninstall workflow
	// itself (reachable only through an admin-initiated plugin deletion, which core itself gates
	// on the delete_plugins capability), not any local current_user_can() check inside the file.
	// This is a distinct classification axis from declaration-only/executable and from
	// unauthenticated/authenticated -- checked with HIGHEST PRIORITY in the main entry loop,
	// before the generic file-scope buckets, precisely because generic buckets would either
	// wrongly suppress it (if it happened to look declaration-only) or wrongly leave it
	// UNKNOWN/unauthenticated (the current default), neither of which reflects what it actually is.
	private static boolean isWordPressUninstallEntry(Long topLevelId) {
		String dir = getDir(topLevelId);
		if( dir == null ) return false;
		String normalized = dir.startsWith("./") ? dir.substring(2) : dir;
		return "uninstall.php".equals(normalized);   // must be the plugin's OWN root file,
			// exactly this name -- not any subdirectory (matching WordPress core's own convention)
	}

	private static final java.util.Set<String> WP_UNINSTALL_GUARD_CONSTANTS = new java.util.HashSet<String>(
		java.util.Arrays.asList("WP_UNINSTALL_PLUGIN")
	);

	// Tracked as SEPARATE, ADDITIONAL evidence -- NOT what makes a file an uninstall entry (the
	// filename/location does that, per isWordPressUninstallEntry). A file legitimately named and
	// located as uninstall.php is still recognized as one even without this guard present; this
	// only records whether the file ALSO carries the conventional
	// `if (!defined('WP_UNINSTALL_PLUGIN')) { exit; }` (or short-circuit `|| exit;`) marker.
	private static boolean hasWpUninstallPluginGuard(Long topLevelId) {
		HashMap<Integer,Long> topKids = PHPCSVEdgeInterpreter.parent2child.get(topLevelId);
		if( topKids == null ) return false;
		Long stmtListId = null;
		for( Long k : topKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn != null && "AST_STMT_LIST".equals(kn.getProperty("type")) ) { stmtListId = k; break; }
		}
		if( stmtListId == null ) return false;
		HashMap<Integer,Long> stmts = PHPCSVEdgeInterpreter.parent2child.get(stmtListId);
		if( stmts == null ) return false;
		for( Long sid : stmts.values() ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(sid);
			if( n == null ) continue;
			String type = n.getProperty("type");
			if( "AST_IF".equals(type) && isIfExitGuardFor(n, WP_UNINSTALL_GUARD_CONSTANTS) ) return true;
			if( isShortCircuitExitGuardFor(n, WP_UNINSTALL_GUARD_CONSTANTS) ) return true;
		}
		return false;
	}

	// Config/data-file candidate: a file whose top-level is entirely declaration-safe statements
	// followed by EXACTLY ONE trailing `return <pure static data>;` -- the standard "this file IS
	// a data structure, meant to be `include`d and used as a value" idiom (WordPress build-asset
	// manifests like *.asset.php, PHP-Scoper config files, plugin-list arrays, etc). Deliberately
	// stricter than isExpressionProvenSafe: requires PURE, fully-static data (literals and nested
	// arrays of literals only) -- no variables (even a harmless-looking one could be attacker-
	// influenced depending on scope) and no function calls at all (even ones proven safe
	// elsewhere), since a "config file" that actually computes anything isn't a data file, it's
	// executable code that happens to return something.
	private static boolean isPureStaticDataExpression(Expression e) {
		if( e == null ) return true;
		if( e instanceof StringExpression ) return true;
		if( e instanceof ast.expressions.IntegerExpression ) return true;
		if( e instanceof ast.expressions.Constant ) return true;
		if( e instanceof ast.expressions.UnaryExpression ) {
			// tolerate a leading unary minus on a numeric literal (e.g. -1), nothing else
			return isPureStaticDataExpression(((ast.expressions.UnaryExpression)e).getExpression());
		}
		if( e instanceof ast.php.expressions.ArrayExpression ) {
			ast.php.expressions.ArrayExpression arr = (ast.php.expressions.ArrayExpression)e;
			for( int i = 0; i < arr.size(); i++ ) {
				ast.php.expressions.ArrayElement el = arr.getArrayElement(i);
				if( el == null ) return false;
				if( el.getKey() != null && !isPureStaticDataExpression(el.getKey()) ) return false;
				if( el.getValue() != null && !isPureStaticDataExpression(el.getValue()) ) return false;
			}
			return true;
		}
		return false;   // a variable, a call, or anything else -- not pure static data
	}

	private static boolean isConfigDataFile(Long topLevelId) {
		HashMap<Integer,Long> topKids = PHPCSVEdgeInterpreter.parent2child.get(topLevelId);
		if( topKids == null ) return false;
		Long stmtListId = null;
		for( Long k : topKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn != null && "AST_STMT_LIST".equals(kn.getProperty("type")) ) { stmtListId = k; break; }
		}
		if( stmtListId == null ) return false;
		HashMap<Integer,Long> stmts = PHPCSVEdgeInterpreter.parent2child.get(stmtListId);
		if( stmts == null || stmts.isEmpty() ) return false;
		java.util.List<Long> ordered = new java.util.ArrayList<Long>(stmts.values());
		java.util.Collections.sort(ordered);   // node ids are parse-order-monotonic (established
			// and relied on elsewhere this session)
		Long lastId = ordered.get(ordered.size() - 1);
		for( Long sid : ordered ) {
			if( sid.equals(lastId) ) continue;
			if( !isFileScopeSafeStatement(sid) ) return false;   // anything before the trailing
				// return must be ordinary declaration-safe boilerplate (namespace/use/declare/etc)
		}
		ASTNode last = ASTUnderConstruction.idToNode.get(lastId);
		if( !(last instanceof ast.statements.jump.ReturnStatement) ) return false;
		return isPureStaticDataExpression(((ast.statements.jump.ReturnStatement)last).getReturnExpression());
	}

	private static boolean isFileScopeDeclarationOnly(Long topLevelId) {
		boolean trace = System.getenv("WP_FSDO_TRACE") != null;
		HashMap<Integer,Long> topKids = PHPCSVEdgeInterpreter.parent2child.get(topLevelId);
		if( topKids == null ) { if(trace) System.err.println("FILE_SCOPE_CLASSIFY node="+topLevelId+" topKids=null -> false"); return false; }
		Long stmtListId = null;
		for( Long k : topKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn != null && "AST_STMT_LIST".equals(kn.getProperty("type")) ) { stmtListId = k; break; }
		}
		if( stmtListId == null ) { if(trace) System.err.println("FILE_SCOPE_CLASSIFY node="+topLevelId+" no stmtList found among topKids="+topKids.values()+" -> false"); return false; }
		HashMap<Integer,Long> stmts = PHPCSVEdgeInterpreter.parent2child.get(stmtListId);
		if( stmts == null ) { if(trace) System.err.println("FILE_SCOPE_CLASSIFY node="+topLevelId+" stmtListId="+stmtListId+" empty body -> true"); return true; }
		if( trace ) {
			StringBuilder sb = new StringBuilder();
			for( Long sid : stmts.values() ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(sid);
				String type = (n != null) ? n.getProperty("type") : "null-node";
				boolean safe = (n != null) && isFileScopeSafeStatement(sid);
				sb.append("[id="+sid+" type="+type+" file="+getDir(sid)+" safe="+safe+"] ");
			}
			System.err.println("FILE_SCOPE_CLASSIFY node="+topLevelId+" file="+getDir(topLevelId)+" stmtListId="+stmtListId+" children: "+sb);
		}
		for( Long sid : stmts.values() ) if( !isFileScopeSafeStatement(sid) ) return false;
		return true;
	}

	// `defined('ABSPATH'|'WPINC') || exit/die;` -- a short-circuit, single-expression variant of
	// the SAME direct-access guard concept as isAbspathGuard, structurally different (a bare
	// BinaryExpression statement, not an AST_IF at all) but semantically identical. Confirmed as
	// the SINGLE DOMINANT rejected shape across Smush's remaining executable bucket (13 of 34
	// entries), via direct FILE_SCOPE_REJECT-style tracing, not assumed from filenames. Same
	// reasoning as isAbspathGuard for why this is safe to treat as inert boilerplate: its only
	// possible runtime effect is terminating the request.
	// A bare, unconditional hook-registration or singleton-bootstrap call sitting directly at file
	// scope -- add_action()/add_filter(), register_activation_hook()-family, Class::init()/
	// Class::instance()/Class::get_instance()(), or `new Class(...)` as a standalone statement.
	// Confirmed as the dominant driver of the top_level_file_scope_executable UNKNOWN bucket via
	// direct count against real Jetpack source: 506 file-scope add_action/add_filter calls + 46
	// Class::init()/instance() calls + 8 bare `new Class()` calls + 3 register_activation_hook-
	// family calls = 563, against a bucket total of 564 for that scan -- a near-exact accounting,
	// not an estimate. This is Jetpack's (and WordPress's generally) standard per-module bootstrap
	// idiom: a small file does a direct-access guard plus one such call, and the real class named
	// there does its own add_action/add_filter wiring internally once loaded. Same spirit and same
	// narrow scope as the existing guards: NOT authorization evidence, says nothing about who can
	// reach anything -- the call's OWN target function/method is still fully call-graph-traversed
	// and any sink reachable through it is unaffected. This only says the STATEMENT ITSELF, sitting
	// bare at file scope, is inert registration/bootstrap boilerplate, not attacker-relevant logic
	// in its own right -- exactly the same claim already made for a bare define() call.
	private static boolean isFileScopeBootstrapCall(ASTNode n) {
		if( !(n instanceof CallExpressionBase) ) return false;
		CallExpressionBase call = (CallExpressionBase)n;
		String cn = callTargetName(call);
		if( cn != null ) {
			if( cn.equals("add_action") || cn.equals("add_filter")
					|| cn.equals("register_activation_hook") || cn.equals("register_deactivation_hook")
					|| cn.equals("register_uninstall_hook") ) return true;
			if( (call instanceof StaticCallExpression)
					&& (cn.equals("init") || cn.equals("instance") || cn.equals("get_instance")) ) return true;
		}
		if( n instanceof NewExpression ) return true;
		return false;
	}

	private static boolean isShortCircuitDirectAccessGuard(ASTNode n) {
		return isShortCircuitExitGuardFor(n, DIRECT_ACCESS_GUARD_CONSTANTS);
	}

	// Parameterized version of the short-circuit `defined(X) || exit;` shape check, reused both
	// for the general ABSPATH/WPINC direct-access guard (declaration-only safe boilerplate) and
	// for the WordPress uninstall.php WP_UNINSTALL_PLUGIN guard (tracked as SEPARATE evidence,
	// not folded into the same "safe boilerplate" bucket -- see hasWpUninstallPluginGuard).
	private static boolean isShortCircuitExitGuardFor(ASTNode n, java.util.Set<String> constants) {
		if( !(n instanceof ast.expressions.BinaryExpression) ) return false;
		if( !"BINARY_BOOL_OR".equals(n.getFlags()) ) return false;
		ast.expressions.BinaryExpression be = (ast.expressions.BinaryExpression)n;
		Expression left = be.getLeft(), right = be.getRight();
		if( !(left instanceof CallExpressionBase) || !"defined".equals(callTargetName((CallExpressionBase)left)) ) return false;
		ArgumentList definedArgs = ((CallExpressionBase)left).getArgumentList();
		if( definedArgs == null || definedArgs.size() < 1 || !(definedArgs.getArgument(0) instanceof StringExpression)
				|| !constants.contains(((StringExpression)definedArgs.getArgument(0)).getEscapedCodeStr()) ) return false;
		return right != null && "AST_EXIT".equals(right.getProperty("type"));
	}

	// `if (!class_exists('X')) { class X { ... } }` -- the standard "avoid redeclaration" idiom
	// used by vendor-bundled libraries (the same library can end up bundled by multiple plugins;
	// this prevents a fatal "cannot redeclare class" error if it's already loaded). Confirmed real
	// via Smush's own wpmudev-analytics vendor bundle. Requires the checked class name to match
	// the declared class name inside (same discipline as isConditionalDefineGuard), and the body
	// to consist of nothing but declaration-only-safe statements (recursing into
	// isFileScopeSafeStatement for each) -- not just "any single class declaration", since a body
	// with additional executable statements alongside the class would not be safe.
	private static boolean isClassExistsGuard(ASTNode ifNode) {
		HashMap<Integer,Long> ifKids = PHPCSVEdgeInterpreter.parent2child.get(ifNode.getNodeId());
		if( ifKids == null || ifKids.size() != 1 ) return false;   // exactly one AST_IF_ELEM (no else)
		Long elemId = ifKids.values().iterator().next();
		ASTNode elem = ASTUnderConstruction.idToNode.get(elemId);
		if( elem == null || !"AST_IF_ELEM".equals(elem.getProperty("type")) ) return false;
		HashMap<Integer,Long> elemKids = PHPCSVEdgeInterpreter.parent2child.get(elemId);
		if( elemKids == null || elemKids.size() != 2 ) return false;
		ASTNode cond = null, body = null;
		for( Long k : elemKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn == null ) continue;
			if( kn instanceof ast.expressions.UnaryExpression ) cond = kn;
			else if( "AST_STMT_LIST".equals(kn.getProperty("type")) ) body = kn;
		}
		if( cond == null || body == null ) return false;
		if( !"UNARY_BOOL_NOT".equals(cond.getFlags()) ) return false;
		Expression inner = ((ast.expressions.UnaryExpression)cond).getExpression();
		if( !(inner instanceof CallExpressionBase) || !"class_exists".equals(callTargetName((CallExpressionBase)inner)) ) return false;
		ArgumentList checkArgs = ((CallExpressionBase)inner).getArgumentList();
		if( checkArgs == null || checkArgs.size() < 1 || !(checkArgs.getArgument(0) instanceof StringExpression) ) return false;
		String checkedName = ((StringExpression)checkArgs.getArgument(0)).getEscapedCodeStr();
		HashMap<Integer,Long> bodyKids = PHPCSVEdgeInterpreter.parent2child.get(body.getNodeId());
		if( bodyKids == null || bodyKids.isEmpty() ) return false;
		boolean sawMatchingClass = false;
		for( Long bid : bodyKids.values() ) {
			ASTNode bn = ASTUnderConstruction.idToNode.get(bid);
			if( bn instanceof ast.php.declarations.ClassDef ) {
				String declaredName = ((ast.php.declarations.ClassDef)bn).getName();
				if( checkedName != null && simpleClassName(checkedName).equalsIgnoreCase(simpleClassName(declaredName)) ) sawMatchingClass = true;
			}
			if( !isFileScopeSafeStatement(bid) ) return false;   // any non-safe statement disqualifies
		}
		return sawMatchingClass;
	}

	private static boolean isFileScopeSafeStatement(Long sid) {
		ASTNode n = ASTUnderConstruction.idToNode.get(sid);
		if( n == null ) return false;
		String type = n.getProperty("type");
		if( FILE_SCOPE_SAFE_TYPES.contains(type) ) return true;
		if( "AST_IF".equals(type) && isAbspathGuard(n) ) return true;
		if( "AST_IF".equals(type) && isConditionalDefineGuard(n) ) return true;
		if( "AST_IF".equals(type) && isClassExistsGuard(n) ) return true;
		if( isShortCircuitDirectAccessGuard(n) ) return true;
		if( isFileScopeBootstrapCall(n) ) return true;
		if( n instanceof CallExpressionBase ) {
			String cn = callTargetName((CallExpressionBase)n);
			if( "define".equals(cn) ) {
				ArgumentList al = ((CallExpressionBase)n).getArgumentList();
				if( al != null && al.size() >= 1 && al.getArgument(0) instanceof StringExpression ) return true;
			}
		}
		return false;
	}

	// `if(!defined('ABSPATH'|'WPINC')){die/exit;}` (and single-armed AST_IF_ELEM variants) -- the
	// standard WordPress direct-file-access guard. Both constants are recognized: ABSPATH and
	// WPINC serve the identical purpose (defined by WordPress core's own bootstrap, used
	// interchangeably across real plugin code to distinguish normal WordPress loading from direct
	// URL access) -- confirmed via direct trace on Smush's real codebase, where
	// class-error-handler.php and multiple other core classes use `if (!defined('WPINC')) { die; }`
	// specifically, not ABSPATH. Explicitly NOT authorization evidence (says nothing about user
	// privilege), but safe, inert boilerplate for the narrow purpose of THIS predicate (declaration-
	// only vs. executable), since its only possible runtime effect is terminating the request.
	// Deliberately strict on shape otherwise: requires the if-elem's condition to be exactly a
	// boolean-NOT of a defined(<recognized constant>) call, and its body to consist of nothing but
	// the exit/die itself -- any additional statement, or an else-branch, fails this check.
	private static final java.util.Set<String> DIRECT_ACCESS_GUARD_CONSTANTS = new java.util.HashSet<String>(
		java.util.Arrays.asList("ABSPATH", "WPINC")
	);

	private static boolean isAbspathGuard(ASTNode ifNode) {
		return isIfExitGuardFor(ifNode, DIRECT_ACCESS_GUARD_CONSTANTS);
	}

	// Parameterized version of the `if(!defined(X)){die/exit;}` shape check, reused for both the
	// general ABSPATH/WPINC direct-access guard and the WordPress uninstall.php WP_UNINSTALL_PLUGIN
	// guard (tracked separately -- see hasWpUninstallPluginGuard).
	private static boolean isIfExitGuardFor(ASTNode ifNode, java.util.Set<String> constants) {
		HashMap<Integer,Long> ifKids = PHPCSVEdgeInterpreter.parent2child.get(ifNode.getNodeId());
		if( ifKids == null || ifKids.size() != 1 ) return false;   // exactly one AST_IF_ELEM (no else)
		Long elemId = ifKids.values().iterator().next();
		ASTNode elem = ASTUnderConstruction.idToNode.get(elemId);
		if( elem == null || !"AST_IF_ELEM".equals(elem.getProperty("type")) ) return false;
		HashMap<Integer,Long> elemKids = PHPCSVEdgeInterpreter.parent2child.get(elemId);
		if( elemKids == null || elemKids.size() != 2 ) return false;   // condition + body only
		ASTNode cond = null, body = null;
		for( Long k : elemKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn == null ) continue;
			if( kn instanceof ast.expressions.UnaryExpression ) cond = kn;
			else if( "AST_STMT_LIST".equals(kn.getProperty("type")) ) body = kn;
		}
		if( cond == null || body == null ) return false;
		if( !"UNARY_BOOL_NOT".equals(cond.getFlags()) ) return false;
		Expression inner = ((ast.expressions.UnaryExpression)cond).getExpression();
		if( !(inner instanceof CallExpressionBase) || !"defined".equals(callTargetName((CallExpressionBase)inner)) ) return false;
		ArgumentList definedArgs = ((CallExpressionBase)inner).getArgumentList();
		if( definedArgs == null || definedArgs.size() < 1 || !(definedArgs.getArgument(0) instanceof StringExpression)
				|| !constants.contains(((StringExpression)definedArgs.getArgument(0)).getEscapedCodeStr()) ) return false;
		HashMap<Integer,Long> bodyKids = PHPCSVEdgeInterpreter.parent2child.get(body.getNodeId());
		if( bodyKids == null || bodyKids.size() != 1 ) return false;   // body must be exactly one statement
		ASTNode onlyStmt = ASTUnderConstruction.idToNode.get(bodyKids.values().iterator().next());
		return onlyStmt != null && "AST_EXIT".equals(onlyStmt.getProperty("type"));
	}

	// `if (!defined('X')) { define('X', <literal>); }` -- the standard "conditionally define a
	// constant if not already set" WordPress plugin bootstrap idiom. Confirmed real via wp-smush.php
	// (Smush's own main plugin file), which opens with roughly a dozen of these back to back for
	// its own version/path/timeout constants. No security-relevant logic; the only effect is
	// setting up a constant, matching the same spirit as the already-recognized bare define() case
	// -- this is that same case, just wrapped in the standard existence check. Strict on shape:
	// requires the checked constant name in the condition to match the SAME name being defined in
	// the body (not just "any defined()-guarded if with any define() inside"), a single-statement
	// body, and a literal-string argument for the define() call's second argument is NOT required
	// (matching the existing bare-define() recognition, which likewise doesn't inspect the value).
	private static boolean isConditionalDefineGuard(ASTNode ifNode) {
		HashMap<Integer,Long> ifKids = PHPCSVEdgeInterpreter.parent2child.get(ifNode.getNodeId());
		if( ifKids == null || ifKids.size() != 1 ) return false;   // exactly one AST_IF_ELEM (no else)
		Long elemId = ifKids.values().iterator().next();
		ASTNode elem = ASTUnderConstruction.idToNode.get(elemId);
		if( elem == null || !"AST_IF_ELEM".equals(elem.getProperty("type")) ) return false;
		HashMap<Integer,Long> elemKids = PHPCSVEdgeInterpreter.parent2child.get(elemId);
		if( elemKids == null || elemKids.size() != 2 ) return false;
		ASTNode cond = null, body = null;
		for( Long k : elemKids.values() ) {
			ASTNode kn = ASTUnderConstruction.idToNode.get(k);
			if( kn == null ) continue;
			if( kn instanceof ast.expressions.UnaryExpression ) cond = kn;
			else if( "AST_STMT_LIST".equals(kn.getProperty("type")) ) body = kn;
		}
		if( cond == null || body == null ) return false;
		if( !"UNARY_BOOL_NOT".equals(cond.getFlags()) ) return false;
		Expression inner = ((ast.expressions.UnaryExpression)cond).getExpression();
		if( !(inner instanceof CallExpressionBase) || !"defined".equals(callTargetName((CallExpressionBase)inner)) ) return false;
		ArgumentList definedArgs = ((CallExpressionBase)inner).getArgumentList();
		if( definedArgs == null || definedArgs.size() < 1 || !(definedArgs.getArgument(0) instanceof StringExpression) ) return false;
		String checkedName = ((StringExpression)definedArgs.getArgument(0)).getEscapedCodeStr();
		HashMap<Integer,Long> bodyKids = PHPCSVEdgeInterpreter.parent2child.get(body.getNodeId());
		if( bodyKids == null || bodyKids.size() != 1 ) return false;   // body must be exactly one statement
		ASTNode onlyStmt = ASTUnderConstruction.idToNode.get(bodyKids.values().iterator().next());
		if( !(onlyStmt instanceof CallExpressionBase) || !"define".equals(callTargetName((CallExpressionBase)onlyStmt)) ) return false;
		ArgumentList defineArgs = ((CallExpressionBase)onlyStmt).getArgumentList();
		if( defineArgs == null || defineArgs.size() < 1 || !(defineArgs.getArgument(0) instanceof StringExpression) ) return false;
		String definedName = ((StringExpression)defineArgs.getArgument(0)).getEscapedCodeStr();
		return checkedName != null && checkedName.equals(definedName);
	}

	private static java.util.List<SecurityShape> configuredShapes() {
		java.util.List<SecurityShape> l = new java.util.ArrayList<SecurityShape>();
		java.util.Map<String,GuardKind> g = wpGuards();
		if( "1".equals(System.getenv("WP_PRIV_ESC")) || "priv_esc".equals(SINK_MODE)
		    || "extended".equals(SINK_MODE) )
			l.add(new SecurityShape("PRIV_ESC", "priv_esc", g));
		if( "1".equals(System.getenv("WP_FILE_DELETE")) || "file_delete".equals(SINK_MODE)
		    || "extended".equals(SINK_MODE) )
			l.add(new SecurityShape("FILE_DELETE", "file-delete", g));
		if( "1".equals(System.getenv("WP_FILE_READ")) || "file_read".equals(SINK_MODE)
		    || "extended".equals(SINK_MODE) )
			l.add(new SecurityShape("FILE_READ", "file-read", g));
		if( "1".equals(System.getenv("WP_POST_WRITE")) || "post_write".equals(SINK_MODE)
		    || "extended".equals(SINK_MODE) )
			l.add(new SecurityShape("POST_WRITE", "post-write", g));
		if( "1".equals(System.getenv("WP_USER_META")) || "user_meta".equals(SINK_MODE)
		    || "extended".equals(SINK_MODE) )
			l.add(new SecurityShape("USER_META", "user-meta", g));
		return l;
	}

	private static void emitControlReachabilityCandidates() {
		for( SecurityShape shape : configuredShapes() ) runControlReachability(shape);
	}

	// ITEM18 coverage reporting: every CTRLREACH PassResult (one per SecurityShape pass), kept for
	// final aggregation. entries_considered/truncation numbers are properties of the SHARED entry-
	// point model and traversal bound, not the specific shape, so they're expected to repeat
	// across shapes (confirmed empirically: identical across FILE_DELETE/FILE_READ/POST_WRITE on
	// real plugins) -- the final summary takes a representative value for those rather than
	// summing (which would over-count by a factor of the shape count), while sinks_considered/
	// paths_found/paths_emitted are genuinely additive across shapes and ARE summed.
	public static java.util.List<PassResult> allCtrlReachResults = new java.util.ArrayList<PassResult>();

	// ITEM18 coverage reporting: dynamic-dispatch resolution counts, tallied from the three
	// mechanisms that add call2mtd edges for otherwise-unresolved calls (resolveCallableDispatch,
	// resolveHookDispatch, resolveIndirectHookDispatch). No attempt is made to compute a total
	// "candidate" denominator (how many dynamic-dispatch call sites exist overall, resolved or
	// not) -- that would require tracking every call_user_func/apply_filters/do_action site
	// whether or not it matched, which none of these three functions currently do. This reports
	// only the numerator (sites successfully resolved), stated as a floor, not a percentage.
	public static int dynDispatchSitesResolved = 0;
	public static int dynDispatchEdgesAdded = 0;

	/** Class-independent traversal. One witness per DISTINCT CALL PATH, not per (sink, entry):
	 *  the same entry can reach one sink through a guarded chain AND an unguarded chain, and
	 *  collapsing those would let the guarded route mask the vulnerable one. Witness identity is
	 *  shape + entry + sink + path fingerprint. Bounded DFS — not exhaustive CFG enumeration —
	 *  with explicit truncation accounting. */
	private static void runControlReachability(SecurityShape shape) {
		PassResult R = new PassResult();
		R.shapeName = shape.name;
		final String PASS = "CTRLREACH[" + shape.name + "]";
		java.util.List<Long> shapeSinks = new java.util.ArrayList<Long>();
		for( Long sk : sinks ) {
			String sc = sinkClass.get(sk);
			if( sc != null && sc.startsWith(shape.sinkClassPrefix) ) shapeSinks.add(sk);
		}
		R.sinksConsidered = shapeSinks.size();
		if( shapeSinks.isEmpty() ) {
			R.terminalReason = "NO_SINKS_OF_THIS_SHAPE_REGISTERED";
			System.err.println(R.render(PASS));
			System.err.println(coverageLimits(PASS));
			allCtrlReachResults.add(R);
			return;
		}
		java.util.Map<Long,java.util.List<Long>> sinkByFunc = new HashMap<Long,java.util.List<Long>>();
		for( Long sk : shapeSinks ) {
			ASTNode sn = ASTUnderConstruction.idToNode.get(sk);
			if( sn == null ) continue;
			Long sfid = null; try { sfid = sn.getFuncId(); } catch( Exception e ) {}
			if( sfid == null ) continue;
			if( !sinkByFunc.containsKey(sfid) ) sinkByFunc.put(sfid, new java.util.ArrayList<Long>());
			sinkByFunc.get(sfid).add(sk);
		}
		// caller -> callees, derived once from the resolved call graph
		java.util.Map<Long,java.util.Set<Long>> fwd = new HashMap<Long,java.util.Set<Long>>();
		for( java.util.Map.Entry<Long,java.util.List<Long>> ce : call2mtd.entrySet() ) {
			ASTNode cs = ASTUnderConstruction.idToNode.get(ce.getKey());
			if( cs == null ) continue;
			Long caller = null; try { caller = cs.getFuncId(); } catch( Exception e ) {}
			if( caller == null ) continue;
			if( !fwd.containsKey(caller) ) fwd.put(caller, new HashSet<Long>());
			fwd.get(caller).addAll(ce.getValue());
		}
		// ITEM18 path-count-limit: a Smush full-scan test at 24/800 (depth+path-count combined)
		// showed a real, nonlinear interaction -- DEPTH_LIMIT truncation, which depth=24 alone
		// eliminated entirely, REAPPEARED (2015 events, higher than the original 1603 baseline)
		// once path-count was also raised to 800, because a wider path-count cap lets many more
		// paths reach the depth ceiling that a tighter cap had been cutting off first. 800 is NOT
		// validated as a global default pending a combined-metric comparison across 12/200, 24/200,
		// 24/400, and 24/800 on Smush. Reverted to 200 (matching the original, still-safe value)
		// until that comparison is done. Overridable via WP_PATH_COUNT_LIMIT for experimentation.
		final int MAX_PATHS_PER_ENTRY = System.getenv("WP_PATH_COUNT_LIMIT") != null
			? Integer.parseInt(System.getenv("WP_PATH_COUNT_LIMIT")) : 200;
		// ITEM18 depth-limit: raised from 12 to 24 after a controlled sweep (12/18/24/36) on Smush
		// and a targeted 12-vs-24 comparison on LiteSpeed, both showing the same pattern: DEPTH_LIMIT
		// truncation eliminated entirely (1603->0 on Smush, 2188->0 on LiteSpeed), unique truncated
		// states down 70-90%, runtime growth negligible (+2-12%), and finding identities EXACTLY
		// unchanged in both cases (confirmed via diff on sorted Vul: node IDs, not just counts).
		// This is evidence of an undertuned constant, not structural recursion/cycles -- the curve
		// plateaus by depth 24 with zero further DEPTH_LIMIT events even at depth 36. Still
		// overridable via WP_DEPTH_LIMIT for further experimentation.
		final int MAX_DEPTH = System.getenv("WP_DEPTH_LIMIT") != null
			? Integer.parseInt(System.getenv("WP_DEPTH_LIMIT")) : 24;
		for( Long entry : topFunIds ) {
			R.entriesConsidered++;
			String priv = entryPriv.get(entry);
			String access;
			// WordPress uninstall.php entry semantics -- checked FIRST, highest priority, before
			// any other classification. This is a distinct execution model, not an ordinary web
			// request entry (see isWordPressUninstallEntry's docstring).
			if( reasonTopLevelFileScope.contains(entry) && isWordPressUninstallEntry(entry) ) {
				access = "framework-gated-non-web-entry:wordpress-uninstall";
				if( System.getenv("WP_INCLUDE_TRACE") != null ) {
					System.err.println("WPUNINSTALL entry="+entry+" file="+getDir(entry)
						+" guard_present="+hasWpUninstallPluginGuard(entry));
				}
			} else
			// ITEM18 Part 2: a FILE_SCOPE_EXECUTABLE entry with resolved include-chain evidence
			// gets its access level from that evidence instead of the generic fallback -- real,
			// structural classification (not accounting bookkeeping like Part 1), so it changes
			// `access` itself, which can affect downstream evidence/ranking, exactly as intended.
			{
			String includeEvidence = reasonTopLevelFileScope.contains(entry) ? fileIncludeAccessEvidence.get(getDir(entry)) : null;
			if( includeEvidence != null && includeEvidence.startsWith("AUTHORIZATION_ESTABLISHED") ) {
				access = "authenticated-min-privilege-not-established";
			} else if( "PUBLICLY_REACHABLE".equals(includeEvidence) ) {
				access = "unauthenticated";
			} else {
				access = wpEntryAccess(priv);
			}
			}
			if( "unknown-not-classified".equals(access) ) {
				String reason = wpEntryAccessUnknownReason(entry, priv);
				unknownReasonBuckets.computeIfAbsent(reason, k -> new HashSet<Long>()).add(entry);
				// FILE_SCOPE_DECLARATION_ONLY and FILE_SCOPE_CONFIG_DATA entries are accounting
				// fixes, not classifications: neither counts toward entries_unclassified, since
				// neither is a meaningful request-reachable entry point in the first place (a bare
				// class/function declaration, or a file whose entire body is a single trailing
				// `return <pure static data>;`, has no source->sink flow of its own to be uncertain
				// about) -- this changes the DENOMINATOR, never suppresses an actual finding.
				if( !"top_level_file_scope_declaration_only".equals(reason)
						&& !"top_level_file_scope_config_data".equals(reason) ) R.entriesUnclassifiedTraversed++;
			}
			if( priv == null ) priv = "(unclassified)";
			java.util.Set<String> emittedFp = new HashSet<String>();
			java.util.ArrayDeque<java.util.List<Long>> stack = new java.util.ArrayDeque<java.util.List<Long>>();
			java.util.List<Long> seed = new java.util.ArrayList<Long>(); seed.add(entry);
			stack.push(seed);
			int explored = 0;
			while( !stack.isEmpty() ) {
				java.util.List<Long> peek = stack.peek();
				if( explored++ > MAX_PATHS_PER_ENTRY ) {
					R.truncate("PATH_COUNT_LIMIT", entry,
						peek==null?null:peek.get(peek.size()-1), peek==null?-1:peek.size());
					break;
				}
				java.util.List<Long> path = stack.pop();
				Long fn = path.get(path.size()-1);
				java.util.List<Long> here = sinkByFunc.get(fn);
				if( here != null ) {
					for( Long sk : here ) {
						// Build the CALLSITE route(s) for this function path. Distinct callsites are
						// distinct witnesses even though the function sequence is identical.
						java.util.List<java.util.List<Long>> routes = new java.util.ArrayList<java.util.List<Long>>();
						routes.add(new java.util.ArrayList<Long>());
						for( int pi = 0; pi + 1 < path.size(); pi++ ) {
							java.util.List<Long> css = callSitesBetween(path.get(pi), path.get(pi+1));
							java.util.List<java.util.List<Long>> nxt = new java.util.ArrayList<java.util.List<Long>>();
							for( java.util.List<Long> r : routes ) {
								if( css.isEmpty() ) { java.util.List<Long> c=new java.util.ArrayList<Long>(r); c.add(-1L); nxt.add(c); }
								else for( Long cs2 : css ) { java.util.List<Long> c=new java.util.ArrayList<Long>(r); c.add(cs2); nxt.add(c); }
							}
							if( nxt.size() > 64 ) { routes = nxt.subList(0, 64); R.traversalsTruncated++; break; }
							routes = nxt;
						}
						for( java.util.List<Long> routeCs : routes ) {
						StringBuilder rsb = new StringBuilder();
						for( Long c : routeCs ) rsb.append(c).append(">");
						String route = rsb.toString();
						StringBuilder fp = new StringBuilder();
						for( Long p : path ) fp.append(p).append(">");
						fp.append("cs:").append(route);
						String key = sk + "@" + fp;
						if( !emittedFp.add(key) ) continue;   // same callsite route already witnessed
						R.pathsFound++;
						ASTNode sn = ASTUnderConstruction.idToNode.get(sk);
						int line = (sn!=null && sn.getLocation()!=null) ? sn.getLocation().startLine : -1;
						// PER-PATH EVIDENCE RECORD (O7/O9). Critical invariant: NO PLUGIN-LEVEL FACT
						// MAY BE ATTACHED TO A PATH UNLESS ITS RELATION TO THAT PATH IS ESTABLISHED.
						// Guard/nonce facts are collected ON THIS CALL CHAIN only, so a nonce in another
						// handler or a capability check in a sibling function is never presented as
						// though it governed this sink.
						StringBuilder chain = new StringBuilder();
						for( Long p : path ) {
							ASTNode pn = ASTUnderConstruction.idToNode.get(p);
							if( chain.length()>0 ) chain.append(">");
							chain.append(p).append(":").append(pn==null?"?":String.valueOf(pn.getProperty("name")));
						}
						System.out.println("ControlReachPath: shape=" + shape.name
							+ " path_instance_id=" + shape.name + ":" + entry + ":" + sk + ":" + fp
							+ " entry=" + entry + " entry_registration=" + priv
							+ " entry_access=" + access
							+ " sink=" + sk + " sink_func=" + fn
														+ " path_fingerprint=" + fp + " path_len=" + path.size()
							+ " path_steps=" + pathSteps(path, sk, line)
						+ " path_edge_resolution=" + pathEdgeResolution(path)
						+ " path_model_completeness=" + pathModelCompleteness()
						+ " alternative_paths_explored=BOUNDED_depth12_paths200"
						+ " canonical_evidence_tuple=" + canonicalEvidenceTuple(shape, path, routeCs, sk,
							access, priv, guardRelationsOnPath(shape, path, sk, routeCs),
							targetFacts(sk, path, shape, entry), pathEdgeResolution(path), line)
						+ " evidence_class=" + (((path.size() < 2) && "unknown-not-classified".equals(access))
								? "LOCAL_SINK_CANDIDATE" : "CONTROL_REACHABILITY")
						+ " collapse_rule=TUPLE_EQUALITY_fingerprint_is_index_only"
						+ " path_semantic_fingerprint=" + pathSemanticFingerprint(shape, path, sk,
							access, guardRelationsOnPath(shape, path, sk, routeCs), pathEdgeResolution(path), line)
						+ " unresolved_calls_in_path_functions=" + unresolvedOnPath(path)
						+ " unresolved_calls_meaning=OTHER_ROUTES_UNEXPLORED_not_a_gap_in_this_chain"
							+ " target_facts=" + targetFacts(sk, path, shape, entry)
							+ " onpath_guard_relations=[" + guardRelationsOnPath(shape, path, sk, routeCs) + "]"
							+ " onpath_guards=[" + guardFactsOnPath(shape, path) + "]"
							+ " evidence_scope=ON_PATH_ONLY_plugin_level_facts_excluded"
							+ " approximations=[" + approximationsUsed() + "]"
							+ " coverage=[bounded_depth12_paths200,guard_dominance_not_established]"
							+ " file=" + getDir(sk) + " line=" + line);
						evjsonAuthEvidence(shape.name + ":" + entry + ":" + sk + ":" + fp, sk,
							String.valueOf(fn), shape, path, routeCs, access);
						R.pathsEmitted++;
						}
					}
				}
				if( path.size() >= MAX_DEPTH ) {
					R.truncate("DEPTH_LIMIT", entry, fn, path.size());
					continue;
				}
				java.util.Set<Long> nxt = fwd.get(fn);
				if( nxt == null ) continue;
				for( Long t : nxt ) {
					if( path.contains(t) ) continue;               // cycle
					java.util.List<Long> np = new java.util.ArrayList<Long>(path); np.add(t);
					stack.push(np);
				}
			}
		}
		System.err.println(R.render(PASS));
		System.err.println(coverageLimits(PASS));
		allCtrlReachResults.add(R);
	}

	/** Guard EVENTS observed anywhere along the witnessed call path — including in CALLERS, which
	 *  is where WordPress guards usually sit (`ajax_handler(){ if(!current_user_can(..)) wp_die();
	 *  perform_op(); }`). Collection is path-scoped; DOMINANCE is not computed, and neither is
	 *  absence exhaustive — unresolved calls and unmodelled registrations remain possible, so the
	 *  negative fact is stated as not-observed-on-this-witness rather than "absent". */
	// Lightweight structured record for ONE on-path guard check. Introduced (2026-08-08) so the
	// existing prose formatter (guardRelationsOnPath, kept byte-identical below for backward
	// compat / human debugging) and a new machine-readable EVJSON emitter share ONE analysis
	// walk instead of two that could silently drift apart -- exactly the failure mode the EVJSON
	// mechanism's own comment warns about ("regex parsing of increasingly structured text failed
	// three times... consumers should ingest EVJSON and never re-derive fields from prose").
	private static final class CheckFact {
		final long nodeId; final String checkKind, checkApi, checkSite, checkArgumentRaw,
			checkArgumentNormalized, resultUseRelation, callerEnforcement, apiEnforcementEffect,
			securityProperty, authorizationProperty;
		final boolean checkControlsSink, sinkExecutesWhenCheckFails;
		CheckFact(long nodeId, String checkKind, String checkApi, String checkSite,
				String checkArgumentRaw, String checkArgumentNormalized, String resultUseRelation,
				String callerEnforcement, String apiEnforcementEffect, boolean checkControlsSink,
				boolean sinkExecutesWhenCheckFails, String securityProperty, String authorizationProperty) {
			this.nodeId = nodeId; this.checkKind = checkKind; this.checkApi = checkApi;
			this.checkSite = checkSite; this.checkArgumentRaw = checkArgumentRaw;
			this.checkArgumentNormalized = checkArgumentNormalized; this.resultUseRelation = resultUseRelation;
			this.callerEnforcement = callerEnforcement; this.apiEnforcementEffect = apiEnforcementEffect;
			this.checkControlsSink = checkControlsSink; this.sinkExecutesWhenCheckFails = sinkExecutesWhenCheckFails;
			this.securityProperty = securityProperty; this.authorizationProperty = authorizationProperty;
		}
	}

	// SINGLE SOURCE OF TRUTH for on-path guard analysis. Both guardRelationsOnPath() (prose,
	// unchanged output) and evjsonAuthEvidence() (structured) call this and format its result --
	// neither re-derives or re-interprets anything independently.
	// Resolves a NAMED-CLASS static call (Class::method()) to "Class::method", matching
	// funcIdentity()'s own format for method definitions exactly, so a guard registered via
	// oneHopGuardWrapperFunctions() can be looked up by a call site using this same string.
	// Deliberately excludes self::/parent::/static:: -- resolving those to the correct concrete
	// class requires the same call-site class-hierarchy context augmentStaticDispatchEdges()
	// already handles for call-GRAPH edges, but reusing that here would couple this guard-name
	// resolution to a mechanism built for a different purpose; a literal, named class is the
	// verified real case and the narrow, safe scope for this pass.
	private static String staticCallTargetName(StaticCallExpression sc) {
		try {
			Expression tf = sc.getTargetFunc();
			Expression tc = sc.getTargetClass();
			if( !(tf instanceof StringExpression) || !(tc instanceof Identifier) ) return null;
			Identifier cid = (Identifier)tc;
			if( cid.getNameChild() == null ) return null;
			String cls = cid.getNameChild().getEscapedCodeStr();
			if( cls == null || "self".equals(cls) || "parent".equals(cls) || "static".equals(cls) )
				return null;
			return cls + "::" + ((StringExpression)tf).getEscapedCodeStr();
		} catch( Exception e ) { return null; }
	}

	private static java.util.List<CheckFact> collectCheckFacts(SecurityShape shape,
			java.util.List<Long> path, Long sinkNode, java.util.List<Long> routeCs) {
		java.util.List<CheckFact> out = new java.util.ArrayList<CheckFact>();
		java.util.Set<Long> onPath = new HashSet<Long>(path);
		// FIX (2026-08-08): guard calls made via a NAMED-CLASS static method call
		// (Class::method()) are now also considered, not only bare function calls -- needed for
		// the static-method guard-wrapper resolution above to have any effect, since without
		// this, a call site invoking a recognized wrapper via Class::method() syntax was never
		// even looked at for guard-detection purposes, regardless of whether the wrapper itself
		// was correctly registered. Deliberately narrow, matching the wrapper-definition side:
		// StaticCallExpression already extends CallExpressionBase (confirmed before writing this,
		// not assumed), so the SAME loop body below works unchanged for both -- only the target-
		// name resolution differs, isolated to a small helper used only in this loop, not the
		// shared callTargetName() every other sink/guard mechanism in this file also calls.
		java.util.List<CallExpressionBase> guardCandidates = new java.util.ArrayList<CallExpressionBase>();
		guardCandidates.addAll(functionCalls);
		guardCandidates.addAll(staticMethodCalls);
		for( CallExpressionBase gc : guardCandidates ) {
			Long gf = null; try { gf = gc.getFuncId(); } catch( Exception e ) {}
			if( gf == null || !onPath.contains(gf) ) continue;
			String gn = ( gc instanceof StaticCallExpression )
				? staticCallTargetName((StaticCallExpression)gc) : callTargetName(gc);
			if( gn == null ) continue;
			GuardKind k = shape.guards.get(gn);
			if( k == null ) continue;
			String rel = guardRelation(gc.getNodeId(), governedNodeFor(gc.getNodeId(), sinkNode, path, routeCs));
			String eff = enforcementEffect(gn, gc);
			// The sink is controlled if the CALLER branches correctly OR the API fails closed itself.
			boolean controls = "STRICT_BRANCH".equals(rel) || "EARLY_RETURN".equals(rel)
			                   || eff.startsWith("INTERNAL_FAIL_CLOSED");
			boolean runsOnFail = "INVERTED_BRANCH".equals(rel);
			String callerEff = ("STRICT_BRANCH".equals(rel) || "EARLY_RETURN".equals(rel))
			                   ? "CALLER_FAIL_CLOSED" : "NONE";
			String cap = "UNKNOWN";
			try {
				ArgumentList al = gc.getArgumentList();
				if( al != null && al.size() >= 1 && al.getArgument(0) instanceof StringExpression )
					cap = ((StringExpression)al.getArgument(0)).getEscapedCodeStr();
				else if( al != null && al.size() >= 1 && al.getArgument(0) instanceof ast.expressions.Constant ) {
					// bare constant reference, e.g. current_user_can(NF_USER_LEVEL) -- resolve
					// only via the narrow, unambiguous define() lookup above; anything not found
					// there (dynamic define(), conflicting defines, an unrelated identifier)
					// stays UNKNOWN rather than guessed at.
					ast.expressions.Constant constArg = (ast.expressions.Constant)al.getArgument(0);
					Identifier idArg = constArg.getIdentifier();
					String cname = (idArg != null && idArg.getNameChild() != null)
						? idArg.getNameChild().getEscapedCodeStr() : null;
					if( cname != null && DEFINE_CONSTANTS().containsKey(cname) )
						cap = DEFINE_CONSTANTS().get(cname);
				}
			} catch( Exception e ) {}
			// A syntactic guard does NOT establish that the capability is ADEQUATE for the
			// operation: `if (current_user_can('read')) { wp_update_user(['role'=>'administrator']) }`
			// is a STRICT_GUARD and still insufficient. Sufficiency is a separate, unestablished fact.
			out.add(new CheckFact(gc.getNodeId(), checkKind(gn), gn, guardSite(gc.getNodeId()),
				cap, normalizedArg(gn, cap), rel, callerEff, eff, controls, runsOnFail,
				securityProperty(gn, eff), "NONCE".equals(checkKind(gn)) ? "NONE" : "CLAIMED"));
		}
		return out;
	}

	private static String guardRelationsOnPath(SecurityShape shape, java.util.List<Long> path,
	                                           Long sinkNode, java.util.List<Long> routeCs) {
		java.util.List<CheckFact> facts = collectCheckFacts(shape, path, sinkNode, routeCs);
		if( facts.isEmpty() ) return "NONE_OBSERVED_ON_MODELED_WITNESS";
		java.util.List<String> out = new java.util.ArrayList<String>();
		for( CheckFact f : facts ) {
			out.add("{check_kind=" + f.checkKind
				+ ",check_api=" + f.checkApi
				+ ",check_site=" + f.checkSite
				+ ",check_argument_raw=" + f.checkArgumentRaw
				+ ",check_argument_normalized=" + f.checkArgumentNormalized
				+ ",result_use_relation=" + f.resultUseRelation
				+ ",caller_enforcement=" + f.callerEnforcement
				+ ",api_enforcement_effect=" + f.apiEnforcementEffect
				+ ",check_controls_sink=" + f.checkControlsSink
				+ ",sink_executes_when_check_fails=" + f.sinkExecutesWhenCheckFails
				+ ",security_property=" + f.securityProperty
				+ ",authorization_property=" + f.authorizationProperty
				+ ",authorization_sufficiency=NOT_ESTABLISHED}");
		}
		StringBuilder sb = new StringBuilder();
		for( String o : out ) { if( sb.length()>0 ) sb.append(";"); sb.append(o); }
		return sb.toString();
	}

	// Typed JSON serializer, matching StaticAnalysis.java's evjson()/jsonVal() convention exactly
	// (PHPCGFactory is a different class and cannot call StaticAnalysis's private method, so this
	// is a deliberate, minimal duplication of the SAME typed-by-value approach -- not a new,
	// divergent protocol). No "does this look like an array" string-sniffing.
	private static String authJsonVal(Object v) {
		if(v == null) return "null";
		if(v instanceof Number) return String.valueOf(v);
		if(v instanceof Boolean) return String.valueOf(v);
		if(v instanceof java.util.List) {
			StringBuilder b = new StringBuilder("[");
			java.util.List<?> l = (java.util.List<?>)v;
			for(int i=0;i<l.size();i++) { if(i>0) b.append(","); b.append(authJsonVal(l.get(i))); }
			return b.append("]").toString();
		}
		if(v instanceof java.util.Map) {
			StringBuilder b = new StringBuilder("{");
			java.util.Map<?,?> m = (java.util.Map<?,?>)v;
			boolean first = true;
			for(java.util.Map.Entry<?,?> e : m.entrySet()) {
				if(!first) b.append(","); first = false;
				b.append(authJsonVal(String.valueOf(e.getKey()))).append(":").append(authJsonVal(e.getValue()));
			}
			return b.append("}").toString();
		}
		String s2 = String.valueOf(v);
		return "\"" + s2.replace("\\","\\\\").replace("\"","\\\"") + "\"";
	}

	// STRUCTURED authorization-evidence record, EVJSON schema "auth-evidence-v1", DISTINCT from
	// StaticAnalysis.java's "value-flow-evidence-v1". Promotes the guard analysis from diagnostic
	// prose (guardRelationsOnPath/guardFactsOnPath, kept unchanged above for backward-compat human
	// debugging) to an authoritative machine interface: Java owns guard-relation, check-kind, and
	// enforcement-effect facts; Python consumers must preserve them verbatim rather than
	// re-deriving a cruder version from prose or raw source text. finding_id uses the SAME
	// path_instance_id already printed in the ControlReachPath line (shape.name+":"+entry+":"+sk+
	// ":"+fp), so Python can join the two without inventing a second identity scheme.
	//
	// SCOPE NOTE (2026-08-08): ownership/object-ID state (objIdState/localOwnership/localAdminCap)
	// are computed in a SEPARATE analysis method as method-local maps, not accessible from this
	// call site without promoting them to class fields -- a broader change than this pass covers.
	// Emitted here as "ownership":{"state":"NOT_WIRED_THIS_PASS"} rather than faked or silently
	// omitted, so a Python consumer can distinguish "Java says no ownership evidence" from "Java
	// hasn't been asked yet" and doesn't misinterpret an absent field as a negative finding.
	// FIX (2026-08-08): propagate the entry's true authentication status (already computed as
	// `access` at the ControlReachPath call site -- unauthenticated / authenticated-min-privilege-
	// not-established / unknown-not-classified) as a structured field, rather than leaving Python
	// to reconstruct it from a placeholder. Motivated directly by a verdict-affecting adjudicator
	// defect found in real-CVE re-adjudication: two Python finding-construction paths
	// (parse_vul_findings/parse_reachability_findings) set an unconditional auth="?" placeholder,
	// which fed heuristic_verdict()'s is_unauth computation incorrectly for genuinely
	// unauthenticated findings (e.g. wp_ajax_nopriv_* entries), silently satisfying a "not
	// is_unauth" condition that should not have been satisfied. Fixing this at the source --
	// making authentication a structured engine fact -- removes the reconstruction step entirely
	// rather than patching each Python parser separately.
	private static void evjsonAuthEvidence(String findingId, Long sinkNode, String handler,
			SecurityShape shape, java.util.List<Long> path, java.util.List<Long> routeCs, String entryAccess) {
		java.util.List<CheckFact> facts = collectCheckFacts(shape, path, sinkNode, routeCs);
		java.util.List<Object> checks = new java.util.ArrayList<Object>();
		boolean anyCapabilityControls = false;
		for( CheckFact f : facts ) {
			java.util.LinkedHashMap<String,Object> c = new java.util.LinkedHashMap<String,Object>();
			c.put("node_id", f.nodeId);
			c.put("kind", f.checkKind);
			c.put("api", f.checkApi);
			c.put("check_site", f.checkSite);
			c.put("argument_raw", f.checkArgumentRaw);
			c.put("argument_normalized", f.checkArgumentNormalized);
			c.put("relation", f.resultUseRelation);
			c.put("caller_enforcement", f.callerEnforcement);
			c.put("enforcement_effect", f.apiEnforcementEffect);
			c.put("controls_sink", f.checkControlsSink);
			c.put("sink_executes_when_check_fails", f.sinkExecutesWhenCheckFails);
			c.put("security_property", f.securityProperty);
			c.put("authorization_property", f.authorizationProperty);
			// FIX (2026-08-08): this fact was already computed and emitted in the separate,
			// prose-style guardRelationsOnPath() string output ("authorization_sufficiency=
			// NOT_ESTABLISHED"), but was never included in THIS structured JSON checks array --
			// the one the Python adjudicator actually parses from auth-evidence-v1. A syntactic
			// guard controlling a sink establishes that a check exists and gates the sink; it
			// does NOT establish that the specific capability/permission checked is the RIGHT
			// one for the operation performed (e.g. current_user_can('edit_user', $target) is
			// satisfied by an Editor editing a Subscriber, but says nothing about whether the
			// ROLE being granted to that target is appropriate -- Multiple Roles per User,
			// CVE-2025-11620, is exactly this shape). Always NOT_ESTABLISHED: no mechanism in
			// this engine currently determines sufficiency for any check kind. Present as an
			// explicit field, not a silent default, so a consumer has to affirmatively decide
			// how to treat it rather than inherit "present and controlling" as "adequate" by
			// omission.
			c.put("authorization_sufficiency", "NOT_ESTABLISHED");
			checks.add(c);
			if( "CAPABILITY".equals(f.checkKind) && f.checkControlsSink ) anyCapabilityControls = true;
		}
		java.util.LinkedHashMap<String,Object> ownership = new java.util.LinkedHashMap<String,Object>();
		ownership.put("state", "NOT_WIRED_THIS_PASS");
		java.util.LinkedHashMap<String,Object> objectId = new java.util.LinkedHashMap<String,Object>();
		objectId.put("state", "NOT_WIRED_THIS_PASS");
		StringBuilder b = new StringBuilder("EVJSON {\"schema\":\"auth-evidence-v1\"")
			.append(",\"finding_id\":").append(authJsonVal(findingId))
			.append(",\"sink_node_id\":").append(authJsonVal(sinkNode))
			.append(",\"handler\":").append(authJsonVal(handler))
			.append(",\"entry_authentication\":").append(authJsonVal(entryAccess))
			.append(",\"checks\":").append(authJsonVal(checks))
			.append(",\"any_capability_check_controls_sink\":").append(authJsonVal(anyCapabilityControls))
			.append(",\"ownership\":").append(authJsonVal(ownership))
			.append(",\"object_id\":").append(authJsonVal(objectId))
			.append("}");
		System.out.println(b.toString());
	}

	private static String guardFactsOnPath(SecurityShape shape, java.util.List<Long> path) {
		java.util.Set<GuardKind> seen = new java.util.LinkedHashSet<GuardKind>();
		java.util.Set<Long> onPath = new HashSet<Long>(path);
		for( CallExpressionBase gc : functionCalls ) {
			Long gf = null; try { gf = gc.getFuncId(); } catch( Exception e ) {}
			if( gf == null || !onPath.contains(gf) ) continue;
			String gn = callTargetName(gc);
			if( gn == null ) continue;
			GuardKind k = shape.guards.get(gn);
			if( k != null ) seen.add(k);
		}
		StringBuilder sb = new StringBuilder();
		for( GuardKind k : GuardKind.values() ) {
			if( sb.length() > 0 ) sb.append(",");
			sb.append(k).append("=").append(seen.contains(k)
				? "observed-on-path" : "not-observed-on-modeled-witness");
		}
		sb.append(",dominance=not-established");
		return sb.toString();
	}


	/** Call sites on THIS path whose targets did not resolve - a path-specific coverage fact. */

	/** Relation of an on-path authorization call to the SINK. "Observed on path" conflates a real
	 *  guard with a check whose result is discarded, inverted, or governs another branch — G2/G4/G5
	 *  in /tmp/guardrel all contain a capability call yet none protects the sink. */
	/** The node a guard must govern. When the check and the sink are in different functions, an
	 *  `if (cap) { helper(); }` guards the sink by governing the CALL EDGE, not the sink node --
	 *  checking the sink node alone made every two-function guarded path read UNRELATED_BRANCH. */
	/** Run-INDEPENDENT site identity. Node ids shift between runs, so embedding them made the
	 *  "semantic" fingerprint sensitive to incidental numbering. */

	/** API-level enforcement, INDEPENDENT of how the caller uses the return value.
	 *  `check_ajax_referer('a')` terminates internally on failure, so a discarded result still
	 *  controls the sink. `check_ajax_referer('a', false, false)` returns instead of dying, so a
	 *  discarded result really does provide nothing. `wp_verify_nonce` never terminates. */
	private static String enforcementEffect(String api, CallExpressionBase call) {
		if( "wp_verify_nonce".equals(api) || "current_user_can".equals(api)
		    || "user_can".equals(api) || "current_user_can_for_blog".equals(api)
		    || "current_user_owns".equals(api) ) return "NONE";
		// check_ajax_referer($action, $query_arg = false, $stop = true) -- ONLY here does an
		// argument disable termination, and it is the THIRD one.
		if( "check_ajax_referer".equals(api) ) {
			try {
				ArgumentList al = call.getArgumentList();
				if( al != null && al.size() > 2 ) {
					ASTNode a = al.getArgument(2);
					String t = (a == null) ? "" : String.valueOf(a.getProperty("type"));
					String c = (a instanceof StringExpression) ? ((StringExpression)a).getEscapedCodeStr() : "";
					if( "AST_CONST".equals(t) || "false".equalsIgnoreCase(c) )
						return "NONE_EXPLICIT_NON_DYING";
				}
			} catch( Exception e ) {}
			return "INTERNAL_FAIL_CLOSED";
		}
		// check_admin_referer($action = -1, $query_arg = '_wpnonce') -- the second argument selects
		// the REQUEST FIELD holding the nonce; it does NOT disable termination. Always fails closed.
		// Real edge case: with $action left at the obsolete default -1, WordPress may accept a
		// same-admin-area referer INSTEAD of a valid nonce. That is a weaker check, not a
		// non-dying mode, so it gets its own value rather than being folded into enforcement.
		if( "check_admin_referer".equals(api) ) {
			try {
				ArgumentList al = call.getArgumentList();
				if( al == null || al.size() < 1 ) return "INTERNAL_FAIL_CLOSED_LEGACY_REFERER_FALLBACK";
				ASTNode a0 = al.getArgument(0);
				String c0 = (a0 instanceof StringExpression) ? ((StringExpression)a0).getEscapedCodeStr() : "";
				if( "-1".equals(c0.trim()) ) return "INTERNAL_FAIL_CLOSED_LEGACY_REFERER_FALLBACK";
			} catch( Exception e ) {}
			return "INTERNAL_FAIL_CLOSED";
		}
		return "UNKNOWN";
	}

	private static String checkKind(String api) {
		if( "check_ajax_referer".equals(api) || "check_admin_referer".equals(api)
		    || "wp_verify_nonce".equals(api) ) return "NONCE";
		if( "current_user_owns".equals(api) ) return "OWNERSHIP";
		return "CAPABILITY";
	}
	/** A nonce proves request INTEGRITY, never authorization: an unauthenticated user can obtain one. */
	/** The legacy default-action form may accept a same-admin-area REFERER instead of a verified
	 *  nonce, so it must not claim nonce integrity. It still controls execution and still grants
	 *  no authorization -- only the strength of the CSRF evidence is weaker. */
	private static String securityProperty(String api, String eff) {
		if( !"NONCE".equals(checkKind(api)) ) return "AUTHORIZATION";
		if( eff != null && eff.endsWith("LEGACY_REFERER_FALLBACK") ) return "CSRF_MITIGATION_LEGACY_REFERER";
		if( "NONE_EXPLICIT_NON_DYING".equals(eff) ) return "CSRF_INTEGRITY_NOT_ENFORCED";
		return "CSRF_INTEGRITY";
	}
	/** Keep the exact observed argument AND its semantic reading; neither replaces the other. */
	private static String normalizedArg(String api, String raw) {
		if( "check_admin_referer".equals(api) && ("-1".equals(raw) || "UNKNOWN".equals(raw)) )
			return "LEGACY_DEFAULT_ACTION";
		return raw;
	}


	/** WHOSE object the operation mutates. Distinct from whether a capability check ran: a handler
	 *  may be capability-guarded yet still let the caller name an arbitrary victim, and a
	 *  self-targeted call is NOT automatically safe -- assigning yourself a higher role is still
	 *  privilege escalation. So SELF_CURRENT_USER is a target fact, never a safety verdict. */

	/** Fold a target expression through simple LOCAL assignments so `$id = 1; 'ID' => $id` is not
	 *  indistinguishable from a genuinely unresolved expression. Records HOW the value was obtained
	 *  and with what confidence -- a folded value is not the same evidence as a written literal. */
	private static String[] foldLocalConstant(Expression v, Long fid) {
		try {
			String vn = varNameOf(v);
			if( vn == null || fid == null ) return null;
			if( varAssignsByFunc == null ) computeEnumValidated();
			HashMap<String, java.util.List<ASTNode>> as = varAssignsByFunc.get(fid);
			if( as == null ) return null;
			java.util.List<ASTNode> rhs = as.get(vn);
			if( rhs == null || rhs.isEmpty() ) return null;
			if( rhs.size() > 1 ) return new String[]{"MULTIPLE_ASSIGNMENTS","LOW"};   // not single-valued
			ASTNode r = rhs.get(0);
			String t = String.valueOf(r.getProperty("type"));
			if( r instanceof StringExpression ) {
				String c = ((StringExpression)r).getEscapedCodeStr();
				if( c != null && c.trim().matches("[0-9]+") ) return new String[]{c.trim(),"HIGH"};
				return null;
			}
			if( "integer".equals(t) ) {
				Object c = r.getProperty("code");
				if( c != null ) return new String[]{String.valueOf(c),"HIGH"};
			}
		} catch( Exception e ) {}
		return null;
	}

	private static String targetFacts(Long sinkNode, java.util.List<Long> path, SecurityShape shape, Long entry) {
		String presence="ABSENT", kind="NONE", norm="NONE", prov="NONE", chosen="NONE",
		       originKind="NONE", originName="NONE";
		Long targetExpr = null;
		try {
			ASTNode sn = ASTUnderConstruction.idToNode.get(sinkNode);
			ArgumentList al = (sn instanceof CallExpressionBase)
				? ((CallExpressionBase)sn).getArgumentList() : null;
			ast.php.expressions.ArrayExpression arr = null;
			if( al != null && al.size() >= 1 && al.getArgument(0) instanceof ast.php.expressions.ArrayExpression )
				arr = (ast.php.expressions.ArrayExpression)al.getArgument(0);
			if( arr != null ) {
				for( int i2 = 0; i2 < arr.size(); i2++ ) {
					ast.php.expressions.ArrayElement el = arr.getArrayElement(i2);
					if( el == null || !(el.getKey() instanceof StringExpression) ) continue;
					String k = ((StringExpression)el.getKey()).getEscapedCodeStr();
					if( k == null ) continue;
					k = k.replace("\"","").replace("'","").trim();
					if( !("ID".equalsIgnoreCase(k) || "user_id".equalsIgnoreCase(k)) ) continue;
					presence = "PRESENT";
					Expression v = el.getValue();
					targetExpr = (v == null) ? null : v.getNodeId();
					String vt = (v == null) ? "" : String.valueOf(v.getProperty("type"));
					if( v instanceof CallExpressionBase ) {
						String cn = callTargetName((CallExpressionBase)v);
						if( "get_current_user_id".equals(cn) || "wp_get_current_user".equals(cn) ) {
							kind="CALL"; norm=cn+"()"; prov="SELF_CURRENT_USER"; chosen="SERVER_SESSION";
							originKind="SESSION"; originName=cn;
						} else { kind="CALL"; norm=cn+"()"; prov="DERIVED_INDIRECT"; chosen="UNKNOWN";
							originKind="CALL"; originName=String.valueOf(cn); }
					} else if( "integer".equals(vt) || "AST_LITERAL".equals(vt)
					           || (v instanceof StringExpression
					               && ((StringExpression)v).getEscapedCodeStr()!=null
					               && ((StringExpression)v).getEscapedCodeStr().trim().matches("[0-9]+")) ) {
						// numeric literal: CONSTANT, but a fixed id is NOT proof of a different user
						String raw = (v instanceof StringExpression)
							? ((StringExpression)v).getEscapedCodeStr() : String.valueOf(v.getProperty("code"));
						kind = (v instanceof StringExpression) ? "NUMERIC_STRING" : "LITERAL_INTEGER";
						norm = (raw==null?"?":raw.replace("\"","").replace("'","").trim());
						prov="CONSTANT"; chosen="SERVER_CODE"; originKind="LITERAL"; originName=norm;
					} else if( v instanceof ast.expressions.Constant || "AST_CONST".equals(vt) ) {
						kind="NAMED_CONSTANT"; norm="UNRESOLVED_NAMED_CONSTANT";
						prov="CONSTANT_UNRESOLVED"; chosen="SERVER_CODE";
						originKind="NAMED_CONSTANT"; originName="UNRESOLVED";
					} else {
						java.util.Set<Long> req = new HashSet<Long>();
						collectRequestNodes(v, req);
						if( !req.isEmpty() ) {
							prov="REQUEST_DERIVED"; chosen="ATTACKER"; kind="EXPRESSION";
							originKind="REQUEST_PARAMETER";
							Long rn = req.iterator().next();
							ASTNode rnode = ASTUnderConstruction.idToNode.get(rn);
							String nm="UNKNOWN";
							try {
								HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(rn);
								if( kk != null && kk.get(1) != null ) {
									ASTNode key = ASTUnderConstruction.idToNode.get(kk.get(1));
									if( key instanceof StringExpression )
										nm = ((StringExpression)key).getEscapedCodeStr();
								}
							} catch( Exception e ) {}
							originName = nm; norm = "$_REQUEST[" + nm + "]";
						} else {
							Long encF = null; try { encF = sn.getFuncId(); } catch( Exception e2 ) {}
							String[] folded = foldLocalConstant(v, encF);
							if( folded != null && !"MULTIPLE_ASSIGNMENTS".equals(folded[0]) ) {
								kind="VARIABLE_CONSTANT_FOLDED"; norm=folded[0];
								prov="CONSTANT_FOLDED_LOCAL"; chosen="SERVER_CODE";
								originKind="VARIABLE"; originName=String.valueOf(varNameOf(v))+"|fold_confidence="+folded[1];
							} else {
								kind="EXPRESSION"; norm="UNRESOLVED_EXPRESSION";
								prov="DERIVED_INDIRECT"; chosen="UNKNOWN";
								originKind="VARIABLE"; originName=String.valueOf(varNameOf(v))
									+ (folded!=null ? "|fold=MULTIPLE_ASSIGNMENTS" : "|fold=NOT_RESOLVED");
							}
					}
					}
					break;
				}
			}
		} catch( Exception e ) { prov="UNKNOWN"; chosen="UNKNOWN"; }
		return "{target_selector_presence=" + presence
			+ ",target_value_kind=" + kind
			+ ",target_value_normalized=" + norm
			+ ",target_provenance=" + prov
			+ ",target_chosen_by=" + chosen
			+ ",target_origin_kind=" + originKind
			+ ",target_origin_name=" + originName
			+ ",target_relation_to_requester=UNKNOWN"
			+ "," + objectAuthorizationFacts(sinkNode, path, shape,
				(targetExpr==null?"NONE":exprIdentity(ASTUnderConstruction.idToNode.get(targetExpr))), entry) + "}";
	}

	/** Minimal target-SPECIFIC authorization model: a capability check taking a SECOND argument
	 *  (`current_user_can('edit_user', $uid)`) is an object-level check. Without this, a path with
	 *  `if(!current_user_can('edit_user',$_POST['uid'])) return;` and one with no check at all both
	 *  read "not modelled" and could collapse together. */
	/** API-SPECIFIC argument positions. current_user_can($cap, $object) puts the object at index 1;
	 *  user_can($user, $cap, $object) puts the CAPABILITY at index 1 and the object at index 2, and
	 *  also names WHO is being checked -- which need not be the requester. Treating index 1 as the
	 *  object for both would read a capability string as a target id. */
	private static int objectArgIndex(String api) {
		if( "current_user_can".equals(api) || "current_user_can_for_blog".equals(api) ) return 1;
		if( "user_can".equals(api) ) return 2;
		return -1;
	}

	/** Normalised identity of an expression, used to compare the CHECKED object against the SINK
	 *  target. A check on a different object than the one mutated is not protection for this path. */
	private static String exprIdentity(ASTNode e) {
		if( e == null ) return "NONE";
		try {
			if( e instanceof CallExpressionBase ) return "call:" + callTargetName((CallExpressionBase)e);
			java.util.Set<Long> req = new HashSet<Long>();
			collectRequestNodes(e, req);
			if( !req.isEmpty() ) {
				Long rn = req.iterator().next();
				HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(rn);
				String nm = "UNKNOWN";
				if( kk != null && kk.get(1) != null ) {
					ASTNode key = ASTUnderConstruction.idToNode.get(kk.get(1));
					if( key instanceof StringExpression ) nm = ((StringExpression)key).getEscapedCodeStr();
				}
				return "request:" + nm;
			}
			String vn = varNameOf(e);
			if( vn != null ) return "var:" + vn;
			if( e instanceof StringExpression ) return "lit:" + ((StringExpression)e).getEscapedCodeStr();
		} catch( Exception ex ) {}
		return "UNRESOLVED";
	}

	private static String objectAuthorizationFacts(Long sinkNode, java.util.List<Long> path,
	                                               SecurityShape shape, String sinkTargetIdentity, Long entry) {
		if( path == null ) return "object_authorization_analysis=NOT_PERFORMED,object_authorization_relation=UNKNOWN";
		java.util.Set<Long> onPath = new HashSet<Long>(path);
		// ITEM42 FIX: a REST route's permission_callback is invoked by WordPress core
		// independently of its callback -- no PHP-level call edge links them, so without this
		// the search below never sees an object check that genuinely exists and genuinely gates
		// this sink, purely because of how WordPress's REST API splits authorization from the
		// handler across two separate closures on the same register_rest_route() call. Additive
		// only: restHandlerToPermCallbackFuncIds is populated solely from resolvable REST
		// permission_callback arguments (see seedRestRoute/resolveCallableFuncIds), so this is
		// empty for every non-REST entry and cannot change any previously-computed evidence there.
		if( entry != null ) {
			java.util.Set<Long> permFids = restHandlerToPermCallbackFuncIds.get(entry);
			if( permFids != null ) onPath.addAll(permFids);
		}
		String best = null, checkedObj = "NONE", subject = "CURRENT_USER", match = "NO_CHECK";
		for( CallExpressionBase gc : functionCalls ) {
			Long gf = null; try { gf = gc.getFuncId(); } catch( Exception e ) {}
			if( gf == null || !onPath.contains(gf) ) continue;
			String gn = callTargetName(gc);
			int oi = (gn == null) ? -1 : objectArgIndex(gn);
			if( oi < 0 ) continue;
			ArgumentList al = gc.getArgumentList();
			if( al == null || al.size() <= oi ) continue;    // no object argument supplied
			String co = exprIdentity(al.getArgument(oi));
			String subj = "user_can".equals(gn) ? exprIdentity(al.getArgument(0)) : "CURRENT_USER";
			String rel = guardRelation(gc.getNodeId(), governedNodeFor(gc.getNodeId(), sinkNode, path, null));
			String m = ("UNRESOLVED".equals(co) || "UNRESOLVED".equals(sinkTargetIdentity)) ? "UNKNOWN"
			           : co.equals(sinkTargetIdentity) ? "SAME_OBJECT" : "DIFFERENT_OBJECT";
			if( best == null || "SAME_OBJECT".equals(m) ) { best = rel; checkedObj = co; subject = subj; match = m; }
			if( "SAME_OBJECT".equals(m) && ("STRICT_BRANCH".equals(rel) || "EARLY_RETURN".equals(rel)) ) break;
		}
		return "object_authorization_analysis=PERFORMED"
			+ ",object_authorization_coverage=PARTIAL_KNOWN_FORMS_ONLY"
			+ ",object_authorization_recognized_forms=[current_user_can(cap,obj),user_can(user,cap,obj),current_user_can_for_blog]"
			+ ",object_authorization_unrecognized_forms=[map_meta_cap_filters,custom_ownership_helpers,author_id_comparisons,capability_wrappers]"
			+ ",object_auth_check_subject=" + subject
			+ ",object_auth_checked_object=" + checkedObj
			+ ",object_auth_sink_target=" + sinkTargetIdentity
			+ ",object_auth_target_match=" + match
			+ ",object_authorization_relation=" + (best == null ? "NONE_OBSERVED_WITHIN_MODELLED_FORMS" : best);
	}
	private static void dumpCallGraph() {
		if( System.getenv("WP_DUMP_CALLGRAPH") == null ) return;
		try {
			java.io.PrintWriter w = new java.io.PrintWriter(new java.io.FileWriter("callgraph.csv"));
			int edges = 0;
			for( Long callsite : call2mtd.keySet() ) {
				ASTNode cs = ASTUnderConstruction.idToNode.get(callsite);
				if( cs == null ) continue;
				Long caller = cs.getFuncId();
				if( caller == null ) continue;
				java.util.List<Long> tgts = call2mtd.get(callsite);
				if( tgts == null ) continue;
				for( Long t : tgts ) { w.println(caller + "\t" + t); edges++; }
			}
			w.close();
			System.err.println("CALLGRAPH dumped " + edges + " resolved edge(s) to callgraph.csv");
		} catch( Exception e ) { System.err.println("CALLGRAPH dump failed: " + e); }
	}

	private static final boolean WP_PROFILE = System.getenv("WP_PROFILE") != null;
	static long STHS_nanos = 0; static long STHS_calls = 0;
	/** The specific source node inside an argument subtree (subtreeHasSourceIn returns only a boolean). */
	/** Resolve the request ACCESS PATH for a tagged base superglobal node. Separate from provenance
	 *  classification: the admission rule proves only the channel. Walks upward through the
	 *  CONTIGUOUS AST_DIM chain in which the tagged base is the dimensioned expression, and stops
	 *  as soon as that relationship no longer holds — never taking an arbitrary AST_DIM ancestor. */
	public static String[] resolveRequestAccess(Long baseNodeId) {
		String channel = PHPCSVEdgeInterpreter.sourceChannel.get(baseNodeId);
		if( channel == null ) return null;
		java.util.List<String> keys = new java.util.ArrayList<String>();
		String precision = "WHOLE_CHANNEL";
		Long cur = baseNodeId;
		for( int d = 0; d < 8; d++ ) {
			Long par = PHPCSVEdgeInterpreter.child2parent.get(cur);
			if( par == null ) break;
			ASTNode pn = ASTUnderConstruction.idToNode.get(par);
			if( !(pn instanceof ArrayIndexing) ) break;
			// the tagged base must BE the dimensioned expression, not merely an ancestor
			Expression arrExpr = ((ArrayIndexing)pn).getArrayExpression();
			if( arrExpr == null || !cur.equals(arrExpr.getNodeId()) ) break;
			Expression idx = ((ArrayIndexing)pn).getIndexExpression();
			if( idx instanceof StringExpression ) {
				String k = ((StringExpression)idx).getEscapedCodeStr();
				k = (k==null) ? "UNKNOWN" : k.replace("\"","").replace("'","").trim();
				keys.add(k); precision = "EXACT_STATIC";
			} else { keys.add("UNKNOWN"); precision = "DYNAMIC"; }
			cur = par;
		}
		return new String[]{ channel, keys.toString(), precision };
	}

	// PERFORMANCE FIX, same session as the correctness fix (unlike ITEM49/53/55, where the
	// unindexed version shipped separately first): the AIOWM ITEM47 gate ran fine (small corpus,
	// ~1s added), but the GiveWP gate exceeded 13 minutes (vs. the ~175s baseline for this same
	// engine lineage) and was killed rather than left to potentially run indefinitely --
	// resolveArgumentTaintSource()'s variable-resolution fallback did a full, unindexed
	// idToNode.values() scan per unresolved bare-Variable argument, per fixpoint round, the
	// exact same full-corpus-scan-per-call anti-pattern ITEM49/53/55 eliminated elsewhere in
	// this file. Indexed here before promotion, not shipped as a known severe regression.
	private static java.util.HashMap<String, java.util.List<AssignmentExpression>> assignmentsByFuncAndVar = null;

	private static void buildAssignmentIndexIfNeeded() {
		if( assignmentsByFuncAndVar != null ) return;
		assignmentsByFuncAndVar = new java.util.HashMap<String, java.util.List<AssignmentExpression>>();
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			Long fid = n.getFuncId();
			Expression lhs = ((AssignmentExpression)n).getLeft();
			if( fid == null || !(lhs instanceof Variable) ) continue;
			String vName = varNameOf(lhs);
			if( vName == null ) continue;
			String key = fid + "|" + vName;
			java.util.List<AssignmentExpression> l = assignmentsByFuncAndVar.get(key);
			if( l == null ) { l = new java.util.ArrayList<AssignmentExpression>(); assignmentsByFuncAndVar.put(key, l); }
			l.add((AssignmentExpression)n);
		}
	}

	// ITEM63/64 FIX: resolves an argument expression's taint source, extending the existing
	// literal-subtree-containment check (firstSourceIn/subtreeHasSourceIn, unchanged below) with
	// a fallback for the confirmed gap (ITEM62/63): a bare variable reference used as a call
	// argument is never recognized as tainted, because the variable-use node and the source
	// expression that established its value are unrelated nodes in different statements, not
	// parent-child. Traces a variable back to its SINGLE, unambiguous same-function assignment
	// (the same "one write cannot launder another" discipline already used elsewhere in this
	// file for other resolvers -- more than one assignment to the same variable name in the same
	// function is ambiguous and left unresolved, not guessed) and recurses into that assignment's
	// right-hand side, bounded to a short depth. Deliberately narrow: only a bare Variable RHS
	// (the alias case) or a direct literal-source RHS (via the existing subtree check) resolve;
	// anything else (a sanitizer call, a method call, array access, etc.) does not, so a
	// sanitized or otherwise-transformed value is never spuriously treated as still-tainted.
	private static Long resolveArgumentTaintSource(Expression arg, java.util.Set<Long> curSources, int varDepth) {
		if( arg == null ) return null;
		Long direct = firstSourceIn(arg.getNodeId(), curSources, 0);
		if( direct != null ) return direct;
		if( varDepth > 4 ) return null;   // bounded: refuse an unbounded alias chain, not chase it
		if( !(arg instanceof Variable) ) return null;
		String vName = varNameOf(arg);
		Long fid = arg.getFuncId();
		if( vName == null || fid == null ) return null;
		buildAssignmentIndexIfNeeded();
		java.util.List<AssignmentExpression> assigns = assignmentsByFuncAndVar.get(fid + "|" + vName);
		if( assigns == null || assigns.size() != 1 ) return null;   // zero (param/unassigned) or ambiguous (2+) -- refuse
		return resolveArgumentTaintSource(assigns.get(0).getRight(), curSources, varDepth + 1);
	}

	private static Long firstSourceIn(Long root, java.util.Set<Long> curSources, int d) {
		if( root == null || d > 40 ) return null;
		if( curSources.contains(root) ) return root;
		HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(root);
		if( kids != null ) for( Long c : kids.values() ) {
			Long r = firstSourceIn(c, curSources, d+1);
			if( r != null ) return r;
		}
		return null;
	}

	private static boolean subtreeHasSourceIn(Long nid, java.util.Set<Long> srcSet, int depth) {
		if( !WP_PROFILE || depth != 0 ) return sths0(nid, srcSet, depth);
		STHS_calls++; long t0 = System.nanoTime();
		boolean r = sths0(nid, srcSet, 0);
		STHS_nanos += System.nanoTime() - t0;
		return r;
	}
	private static boolean sths0(Long nid, java.util.Set<Long> srcSet, int depth) {
		if( nid == null || depth > 60 ) return false;
		if( srcSet.contains(nid) ) return true;
		java.util.HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(nid);
		if( kids != null ) for( Long c : kids.values() ) if( sths0(c, srcSet, depth+1) ) return true;
		return false;
	}

	// WordPress hook dispatch: add_action/add_filter($tag,$cb) registers $cb for $tag; do_action/
	// apply_filters($tag,$arg...) invokes every registered $cb with those args. The engine parsed the
	// registrations for entry-point seeding but never built the do_action->handler CALL EDGE, so taint
	// carried THROUGH a hook argument into a handler was lost (measured MISS: do_action('t',$_GET) ->
	// handler echoes -> not flagged). Build tag->callbacks from the registrations, then for each
	// literal-tag dispatch add call2mtd edges and mark the site like a callable-arg site (tag is arg 0),
	// so forwardInlineSourceArgs maps do_action('t',$_GET) -> handler($p). Dynamic (non-literal) tags are
	// skipped (sound: no spurious edge). Over-approximate when a tag has many handlers — that's recall;
	// the adjudicator filters. apply_filters keeps its existing return-passthrough model too (additive).
	private static void resolveHookDispatch() {
		java.util.HashMap<String, java.util.Set<Long>> hookCbs = buildHookCallbackRegistry();
		if( hookCbs.isEmpty() ) return;
		int edges = 0, sites = 0;
		for( CallExpressionBase fc : functionCalls ) {
			String cn = callTargetName(fc);
			if( !"do_action".equals(cn) && !"apply_filters".equals(cn) && !"apply_filters_deprecated".equals(cn) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 1 || !(al.getArgument(0) instanceof StringExpression) ) continue;
			String tag = ((StringExpression)al.getArgument(0)).getEscapedCodeStr();
			java.util.Set<Long> cbs = hookCbs.get(tag);
			if( cbs == null || cbs.isEmpty() ) continue;
			for( Long fid : cbs ) {
				java.util.List<Long> ex = call2mtd.get(fc.getNodeId());
				if( ex == null || !ex.contains(fid) ) { call2mtd.add(fc.getNodeId(), fid); edges++; }
			}
			callableArgOffset.add(fc.getNodeId());   // arg[0] is the tag -> shift args by one to params
			sites++;
		}
		if( edges > 0 ) { System.err.println("HOOKDISPATCH resolved "+sites+" do_action/apply_filters site(s), "+edges+" handler edge(s)"); dynDispatchSitesResolved += sites; dynDispatchEdgesAdded += edges; }
		resolveIndirectHookDispatch(hookCbs);
	}

	private static java.util.HashMap<String, java.util.Set<Long>> buildHookCallbackRegistry() {
		java.util.HashMap<String, java.util.Set<Long>> hookCbs = new java.util.HashMap<String, java.util.Set<Long>>();
		for( CallExpressionBase fc : functionCalls ) {
			String cn = callTargetName(fc);
			if( !"add_action".equals(cn) && !"add_filter".equals(cn) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 2 || !(al.getArgument(0) instanceof StringExpression) ) continue;
			String tag = ((StringExpression)al.getArgument(0)).getEscapedCodeStr();
			Set<Long> fids = resolveCallbackFidsPinned(al.getArgument(1));
			if( fids == null || fids.isEmpty() ) continue;
			java.util.Set<Long> s = hookCbs.get(tag);
			if( s == null ) { s = new java.util.HashSet<Long>(); hookCbs.put(tag, s); }
			s.addAll(fids);
		}
		return hookCbs;
	}

	// Named functions confirmed (against real plugin source, not assumed) to reimplement
	// "retrieve WordPress's own registered $wp_filter callbacks for a tag" and return them for
	// manual iteration/dispatch, rather than dispatching directly via apply_filters()/do_action().
	// AIOWM's ai1wm_get_filters($tag) is the verified case: `global $wp_filter; ... return
	// $wp_filter[$tag]->callbacks (or ...[$tag]);`. Narrow allowlist by design, matching this
	// file's existing convention of specific, real-plugin-motivated special cases -- NOT a claim
	// that every "get_filters"-shaped function behaves this way.
	private static final java.util.Set<String> INDIRECT_HOOK_GETTER_FNS = new java.util.HashSet<String>(
		java.util.Arrays.asList("ai1wm_get_filters")
	);

	// Handles the shape resolveHookDispatch()'s direct apply_filters/do_action matching does NOT
	// cover: a plugin-specific helper (see INDIRECT_HOOK_GETTER_FNS) retrieves the registered
	// callbacks for a LITERAL tag, and the SAME enclosing function later dispatches one of them
	// via call_user_func()/call_user_func_array() with a callable argument that resolveCallable
	// Dispatch() could not otherwise resolve (e.g. array indexing into the retrieved structure,
	// $hook['function']). Confirmed real shape: AIOWM 9.x, Ai1wm_Import_Controller::import().
	//
	// Deliberately coarse (same-function co-occurrence, not exact data-flow from the getter call
	// to the specific call_user_func argument) rather than precise taint tracing through the
	// getter's return value -- precise tracing would need to model WordPress's own nested
	// priority=>callback-id=>['function'=>...] $wp_filter structure, which is far more machinery
	// than this narrow extension warrants. Fail-conservative in the direction that matters: this
	// only ADDS edges (never removes the existing "unresolved" fallback elsewhere), and only when
	// a LITERAL tag resolves to a KNOWN, non-empty registered-callback set -- an unresolved tag,
	// an empty registry, or the getter call absent from the function leaves the dispatch exactly
	// as conservative as before this change.
	private static void resolveIndirectHookDispatch(java.util.HashMap<String, java.util.Set<Long>> hookCbs) {
		// Which literal tag(s) are "in scope" for the getter, per enclosing function.
		java.util.HashMap<Long, java.util.Set<String>> tagsInFunc = new java.util.HashMap<Long, java.util.Set<String>>();
		for( CallExpressionBase fc : functionCalls ) {
			String cn = callTargetName(fc);
			if( !INDIRECT_HOOK_GETTER_FNS.contains(cn) ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 1 || !(al.getArgument(0) instanceof StringExpression) ) continue;
			String tag = ((StringExpression)al.getArgument(0)).getEscapedCodeStr();
			Long fid = fc.getFuncId();
			if( fid == null ) continue;
			tagsInFunc.computeIfAbsent(fid, k -> new java.util.HashSet<String>()).add(tag);
		}
		if( tagsInFunc.isEmpty() ) return;
		int edges = 0, sites = 0;
		for( CallExpressionBase fc : functionCalls ) {
			String cn = callTargetName(fc);
			boolean isCufa = "call_user_func_array".equals(cn);
			if( !"call_user_func".equals(cn) && !isCufa ) continue;
			Long fid = fc.getFuncId();
			if( fid == null ) continue;
			java.util.Set<String> tags = tagsInFunc.get(fid);
			if( tags == null || tags.isEmpty() ) continue;
			// Only step in where resolveCallableDispatch() found NOTHING -- never override an
			// already-resolved (even if narrower) set of targets.
			java.util.List<Long> already = call2mtd.get(fc.getNodeId());
			if( already != null && !already.isEmpty() ) continue;
			java.util.Set<Long> targets = new java.util.HashSet<Long>();
			for( String tag : tags ) {
				java.util.Set<Long> cbs = hookCbs.get(tag);
				if( cbs != null ) targets.addAll(cbs);
			}
			if( targets.isEmpty() ) continue;
			for( Long t : targets ) { call2mtd.add(fc.getNodeId(), t); edges++; }
			if( isCufa ) cufaArrayArg.add(fc.getNodeId()); else callableArgOffset.add(fc.getNodeId());
			sites++;
		}
		if( edges > 0 ) { System.err.println("INDIRECT_HOOKDISPATCH resolved "+sites+" indirect-registry dispatch site(s), "+edges+" handler edge(s)"); dynDispatchSitesResolved += sites; dynDispatchEdgesAdded += edges; }
	}

	// foreach($SOURCE as $k => $v): if the iterated expression is tainted, the iteration variables ($v,
	// and the key $k) carry that taint. The engine otherwise drops taint at foreach. This root-causes
	// real CVEs — e.g. CVE-2022-0513 (WP Statistics): rest_params() does foreach($_REQUEST as $k=>$v)
	// {$data[$k]=$v;} and the copied request data reaches $wpdb->query. Decomposition confirmed the loop
	// is the SOLE break (object-cast/array-field/static-call downstream all propagate). Seed the
	// iteration-variable uses as sources so the copy taints its destination (arrays are field-insensitive).
	// $base[$dynKey] = <tainted>: a dynamic-index array write with a tainted RHS taints the whole base
	// array (field-insensitive — matches the engine's array model). The reaching-def logic overrides a
	// prior safe `$base=array()` def for STATIC keys but not DYNAMIC ones (diagnosed via init_dyn_write
	// vs init_static_write), which drops the WP Statistics CVE-2022-0513 shape:
	//   $data=array(); foreach($_REQUEST as $k=>$v){ $data[$k]=$v; }
	// Wire it explicitly: seed the base variable's uses when a dynamic-key write receives tainted data.
	// Runs after seedForeachOverSource so a foreach-seeded $v counts as the tainted RHS.
	private static void seedDynKeyArrayWrite() {
		java.util.HashMap<Long, java.util.Set<String>> seedVars = new java.util.HashMap<Long, java.util.Set<String>>();
		PHPCGFactory.recordScanSite("PCG_11469", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof AssignmentExpression) ) continue;
			Expression lhs = ((AssignmentExpression)n).getLeft();
			if( !(lhs instanceof ArrayIndexing) ) continue;
			ArrayIndexing dim = (ArrayIndexing)lhs;
			if( dim.getIndexExpression() instanceof StringExpression ) continue;   // static key already works
			Expression base = dim.getArrayExpression();
			String bn = (base instanceof Variable) ? varNameOf(base) : null;
			if( bn == null ) continue;
			Expression rhs = ((AssignmentExpression)n).getRight();
			if( rhs == null || !subtreeHasSourceIn(rhs.getNodeId(), PHPCSVEdgeInterpreter.sources, 0) ) continue;
			Long fid = n.getFuncId();
			if( fid != null ) seedVars.computeIfAbsent(fid, k -> new java.util.HashSet<String>()).add(bn);
		}
		if( seedVars.isEmpty() ) return;
		int seeded = 0;
		PHPCGFactory.recordScanSite("PCG_11485", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null ) continue;
			java.util.Set<String> names = seedVars.get(f);
			if( names == null ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne != null && names.contains(ne.getEscapedCodeStr()) )
				if( PHPCSVEdgeInterpreter.sources.add(node.getNodeId()) ) seeded++;
		}
		if( seeded > 0 ) System.err.println("DYNKEYARR seeded "+seeded+" base-array use(s) from dynamic-key tainted write(s)");
	}

	private static void seedForeachOverSource() {
		java.util.HashMap<Long, java.util.Set<String>> seedVars = new java.util.HashMap<Long, java.util.Set<String>>();
		PHPCGFactory.recordScanSite("PCG_11500", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !"AST_FOREACH".equals(n.getProperty("type")) ) continue;
			Long fid = n.getFuncId();
			if( fid == null ) continue;
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(n.getNodeId());
			if( kids == null ) continue;
			Long iterId = kids.get(0);
			if( iterId == null || !subtreeHasSourceIn(iterId, PHPCSVEdgeInterpreter.sources, 0) ) continue;
			for( int slot : new int[]{1, 2} ) {   // 1=value var, 2=key var (optional)
				Long vid = kids.get(slot);
				if( vid == null ) continue;
				ASTNode vv = ASTUnderConstruction.idToNode.get(vid);
				String vn = varNameOf(vv instanceof Expression ? (Expression)vv : null);
				if( vn != null )
					seedVars.computeIfAbsent(fid, k -> new java.util.HashSet<String>()).add(vn);
			}
		}
		if( seedVars.isEmpty() ) return;
		int seeded = 0;
		PHPCGFactory.recordScanSite("PCG_11519", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null ) continue;
			java.util.Set<String> names = seedVars.get(f);
			if( names == null ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne != null && names.contains(ne.getEscapedCodeStr()) )
				if( PHPCSVEdgeInterpreter.sources.add(node.getNodeId()) ) seeded++;
		}
		if( seeded > 0 ) System.err.println("FOREACHSRC seeded "+seeded+" foreach-over-source iteration-var use(s)");
	}

	private static void forwardInlineSourceArgs() {
		if( System.getenv("WP_NO_INLINEFWD") != null ) return;   // engine-only baseline (metric separation)
		int totalSeeded = 0, rounds = 0; long examined = 0;
		// FIXPOINT: forward inline-source args TRANSITIVELY so multi-hop argument taint is caught
		// (a($_GET) -> b($x) -> echo $y). Each round recomputes curSources from the growing source set;
		// a param seeded in round N can forward to a further callee in round N+1. Bounded to 12 rounds
		// (converges in 1-2; breaks early). MEASURED effect on real plugins: DISTINCT findings unchanged
		// (wp-google-maps 17->17, sdm 24->24, wp-recall 7->7) and runtime +~6% on the largest plugin.
		// It does emit more DUPLICATE 'Vul:' lines (same sink reached via more paths) — an earlier raw
		// grep -c made that look like a 33x "explosion", but sort -u shows distinct is flat and the
		// adjudicator dedups by node then file:line anyway. WP_NO_INLINEFWD=1 still bypasses (recall
		// baseline). Var-mediated multi-hop ($z=$x; b($z)) is still missed — that needs real def-use.
		for( int round = 0; round < 12; round++ ) {
		rounds++;
		java.util.Set<Long> curSources = new java.util.HashSet<Long>(PHPCSVEdgeInterpreter.sources);
		// ITEM79: a value already proven to DERIVE from a source can itself forward taint to a
		// further callee -- otherwise the fixpoint stops after one hop and two-hop chains
		// (src -> fwd -> snk) never seed the final callee's parameter, which is exactly why
		// ITEM78's derived facts produced no findings. Derived nodes participate in the
		// fixpoint's reachability question only; they are still never added to
		// PHPCSVEdgeInterpreter.sources, so srcStmt and statement classification stay untouched.
		if( System.getenv("WP_EXPERIMENTAL_VALUE_PROVENANCE_CONSUME") != null )
			curSources.addAll(derivedProvenanceNodes);
		// target function id -> param NAMES whose uses carry a forwarded inline source
		java.util.HashMap<Long, java.util.Set<String>> seedParams = new java.util.HashMap<Long, java.util.Set<String>>();
		// FIX (2026-07-19, see engine_fixtures/chained_static_factory_gap/README.md): this loop
		// previously iterated `functionCalls` ONLY (plain function calls). Static-method calls
		// (`Foo::bar($x)`) are collected in the SEPARATE `staticMethodCalls` list and were never
		// examined here, so a source argument passed to a call reached via `Class::method($src)`
		// (exactly the LearnPress `LP_Course::get_courses($filter)` / wp-statistics shape) never
		// forwarded to the callee's parameter, even though the identical shape for a plain
		// function call (`helper($src)`) already worked correctly. NOTE: instance-method calls
		// (`$obj->method($x)`, the `nonStaticMethodCalls` list) were ALSO tried here and reverted
		// -- widening to include them caused a confirmed regression on ultimate-member (48 lost
		// findings, verified as genuine unescaped-echo candidates, not false positives) via an
		// interaction not fully root-caused. Scoped to static calls only, which is what the
		// target gap actually needs and does not reproduce that regression (verified).
		java.util.List<CallExpressionBase> allCallsForForwarding = new java.util.ArrayList<CallExpressionBase>();
		allCallsForForwarding.addAll(functionCalls);
		allCallsForForwarding.addAll(staticMethodCalls);
		allCallsForForwarding.addAll(nonStaticMethodCalls);
		for( CallExpressionBase fc : allCallsForForwarding ) {
			java.util.List<Long> tgts = call2mtd.get(fc.getNodeId());
			if( tgts == null || tgts.isEmpty() ) continue;
			examined++;
			ArgumentList al = fc.getArgumentList();
			if( al == null ) continue;
			// map each callee param index to the caller arg expression feeding it:
			//   call_user_func_array('f', array(a,b)) -> element[i] -> param[i]
			//   call_user_func('f', a, b) / f(a, b)   -> arg[i-coff] -> param[i]
			java.util.List<Expression> byParam = new java.util.ArrayList<Expression>();
			if( cufaArrayArg.contains(fc.getNodeId()) ) {
				if( al.size() < 2 || !(al.getArgument(1) instanceof ArrayExpression) ) continue;
				ArrayExpression ae = (ArrayExpression)al.getArgument(1);
				for( int j = 0; j < ae.size(); j++ ) byParam.add(ae.getArrayElement(j).getValue());
			} else {
				int coff = callableArgOffset.contains(fc.getNodeId()) ? 1 : 0;
				for( int i = 0; i < al.size(); i++ ) {
					int pidx = i - coff;
					if( pidx < 0 ) continue;
					while( byParam.size() <= pidx ) byParam.add(null);
					byParam.set(pidx, al.getArgument(i));
				}
			}
			for( int pidx = 0; pidx < byParam.size(); pidx++ ) {
				Expression arg = byParam.get(pidx);
				// ITEM65: the reaching-definition fallback (resolveArgumentTaintSource's
				// variable-resolution path) is opt-in, NOT the default, per the ITEM47 gate
				// failure on GiveWP (88->51 findings, entire billing-address XSS candidate
				// lost -- root cause not yet found; the failure point is downstream in
				// isrelated()'s DDG-relation matching, not in this function itself, but the
				// safe response until that's understood is to keep this OFF by default).
				// Default behavior (flag unset) is exactly the pre-ITEM63/64 baseline:
				// firstSourceIn only, the behavior that provably preserves the known-positive
				// set. WP_EXPERIMENTAL_ARG_REACHDEF=1 additionally tries the reaching-definition
				// fallback ONLY when the direct check fails -- an OR, never a replacement.
				Long _resolvedSrc = firstSourceIn(arg == null ? null : arg.getNodeId(), curSources, 0);
				boolean _viaDerived = false;
				// ITEM79 FIX: if what firstSourceIn() matched is ITSELF a derived-provenance
				// node, the resulting seed must stay DERIVED. Without this the transitive
				// fixpoint launders a derived fact into a primary one on the second hop --
				// the next callee's parameter would be added to global `sources`, recreating
				// exactly the srcStmt shadowing that ARG_REACHDEF caused (GiveWP 88 -> 64,
				// known positives 9/9 -> 4/9, measured).
				if( _resolvedSrc != null && derivedProvenanceNodes.contains(_resolvedSrc) )
					_viaDerived = true;
				if( _resolvedSrc == null && System.getenv("WP_EXPERIMENTAL_ARG_REACHDEF") != null ) {
					_resolvedSrc = resolveArgumentTaintSource(arg, curSources, 0);
				}
				// ITEM78: WP_EXPERIMENTAL_VALUE_PROVENANCE -- same reaching-definition resolver,
				// different OUTPUT REPRESENTATION. The ARG_REACHDEF experiment promoted the
				// resolved value into the global `sources` set, which gave it far broader
				// semantics than "we know where this value came from": membership in `sources`
				// makes the CONTAINING STATEMENT a srcStmt, which in turn diverts traverse()
				// into the source-statement branch and can terminate existing propagation
				// ("source is sanitized"). That is what caused the 88 -> 51 regression.
				// Here the fact is retained as DERIVED provenance instead: the value is known to
				// derive from a source and may propagate, but it is NOT a primary source and its
				// statement is NOT reclassified.
				if( _resolvedSrc == null && System.getenv("WP_EXPERIMENTAL_VALUE_PROVENANCE") != null ) {
					_resolvedSrc = resolveArgumentTaintSource(arg, curSources, 0);
					if( _resolvedSrc != null ) _viaDerived = true;
				}
				if( arg == null || _resolvedSrc == null ) continue;
				for( Long t : tgts ) {
					ASTNode fn = ASTUnderConstruction.idToNode.get(t);
					if( !(fn instanceof FunctionDef) ) continue;
					ParameterList pl = ((FunctionDef)fn).getParameterList();
					if( pl == null || pl.size() <= pidx ) continue;
					String pname = ((Parameter)pl.getParameter(pidx)).getName();
					if( pname == null ) continue;
					java.util.Set<String> s = seedParams.get(t);
					if( s == null ) { s = new java.util.HashSet<String>(); seedParams.put(t, s); }
					s.add(pname);
					if( _viaDerived ) derivedProvenanceKeys.add(t + "|" + pname);
					else derivedProvenanceKeys.remove(t + "|" + pname);   // primary evidence wins
					// keep WHICH caller caused this promotion; seedParams alone drops it
					Long _srcNode = _resolvedSrc;
					String _pk = t + "|" + pname;
					java.util.List<long[]> _pl2 = pendingPromotions.get(_pk);
					if( _pl2 == null ) { _pl2 = new java.util.ArrayList<long[]>(); pendingPromotions.put(_pk, _pl2); }
					_pl2.add(new long[]{ fc.getNodeId(), pidx, _srcNode == null ? -1L : _srcNode.longValue() });
				}
			}
		}
		if( seedParams.isEmpty() ) break;
		int seeded = 0;
		PHPCGFactory.recordScanSite("PCG_11612", ASTUnderConstruction.idToNode.size());
		for( ASTNode node : ASTUnderConstruction.idToNode.values() ) {
			if( !(node instanceof Variable) ) continue;
			Long f = node.getFuncId();
			if( f == null ) continue;
			java.util.Set<String> names = seedParams.get(f);
			if( names == null ) continue;
			Expression ne = ((Variable)node).getNameExpression();
			if( ne != null && names.contains(ne.getEscapedCodeStr()) ) {
				// ITEM78: a param seeded ONLY by derived (reaching-definition) provenance does
				// not enter the global `sources` set. It is recorded separately so the taint
				// layer can let it PROPAGATE (sourceFunc) without letting it RECLASSIFY its
				// containing statement (srcStmt). Keeping `sources` at baseline is the whole
				// point -- that set's membership carries statement-level semantics.
				if( derivedProvenanceKeys.contains(f + "|" + ne.getEscapedCodeStr()) ) {
					if( derivedProvenanceNodes.add(node.getNodeId()) ) seeded++;
					continue;
				}
				if( PHPCSVEdgeInterpreter.sources.add(node.getNodeId()) ) seeded++;
				hookParamSourceNodes.add(node.getNodeId());   // compatibility projection
				forwardedParamSources.add(node.getNodeId());  // provenance-category marker (see field doc)
				java.util.List<long[]> _ins = pendingPromotions.get(f + "|" + ne.getEscapedCodeStr());
				if( _ins != null ) {
					java.util.LinkedHashMap<String,PromotedParameterEvidence> _m =
						promotedParamEvidence.get(node.getNodeId());
					if( _m == null ) { _m = new java.util.LinkedHashMap<String,PromotedParameterEvidence>();
						promotedParamEvidence.put(node.getNodeId(), _m); }
					for( long[] _i : _ins ) {
						PromotedParameterEvidence _e = new PromotedParameterEvidence(node.getNodeId(), f,
							ne.getEscapedCodeStr(), (int)_i[1], _i[0], _i[2] == -1L ? null : _i[2]);
						_m.put(_e.key(), _e);   // dedupe on the FULL canonical tuple
					}
				}
			}
		}
		totalSeeded += seeded;
		if( seeded == 0 ) break;
		}
		if( totalSeeded > 0 ) System.err.println("INLINEFWD seeded "+totalSeeded+" (transitive)");
		if( WP_PROFILE )
			System.err.println("FWDPROFILE rounds="+rounds+" call-examinations="+examined
				+" seeds="+totalSeeded+" | subtreeHasSourceIn: calls="+STHS_calls
				+" total_ms="+(STHS_nanos/1000000));
	}

	private static void resolveCallableDispatch() {
		java.util.HashMap<Long,java.util.List<Long>> methodsByClass = null;   // built lazily (dynamic-method case)
		java.util.HashMap<String,Set<String>> recvFallback = null;           // built lazily (receiver-name -> class names)
		java.util.HashMap<String,Set<String>> recvByClass = null;            // built lazily (class::receiver-name -> class names)
		for( CallExpressionBase fc : functionCalls ) {
			String cufName = callTargetName(fc);
			boolean isCufa = "call_user_func_array".equals(cufName);
			if( !"call_user_func".equals(cufName) && !isCufa ) continue;
			ArgumentList al = fc.getArgumentList();
			if( al == null || al.size() < 1 ) continue;
			Expression cb = al.getArgument(0);
			java.util.List<Long> targets = new java.util.ArrayList<Long>();

			// form 1: call_user_func('funcname', ...)
			if( cb instanceof StringExpression ) {
				String fn = ((StringExpression)cb).getEscapedCodeStr();
				for( Long mid : allFunc ) {
					ASTNode n = ASTUnderConstruction.idToNode.get(mid);
					if( n instanceof FunctionDef && fn.equals(((FunctionDef)n).getName()) ) targets.add(mid);
				}
			}
			// form 2: call_user_func(array($obj,$method), ...)
			else if( cb instanceof ArrayExpression && ((ArrayExpression)cb).size() >= 2 ) {
				ArrayExpression arr = (ArrayExpression)cb;
				Expression recv  = arr.getArrayElement(0).getValue();
				Expression mexpr = arr.getArrayElement(1).getValue();
				Set<Long> classIds = new HashSet<Long>();
				// FIX (2026-08-08): form 2a -- call_user_func(array('ClassName','method'), ...), a
				// literal string class-name receiver (a static-style dispatch through the array-
				// callable form). Confirmed before adding this that createFunctionCallEdges's older
				// call_user_func handling ALREADY creates the call2mtd edge for this exact shape (its
				// own "classEle.getValue().getProperty(\"type\").equals(\"string\")" branch) -- so this
				// is not a missing call-graph edge. The actual gap is narrower: only THIS function
				// (resolveCallableDispatch) marks callableArgOffset/cufaArrayArg, the metadata
				// forwardInlineSourceArgs() needs to forward a tainted call-site argument through to
				// the resolved callee's parameter. The legacy path creates the edge but never marks
				// this, so a target reached only via a string-class-receiver callable array was
				// call-graph-reachable but never received forwarded taint through this specific
				// dispatch site. Handled here, ahead of the existing ParseVar-based inference below,
				// since a literal string needs no inference at all -- self/parent/static resolve
				// against the dispatch's own enclosing context, matching the pattern already used
				// elsewhere in this file (e.g. the legacy call_user_func handler just read).
				if( recv instanceof StringExpression ) {
					String cn = ((StringExpression)recv).getEscapedCodeStr();
					String dns = fc.getEnclosingNamespace();
					Long cid;
					if( cn.equals("self") || cn.equals("static") || cn.equals("parent") ) {
						String dcls = enclosingClassName(fc);
						cid = ( dcls != null ) ? getClassId(dcls, fc.getNodeId(), dns) : null;
						if( cn.equals("parent") && cid != null && cid != -1 && ch2prt.containsKey(cid) ) {
							cid = ch2prt.get(cid).get(0);
						}
					} else {
						cid = getClassId(cn, fc.getNodeId(), dns);
					}
					if( cid != null && cid != -1 ) classIds.add(cid);
				}
				try {                                            // reuse TChecker's own receiver type inference
					ParseVar pv = new ParseVar();
					pv.init(recv.getNodeId(), true, "");
					pv.handle();
					for( String cv : pv.getVar() ) { try { classIds.add(Long.parseLong(cv)); } catch(Exception e){} }
					pv.reset();
				} catch(Exception e) {}
				if( recv instanceof NewExpression && ((NewExpression)recv).getTargetClass() instanceof Identifier ) {
					Identifier id = (Identifier)((NewExpression)recv).getTargetClass();
					if( id.getNameChild()!=null ) {
						Long cid = getClsId(id.getNameChild().getEscapedCodeStr(), id.getEnclosingNamespace());
						if( cid != null && cid != -1 ) classIds.add(cid);
					}
				}
				// Class-scoped, apply_filters-aware augmentation (ALWAYS runs, merges into classIds):
				// resolve the receiver property/var by looking ONLY at assignments to the same name within
				// the dispatch's own enclosing class, seeing through wrappers like apply_filters(...). This
				// fixes mis-resolution when ParseVar latches onto a same-named property of an unrelated class
				// (e.g. $this->commands resolving to WP_Optimize_Cache_Commands instead of the real
				// WP_Optimize_Commands constructed inside apply_filters in this class).
				if( recvByClass == null ) {
					recvByClass = new java.util.HashMap<String,Set<String>>();
					PHPCGFactory.recordScanSite("PCG_11726", ASTUnderConstruction.idToNode.size());
					for( ASTNode an : ASTUnderConstruction.idToNode.values() ) {
						if( !(an instanceof AssignmentExpression) ) continue;
						Set<String> cn = new HashSet<String>();
						collectNewClassNames(((AssignmentExpression)an).getRight(), cn, 0);
						if( cn.isEmpty() ) continue;
						String prop = receiverName(((AssignmentExpression)an).getLeft());
						if( prop == null || prop.isEmpty() ) continue;
						String cls = enclosingClassName(an);
						if( cls == null || cls.isEmpty() ) continue;
						String key = cls+"::"+prop;
						Set<String> s = recvByClass.get(key);
						if( s == null ) { s = new HashSet<String>(); recvByClass.put(key, s); }
						s.addAll(cn);
					}
				}
				{
					String rkS = receiverName(recv);
					String dcls = enclosingClassName(fc);
					if( rkS != null && !rkS.isEmpty() && dcls != null ) {
						Set<String> s = recvByClass.get(dcls+"::"+rkS);
						if( s != null ) for( String cn : s ) {
							Long cid = getClsId(cn, "");
							if( cid != null && cid != -1 ) classIds.add(cid);
						}
					}
				}
				if( classIds.isEmpty() ) {
					// Fallback: ParseVar couldn't infer the receiver type (e.g. constructor hidden inside
					// apply_filters). Match the receiver's property/var name to assignments that construct a
					// class anywhere in their RHS, and use those class(es).
					if( recvFallback == null ) {
						recvFallback = new java.util.HashMap<String,Set<String>>();
						PHPCGFactory.recordScanSite("PCG_11758", ASTUnderConstruction.idToNode.size());
						for( ASTNode an : ASTUnderConstruction.idToNode.values() ) {
							if( !(an instanceof AssignmentExpression) ) continue;
							Set<String> cn = new HashSet<String>();
							collectNewClassNames(((AssignmentExpression)an).getRight(), cn, 0);
							if( cn.isEmpty() ) continue;
							String key = receiverName(((AssignmentExpression)an).getLeft());
							if( key == null || key.isEmpty() ) continue;
							Set<String> s = recvFallback.get(key);
							if( s == null ) { s = new HashSet<String>(); recvFallback.put(key, s); }
							s.addAll(cn);
						}
					}
					String rk = receiverName(recv);
					if( rk != null && !rk.isEmpty() && recvFallback.containsKey(rk) ) {
						for( String cn : recvFallback.get(rk) ) {
							Long cid = getClsId(cn, "");
							if( cid != null && cid != -1 ) classIds.add(cid);
						}
					}
				}
				if( classIds.isEmpty() ) continue;
				if( mexpr instanceof StringExpression ) {        // constant method name -> resolve precisely
					String m = ((StringExpression)mexpr).getEscapedCodeStr();
					for( Long cid : classIds ) { Long t = resolveMethodInHierarchy(cid, m); if( t != null ) targets.add(t); }
				} else {                                         // dynamic method name -> every method of the receiver class
					if( methodsByClass == null ) {
						methodsByClass = new java.util.HashMap<Long,java.util.List<Long>>();
						for( Long mid : allMtd ) {
							ASTNode n = ASTUnderConstruction.idToNode.get(mid);
							if( !(n instanceof Method) ) continue;
							Long cid = getClsId(((Method)n).getEnclosingClass(), ((Method)n).getEnclosingNamespace());
							if( cid == null || cid == -1 ) continue;
							java.util.List<Long> l = methodsByClass.get(cid);
							if( l == null ) { l = new java.util.ArrayList<Long>(); methodsByClass.put(cid, l); }
							l.add(mid);
						}
					}
					for( Long cid : classIds ) {
						java.util.List<Long> l = methodsByClass.get(cid);
						if( l != null ) targets.addAll(l);
					}
				}
			}

			if( targets.isEmpty() ) continue;
			java.util.List<Long> ex = call2mtd.get(fc.getNodeId());
			for( Long t : targets ) {
				if( !(allMtd.contains(t) || allStaticMtd.contains(t) || allFunc.contains(t)) ) continue;
				if( ex == null || !ex.contains(t) ) call2mtd.add(fc.getNodeId(), t);   // add only missing edges
			}
			if( isCufa ) cufaArrayArg.add(fc.getNodeId());       // args are array-wrapped in arg[1]
			else callableArgOffset.add(fc.getNodeId());          // arg[0] is the callable -> shift by one
		}
		if( !callableArgOffset.isEmpty() || !cufaArrayArg.isEmpty() ) {
			int wpcSites = callableArgOffset.size()+cufaArrayArg.size();
			System.err.println("WPCALLABLE resolved "+wpcSites+" call_user_func[_array] dispatch site(s)");
			dynDispatchSitesResolved += wpcSites;
		}
	}


	/**
	 * Load language-frontend call-resolution facts from a small TSV sidecar.
	 * Enabled only when WP_FRONTEND_CALL_RESOLUTION points at a readable file.
	 *
	 * Format (one record per line):
	 *   callNodeId<TAB>EXACT|HEURISTIC|AMBIGUOUS|UNRESOLVED<TAB>targetId[,targetId...]
	 *
	 * EXACT with exactly one valid target may add a legacy call2mtd edge.  The other
	 * resolution classes are recorded but deliberately do not create hard edges.
	 */
	private static void loadFrontendCallResolution(CG cg) {
		String sidecar = System.getenv("WP_FRONTEND_CALL_RESOLUTION");
		if( sidecar == null || sidecar.trim().isEmpty() ) return;
		File f = new File(sidecar);
		if( !f.isFile() ) {
			System.err.println("FRONTEND_RESOLUTION missing sidecar: "+sidecar);
			return;
		}
		int loaded=0, exactAdded=0, rejected=0;
		try(BufferedReader br = new BufferedReader(new FileReader(f))) {
			String line;
			while((line=br.readLine())!=null) {
				line=line.trim();
				if(line.isEmpty() || line.startsWith("#")) continue;
				String[] parts=line.split("\\t",-1);
				if(parts.length<2) { rejected++; continue; }
				long callId;
				try { callId=Long.parseLong(parts[0].trim()); }
				catch(NumberFormatException nfe) { rejected++; continue; }
				String resolution=parts[1].trim().toUpperCase();
				if(!(resolution.equals("EXACT") || resolution.equals("HEURISTIC") || resolution.equals("AMBIGUOUS") || resolution.equals("UNRESOLVED"))) {
					rejected++; continue;
				}
				ASTNode callNode=ASTUnderConstruction.idToNode.get(callId);
				if(!(callNode instanceof CallExpressionBase)) { rejected++; continue; }
				frontendCallResolution.put(callId,resolution);
				frontendResolutionCounts.put(resolution, frontendResolutionCounts.getOrDefault(resolution,0)+1);
				java.util.ArrayList<Long> targets=new java.util.ArrayList<Long>();
				if(parts.length>=3 && !parts[2].trim().isEmpty()) {
					for(String tok: parts[2].split(",")) {
						try {
							Long tid=Long.parseLong(tok.trim());
							ASTNode target=ASTUnderConstruction.idToNode.get(tid);
							if(target instanceof FunctionDef) { targets.add(tid); frontendCallTargets.add(callId,tid); }
							else rejected++;
						} catch(NumberFormatException nfe) { rejected++; }
					}
				}
				loaded++;
				if(resolution.equals("EXACT") && targets.size()==1) {
					FunctionDef target=(FunctionDef)ASTUnderConstruction.idToNode.get(targets.get(0));
					if(addCallEdge(cg,(CallExpressionBase)callNode,target,false)) exactAdded++;
				} else if(resolution.equals("EXACT") && targets.size()!=1) {
					System.err.println("FRONTEND_RESOLUTION rejected EXACT call "+callId+" with "+targets.size()+" targets");
					rejected++;
				}
			}
		} catch(IOException ioe) {
			System.err.println("FRONTEND_RESOLUTION read error: "+ioe.getMessage());
			return;
		}
		System.err.println("FRONTEND_RESOLUTION loaded="+loaded+" exact_edges_added="+exactAdded+" rejected="+rejected+" classes="+frontendResolutionCounts);
	}


	/**
	 * Gate 11: load receiver-sensitive state-derived return summaries.
	 * Format: fid<TAB>COMPLETE<TAB>comma-separated-param-positions
	 * COMPLETE is intentionally strong: the frontend state model is asserting that it
	 * fully determined the caller-parameter contribution to this function's return for
	 * the modeled state operations. UNKNOWN/partial cases must be omitted from the file.
	 */
	private static void loadFrontendStateReturnSummaries() {
		String sidecar = System.getenv("WP_FRONTEND_STATE_RETURN_SUMMARY");
		if( sidecar == null || sidecar.trim().isEmpty() ) return;
		File f = new File(sidecar);
		if( !f.isFile() ) { System.err.println("FRONTEND_STATE_RETURN missing sidecar: "+sidecar); return; }
		frontendStateReturnPositions.clear(); frontendStateReturnComplete.clear();
		int loaded=0,rejected=0;
		try(BufferedReader br=new BufferedReader(new FileReader(f))) {
			String line;
			while((line=br.readLine())!=null) {
				line=line.trim(); if(line.isEmpty()||line.startsWith("#")) continue;
				String[] parts=line.split("\\t",-1); if(parts.length<2){rejected++;continue;}
				long fid; try{fid=Long.parseLong(parts[0].trim());}catch(NumberFormatException e){rejected++;continue;}
				if(!"COMPLETE".equalsIgnoreCase(parts[1].trim())){rejected++;continue;}
				ASTNode fn=ASTUnderConstruction.idToNode.get(fid); if(!(fn instanceof FunctionDef)){rejected++;continue;}
				Set<Integer> ps=new HashSet<Integer>();
				if(parts.length>=3 && !parts[2].trim().isEmpty()) for(String tok:parts[2].split(",")) {
					try { int idx=Integer.parseInt(tok.trim()); if(idx<0){rejected++;continue;} ps.add(idx); }
					catch(NumberFormatException e){rejected++;}
				}
				frontendStateReturnComplete.add(fid); frontendStateReturnPositions.put(fid,ps); loaded++;
			}
		} catch(IOException ioe) { System.err.println("FRONTEND_STATE_RETURN read error: "+ioe.getMessage()); return; }
		System.err.println("FRONTEND_STATE_RETURN loaded="+loaded+" rejected="+rejected+" complete="+frontendStateReturnComplete.size());
	}

	private static void applyFrontendStateReturnSummaries(HashMap<Long,Set<Integer>> pos, Set<Long> analyzed) {
		for(Long fid:frontendStateReturnComplete) {
			analyzed.add(fid);
			Set<Integer> ps=frontendStateReturnPositions.get(fid);
			if(ps==null || ps.isEmpty()) pos.remove(fid);
			else pos.put(fid,new HashSet<Integer>(ps));
		}
	}

	/** Gate 23: exact lexical-closure return summaries from a language frontend.
	 * Format: fid<TAB>COMPLETE<TAB>comma-separated outer-function parameter positions.
	 * Only COMPLETE summaries are accepted. This does not guess closure captures in Java;
	 * the frontend proves lexical binding/call semantics and the legacy engine consumes the
	 * resulting exact return dependency through its existing fixed-point machinery.
	 */
	private static void loadFrontendClosureReturnSummaries() {
		String sidecar=System.getenv("WP_FRONTEND_CLOSURE_RETURN_SUMMARY");
		if(sidecar==null || sidecar.trim().isEmpty()) return;
		File f=new File(sidecar);
		if(!f.isFile()){System.err.println("FRONTEND_CLOSURE_RETURN missing sidecar: "+sidecar);return;}
		frontendClosureReturnPositions.clear(); frontendClosureReturnComplete.clear();
		int loaded=0,rejected=0;
		try(BufferedReader br=new BufferedReader(new FileReader(f))){
			String line; while((line=br.readLine())!=null){
				line=line.trim(); if(line.isEmpty()||line.startsWith("#"))continue;
				String[] parts=line.split("\\t",-1); if(parts.length<2){rejected++;continue;}
				long fid; try{fid=Long.parseLong(parts[0].trim());}catch(NumberFormatException e){rejected++;continue;}
				if(!"COMPLETE".equalsIgnoreCase(parts[1].trim())){rejected++;continue;}
				ASTNode fn=ASTUnderConstruction.idToNode.get(fid); if(!(fn instanceof FunctionDef)){rejected++;continue;}
				Set<Integer> ps=new HashSet<Integer>();
				if(parts.length>=3&&!parts[2].trim().isEmpty()) for(String tok:parts[2].split(",")){
					try{int idx=Integer.parseInt(tok.trim());if(idx<0){rejected++;continue;}ps.add(idx);}catch(NumberFormatException e){rejected++;}
				}
				frontendClosureReturnComplete.add(fid); frontendClosureReturnPositions.put(fid,ps); loaded++;
			}
		}catch(IOException ioe){System.err.println("FRONTEND_CLOSURE_RETURN read error: "+ioe.getMessage());return;}
		System.err.println("FRONTEND_CLOSURE_RETURN loaded="+loaded+" rejected="+rejected+" complete="+frontendClosureReturnComplete.size());
	}

	private static void applyFrontendClosureReturnSummaries(HashMap<Long,Set<Integer>> pos, Set<Long> analyzed){
		for(Long fid:frontendClosureReturnComplete){
			analyzed.add(fid); Set<Integer> ps=frontendClosureReturnPositions.get(fid);
			if(ps==null||ps.isEmpty()) pos.remove(fid); else pos.put(fid,new HashSet<Integer>(ps));
		}
	}


	/**
	 * Gate 14: load uncertain state-derived return provenance.
	 * Format: fid<TAB>AMBIGUOUS|UNKNOWN<TAB>comma-separated-param-positions
	 * This channel is deliberately disjoint from the hard return-taint summary.
	 */
	private static void loadFrontendStateReturnUncertain() {
		String sidecar = System.getenv("WP_FRONTEND_STATE_RETURN_UNCERTAIN");
		if(sidecar==null || sidecar.trim().isEmpty()) return;
		File f=new File(sidecar);
		if(!f.isFile()){System.err.println("FRONTEND_STATE_MAY missing sidecar: "+sidecar);return;}
		frontendStateReturnMayPositions.clear(); frontendStateReturnMayResolution.clear();
		int loaded=0,rejected=0;
		try(BufferedReader br=new BufferedReader(new FileReader(f))){
			String line; while((line=br.readLine())!=null){
				line=line.trim(); if(line.isEmpty()||line.startsWith("#"))continue;
				String[] parts=line.split("\\t",-1); if(parts.length<2){rejected++;continue;}
				long fid; try{fid=Long.parseLong(parts[0].trim());}catch(NumberFormatException e){rejected++;continue;}
				String res=parts[1].trim().toUpperCase(); if(!("AMBIGUOUS".equals(res)||"UNKNOWN".equals(res))){rejected++;continue;}
				ASTNode fn=ASTUnderConstruction.idToNode.get(fid); if(!(fn instanceof FunctionDef)){rejected++;continue;}
				Set<Integer> ps=new HashSet<Integer>();
				if(parts.length>=3&&!parts[2].trim().isEmpty()) for(String tok:parts[2].split(",")){
					try{int idx=Integer.parseInt(tok.trim()); if(idx<0){rejected++;continue;} ps.add(idx);}catch(NumberFormatException e){rejected++;}
				}
				frontendStateReturnMayPositions.put(fid,ps); frontendStateReturnMayResolution.put(fid,res); loaded++;
			}
		}catch(IOException ioe){System.err.println("FRONTEND_STATE_MAY read error: "+ioe.getMessage());return;}
		System.err.println("FRONTEND_STATE_MAY loaded="+loaded+" rejected="+rejected+" uncertain="+frontendStateReturnMayResolution.size());
	}

	private static String weakerResolution(String a,String b){
		if(a==null)return b; if(b==null)return a;
		java.util.Map<String,Integer> rank=new java.util.HashMap<String,Integer>();
		rank.put("EXACT",0); rank.put("HEURISTIC",1); rank.put("AMBIGUOUS",2); rank.put("UNKNOWN",3); rank.put("UNRESOLVED",3);
		return rank.getOrDefault(a,3)>=rank.getOrDefault(b,3)?a:b;
	}

	/**
	 * Gate 15 helper: resolve a return expression to a call through a narrow, proven
	 * same-function local assignment chain.  We deliberately require exactly one
	 * defining assignment for each local variable.  Multiple definitions (branches,
	 * overwrites, loops) abstain rather than manufacturing a MAY path.
	 *
	 * Supported shapes:
	 *   return f(x);
	 *   const y = f(x); return y;
	 *   const y = f(x); const z = y; return z;
	 */
	private static CallExpressionBase resolveMayReturnCall(Expression e, Long fid, int depth) {
		if(e==null || fid==null || depth>8) return null;
		if(e instanceof CallExpressionBase) return (CallExpressionBase)e;
		String v=simpleVarName(e); if(v==null) return null;
		Expression rhs=null; int defs=0;
		for(ASTNode n:ASTUnderConstruction.idToNode.values()) {
			Long nf; try{nf=n.getFuncId();}catch(Exception ex){continue;}
			if(nf==null || !nf.equals(fid) || !(n instanceof AssignmentExpression)) continue;
			AssignmentExpression ae=(AssignmentExpression)n;
			if(v.equals(simpleVarName(ae.getLeft()))) { defs++; rhs=ae.getRight(); if(defs>1) return null; }
		}
		return defs==1 ? resolveMayReturnCall(rhs,fid,depth+1) : null;
	}

	/** Gate 16 expression-level MAY trace. */
	private static class MayExprTrace {
		boolean present=false;
		Set<Integer> positions=new HashSet<Integer>();
		String resolution=null;
	}

	private static Expression uniqueLocalRhs(String v, Long fid) {
		if(v==null || fid==null) return null;
		Expression rhs=null; int defs=0;
		for(ASTNode n:ASTUnderConstruction.idToNode.values()) {
			Long nf; try{nf=n.getFuncId();}catch(Exception ex){continue;}
			if(nf==null || !nf.equals(fid) || !(n instanceof AssignmentExpression)) continue;
			AssignmentExpression ae=(AssignmentExpression)n;
			if(v.equals(simpleVarName(ae.getLeft()))) { defs++; rhs=ae.getRight(); if(defs>1) return null; }
		}
		return defs==1 ? rhs : null;
	}

	/**
	 * Resolve an expression that is known to feed a MAY-producing callee argument
	 * back to caller parameters. This is deliberately exact-only: direct parameter
	 * or a unique local-alias chain. Branches/multiple defs abstain.
	 */
	private static Set<Integer> exactCallerParamsForExpr(Expression e, Long fid, FunctionDef fd, int depth) {
		Set<Integer> out=new HashSet<Integer>();
		if(e==null || fid==null || fd==null || depth>8) return out;
		String v=simpleVarName(e);
		if(v==null) return out;
		ParameterList pl=fd.getParameterList();
		if(pl!=null) for(int i=0;i<pl.size();i++) if(v.equals(((Parameter)pl.getParameter(i)).getName())) { out.add(i); return out; }
		Expression rhs=uniqueLocalRhs(v,fid);
		if(rhs!=null) return exactCallerParamsForExpr(rhs,fid,fd,depth+1);
		return out;
	}

	private static void mergeMay(MayExprTrace dst, MayExprTrace src) {
		if(src==null || !src.present) return;
		dst.present=true; dst.positions.addAll(src.positions);
		dst.resolution=weakerResolution(dst.resolution,src.resolution==null?"UNKNOWN":src.resolution);
	}

	/**
	 * Gate 16: trace uncertain provenance through ordinary expression composition.
	 * Supported conservatively:
	 *   - unique local aliases;
	 *   - calls whose callee has a MAY return summary;
	 *   - exact/hard return wrappers whose selected argument itself carries MAY;
	 *   - conditional expressions (union of arms; one-arm MAY is capped AMBIGUOUS).
	 *
	 * A plain caller parameter is NOT itself a MAY fact. Uncertainty must originate
	 * from the MAY channel and is never copied to returnTaintPositions.
	 */
	private static MayExprTrace traceMayExpr(Expression e, Long fid, FunctionDef fd, int depth) {
		MayExprTrace out=new MayExprTrace();
		if(e==null || fid==null || fd==null || depth>12) return out;

		if(e instanceof ast.expressions.ConditionalExpression) {
			ast.expressions.ConditionalExpression ce=(ast.expressions.ConditionalExpression)e;
			MayExprTrace a=traceMayExpr(ce.getTrueExpression(),fid,fd,depth+1);
			MayExprTrace b=traceMayExpr(ce.getFalseExpression(),fid,fd,depth+1);
			mergeMay(out,a); mergeMay(out,b);
			if(out.present && (a.present != b.present)) out.resolution=weakerResolution(out.resolution,"AMBIGUOUS");
			return out;
		}

		// Gate 17: non-call expression composition. A binary expression's result
		// depends on both operands, so uncertain provenance from either side survives.
		// Unlike a conditional, one-sided MAY does not add dispatch/control ambiguity:
		// the operand is definitely evaluated for the supported ordinary binary ops.
		if(e instanceof ast.expressions.BinaryExpression) {
			ast.expressions.BinaryExpression be=(ast.expressions.BinaryExpression)e;
			mergeMay(out,traceMayExpr(be.getLeft(),fid,fd,depth+1));
			mergeMay(out,traceMayExpr(be.getRight(),fid,fd,depth+1));
			return out;
		}

		String v=simpleVarName(e);
		if(v!=null && !(e instanceof CallExpressionBase)) {
			Expression rhs=uniqueLocalRhs(v,fid);
			if(rhs!=null) return traceMayExpr(rhs,fid,fd,depth+1);
			return out;
		}

		if(!(e instanceof CallExpressionBase)) return out;
		CallExpressionBase call=(CallExpressionBase)e;
		List<Long> targets=call2mtd.get(call.getNodeId());
		if(targets==null || targets.isEmpty()) return out;
		ArgumentList al=call.getArgumentList(); if(al==null) return out;

		for(Long t:targets) {
			// MAY callee: its uncertain return positions map through exact caller arguments.
			String tr=returnMayTaintResolution.get(t);
			if(tr!=null) {
				out.present=true; out.resolution=weakerResolution(out.resolution,tr);
				for(Integer p:returnMayTaintPositions.getOrDefault(t,Collections.<Integer>emptySet())) {
					if(p<0 || p>=al.size()) continue;
					out.positions.addAll(exactCallerParamsForExpr(al.getArgument(p),fid,fd,depth+1));
				}
			}

			// Exact/hard wrapper: MAY in an argument survives only if that argument is
			// proven to contribute to the callee return.
			if(returnTaintAnalyzed.contains(t)) {
				for(Integer p:returnTaintPositions.getOrDefault(t,Collections.<Integer>emptySet())) {
					if(p<0 || p>=al.size()) continue;
					mergeMay(out,traceMayExpr(al.getArgument(p),fid,fd,depth+1));
				}
			}
		}
		if(out.present && targets.size()>1) out.resolution=weakerResolution(out.resolution,"AMBIGUOUS");
		String cr=frontendCallResolution.get(call.getNodeId());
		if(out.present && cr!=null) out.resolution=weakerResolution(out.resolution,cr);
		return out;
	}

	/**
	 * Gate 14-17: fixed-point propagation of uncertain return provenance. Gate 16-17
	 * generalizes the return expression from a direct/local call to conservative
	 * expression composition while preserving the hard/MAY separation.
	 */
	private static void buildReturnMayTaintSummaries() {
		returnMayTaintPositions.clear(); returnMayTaintResolution.clear();
		for(Long fid:frontendStateReturnMayResolution.keySet()){
			returnMayTaintPositions.put(fid,new HashSet<Integer>(frontendStateReturnMayPositions.getOrDefault(fid,Collections.<Integer>emptySet())));
			returnMayTaintResolution.put(fid,frontendStateReturnMayResolution.get(fid));
		}
		HashMap<Long,FunctionDef> funcs=new HashMap<Long,FunctionDef>();
		for(ASTNode n:ASTUnderConstruction.idToNode.values()) if(n instanceof FunctionDef) funcs.put(n.getNodeId(),(FunctionDef)n);
		boolean changed=true; int rounds=0;
		while(changed && rounds++<12){
			changed=false;
			for(ASTNode n:ASTUnderConstruction.idToNode.values()){
				if(!(n instanceof ast.statements.jump.ReturnStatement))continue;
				Long caller=n.getFuncId(); FunctionDef fd=funcs.get(caller); if(fd==null)continue;
				ASTNode re=((ast.statements.jump.ReturnStatement)n).getReturnExpression(); if(!(re instanceof Expression))continue;
				MayExprTrace mt=traceMayExpr((Expression)re,caller,fd,0); if(!mt.present)continue;
				Set<Integer> old=returnMayTaintPositions.get(caller); String oldr=returnMayTaintResolution.get(caller);
				Set<Integer> nu=new HashSet<Integer>(); if(old!=null)nu.addAll(old); nu.addAll(mt.positions);
				String nur=weakerResolution(oldr,mt.resolution==null?"UNKNOWN":mt.resolution);
				if(old==null||!old.equals(nu)||!java.util.Objects.equals(oldr,nur)){returnMayTaintPositions.put(caller,nu);returnMayTaintResolution.put(caller,nur);changed=true;}
			}
		}
		System.err.println("RETURN_MAY_SUMMARY functions="+returnMayTaintResolution.size()+" rounds="+rounds);
	}

	public static CG newInstance() {
		CG cg = new CG();
		
		init();
		
		//createSpiderEdges(cg);
		System.err.println("@");
		createFunctionCallEdges(cg);
		System.err.println("@@");
		createConstructorCallEdges(cg);
		System.err.println("@@@");
		createStaticMethodCallEdges(cg);
		System.err.println("@@@@");
		// Collect $wpdb aliases ($_db = $wpdb, $this->wpdb = $wpdb) BEFORE non-static
		// method-call processing, because that pass is where $wpdb sinks are detected
		// and it must recognize alias receivers too.
		collectWpdbAliases();
		collectWpdbAccessorMethods();
		// Prove-before-recognize inference of user-defined sanitizers: integer sanitizers
		// (ctype_digit/intval-style) and quote-escapers (addslashes/strtr-map). Must run after
		// parsing populated the AST/sqlSanitizers and BEFORE the esc_sql demotion, so inferred
		// escaper calls registered into sqlSanitizers are subject to the unquoted-context drop.
		classifyUserSanitizers();
		registerInferredSanitizerNodes();
		computeLiteralOnlyVars();       // resolve constant-bearing locals so the XSS suppressor can credit them
		// Context-sensitive esc_sql: drop unquoted inline esc_sql calls from the SQL
		// sanitizer set so their taint is reported (CVE-2021-24340 class). Must run
		// after parsing populated sqlSanitizers and before the taint analysis consumes it.
		demoteAllUnquotedEscSql();
		createNonStaticMethodCallEdges(cg);
		resolveCallableDispatch();   // model call_user_func / array-callable dispatch (recall fix)
		resolveHookDispatch();       // model do_action/apply_filters -> registered handler dispatch (recall fix)
		seedForeachOverSource();     // foreach($SOURCE as $v): taint iteration vars (CVE-2022-0513 class)
		seedDynKeyArrayWrite();      // $base[$dynKey]=<tainted>: taint base array (CVE-2022-0513 remaining link)
		forwardInlineSourceArgs();   // seed callee params from inline-source call args (recall fix)
		// Dispatch augmentation must run for EVERY taint class, not only when the ACL/CSRF/IDOR/
		// OPTIONS_WRITE audit or XSS_ONLY happens to be on. Both are idempotent.
		augmentStaticDispatchEdges();
		augmentInstanceDispatchEdges();
		loadFrontendCallResolution(cg);   // Gate 6: explicit frontend facts; exact-only hard-edge bridge
		if( System.getenv("WP_DECLARATIVE_DISPATCH") != null ) scanDeclarativeDispatchCandidates();
		dumpCallGraph();             // export resolved call2mtd for the adjudicator (node-accurate chain)
		dumpCallResolutionStats();   // WP_CALL_RESOLUTION_STATS=1: M/N call2mtd resolution rate by call kind
		dumpPropertyReceiverStats(); // WP_PROP_STATS=1: cross-object over-taint surface of Class::property
		dumpSetterStats();           // WP_SETTER_STATS=1: setter-propagation ($o->field=$v) surface
		// Resolve setting-getter wrappers to their backing stored key BEFORE the XSS suppressor runs, so
		// an output of a wrapper (e.g. echo get_close_text()) is credited as a stored read and kept as a
		// sink. Runs after call-edge creation so wrapper-of-wrapper chains resolve. Inert unless stored-
		// taint is on, so the oracle runs (stored-taint off) are unaffected by this reordering.
		resolveStoredReadWrappers(buildVarAssigns());
		filterProvablySafeXssSinks();   // drop echo/print sinks fully escaped at output (all modes)
		// Model thin DB query-wrappers as sinks so taint passed to them is reported.
		// Runs after base $wpdb sinks are known and before seeding, so a handler that
		// contains a wrapper call is also picked up as a self-contained entry point.
		seedQueryVarsSources();
		loadFrontendStateReturnSummaries(); // Gate 11: seed state-derived return facts before RTP fixed point
		loadFrontendClosureReturnSummaries(); // Gate 23: exact lexical-closure frontend summaries
		loadFrontendStateReturnUncertain(); // Gate 14: parallel MAY/UNKNOWN channel; never hardens into RTP
		detectQueryWrappers();
		buildReturnSafetySummaries();   // echo-of-call precision: classify callee returns (needs call2mtd + retArbitrary built)
		suppressWhitelistGuardedSources();   // FIX 35: in_array() whitelist guards
		System.err.println("@@@@@");

		// WP REST handlers receive user input via $request->get_param()/get_params()/etc.,
		// not superglobals. Model that getter family as taint sources so REST routes seeded
		// below (esp. permissive permission_callbacks in public mode) actually propagate taint.
		// MOVED (2026-08-08, alongside its fix): must run AFTER seedWordPressEntryPoints() below,
		// since it now requires entryPriv (populated there) to confirm the receiver is really a
		// REST callback's own first parameter -- it previously ran here, before entryPriv
		// existed, which is part of why the receiver check had never been added.
		seedRawInputSources();
		seedStoredTaintSources();

		// Extended sink classes (object injection, SSRF, LFI/RFI, RCE, file access).
		detectAdditionalSinks();
		// File-upload sources ($_FILES[*][name|type]); pairs with the file-access sinks above.
		seedFileUploadSources();

		// WORDPRESS ENTRY-POINT SEEDING: WordPress invokes plugin handlers through hooks
		// (add_action('wp_ajax_*', cb), register_rest_route(..., cb)), so those handler
		// functions/methods are never called from top-level PHP and TChecker would never
		// analyze them. Stock TChecker learns entry points from an XDebug profiler trace;
		// this is the WordPress analogue. We scan for hook registrations, resolve the
		// callback to its definition, and register it as an analysis root (topFunIds) so
		// taint analysis starts from WordPress request handlers.
		seedWordPressEntryPoints();
		seedRestRequestSources();    // moved here: needs entryPriv (populated above) for the receiver check
		seedRestArrayAccess();       // $request['key'] array-access as REST source (CVE-2022-45808 class)
		seedBlockRegistrations();
		seedElementorWidgets();
		seedWidgetQueryVarTemplates();   // WP-core the_widget->set_query_var->load_template(extract) bridge
		seedSelfContainedHandlers();
		resolveFileScopeIncludeProvenance();   // ITEM18 Part 2: needs entryPriv (populated above)
		auditAccessControl();
		emitControlReachabilityCandidates();   // after sinks + entry seeding are populated

		dumpSummaries();             // export Layer-1B return/hook summaries AFTER all seeding populated
		                             // retArbitraryFids / topFunIds / sinks (WP_DUMP_SUMMARIES=1 only)
		reset(cg);
		
		return cg;
	}

	private static void createSpiderEdges(CG cg) {
		
		File profile = new File("/data/xdebug/wp");
		File[] files = profile.listFiles();
		if (files != null) {
		    for (File file : files) {
		    	try (BufferedReader br = new BufferedReader(new FileReader(file), (int) file.length())) {
		    	    String line;
		    	    while ((line = br.readLine()) != null) {
		    	       //line = line.replaceAll("[^\\x00-\\x7F]", " ");
		    	       String[] words = line.split("\\s+");
		    	       if(words.length!=6) {
		    	    	   continue;
		    	       }
		    	       String iden = words[words.length-1]+words[words.length-2];
		    	       if(bwlines.contains(iden)) {
		    	    	   continue;
		    	       }
		    	       bwlines.add(iden);
		    	       //integrate with results produced by Spider.
		    	       if(words.length==6) {
		    	    	   String target = words[4];
		    	    	   target = target.replace("/var/www/html/", "/home/users/chluo/goal/");
		    	    	   target = target.replace("()", "");
		    	    	   String path = words[5].replace("/var/www/html/", "/home/users/chluo/goal/");
		    	    	   //main functon
		    	    	   if(target.equals("{main}")) {
		    	    		   String entry = path.substring(0, path.indexOf(":"));
		    	    		   entry = "<"+entry+">";
		    	    		   entrypoint.add(entry);
 		    	    	   }
		    	    	   //require or include
		    	    	   if(target.startsWith("include(") || target.startsWith("require(") ||
		    	    			   target.startsWith("require_once(") || target.startsWith("include_once(")) {
		    	    		   target = target.substring(target.indexOf("/"));
		    	    		   target = target.replace(")", "");
		    	    		   //System.out.println("target: "+target);
		    	    		   //we find the included file
		    	    		   if(topLevelFunctionDefs.containsKey(target)) {
		    	    			   Long targetID = topLevelFunctionDefs.get(target);
		    	    			   if(!(path2callee.containsKey(path) && path2callee.get(path).contains(targetID))) {
		    	    				   path2callee.add(path, targetID);
		    	    			   }
		    	    		   }
		    	    	   }
		    	    	   //general function calls
		    	    	   else {
		    	    		   target = target.replace("->", "::");
		    	    		   //System.out.println("className: "+target);
		    	    		   //it is a method
		    	    		   if(target.contains("::")){
		    	    			   String className=target.substring(0, target.indexOf("::"));
		    	    			   String rest=target.substring(target.indexOf("::"));
		    	    			   rest=rest.replace("::__construct", "");
		    	    			   Long classID = getClsId(className, "-1");
		    	    			   String methodkey = classID+rest;
		    	    			   for(String funcKey: constructorDefs.keySet()) {
		    	    				   if(funcKey.equals(methodkey)) {
		    	    						for(FunctionDef func: constructorDefs.get(funcKey)){
		    	    							if(!(path2callee.containsKey(path) && path2callee.get(path).contains(func.getNodeId()))) {
		    	    								path2callee.add(path, func.getNodeId());
		    	    							}
		    	    						}
		    	    					}
		    	    			   }
		    	    			   for(String funcKey: nonStaticMethodDefs.keySet()) {
		    	    				   if(funcKey.equals(methodkey)) {
		    	    						for(FunctionDef func: nonStaticMethodDefs.get(funcKey)){
		    	    							if(!(path2callee.containsKey(path) && path2callee.get(path).contains(func.getNodeId()))) {
		    	    								path2callee.add(path, func.getNodeId());
		    	    							}
		    	    						}
		    	    					}
		    	    			   }
		    	    			   for(String funcKey: staticMethodDefs.keySet()) {
		    	    				   if(funcKey.equals(methodkey)) {
		    	    						for(FunctionDef func: staticMethodDefs.get(funcKey)){
		    	    							if(!(path2callee.containsKey(path) && path2callee.get(path).contains(func.getNodeId()))) {
		    	    								path2callee.add(path, func.getNodeId());
		    	    							}
		    	    						}
		    	    					}
		    	    			   }
		    	    		   }
		    	    		   //it is a function
		    	    		   else {
		    	    			   String functionKey = target;
		    	    			   for(String funcKey: staticMethodDefs.keySet()) {
		    	    				   if(funcKey.equals(functionKey)) {
		    	    						for(FunctionDef func: staticMethodDefs.get(funcKey)){
		    	    							if(!(path2callee.containsKey(path) && path2callee.get(path).contains(func.getNodeId()))) {
		    	    								path2callee.add(path, func.getNodeId());
		    	    							}
		    	    						}
		    	    					}
		    	    			   }
		    	    		   }
		    	    	   }   
		    	    	   //path2callee.add(path, target);
		    	       }
		    	    }
		    	} catch(Exception e) {
		    		
		    	}
		    }
		  } 
		
		System.out.println("pat2callee: "+path2callee.size());
		//require and include
		for(Long ildId: toTopLevelFile.includeLoc) {
			String path = getDir(ildId);
			ASTNode require = ASTUnderConstruction.idToNode.get(ildId);
			path=path+":"+require.getLocation().startLine;
			if(path2callee.containsKey(path)) {
				//one line may call multiple target functions
				//System.out.println("require path "+path);
				call2mtd.addAll(ildId, path2callee.get(path));
				continue;
			}
		}
		
	}

	static void init() {
		setInheritance();
		getComment();
		// FIX (2026-07-20): infer return-class for static factory methods that have no @return
		// docblock. The common WordPress/PHP pattern `Foo::getInstance()` returns `new self()`
		// or `self::$_instance` — an instance of the class it's called on. Without a @return
		// docblock, retCls is empty, and any chained call `Foo::getInstance()->method($x)`
		// cannot resolve `->method()` to `Foo::method`, breaking the entire chain. This is
		// confirmed as the final remaining gap for LearnPress CVE-2022-45808 after seven prior
		// fixes this session.
		//
		// Heuristic: for every static method NOT already in retCls, if its name matches a small
		// set of known factory-pattern names (getInstance, instance, get_instance, factory,
		// create), set retCls to the method's own enclosing class. This is intentionally broad
		// for recall (matching this project's established philosophy for WPENTRY seeding and
		// wrapper classification elsewhere) — a static method named getInstance that does NOT
		// return its own class would be unusual enough to accept as a rare false positive.
		{
			java.util.Set<String> factoryNames = new java.util.HashSet<String>(
				java.util.Arrays.asList("getInstance", "instance", "get_instance", "factory", "create"));
			int inferred = 0;
			for(Long fid : allStaticMtd) {
				if(retCls.containsKey(fid)) continue;
				ASTNode fn = ASTUnderConstruction.idToNode.get(fid);
				if(!(fn instanceof FunctionDef)) continue;
				String name = ((FunctionDef) fn).getName();
				if(name == null || !factoryNames.contains(name)) continue;
				String clsName = fn.getEnclosingClass();
				if(clsName == null || clsName.isEmpty()) continue;
				Long clsId = null;
				for(java.util.Map.Entry<Long, ASTNode> entry : ASTUnderConstruction.idToNode.entrySet()) {
					if(entry.getValue() instanceof ClassDef && clsName.equals(((ClassDef) entry.getValue()).getName())) {
						clsId = entry.getKey();
						break;
					}
				}
				if(clsId == null || clsId == -1) continue;
				retCls.put(fid, clsId);
				inferred++;
			}
			if(inferred > 0) System.err.println("RETCLS_INFER inferred return-class for " + inferred + " factory method(s)");
		}
		ParseVar.ParseInterRelationship();
		
		HashSet<Long> save = new HashSet<Long>(topFunIds);
		for(Long topId: save) {
			String path = getDir(topId);
			//we do not consider vendor files
			if(path.contains("/vendor/")) {
				topFunIds.remove(topId);
			}
		}
		
		for(Long nodeid : PHPCSVEdgeInterpreter.collectUse.keySet()) {
			Long topid = toTopLevelFile.getTopLevelId(nodeid);
			allUse.add(topid, PHPCSVEdgeInterpreter.collectUse.get(nodeid));
		}
	
	}
	
	
	private static void getComment() {
		for(Long funcId: allFuncDef) {
			FunctionDef func = (FunctionDef) ASTUnderConstruction.idToNode.get(funcId);
			String namespace = func.getEnclosingNamespace();
			String comment = func.getDocComment();
			if(comment==null || comment.isEmpty()) {
				continue;
			}
			String[] comments = comment.split("\n");
			ParameterList paramList = func.getParameterList();
			HashMap<String, Long> name2Id = new HashMap<String, Long>();
			for(int i=0; i<paramList.size(); i++) {
				Parameter param = (Parameter) paramList.getParameter(i);
				name2Id.put(param.getName(), param.getNodeId());
			}
			
			//parse each comment line
			for(String line: comments) {
				//it is a param line
				if(line.contains("@param")) {
					for(String param: name2Id.keySet()) {
						//this line contains one param name
						if(line.contains('$'+param)) {
							line = line.replace("|", " ");
							String[] words = line.split("\\s+");
							for(String word: words) {
								if(word==null || word.isEmpty()) {
									continue;
								}
								//get the class of param from its comment
								Long classId = getClassId(word, funcId, namespace);
								if(classId!=-1) {
									paramCls.put(name2Id.get(param), classId);
									break;
								}
							}
							//there is no a valid class name
							if(!paramCls.containsKey(name2Id.get(param)) && !line.toLowerCase().contains("mix")) {
								paramCls.put(name2Id.get(param), (long) -2);
							}
						}
				
					}
					
				}
				//it is a return line
				else if(line.contains("@return")) {
					String[] words = line.split("\\s+");
					for(String word: words){
						Long classId = getClassId(word, funcId, namespace);
						if(classId!=-1) {
							retCls.put(funcId, classId);
						}
					}
				}
			}
		}
	}

	public static String getDir(Long astid) {
		Long topId = toTopLevelFile.getTopLevelId(astid);
		//FunctionDef funNode =  (FunctionDef) ASTUnderConstruction.idToNode.get(funId);
		if(!ASTUnderConstruction.idToNode.get(topId).getFlags().equals("TOPLEVEL_FILE")) {
			System.err.println("Fail to find top file for target function "+astid);
			return "";
		}
		TopLevelFunctionDef topFile = (TopLevelFunctionDef) ASTUnderConstruction.idToNode.get(topId);
		String phpPath = topFile.getName();
		phpPath = phpPath.substring(1, phpPath.length()-1);
		phpPath = phpPath.replace("//", "/");
		//topIdcache.put(astid, phpPath);
		return phpPath;
	}
	
	//class inheritance
	private static void setInheritance() {
		for(Long clsId:  inhe.keySet()) {
			Set<Long> prts = getParentClassId(clsId);
			for(Long prt: prts) {
				if(clsId.equals(prt)) {
					continue;
				}
				//System.out.println("cls2prt:"+clsId+" "+prt);
				if(clsId!=-1 && prt!=-1) {
					ch2prt.add(clsId, prt);
					prt2ch.add(prt, clsId);
				}
			}
		}	
	}
	
	public static Set<Long> getAllChild(Long prtId){
		
		Set<Long> cldList = new HashSet<Long>();
		Queue<Long> crtCld = new LinkedList<Long>();
		crtCld.offer(prtId);
		while(!crtCld.isEmpty()) {
			Long crtId = crtCld.poll();
			if(prt2ch.containsKey(crtId)) {
				for(Long ele: prt2ch.get(crtId)) {
					crtCld.add(ele);
					cldList.add(ele);
				}
			}
		}
		
		return cldList;
	}
	
	public static Set<Long> getAllParent(Long childId){
		Set<Long> prtList = new HashSet<Long>();
		Queue<Long> crtPrt = new LinkedList<Long>();
		crtPrt.offer(childId);
		while(!crtPrt.isEmpty()) {
			Long crtId = crtPrt.poll();
			if(ch2prt.containsKey(crtId)) {
				crtPrt.addAll(ch2prt.get(crtId));
				prtList.addAll(ch2prt.get(crtId));
			}
		}
		
		return prtList;
	}

	
	private static void createFunctionCallEdges(CG cg) {
		
		int x1 = functionCalls.size();
		
		AtomicInteger c1= new AtomicInteger(0);
		for(CallExpressionBase functionCall : functionCalls) {
			c1.incrementAndGet();
			//System.err.println("function: "+c1+" "+x1);
			
			String path = getDir(functionCall.getNodeId());
			path=path+":"+functionCall.getLocation().startLine;
			if(path2callee.containsKey(path)) {
				//one line may call multiple target functions
				if( functionCall.getTargetFunc() instanceof Identifier) {
					Identifier callIdentifier = (Identifier)functionCall.getTargetFunc();
					if(callIdentifier.getNameChild().getEscapedCodeStr().equals("call_user_func")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("call_user_func_array")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("spl_autoload_register")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("spl_autoload_unregister")) {
						call2mtd.addAll(functionCall.getNodeId(), path2callee.get(path));
					}
					else {
						for(Long target: path2callee.get(path)) {
							ASTNode targetFunc = ASTUnderConstruction.idToNode.get(target);
							String funKey = targetFunc.getEscapedCodeStr();
							if(allFunc.contains(target) && callIdentifier.getNameChild().getEscapedCodeStr().equals(funKey)){
								call2mtd.add(functionCall.getNodeId(), target);
							}
						}
					}
				}
				else {
					for(Long target: path2callee.get(path)) {
						if(allFunc.contains(target)){
							call2mtd.add(functionCall.getNodeId(), target);
						}
					}
				}
				continue;
			}
			
			// make sure the call target is statically known
			if( functionCall.getTargetFunc() instanceof Identifier) {
				
				Identifier callIdentifier = (Identifier)functionCall.getTargetFunc();
				
				// Add the sinks there.
				if(callIdentifier.getNameChild().getEscapedCodeStr().equals("mysql_query") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("mysqli_query") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("pg_query") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("sqlite_query")) {
					if( sqlSinkProvablySafe(functionCall) ) {
						System.err.println("WPSAFE suppressed provably-safe SQL call sink "+functionCall.getNodeId());
					} else {
						sinks.add(functionCall.getNodeId());
					}
				}

				// CALLBACK SANITIZER: array_map('absint', $x) / array_walk applies a sanitizer
				// to every element, so the result is clean. The call name is array_map (not the
				// sanitizer), so we look at the first argument: if it is a string literal naming
				// a known sanitizer, treat the whole array_map(...) call as a SQL sanitizer.
				// FIX (2026-08-08): array_filter deliberately removed from this list, confirmed
				// as a genuine semantic error, not merely a style concern -- array_filter($arr,
				// $callback) uses the callback's return value to decide RETENTION, not to
				// TRANSFORM each element the way array_map/array_walk's callback does.
				// array_filter($ids, 'is_numeric') preserves the ORIGINAL, unmodified value of
				// every element that passes the check -- a malicious string that happens to be
				// numeric-ish under a loose check survives in the result completely unchanged.
				// Unlike array_walk (whose own return value is a boolean, essentially never used
				// directly as SQL input regardless of this mischaracterization, so left as-is
				// rather than pursued as a separate, lower-value fix), array_filter's return
				// value is a genuinely SQL-relevant collection in realistic code
				// ($safe_ids = array_filter($ids, 'is_numeric'); ...IN (...$safe_ids...)), so
				// this specific misclassification had real, practical reach.
				String cbName = callIdentifier.getNameChild().getEscapedCodeStr();
				if( (cbName.equals("array_map") || cbName.equals("array_walk"))
					&& functionCall.getArgumentList() != null
					&& functionCall.getArgumentList().size() >= 1
					&& functionCall.getArgumentList().getArgument(0) instanceof StringExpression ) {
					String inner = ((StringExpression)functionCall.getArgumentList().getArgument(0)).getEscapedCodeStr();
					if( PHPCSVEdgeInterpreter.repairs.contains(inner) ) {
						PHPCSVEdgeInterpreter.sqlSanitizers.add(functionCall.getNodeId());
					}
				}
				
				if(callIdentifier.getNameChild().getEscapedCodeStr().equals("echo") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("print") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("print_r") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("printf") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("exit") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("die") ||
						callIdentifier.getNameChild().getEscapedCodeStr().equals("vprintf")) {
					if( !SQLI_ONLY ) { sinks.add(functionCall.getNodeId()); sinkClass.put(functionCall.getNodeId(),"xss"); }
				}
				
			
				if(filterTest(callIdentifier.getNameChild().getEscapedCodeStr())) {
					continue;
				}
				
				//callback in built-in functions
				if(callIdentifier.getNameChild().getEscapedCodeStr().equals("usort") ||
							callIdentifier.getNameChild().getEscapedCodeStr().equals("array_walk")) {
					if(functionCall.getArgumentList().size()<2) {
						continue;
					}
					ASTNode secondArg = functionCall.getArgumentList().getArgument(1);
					//calling method
					if(secondArg.getProperty("type").equals("AST_ARRAY")) {
						String classname = new String();
						String methodname = "";
						// The [class,method] callable array must have both elements. A malformed single-
						// element array (e.g. array($obj) with no method) previously crashed the whole scan
						// with IndexOutOfBoundsException at getArrayElement(1) — createFunctionCallEdges only
						// checked the CALL's arg count, not the array's. Skip such edges instead. (everest-forms
						// batch #12 crash.)
						if( ((ArrayExpression) secondArg).size() < 2 ) {
							continue;
						}
						ArrayElement classEle = ((ArrayExpression) secondArg).getArrayElement(0);
						ArrayElement methodEle = ((ArrayExpression) secondArg).getArrayElement(1);
						Long clsId = (long) -1;
						if(classEle.getValue().getProperty("type").equals("string")) {
							String namespace = secondArg.getEnclosingNamespace();
							//Long prtId = getClassId(classname, functionCall.getNodeId(), namespace);
							classname = ((StringExpression)(classEle.getValue())).getEscapedCodeStr();
							if(classname.equals("static") || classname.equals("parent") || classname.equals("self")) {
								classname = secondArg.getEnclosingClass(); 
								clsId = getClassId(classname, functionCall.getNodeId(), namespace);
							}
							else {
								clsId = getClassId(classname, functionCall.getNodeId(), namespace);
							}
						}
						else if( classEle.getValue() instanceof Variable
								&& ((Variable)classEle.getValue()).getNameExpression() instanceof StringExpression
								&& ((StringExpression)((Variable)classEle.getValue()).getNameExpression()).getEscapedCodeStr().equals("this")) {
							String namespace = secondArg.getEnclosingNamespace();
							classname = secondArg.getEnclosingClass(); 
							clsId = getClassId(classname, functionCall.getNodeId(), namespace);
						}
						else {
							System.err.println("USORT CLASS: "+functionCall.getNodeId());
						}
						
						if(methodEle.getValue().getProperty("type").equals("string")) {
							methodname = (((StringExpression)(methodEle.getValue())).getEscapedCodeStr());
						}
						else {
							System.err.println("USORT METHOD: "+methodEle.getValue().getProperty("type"));
						}
						
						if(methodname==null) {
							System.err.println("NULL"+functionCall.getNodeId());
						}
						if(clsId!=-1 && !methodname.isEmpty()) {
							System.err.println("USORT: "+functionCall.getNodeId());
							String methodKey = clsId+"::"+methodname;
							addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, functionCall, methodKey, false);
						}
					}
					else {
						System.err.println("Unknown USORT: "+functionCall.getNodeId());
					}
				}
				
				else if(callIdentifier.getNameChild().getEscapedCodeStr().equals("call_user_func")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("call_user_func_array")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("spl_autoload_register")
						|| callIdentifier.getNameChild().getEscapedCodeStr().equals("spl_autoload_unregister")) {
					//System.err.println(functionCall);
					callsiteNumber++;
					//comparing argument numbers does not apply here
					call_user.add(functionCall.getNodeId());
					
					if(functionCall.getArgumentList().size()==0) {
						continue;
					}
					
					ASTNode firstArg = functionCall.getArgumentList().getArgument(0);
					//System.err.println("CALL_USER: "+firstArg.getProperty("type"));
					
					//call_user_func calls method
					if(firstArg.getProperty("type").equals("AST_ARRAY")) {
						String classname = new String();
						Set<String> methodname = new HashSet<String>();
						Set<Long> clds = new HashSet<Long>();
						
						// PHP callable arrays reaching call_user_func*/new are not always well-formed
						// [class, method] pairs; a single-element or empty array would make
						// getArrayElement(1) throw IndexOutOfBounds and abort the entire file.
						if(((ArrayExpression) firstArg).size() < 2) {
							continue;
						}
						ArrayElement classEle = ((ArrayExpression) firstArg).getArrayElement(0);
						ArrayElement methodEle = ((ArrayExpression) firstArg).getArrayElement(1);
						
						//System.err.println("CALL_USER_METHOD: "+classEle.getValue().getProperty("type")+" "+methodEle.getValue().getProperty("type"));
						
						if(classEle.getValue().getProperty("type").equals("string")) {
							String namespace = firstArg.getEnclosingNamespace();
							classname = ((StringExpression)(classEle.getValue())).getEscapedCodeStr();
							if(classname.equals("static") || classname.equals("parent") || classname.equals("self")) {
								classname = firstArg.getEnclosingClass(); 
								Long prtId = getClassId(classname, functionCall.getNodeId(), namespace);
								clds.add(prtId);
							}
							else {
								Long clsId = getClassId(classname, functionCall.getNodeId(), namespace);
								clds.add(clsId);
							}
						}
						else if( classEle.getValue() instanceof Variable
								&& ((Variable)classEle.getValue()).getNameExpression() instanceof StringExpression
								&& ((StringExpression)((Variable)classEle.getValue()).getNameExpression()).getEscapedCodeStr().equals("this")) {
							String namespace = firstArg.getEnclosingNamespace();
							classname = firstArg.getEnclosingClass(); 
							clds.add(getClassId(classname, functionCall.getNodeId(), namespace));
						}
						else if(classEle.getValue() instanceof NewExpression && 
								((NewExpression)classEle.getValue()).getTargetClass() instanceof Identifier) {
							NewExpression classNew = (NewExpression) classEle.getValue();
							Identifier classNode = (Identifier) classNew.getTargetClass();
							String className = classNode.getNameChild().getEscapedCodeStr();
							String namespace = classNode.getEnclosingNamespace();
							clds.add(getClassId(className, functionCall.getNodeId(), namespace));
						}
						else {
							ASTNode classVar = classEle.getValue();
							//System.err.println("class: "+classVar.getNodeId());
							ParseVar parsevar = new ParseVar();
							parsevar.init(classVar.getNodeId(), true, "");
							parsevar.handle();
							Set<String> classValue = parsevar.getVar();
							for(String classvalue: classValue) {
								try {
									System.err.println("Parse Long: "+classVar.getNodeId()+" "+classvalue);
									clds.add(Long.parseLong(classvalue));
								} catch(NumberFormatException nfe) {
									System.err.println("Unknown class NodeId: "+classVar.getNodeId()+" "+classvalue);
								}
							}
							parsevar.reset();
						}
						
						//parse method name
						if(methodEle.getValue().getProperty("type").equals("string")) {
							methodname.add(((StringExpression)(methodEle.getValue())).getEscapedCodeStr());
						}
						else {
							ParseVar parsevar = new ParseVar();
							parsevar.init(methodEle.getValue().getNodeId(), false, "");
							parsevar.handle();
							methodname = parsevar.getVar();
						}
						
						//debug call_user_funnc
						System.err.println("call_user_func "+functionCall.getNodeId()+" "+clds.toString()+" "+methodname.toString());
						
						
						for(Long clsDefId: clds) {
							for(String mtdkey: methodname) {
								String methodKey = clsDefId+"::"+mtdkey;
								addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, functionCall, methodKey, false);
							}	
						}
					}
					
					//call_user_func calls function
					else {
						if(firstArg.getProperty("type").equals("string")) {
							String funcname = ((StringExpression)(firstArg)).getEscapedCodeStr();
							addCallEdgeIfDefinitionKnown(cg, functionDefs, functionCall, funcname, false);
						}
					}
				}
				
				
				// if call identifier is fully qualified,
				// just look for the function's definition right away
				if( callIdentifier.getFlags().contains( PHPCSVNodeTypes.FLAG_NAME_FQ)) {
					String functionKey = callIdentifier.getNameChild().getEscapedCodeStr();
					addCallEdgeIfDefinitionKnown(cg, functionDefs, functionCall, functionKey, false);
				}

				// otherwise, i.e., if the call identifier is not fully qualified,
				// first look in the current namespace, then if the function is not found,
				// look in the global namespace
				// (see http://php.net/manual/en/language.namespaces.rules.php)
				else {
					boolean found = false;
					// note that looking in the current namespace first only makes
					// sense if we are not already in the global namespace anyway
					if( !callIdentifier.getEnclosingNamespace().isEmpty()) {
						String functionKey = callIdentifier.getEnclosingNamespace() + "\\"
								+ callIdentifier.getNameChild().getEscapedCodeStr();
						found = addCallEdgeIfDefinitionKnown(cg, functionDefs, functionCall, functionKey, false);
					}
					
					// we did not find the function or were already in global namespace;
					// try to find the function in the global namespace
					if( !found) {
						String functionKey = callIdentifier.getNameChild().getEscapedCodeStr();
						addCallEdgeIfDefinitionKnown(cg, functionDefs, functionCall, functionKey, false);
					}
				}
			}
			//we don't know the function name
			else if( functionCall.getTargetFunc() != null ) {
				ParseVar parsevar = new ParseVar();
				parsevar.init(functionCall.getTargetFunc().getNodeId(), false, "");
				parsevar.handle();
				Set<String> funcValues = parsevar.getVar();
				for(String funName: funcValues) {
					addCallEdgeIfDefinitionKnown(cg, functionDefs, functionCall, funName, false);
					System.err.println("Call variable function: "+functionCall.getNodeId()+" "+funName);
				}
				parsevar.reset();
			}
			//System.err.println("Statically unknown function call at node id " + functionCall.getNodeId() + "!");
		};
	}
	
	// FIX (2026-08-08): confirmed as a real, observable PRODUCTION recall hole, not merely a
	// fixture-naming hazard -- the plain substring checks below match "test" inside ordinary
	// English words with no relation to test code: "latest", "attest", "contest", "protest".
	// Confirmed directly against real plugin source, not assumed: UpdraftPlus alone ships
	// get_latest_backup() and get_latest_full_backup() -- genuine, security-relevant application
	// functions (a backup plugin's own "find the most recent backup" logic) that this filter was
	// silently excluding from call-graph edge creation entirely.
	// The capitalized "Test" check is left as a plain substring match: a mid-string uppercase
	// letter already signals a genuine CamelCase word boundary in practice (getTestButton,
	// TestLogger), and no ordinary English word capitalizes "Test" mid-word by coincidence.
	// The problem is specific to the LOWERCASE "test" check, which the false-positive examples
	// above all go through. Fixed by requiring lowercase "test" not be immediately preceded by a
	// letter -- i.e. it must sit at the very start of the string or immediately after a
	// non-letter (most commonly an underscore: get_test_button, credentials_test_go), which
	// correctly accepts every genuine test-related name checked and rejects all four false-
	// positive words above. Deliberately conservative in the safe direction: an unusual
	// concatenated name like "unittest" (no separator) would no longer match and so would no
	// longer be excluded -- a minor loss of test-code exclusion precision, not a security
	// concern, traded against the real recall loss on genuine application code this was causing.
	private static boolean filterTest(String escapedCodeStr) {
		if( escapedCodeStr == null ) return false;
		if( escapedCodeStr.contains("Test") ) return true;
		int idx = escapedCodeStr.indexOf("test");
		while( idx >= 0 ) {
			boolean precededByLetter = idx > 0 && Character.isLetter(escapedCodeStr.charAt(idx - 1));
			if( !precededByLetter ) return true;
			idx = escapedCodeStr.indexOf("test", idx + 1);
		}
		return false;
	}

	private static void createConstructorCallEdges(CG cg) {
		int x3=constructorCalls.size();
		AtomicInteger c3 = new AtomicInteger(0);
		
		for( NewExpression constructorCall : constructorCalls) {
		//constructorCalls.parallelStream().forEach(constructorCall -> {
			c3.incrementAndGet();
			System.err.println(x3+" "+c3+" "+constructorCall.getNodeId());
			// make sure the call target is statically known
			
			String path = getDir(constructorCall.getNodeId());
			path=path+":"+constructorCall.getLocation().startLine;
			if(path2callee.containsKey(path)) {
				//one line may call multiple target functions
				//System.out.println("construct:" +path);
				for(Long target: path2callee.get(path)) {
					if(allConstructor.contains(target)) {
						call2mtd.add(constructorCall.getNodeId(), target);
					}
				}	
				continue;
			}
			
			if( constructorCall.getTargetClass() instanceof Identifier) {
				
				Identifier classIdentifier = (Identifier)constructorCall.getTargetClass();
				String constructorKey = classIdentifier.getNameChild().getEscapedCodeStr();
				String nameSpace = classIdentifier.getEnclosingNamespace();
				
				//we ignore test files
				if(filterTest(constructorKey) ||
						filterTest(constructorCall.getEnclosingClass()) ||
						filterTest(getDir(constructorCall.getNodeId()))) {
					continue;
				}
				
				// if class identifier is fully qualified,
				// just look for the constructor's definition right away
				if(constructorKey.equals("static")) {
					constructorKey = constructorCall.getEnclosingClass();
					Long prtId = getClassId(constructorKey, constructorCall.getNodeId(), nameSpace);
					Set<Long> clds = getAllChild(prtId);
					clds.add(prtId);
					for(Long cld: clds) {
						addCallEdgeIfDefinitionKnown(cg, constructorDefs, constructorCall, cld.toString(), false);
					}
				}
				else if (constructorKey.equals("parent")) {
					constructorKey = constructorCall.getEnclosingClass();
					Long ClassDefId = getClassId(constructorKey, constructorCall.getNodeId(), nameSpace);
					if(ch2prt.containsKey(ClassDefId)) {
						ClassDefId = ch2prt.get(ClassDefId).get(0);
						addCallEdgeIfDefinitionKnown(cg, constructorDefs, constructorCall, ClassDefId.toString(), false);
					}
				}
				else if (constructorKey.equals("self")) {
					constructorKey = constructorCall.getEnclosingClass();
					Long ClassDefId = getClassId(constructorKey, constructorCall.getNodeId(), nameSpace);
					addCallEdgeIfDefinitionKnown(cg, constructorDefs, constructorCall, ClassDefId.toString(), false);
				}
				else {
					// FIX (2026-08-08): plain `new Foo()` resolution passed "" (empty
					// namespace) instead of the already-extracted `nameSpace` variable, unlike
					// the sibling self/parent/static branches just above, which all correctly
					// use it. Confirmed observable: two classes sharing the same bare name in
					// different namespaces resolve the constructor to whichever the global,
					// namespace-blind lookup happens to prefer, not necessarily the one actually
					// in scope at the call site -- silently losing (or misattributing) the
					// constructor call edge for any bare-name class that collides across
					// namespaces. Fixed to pass the already-available nameSpace variable,
					// matching the pattern already used by every other branch in this method.
					Long classId = getClassId(constructorKey, constructorCall.getNodeId(), nameSpace);
					addCallEdgeIfDefinitionKnown(cg, constructorDefs, constructorCall, classId.toString(), false);
					//getMethodCall(cg, constructorCall, classId, "__destruct", false);
				}
			}
			else {
				// PHP 8 dynamic instantiation new (expr)() has no static target-class node;
				// skip the constructor-edge for it rather than NPE on a null target class.
				if(constructorCall.getTargetClass() == null) {
					continue;
				}
				ParseVar parsevar = new ParseVar();
				parsevar.init(constructorCall.getTargetClass().getNodeId(), false, "");
				parsevar.handle();
				Set<String> classValue = parsevar.getVar();
				if(1191711==constructorCall.getNodeId()) {
					System.out.println(1191711+" "+classValue);
				}
				for(String constructorKey: classValue) {
					addCallEdgeIfDefinitionKnown(cg, constructorNameDefs, constructorCall, constructorKey, false);
				}
				//addCallEdgeIfDefinitionKnown(cg, destructorDefs, constructorCall, constructorKey, false);
			}
		};
		constructorCalls.clear();
	}
	

	/** Bind a named-class static call INTO call2mtd, not just the CG graph.
	 *  getStaticCall()/addCallEdgeIfDefinitionKnown() only ever added CG edges, but the taint
	 *  analysis propagates interprocedurally via call2mtd -- so every `C::m(...)` call was invisible
	 *  to taint for EVERY shape. Tries the exact class first, then ancestors NEAREST-FIRST, stopping
	 *  at the first defining level so an override binds to the child rather than the ancestor.
	 *  Parents are computed via getParentClassId() because ch2prt is built by setInheritance(),
	 *  which runs AFTER createStaticMethodCallEdges() and is therefore still empty here. */
	private static boolean bindStaticCall2Mtd(Long classDefId, String methodname, CallExpressionBase staticCall) {
		if( classDefId == null || classDefId == -1L || methodname == null ) return false;
		java.util.Set<Long> seen = new HashSet<Long>();
		java.util.List<Long> level = new java.util.ArrayList<Long>();
		level.add(classDefId); seen.add(classDefId);
		int depth = 0;
		while( !level.isEmpty() && depth++ < 8 ) {
			boolean hit = false;
			for( Long cid : level ) {
				java.util.List<? extends FunctionDef> defs = staticMethodDefs.get(cid+"::"+methodname);
				if( defs == null || defs.isEmpty() ) continue;
				for( FunctionDef fd : defs ) {
					java.util.List<Long> ex = call2mtd.get(staticCall.getNodeId());
					if( ex == null || !ex.contains(fd.getNodeId()) ) {
						call2mtd.add(staticCall.getNodeId(), fd.getNodeId());
						hit = true;
					}
				}
			}
			if( hit ) return true;
			java.util.List<Long> next = new java.util.ArrayList<Long>();
			for( Long cid : level ) {
				java.util.Set<Long> prts = null;
				try { prts = getParentClassId(cid); } catch( Exception e ) {}
				if( (prts == null || prts.isEmpty()) && ch2prt.containsKey(cid) )
					prts = new HashSet<Long>(ch2prt.get(cid));
				if( prts == null ) continue;
				for( Long p : prts ) if( seen.add(p) ) next.add(p);
			}
			level = next;
		}
		return false;
	}

	private static void getStaticCall(Identifier classIdentifier, String methodname, CG cg, StaticCallExpression staticCall) {
		if( classIdentifier.getFlags().contains( PHPCSVNodeTypes.FLAG_NAME_FQ)) {
			Long classId = getClassId(classIdentifier.getNameChild().getEscapedCodeStr(), staticCall.getNodeId(), "");
			String staticMethodKey = classId + "::" + methodname;
			if(methodname.equals("__construct")) {
				staticMethodKey=classId.toString();
				addCallEdgeIfDefinitionKnown(cg, constructorDefs, staticCall, staticMethodKey, false);
			}
			else {
				addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, staticMethodKey, false);
				bindStaticCall2Mtd(classId, methodname, staticCall);
			}
		}
		//parent::method
		else if(classIdentifier.getNameChild().getEscapedCodeStr().equals("parent")) {
			String className = staticCall.getEnclosingClass();
			String nameSpace = classIdentifier.getEnclosingNamespace();
			//get self::class nodeId
		    Long ClassDefId = getClassId(className,  staticCall.getNodeId(), nameSpace);
		    if(ClassDefId != -1 && ch2prt.containsKey(ClassDefId)) {
		    	List<Long> prtIds = ch2prt.get(ClassDefId);
		    	for(Long prtId: prtIds) {
		    		String staticMethodKey = prtId+"::"+methodname;
		    		if(methodname.equals("__construct")) {
						staticMethodKey=prtId.toString();
						addCallEdgeIfDefinitionKnown(cg, constructorDefs, staticCall, staticMethodKey, false);
					}
					else {
						addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, staticMethodKey, false);
						bindStaticCall2Mtd(prtId, methodname, staticCall);
					}
		    	}
		    }
		}
		//static call
		else if(classIdentifier.getNameChild().getEscapedCodeStr().equals("static")) {
			String className = staticCall.getEnclosingClass();
			String nameSpace = classIdentifier.getEnclosingNamespace();
			Long prtId = getClassId(className, staticCall.getNodeId(), nameSpace);
			Set<Long> clds = getAllChild(prtId);
			clds.add(prtId);
			for(Long cld: clds) {
				String staticMethodKey = cld+"::"+methodname;
				if(methodname.equals("__construct")) {
					staticMethodKey=cld.toString();
					addCallEdgeIfDefinitionKnown(cg, constructorDefs, staticCall, staticMethodKey, false);
				}
				else {
					addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, staticMethodKey, false);
				}
			}
		}
		//self::method and className::method
		else {
				String className = classIdentifier.getNameChild().getEscapedCodeStr();
				String nameSpace = classIdentifier.getEnclosingNamespace();
				if (classIdentifier.getNameChild().getEscapedCodeStr().equals("self")) {
			    	className = staticCall.getEnclosingClass();
			    }
				Long ClassDefId = getClassId(className, staticCall.getNodeId(), nameSpace);
				//we expect to get class of statically defined class
				if(ClassDefId==-1) {
					return;
				}
				String staticMethodKey = ClassDefId+"::"+methodname;
				if(methodname.equals("__construct")) {
					staticMethodKey=ClassDefId.toString();
					addCallEdgeIfDefinitionKnown(cg, constructorDefs, staticCall, staticMethodKey, false);
				}
				else {
					addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, staticMethodKey, false);
					bindStaticCall2Mtd(ClassDefId, methodname, staticCall);
				}
		}
	}
	
	private static void createStaticMethodCallEdges(CG cg) {
		int x2 = staticMethodCalls.size();
		AtomicInteger c2 = new AtomicInteger(0);
		for( StaticCallExpression staticCall : staticMethodCalls) {
		//staticMethodCalls.parallelStream().forEach(staticCall -> {
			c2.incrementAndGet();
			System.err.println(x2+" "+c2+" "+staticCall.getNodeId());
			
			String path = getDir(staticCall.getNodeId());
			path=path+":"+staticCall.getLocation().startLine;
			if(path2callee.containsKey(path)) {
				for(Long target: path2callee.get(path)) {
					if(allStaticMtd.contains(target) || allConstructor.contains(target)) {
						ASTNode targetFunc = ASTUnderConstruction.idToNode.get(target);
						if( staticCall.getTargetFunc() instanceof StringExpression) {
							StringExpression methodName = (StringExpression)staticCall.getTargetFunc();
							String methodKey = methodName.getEscapedCodeStr();
							//the target function has incorrect method name
							if(!methodKey.equals(targetFunc.getEscapedCodeStr())) {
								continue;
							}
						}
						call2mtd.add(staticCall.getNodeId(), target);
					}
					//only parent, self, static call calls non-static method
					else if( staticCall.getTargetClass() instanceof Identifier) {
						Identifier classIdentifier = (Identifier)staticCall.getTargetClass();
						if(classIdentifier.getNameChild().getEscapedCodeStr().equals("parent") ||
								classIdentifier.getNameChild().getEscapedCodeStr().equals("self") ||
								classIdentifier.getNameChild().getEscapedCodeStr().equals("static")) {
							ASTNode targetFunc = ASTUnderConstruction.idToNode.get(target);
							if( staticCall.getTargetFunc() instanceof StringExpression) {
								StringExpression methodName = (StringExpression)staticCall.getTargetFunc();
								String methodKey = methodName.getEscapedCodeStr();
								//the target function has incorrect method name
								if(!methodKey.equals(targetFunc.getEscapedCodeStr())) {
									continue;
								}
							}
							call2mtd.add(staticCall.getNodeId(), target);
						}
					}
							
				}	
				continue;
			}
			
			// make sure the call target is statically known
			if( staticCall.getTargetClass() instanceof Identifier
					&& staticCall.getTargetFunc() instanceof StringExpression) {
				
				Identifier classIdentifier = (Identifier)staticCall.getTargetClass();
				StringExpression methodName = (StringExpression)staticCall.getTargetFunc();
				
				if(filterTest(classIdentifier.getNameChild().getEscapedCodeStr()) ||
						filterTest(staticCall.getEnclosingClass()) ||
						filterTest(getDir(staticCall.getNodeId()))){
					continue;
				}
				
				getStaticCall(classIdentifier, methodName.getEscapedCodeStr(), cg, staticCall);
			}
			//class name is a variable or method name is a variable
			else{
				//method name is a string and class name is a variable
				if(staticCall.getTargetFunc() instanceof StringExpression) {
					// FIX (2026-08-08): to resolve $cls::method(), ParseVar must run on the CLASS
					// expression ($cls, staticCall.getTargetClass()), not the method name -- the
					// method name here is already confirmed a StringExpression (a literal), and
					// running ParseVar on a string literal just returns that same string, so
					// classId below silently became "methodname" instead of any of $cls's
					// possible values. Every variable-class static call (Class::method() where
					// Class is a variable) was therefore unresolved via this path.
					ParseVar parsevar = new ParseVar();
					parsevar.init(staticCall.getTargetClass().getNodeId(), false, "");
					parsevar.handle();
					for(String classId: parsevar.getVar()) {
						// FIX (2026-08-08): staticMethodDefs is keyed by NUMERIC class id
						// ("classId::methodName", matching getStaticCall()'s own pattern), not by
						// class name string -- confirmed by reading staticMethodDefs' population
						// code before assuming. The resolved class NAME from ParseVar must be
						// converted via getClassId() first; without this second conversion, the
						// ParseVar fix above resolves the correct name but the lookup key still
						// never matches anything, so variable-class static calls remained
						// unresolved even after fixing which node ParseVar runs on. Caught by
						// direct instrumentation (resolvedClasses=[MyClass], but
						// staticMethodDefsHasKey=false for "MyClass::method") rather than assumed
						// fixed once the first part compiled.
						Long resolvedClassId = getClassId(classId, staticCall.getNodeId(), "");
						if( resolvedClassId == null || resolvedClassId == -1L ) continue;
						String methodKey = resolvedClassId+"::"+staticCall.getTargetFunc().getEscapedCodeStr();
						addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, methodKey, false);
					}
					parsevar.reset();
				}
				//method name is a variable
				else{
					Set<String> methodnames = getMethodName(staticCall);
					//class name is a string
					if(staticCall.getTargetClass() instanceof Identifier) {
						Identifier classIdentifier = (Identifier)staticCall.getTargetClass();
						for(String methodname: methodnames) {
							getStaticCall(classIdentifier, methodname, cg, staticCall);
						}
					}
					//method name is also a variable
					else{
						// FIX (2026-08-08): same two bugs as the branch above -- ParseVar must run
						// on the CLASS expression (staticCall.getTargetClass()), not the method-name
						// variable a second time (getMethodName() above already resolves the
						// method-name side separately); and the resolved class NAME must be
						// converted to staticMethodDefs' numeric-classId key format via
						// getClassId() before building the lookup key.
						ParseVar parsevar = new ParseVar();
						parsevar.init(staticCall.getTargetClass().getNodeId(), false, "");
						parsevar.handle();
						for(String classId: parsevar.getVar()) {
							Long resolvedClassId = getClassId(classId, staticCall.getNodeId(), "");
							if( resolvedClassId == null || resolvedClassId == -1L ) continue;
							for(String methodname: methodnames) {
								String methodKey = resolvedClassId+"::"+methodname;
								addCallEdgeIfDefinitionKnown(cg, staticMethodDefs, staticCall, methodKey, false);
							}
						}
						parsevar.reset();
					}
				}
			}
		};
	}
	
	//given the method name, we get the target method
	private static void withMethodKey(CG cg, MethodCallExpression callsite, String methodkey) {
		//the object is a variable
		// FIX (2026-08-08): checked callsite.getTargetFunc() -- the METHOD NAME slot --
		// instead of callsite.getTargetObject() -- the RECEIVER slot -- for the
		// PropertyExpression/StaticPropertyExpression cases, despite the comment and the
		// getTargetObject()-based handling immediately below both making clear the intent is "the
		// RECEIVER is some kind of variable-like expression". This was stronger than a simple
		// wrong-getter mismatch: whenever the METHOD NAME happened to be dynamic
		// ($obj->$m(), Foo::$m()) even while the RECEIVER was actually a `new Foo()->method()` or
		// a chained `foo()->method()` call, this branch's condition was already satisfied via the
		// getTargetFunc() checks, so the `else if` branches for NewExpression/CallExpressionBase
		// receivers below became unreachable dead code for those call shapes -- not just an
		// occasional false miss, but a structural branch-ordering bug. Fixed by checking
		// getTargetObject() instead, matching the receiver-classification intent the rest of the
		// method already follows.
		if(callsite.getTargetObject() instanceof Variable
				|| callsite.getTargetObject() instanceof PropertyExpression
				|| callsite.getTargetObject() instanceof StaticPropertyExpression){
			Expression classVar = callsite.getTargetObject();
			long varId = classVar.getNodeId();
			ParseVar parsevar = new ParseVar();
			parsevar.init(varId, true, "");
			parsevar.handle();
			Set<String> classValues = parsevar.getVar();
			
			for(String classValue: classValues) {
				try {
					Long ClassDefId = Long.parseLong(classValue);
					String methodKey = ClassDefId+"::"+methodkey;
					addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, callsite, methodKey, false);
				}
				catch( Exception e ) {
			        //System.err.println("!"+callsite.getNodeId());
				}
				
			}
			parsevar.reset();
		}
		//new class->method
		else if(callsite.getTargetObject() instanceof NewExpression) {
			NewExpression classNew = (NewExpression) callsite.getTargetObject();
			if(classNew.getTargetClass() instanceof Identifier) {
				Identifier classNode = (Identifier) classNew.getTargetClass();
				String className = classNode.getNameChild().getEscapedCodeStr();
				String namespace = classNode.getEnclosingNamespace();
				Long ClassDefId = getClassId(className, callsite.getNodeId(), namespace);
				String methodKey = ClassDefId+"::"+methodkey;
				addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, callsite, methodKey, false);
			}
		}
		//the object is returned from a function
		else if(callsite.getTargetObject() instanceof CallExpressionBase) {
			objCaller.add(callsite.getNodeId());
		}
		//We don't parse variables with strange representation 
		else { 
			System.err.println("Unsopported method call: "+callsite.getNodeId());
			//System.err.println("Unknown methoddCall type at node id "+methodCall.getNodeId());
		}
	}
	
	private static void createNonStaticMethodCallEdges(CG cg) {
		int x4=nonStaticMethodCalls.size(), x5=0;
		AtomicInteger c4 = new AtomicInteger(0);
		for(MethodCallExpression methodCall: nonStaticMethodCalls) {
		//nonStaticMethodCalls.parallelStream().forEach(methodCall -> {
			c4.getAndIncrement();
			System.err.println(x4+" "+c4+" "+methodCall.getNodeId());

			// WORDPRESS SINK DETECTION: WordPress plugins issue SQL through the $wpdb
			// abstraction (e.g. $wpdb->get_var(...)), not raw mysql_query(). Stock
			// TChecker only treats bare function calls as sinks and is therefore blind
			// to these. Here (where getTargetFunc/getTargetObject are populated) we mark
			// $wpdb-> query methods as SQLi sinks, matching the method name and requiring
			// the receiver variable to be named "wpdb" to limit false positives.
			if( methodCall.getTargetFunc() instanceof StringExpression) {
				String wpMethod = ((StringExpression) methodCall.getTargetFunc()).getEscapedCodeStr();
				if( wpMethod.equals("query") || wpMethod.equals("get_results") ||
					wpMethod.equals("get_var") || wpMethod.equals("get_col") ||
					wpMethod.equals("get_row") ) {
					if( receiverIsWpdb(methodCall.getTargetObject()) ) {
						if( sqlSinkProvablySafe(methodCall) ) {
							System.err.println("WPSAFE suppressed provably-safe $wpdb sink "+methodCall.getNodeId());
						} else {
							sinks.add(methodCall.getNodeId());
						}
					}
				}
				// WORDPRESS SANITIZER: $wpdb->prepare(...) parameterizes the query (its
				// %s/%d placeholders bind values safely), so it neutralizes SQLi taint.
				// It is the dominant real-world WordPress SQL sanitizer. Like the sinks
				// above it is a method call, so we recognize it here and register it in
				// the SQL sanitizer set the taint analysis consumes.
				if( wpMethod.equals("prepare") ) {
					if( receiverIsWpdb(methodCall.getTargetObject()) ) {
						// prepare parameterizes its %s/%d ARGUMENTS, but a value interpolated into the
						// FORMAT string itself (arg 0) is NOT protected — the column/table-name injection
						// pattern, e.g. $wpdb->prepare("SELECT $col FROM t"), missed reviewx CVE-2023-26325.
						// Only treat prepare as a sanitizer when arg 0 carries no attacker-controllable
						// interpolation. Reuse the safe-argument suppressor's logic: a provably-safe format
						// leaves at most {wpdb,this} in the collected var set (table-name props / literals /
						// sanitizer-wrapped casts); any other name (a request var, a plain local) means the
						// format is injectable, so leave prepare UNREGISTERED and let the taint reach the sink.
						boolean fmtSafe = true;
						ArgumentList pargs = methodCall.getArgumentList();
						if( pargs != null && pargs.size() >= 1 ) {
							Set<String> vn = new HashSet<String>();
							collectUnsanitizedVarNames(pargs.getArgument(0), vn);
							vn.remove("wpdb"); vn.remove("this");
							if( !vn.isEmpty() ) {
								// drop placeholder-string locals (the array_fill('%d') IN-clause idiom): they are
								// parameterization templates, not attacker data, and were the dominant false positive.
								Set<String> ph = new HashSet<String>();
								collectPlaceholderVars(enclosingFunctionId(methodCall.getNodeId()), ph);
								vn.removeAll(ph);
							}
							if( !vn.isEmpty() ) fmtSafe = false;
						}
						if( fmtSafe ) {
							PHPCSVEdgeInterpreter.sqlSanitizers.add(methodCall.getNodeId());
						} else {
							// The format string carries attacker-controllable interpolation, so the query
							// identifier/clause is injectable and prepare cannot protect it (the format string
							// IS the query). Treat the prepare call itself as the SQLi sink, reusing the normal
							// sink machinery — which only fires when a taint SOURCE actually reaches arg 0, so a
							// merely non-wpdb but untainted local in the format produces no false positive.
							sinks.add(methodCall.getNodeId());
						}
					}
				}
			}

			String path = getDir(methodCall.getNodeId());
			path=path+":"+methodCall.getLocation().startLine;
			if(path2callee.containsKey(path)) {
				//one line may call multiple target functions
				x5++;
				for(Long target: path2callee.get(path)) {
					if(allStaticMtd.contains(target) || allMtd.contains(target) || allConstructor.contains(target)) {
						ASTNode targetFunc = ASTUnderConstruction.idToNode.get(target);
						if( methodCall.getTargetFunc() instanceof StringExpression) {
							StringExpression methodName = (StringExpression)methodCall.getTargetFunc();
							String methodKey = methodName.getEscapedCodeStr();
							//the target function has incorrect method name
							if(!methodKey.equals(targetFunc.getEscapedCodeStr())) {
								continue;
							}
						}
						call2mtd.add(methodCall.getNodeId(), target);
					}
				}	
				continue;
			}
			
			if(filterTest(methodCall.getEnclosingClass()) ||
					filterTest(getDir(methodCall.getNodeId()))) {
				continue;
			}
			
			//method name is a string
			if( methodCall.getTargetFunc() instanceof StringExpression) {
				StringExpression methodName = (StringExpression)methodCall.getTargetFunc();
				String methodKey = methodName.getEscapedCodeStr();
				// let's count the dynamic methods
				if( nonStaticMethodNameDefs.containsKey(methodKey)) {
					// check whether there is only one matching function definition
					if( nonStaticMethodNameDefs.get(methodKey).size() == 1) {
						lock.lock();
				        try {
				        	addCallEdge(cg, methodCall, nonStaticMethodNameDefs.get(methodKey).get(0), true);
				        } finally {
				            lock.unlock();
				        }
					}
					else {
						//override methods
						List<Method> allMatch = nonStaticMethodNameDefs.get(methodKey);
						Method first = allMatch.get(0);
						Long firstClass = getClassId(first.getEnclosingClass(), first.getNodeId(), first.getEnclosingNamespace());
						boolean flag = true;
						for(Method candidate: allMatch) {
							Long crtClass = getClassId(candidate.getEnclosingClass(), candidate.getNodeId(), candidate.getEnclosingNamespace());
							//they are methods from different classes 
							if(!(getAllChild(firstClass).contains(crtClass) 
									|| getAllChild(crtClass).contains(firstClass))) {
								flag = false;
								break;
							}
						}
						//they are override methods
						if(flag==true) {
							for(Method candidate: allMatch) {
								lock.lock();
						        try {
						        	addCallEdge(cg, methodCall, candidate, true);
						        } finally {
						            lock.unlock();
						        }
							}
							continue;
						}
						
						//$this->method()
						if( methodCall.getTargetObject() instanceof Variable
							&& ((Variable)methodCall.getTargetObject()).getNameExpression() instanceof StringExpression
							&& ((StringExpression)((Variable)methodCall.getTargetObject()).getNameExpression()).getEscapedCodeStr().equals("this")) {
							
							String enclosingClass = methodCall.getEnclosingClass();
							String nameSpace = methodCall.getEnclosingNamespace();
							Long ClassDefId = getClassId(enclosingClass, methodCall.getNodeId(), nameSpace);
							
							String methodkey = ClassDefId+"::"+methodKey;
							addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, methodCall, methodkey, false);
						}
						//$var->method()
						else {
							withMethodKey(cg, methodCall, methodKey);
						}
					}
					
				}
			}
			
			//$var->$name
			else {
				Set<Long> ClassDefId = new HashSet<Long>();
				Set<String> methodname = new HashSet<String>();
				//Set<Long> classId = new HashSet<Long>();
				
				//we first get class name(if we can get it)
				if( methodCall.getTargetObject() instanceof Variable
						&& ((Variable)methodCall.getTargetObject()).getNameExpression() instanceof StringExpression
						&& ((StringExpression)((Variable)methodCall.getTargetObject()).getNameExpression()).getEscapedCodeStr().equals("this")) {
					String enclosingClass = methodCall.getEnclosingClass();
					String nameSpace = methodCall.getEnclosingNamespace();
					ClassDefId.add(getClassId(enclosingClass, methodCall.getNodeId(), nameSpace));
				}
				else if(methodCall.getTargetObject() instanceof NewExpression && 
						((NewExpression) methodCall.getTargetObject()).getTargetClass() instanceof Identifier) {
					NewExpression classNew = (NewExpression) methodCall.getTargetObject();
					Identifier classNode = (Identifier) classNew.getTargetClass();
					String className = classNode.getNameChild().getEscapedCodeStr();
					String namespace = classNode.getEnclosingNamespace();
					ClassDefId.add(getClassId(className, methodCall.getNodeId(), namespace));
				}
				else if(methodCall.getTargetObject() instanceof Variable ||
						methodCall.getTargetObject() instanceof PropertyExpression ||
						methodCall.getTargetObject() instanceof StaticPropertyExpression){
					ASTNode classVar = methodCall.getTargetObject();
					ParseVar parsevar = new ParseVar();
					parsevar.init(classVar.getNodeId(), true, "");
					parsevar.handle();
					Set<String> classValue = parsevar.getVar();
					//System.err.println(classValue);
					for(String classvalue: classValue) {
						try {
							ClassDefId.add(Long.parseLong(classvalue));
						}catch(NumberFormatException e) {
							
						}
					}
					parsevar.reset();
				}
				else {
					ClassDefId.add((long) -1);
				}
				
				methodname = getMethodName(methodCall);
				
				for(Long clsDefId: ClassDefId) {
					for(String mtdname: methodname) {
						String methodKey = clsDefId+"::"+mtdname;
						addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, methodCall, methodKey, false);
					}
				}
				
				//System.err.println("Statically unknown non-static method call at node id " + methodCall.getNodeId());
			}
			
		};
		
		System.out.println("x5: "+x5);
		
		Collections.sort(objCaller);
		Collections.reverse(objCaller);
		for(Long callsiteID: objCaller) {
			MethodCallExpression callsite = (MethodCallExpression) ASTUnderConstruction.idToNode.get(callsiteID);
			//obj variable
			Long caller = callsite.getTargetObject().getNodeId();
			//methodname
			StringExpression methodName = (StringExpression) (callsite.getTargetFunc());
			String methodKey = methodName.getEscapedCodeStr();
			
			lock.lock();
	        try {
	        	if(call2mtd.containsKey(caller)) {
	        		Set<Long> targetFuncs = new HashSet<Long>(call2mtd.get(caller));
	        		for(Long fun: targetFuncs) {
	        			if(retCls.containsKey(fun)) {
	        				Long classId = retCls.get(fun);
	        				Set<Long> allChild = PHPCGFactory.getAllChild(classId);
	    					allChild.add(classId);
	    					for(Long clsId: allChild) {
	    						// FIX (2026-08-08): was reassigning the outer methodKey itself inside this
	    						// loop ("methodKey = clsId+::+methodKey"), so each iteration's result
	    						// compounded onto the previous one -- iteration 1 produces "A::foo"
	    						// (correct), iteration 2 produces "B::A::foo" (wrong, matches no real
	    						// definition), iteration 3 "C::B::A::foo", etc. Only the first class in
	    						// allChild (whichever happened to be first in HashSet iteration order) ever
	    						// got a valid lookup key; every other subclass resolution silently failed,
	    						// losing call-graph edges to overridden methods. Fixed by keeping the bare
	    						// method name in methodKey and building each iteration's key separately.
	    						String candidateKey = clsId+"::"+methodKey;
		        				addCallEdgeIfDefinitionKnown(cg, nonStaticMethodDefs, callsite, candidateKey, false);
	    					}
	        			}
	        		}
	        	}
	        } finally {
	            lock.unlock();
	        }
		}
	}
	
	private static Set<String> getMethodName(CallExpressionBase callsite){
		Set<String> ret = new HashSet<String>();
		//we try to get method name
		if(callsite.getTargetFunc() instanceof BinaryOperationExpression) {
			BinaryOperationExpression methodNameNode = (BinaryOperationExpression) callsite.getTargetFunc();
			ParseVar parsevar = new ParseVar();
			parsevar.init(1, false, "");
			LinkedList<String> methodNameStrs = parsevar.ParseExp(methodNameNode);
			for(String methodNameStr: methodNameStrs) {
				methodNameStr = methodNameStr.replaceAll("\\$[0-9]+\\$", "*");
				ret.add(methodNameStr);
			}
			parsevar.reset();
		}
		else {
			ParseVar parsevar = new ParseVar();
			parsevar.init(callsite.getTargetFunc().getNodeId(), false, "");
			parsevar.handle();
			Set<String> methodNameStrs = parsevar.getVar();
			for(String methodNameStr: methodNameStrs) {
				ret.add(methodNameStr);
			}
			parsevar.reset();
		}
		return ret;
	}
	
	/**
	 * Checks whether a given function key is known and if yes,
	 * adds a corresponding edge in the given call graph.
	 * 
	 * @return true if an edge was added, false otherwise
	 */
	private static boolean addCallEdgeIfDefinitionKnown(CG cg, MultiHashMap<String,? extends FunctionDef> defSet, CallExpressionBase functionCall, String functionKey, boolean prt2cld) {
		
		//We cannot get the full name of function call
		if(functionKey.contains("-1::") || functionKey.contains("*")) {
			//suspicious.add(functionCall.getNodeId());
			functionKey = functionKey.replace("*", "");
			//we get nothing from the method/function call
			if(functionKey.equals("-1::") || functionKey.equals("")) {
				//suspicious.add(functionCall.getNodeId());
				return true;
			}
			
			functionKey = functionKey.replace("-1::", "::");
			String functionName = functionKey;
			
			int thre = 0;
			//defSet.keySet().parallelStream().forEach(funcKey ->{
			for(String funcKey: defSet.keySet()) {
				
				//candidate
				if(funcKey.contains(functionName) && !funcKey.equals(functionName)) {
					for(FunctionDef func: defSet.get(funcKey)){
						addCallEdge(cg, functionCall, func, prt2cld);
						thre++;
					}
				}
			}
		}
		//the target function is a method and we get the full name of the method
		else if(functionKey.indexOf("::")>0) {
			String classValue = functionKey.substring(0, functionKey.indexOf("::"));
			//we parse correct class Id
			try {
				Long classId = Long.parseLong(classValue);
				while(true) {
					//we get the target function
					if(defSet.keySet().contains(functionKey)) {
						for(FunctionDef func: defSet.get(functionKey)) {
							addCallEdge(cg, functionCall, func, prt2cld);
						}
						return true;
					}
					//we find the target function via parent class
					if(ch2prt.containsKey(classId)) {
						Long parentId = ch2prt.get(classId).get(0);
						functionKey = functionKey.replace(classId+"::", parentId+"::");
						classId = parentId;
					}
					else {
						return false;
					}
				}
			} catch(Exception e) {
				
			}
		}
		//the target function is a constructor 
		else if(functionCall instanceof NewExpression) {
			//we do not know the constructor name
			if(functionKey.equals("-1")) {
				return true;
			}
			try {
				Long classId = Long.parseLong(functionKey);
				while(true) {
					//we get the target function
					if(defSet.keySet().contains(functionKey)) {
						for(FunctionDef func: defSet.get(functionKey)) {
							addCallEdge(cg, functionCall, func, prt2cld);
						}
						return true;
					}
					//we find the target function via parent class
					if(ch2prt.containsKey(classId)) {
						Long parentId = ch2prt.get(classId).get(0);
						functionKey = parentId.toString();
						classId = parentId;
					}
					else {
						return false;
					}
				}
			} catch(Exception e) {
				
			}
		}
		//the target function is a function and we get the full name of the function
		else if(defSet.keySet().contains(functionKey)) {
			for(FunctionDef func: defSet.get(functionKey)) {
				addCallEdge(cg, functionCall, func, prt2cld);
			}
			return true;
		}
		
		return false;
	}
	
	/**
	 * Adds an edge to a given call graph.
	 * 
	 * @return true if an edge was added, false otherwise
	 */
	private static boolean addCallEdge(CG cg, CallExpressionBase functionCall, FunctionDef functionDef, boolean prt2cld) {
		
		//third-party code cannot call first-party code
		if(getDir(functionCall.getNodeId()).contains("vendor")
				&& !getDir(functionDef.getNodeId()).contains("vendor")) {
			return false;
		}
		
		if(filterTest(functionDef.getName()) ||
				filterTest(functionDef.getEnclosingClass()) ||
				filterTest(getDir(functionDef.getNodeId()))) {
			return false;
		}
		
		Long funid = functionCall.getFuncId();
		while(ASTUnderConstruction.idToNode.get(funid) instanceof Closure) {
			funid = ASTUnderConstruction.idToNode.get(funid).getFuncId();
		}
		
		//call site arguments number must bigger than function definition parameter's number
		int callArgSize = functionCall.getArgumentList().size();
		//System.err.println(functionCall);
		int functionDefSize = functionDef.getParameterList().size();
		
		if(callArgSize>functionDefSize 
				&&!func_get_args.contains(functionDef.getNodeId())
				&&!call_user.contains(functionCall.getNodeId())) {
			return false;
		}
		
		
		if(functionDef instanceof Method && 
				(functionDef.getFlags().contains("MODIFIER_PRIVATE") ||  
						functionDef.getFlags().contains("MODIFIER_PROTECTED"))) {
			String callsiteClassName = functionCall.getEnclosingClass();
			String callsiteNamespace = functionCall.getEnclosingNamespace();
			Long callsiteClassId = getClassId(callsiteClassName, functionCall.getNodeId(), callsiteNamespace);
			
			String mtdDefClassName = ((Method) functionDef).getEnclosingClass();
			String mtdDefNamespace = functionDef.getEnclosingNamespace();
			Long mtdClsId =  getClassId(mtdDefClassName, functionDef.getNodeId(), mtdDefNamespace);
			Set<Long> cldIds = getAllChild(mtdClsId);
			cldIds.add(mtdClsId);
			
			//call a public/private method from a function
			if(callsiteClassId==null) {
				return false;
			}
			//only the methods in the same class could call this method
			else if(functionDef.getFlags().contains("MODIFIER_PRIVATE")) {
				if(!callsiteClassId.equals(mtdClsId)) {
					return false;
				}
			}
			else if(functionDef.getFlags().contains("MODIFIER_PROTECTED")) {
				if(!cldIds.contains(callsiteClassId)) {
					return false;
				}
			}
		}
		
		if(functionCall instanceof StaticCallExpression 
				&& ((StaticCallExpression)functionCall).getTargetClass() instanceof Identifier ) {
			Identifier classname = (Identifier) ((StaticCallExpression)functionCall).getTargetClass();
			if(!classname.getNameChild().getEscapedCodeStr().equals("parent") 
					&& !classname.getNameChild().getEscapedCodeStr().equals("self")
					&& !classname.getNameChild().getEscapedCodeStr().equals("static")) {
				if(!(functionDef instanceof Method && functionDef.getFlags().contains("MODIFIER_STATIC"))){
					return false;
				}
			}
		}
		
		lock.lock();
		try {
			//CGNode caller = new CGNode(functionCall);
			//CGNode callee = new CGNode(functionDef);
			//the caller cannot call it self
			if(functionCall.getFuncId().equals(functionDef.getNodeId())) {
				return true;
			}
			if(!(call2mtd.containsKey(functionCall.getNodeId()) && call2mtd.get(functionCall.getNodeId()).contains(functionDef.getNodeId()))) {
				call2mtd.add(functionCall.getNodeId(), functionDef.getNodeId());
				//file2file.add(toTopLevelFile.getTopLevelId(functionCall.getNodeId()), toTopLevelFile.getTopLevelId(functionDef.getNodeId()));
			}
        } finally {
            lock.unlock();
        }
		
		return true;
	}
	
	private static void reset(CG cg) {
	
		MultiHashMap<Long, Long> save = new MultiHashMap<Long, Long>();
		int i1=-1, i2=-1;
		for(Long caller: call2mtd.keySet()) {
			i1=Math.max(i1, call2mtd.get(caller).size());
			ASTNode callerNode = ASTUnderConstruction.idToNode.get(caller);
			Long callerFileId = toTopLevelFile.getTopLevelId(callerNode.getNodeId());
			String callerFile = ASTUnderConstruction.idToNode.get(callerFileId).getEscapedCodeStr();
			List<Long> callees = call2mtd.get(caller);
			if(callees.size()<2) {
				save.addAll(caller, callees);
				continue;
			}
			//System.err.println("caller: "+caller);
			MultiHashMap<Integer, Long> tmp = new MultiHashMap<Integer, Long>();
			for(Long callee: callees) {
				ASTNode calleeNode = ASTUnderConstruction.idToNode.get(callee);
				Long calleeFileId = toTopLevelFile.getTopLevelId(calleeNode.getNodeId());
				String calleeFile = ASTUnderConstruction.idToNode.get(calleeFileId).getEscapedCodeStr();
				int com = getCommon(callerFile, calleeFile);
				tmp.add(com, callee);
			}
			Set<Integer> keys =tmp.keySet();
			List<Integer> lKeys = new ArrayList<Integer>(keys);
			// FIX (2026-08-08): reverse() was applied directly to keySet()'s insertion into an
			// ArrayList, which carries HashMap's unspecified bucket iteration order, not a sorted
			// one -- so this pruning step (keep only the top-5 callees with the HIGHEST "com"
			// common-path-prefix score per caller) was never guaranteed to actually keep the
			// highest-scoring candidates. Small, dense non-negative Integer keys often happen to
			// hash-bucket in ascending numeric order in practice, which likely masked this most
			// of the time -- but that's a coincidence of HashMap's internals, not a guarantee,
			// and doesn't hold for negative or sparse "com" values. Added the missing sort so
			// reverse() has a well-defined, deterministic ascending order to invert.
			Collections.sort(lKeys);
			Collections.reverse(lKeys);
			for(int i=0; i<lKeys.size()&&i<5; i++) {
				Integer close = lKeys.get(i);
				List<Long> target = tmp.get(close);
				//System.err.println("Close: "+close+" "+caller+target);
				save.addAll(caller, target);
			}
		}
		
		call2mtd=save;	
		//System.out.println("reset: "+call2mtd);
		
		for(Long caller: call2mtd.keySet()) {
			i2=Math.max(i2, call2mtd.get(caller).size());
			Long callFunc = ASTUnderConstruction.idToNode.get(caller).getFuncId();
			for(Long mtd: call2mtd.get(caller)) {
				CGNode callerNode = null;
				if(ASTUnderConstruction.idToNode.get(caller) instanceof CallExpressionBase) {
					callerNode = new CGNode((CallExpressionBase) ASTUnderConstruction.idToNode.get(caller));
				}
				else if(ASTUnderConstruction.idToNode.get(caller) instanceof IncludeOrEvalExpression) {
					callerNode = new CGNode((IncludeOrEvalExpression) ASTUnderConstruction.idToNode.get(caller));
				}
				CGNode calleeNode = new CGNode((FunctionDef) ASTUnderConstruction.idToNode.get(mtd));
				mtd2call.add(mtd, caller);
				mtd2mtd.add(callFunc, mtd);
				callee2caller.add(mtd, caller);
				cg.addVertex(callerNode);
				cg.addVertex(calleeNode);
				cg.addEdge(new CGEdge(callerNode, calleeNode));
			}
		}
		
		System.err.println("Maximum: "+i1+" "+i2);
		
		functionDefs.clear();
		functionCalls.clear();
		
		staticMethodDefs.clear();
		staticMethodCalls.clear();
		
		//constructorDefs.clear();
		// constructorCalls is cleared in createConstructorCallEdges after use
		
		nonStaticMethodDefs.clear();
		nonStaticMethodNameDefs.clear();
		nonStaticMethodCalls.clear();

	}
	
	private static int getCommon(String callerFile, String calleeFile) {
		int ret=0;
		int min=Math.min(callerFile.length(), calleeFile.length());
		for(ret=0; ret<min; ret++) {
			if(callerFile.charAt(ret)!=calleeFile.charAt(ret)) {
				break;
			}
		}
		return ret;
	}

	/**
	 * Adds a new known function definition.
	 * 
	 * @param functionDef A PHP function definition. If a function definition with the same
	 *                    name was previously added, then the new function definition will
	 *                    be used for that name and the old function definition will be returned.
	 * @return If there already exists a PHP function definition with the same name,
	 *         then returns that function definition. Otherwise, returns null. For non-static method
	 *         definitions, always returns null.
	 */
	public static FunctionDef addFunctionDef( FunctionDef functionDef) {
		
		
		allFuncDef.add(functionDef.getNodeId());
		// artificial toplevel functions wrapping toplevel code cannot be called
		if( functionDef instanceof TopLevelFunctionDef) {
			topFunIds.add(functionDef.getNodeId());
			reasonTopLevelFileScope.add(functionDef.getNodeId());
			String path = getDir(functionDef.getNodeId());
			topLevelFunctionDefs.put(path, functionDef.getNodeId());
			return null;
		}
			
		// we also ignore closures as they do not have a statically known reference
		else if( functionDef instanceof Closure)
			return null;
		
		// finally, abstract methods cannot be called either
		else if( functionDef instanceof Method
				&& functionDef.getFlags().contains(PHPCSVNodeTypes.FLAG_MODIFIER_ABSTRACT)) {
			Abstract.add(functionDef.getNodeId());
			return null;
		}
		
		
		// it's a static method
		else if( functionDef instanceof Method
				&& functionDef.getFlags().contains(PHPCSVNodeTypes.FLAG_MODIFIER_STATIC)) {
			
			allStaticMtd.add(functionDef.getNodeId());
			// get class Id
			Long classId = getClsId(((Method)functionDef).getEnclosingClass(), functionDef.getEnclosingNamespace());
			if(classId!=-1) {
				String staticMethodKey = classId+"::"+functionDef.getName();
				nonStaticMethodNameDefs.add(((Method)functionDef).getName(), (Method)functionDef);
				staticMethodDefs.add(staticMethodKey, (Method)functionDef);
				nonStaticMethodDefs.add(staticMethodKey, (Method)functionDef);
			}
			return null;
		}
		
		// it's a constructor
		// Note that a PHP constructor cannot be static, so the previous case for static methods evaluates to false;
		// also note that there are two possible constructor names: __construct() (recommended) and ClassName() (legacy)
		else if( functionDef instanceof Method
				&& (functionDef.getName().equals("__construct")
						|| functionDef.getName().equals(((Method)functionDef).getEnclosingClass()))) {
			
			allConstructor.add(functionDef.getNodeId());
			// use A\B\C as key for the unique constructor of a class A\B\C
			Long classId = getClsId(((Method)functionDef).getEnclosingClass(), functionDef.getEnclosingNamespace());
			if(classId!=-1) {
				String constructorKey = classId.toString();
				constructorDefs.add( constructorKey, (Method)functionDef);
			}
			constructorNameDefs.add(((Method)functionDef).getEnclosingClass(), (Method)functionDef);
			
			return null;
		}
		
		// other methods than the above are non-static methods
		else if( functionDef instanceof Method) {
			// use foo as key for a non-static method foo in any class in any namespace;
			// note that the enclosing namespace of a non-static method definition is irrelevant here,
			// as that is usually not known at the call site (neither is the class name, except
			// when the keyword $this is used)
			//System.err.println("Function Def: "+((Method)functionDef).getEnclosingClass()+" "+functionDef.getNodeId());
			allMtd.add(functionDef.getNodeId());
			
			Long classId = getClsId(((Method)functionDef).getEnclosingClass(), functionDef.getEnclosingNamespace());
			if(classId!=-1) {
				String methodKey = classId+"::"+functionDef.getName();
				
				nonStaticMethodNameDefs.add(((Method)functionDef).getName(), (Method)functionDef);
				nonStaticMethodDefs.add( methodKey, (Method)functionDef);
			}
			return null;
		}
		
		// it's a function (i.e., not inside a class)
		else {
			// use A\B\foo as key for a function foo() in namespace \A\B
			allFunc.add(functionDef.getNodeId());
			String functionKey = functionDef.getName();
			if( !functionDef.getEnclosingNamespace().isEmpty())
				functionKey = functionDef.getEnclosingNamespace() + "\\" + functionKey;
			functionDefs.add( functionKey, functionDef);
			return null;
		}		
	}
	
	/**
	 * Adds a new function call.
	 * 
	 * @param functionCall A PHP function/method/constructor call. An arbitrary number of
	 *                     distinguished calls to the same function/method/constructor can
	 *                     be added.
	 */
	public static boolean addFunctionCall( CallExpressionBase callExpression) {
		
		// Note: we cannot access any of the CallExpression's getter methods here
		// because this method is called from the PHPCSVNodeInterpreter at the point
		// where it constructs the CallExpression. That is, this method is called for each
		// CallExpression *immediately* after its construction. At that point, the PHPCSVNodeInterpreter
		// has not called the CallExpression's setter methods  (as it has not yet interpreted the
		// corresponding CSV lines).
		// Hence, we only store the references to the CallExpression objects themselves.
	
		callsiteNumber++;
		if( callExpression instanceof StaticCallExpression)
			return staticMethodCalls.add( (StaticCallExpression)callExpression);
		else if( callExpression instanceof NewExpression)
			return constructorCalls.add( (NewExpression)callExpression);
		else if( callExpression instanceof MethodCallExpression) {
			if(nonStaticMethodCalls.isEmpty()) {
				nonStaticMethodCalls.add((MethodCallExpression)callExpression);
				return true;
			}
			MethodCallExpression save = nonStaticMethodCalls.getLast();
			Long lastId = nonStaticMethodCalls.getLast().getNodeId();
			if(lastId+1==callExpression.getNodeId()) {
				nonStaticMethodCalls.removeLast();
				nonStaticMethodCalls.add((MethodCallExpression) callExpression);
				nonStaticMethodCalls.add(save);
			}
			else {
				nonStaticMethodCalls.add((MethodCallExpression)callExpression);
			}
			return true;
		}
		else
			return functionCalls.add(callExpression);
	}
	
	//we do not analyze the alias;
	
	public static Long getClsId(String className, String nameSpace) {
		Long classId = (long) -1;
		String fullName = nameSpace + "\\" + className;
		for(String clsDef: classDef.keySet()) {
			if(clsDef.equals(fullName)) {
				classId = classDef.get(clsDef);
				return classId;
			}
		}
		for(String clsDef: classDef.keySet()) {
			if(clsDef.equals(className)) {
				classId = classDef.get(clsDef);
				return classId;
			}
		}
		return classId;
	}
	
	//From class name to its classId
	
	// ITEM52 FIX: getClassId() -- confirmed via live jstack sampling (2 of 6 samples across a
	// real GiveWP run, ~49 call sites codebase-wide) as a genuine hot path, distinct in kind
	// from ITEM49's full-corpus-scan pattern: classDef is a HashMap<String,Long>, but all three
	// lookups below did a LINEAR SCAN through classDef.keySet() comparing String.equals(), where
	// classDef.get(key) is exactly equivalent -- HashMap keys are unique, so "does any key equal
	// X" IS classDef.containsKey(X), and the corresponding value IS classDef.get(X). Verified no
	// hidden normalization/case-folding/mutation in the original loops before this substitution
	// (read the full function, not just the loop bodies, specifically to rule that out). This is
	// an O(1)-lookup-instead-of-O(classes-in-corpus)-scan fix, not an indexing-the-inputs fix
	// like ITEM49 -- there is nothing to index; the existing HashMap already IS the index, it
	// just wasn't being used as one.
	public static long GCID_calls = 0, GCID_cumulativeNanos = 0;

	public static Long getClassId(String className, Long callSiteId, String nameSpace) {
		long __t0 = System.nanoTime();
		try {
			return getClassIdImpl(className, callSiteId, nameSpace);
		} finally {
			GCID_calls++;
			GCID_cumulativeNanos += (System.nanoTime() - __t0);
		}
	}

	private static Long getClassIdImpl(String className, Long callSiteId, String nameSpace) {
		if(className.equals("-1")) {
			className = ASTUnderConstruction.idToNode.get(callSiteId).getEnclosingClass();
			nameSpace = ASTUnderConstruction.idToNode.get(callSiteId).getEnclosingNamespace();
		}
		Long classId = (long) -1;
		HashMap<String, String> alias;
		//LinkedList<String> inclusion = Inclusion.getInclusion(toTopLevelFile.getTopLevelId(callSiteId));
		lockC.lock();
        try {
        	alias = Inclusion.getAliasMap(toTopLevelFile.getTopLevelId(callSiteId));
        } finally {
            lockC.unlock();
        }
        String fullName = nameSpace + "\\" + className;
		String aliaName = "-1";
		
		//use ... as ...
		if(alias.containsKey(className)) {
			aliaName = alias.get(className) ;
		}
		
		//no namespace
		if(nameSpace==null || nameSpace.equals("")){
			fullName = className;
		}
		
		//first check alias name
		Long v = classDef.get(aliaName);
		if(v != null) return v;

		//then full name
		v = classDef.get(fullName);
		if(v != null) return v;

		//finally, the className may be full qualified.
		v = classDef.get(className);
		if(v != null) return v;
		
		return classId;
	}
	
	public static Set<Long> getParentClassId(Long ClassId){
		Set<Long> prtIds = new HashSet<Long>();
		//LinkedList<String> inclusion = Inclusion.getInclusion(toTopLevelFile.getTopLevelId(ClassId));
		ClassDef classNode = (ClassDef) ASTUnderConstruction.idToNode.get(ClassId);
		String namespace = classNode.getEnclosingNamespace();
		
		List<Long> prtNodes = inhe.get(ClassId); 
		for(Long prt: prtNodes) {
			//get inheritance name
			Identifier prtNode = (Identifier) ASTUnderConstruction.idToNode.get(prt);
			String prtClass = prtNode.getNameChild().getEscapedCodeStr();
			Long prtId = getClassId(prtClass, prt, namespace);
			if(prtId!=-1) {
				prtIds.add(prtId);
			}
		}
		
		return prtIds;
	}
	

	// ---- recovered from Jul-31 base after truncation ----
	// Walks from `start` up to (and including checks at) `stop` (the condition root), returning
	// true if a boolean-NOT (UNARY_BOOL_NOT) or boolean-OR (BINARY_BOOL_OR) node sits anywhere
	// on that path -- either of which means an in_array() call at `start` does not constrain
	// whatever executes when the overall condition is true the way a plain, unnegated,
	// non-disjunctive in_array() would.
	private static boolean negatedOrDisjunctiveAncestor(Long start, Long stop) {
		Long cur = start; int guard = 0;
		while( cur != null && guard++ < 256 ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(cur);
			if( n instanceof ast.expressions.UnaryOperationExpression
			    && PHPCSVNodeTypes.FLAG_UNARY_BOOL_NOT.equals(n.getFlags()) ) return true;
			if( n instanceof BinaryOperationExpression
			    && PHPCSVNodeTypes.FLAG_BINARY_BOOL_OR.equals(n.getFlags()) ) return true;
			if( cur.equals(stop) ) break;   // checked stop itself above before stopping, not before
			cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
		}
		return false;
	}

	private static void suppressWhitelistGuardedSources() {
		int removed = 0;
		PHPCGFactory.recordScanSite("PCG_13839", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.php.statements.blockstarters.IfStatement) ) continue;
			ast.php.statements.blockstarters.IfStatement is = (ast.php.statements.blockstarters.IfStatement) n;
			if( is.size() < 1 ) continue;
			Long elemId;
			try { elemId = is.getIfElement(0).getNodeId(); } catch( Exception ex ) { continue; }
			HashMap<Integer,Long> ec = PHPCSVEdgeInterpreter.parent2child.get(elemId);
			if( ec == null ) continue;
			Long condId = ec.get(0), bodyId = ec.get(1);
			if( condId == null || bodyId == null ) continue;

			// 1. collect access keys constrained by an all-literal in_array() in the CONDITION
			Set<String> constrained = new HashSet<String>();
			for( Long cid : subtreeIds(condId) ) {
				ASTNode c = ASTUnderConstruction.idToNode.get(cid);
				if( !(c instanceof CallExpressionBase) ) continue;
				if( !"in_array".equals(callTargetName((CallExpressionBase)c)) ) continue;
				// FIX (2026-08-08): no polarity or connective check previously existed here --
				// confirmed as a real, observable false negative before fixing: an in_array()
				// call constrained sources in the guarded body regardless of whether it was
				// negated (if(!in_array(...)){...} -- the body is exactly the "not allowlisted"
				// branch, the opposite of what this suppressor assumes) or joined by || (the body
				// can run even when this particular in_array() is false, via the other
				// disjunct). Directly reproduced: if (!in_array($_GET['k'], ['a','b']))
				// { echo $_GET['k']; } -- the genuinely unsafe branch -- had its source silently
				// suppressed. Fixed by walking from the in_array() call up to the condition root
				// and rejecting the constraint if a boolean-NOT or boolean-OR sits anywhere in
				// between; only an unnegated, non-disjunctive in_array() actually constrains the
				// body the way this suppressor assumes.
				if( negatedOrDisjunctiveAncestor(cid, condId) ) continue;
				ArgumentList al = ((CallExpressionBase)c).getArgumentList();
				if( al == null || al.size() < 2 ) continue;
				ASTNode arr = al.getArgument(1);
				if( !(arr instanceof ast.php.expressions.ArrayExpression) ) continue;
				ast.php.expressions.ArrayExpression ae = (ast.php.expressions.ArrayExpression) arr;
				if( ae.size() == 0 ) continue;
				boolean allLiteral = true;
				for( int i = 0; i < ae.size(); i++ ) {
					ArrayElement el = ae.getArrayElement(i);
					Expression v = ( el != null ) ? el.getValue() : null;
					if( v == null || !isLiteralValue(v) ) { allLiteral = false; break; }
				}
				if( !allLiteral ) continue;   // needle set not provably constant -> no constraint
				ASTNode a0 = al.getArgument(0);
				String key = ( a0 instanceof Expression ) ? lvalKey((Expression) a0) : null;
				if( key != null ) constrained.add(key);
			}
			if( constrained.isEmpty() ) continue;

			// 2. drop matching source occurrences inside the guarded BODY
			for( Long bid : subtreeIds(bodyId) ) {
				if( !PHPCSVEdgeInterpreter.sources.contains(bid) ) continue;
				ASTNode b = ASTUnderConstruction.idToNode.get(bid);
				String bk = ( b instanceof Expression ) ? lvalKey((Expression) b) : null;
				// The registered source node is typically the AST_VAR ($_GET); the whitelist key
				// ("_GET[by]") belongs to its enclosing AST_DIM, so also test the parent.
				Long parId = PHPCSVEdgeInterpreter.child2parent.get(bid);
				ASTNode par = ( parId != null ) ? ASTUnderConstruction.idToNode.get(parId) : null;
				String pk = ( par instanceof Expression ) ? lvalKey((Expression) par) : null;
				if( ( bk != null && constrained.contains(bk) ) || ( pk != null && constrained.contains(pk) ) ) {
					PHPCSVEdgeInterpreter.sources.remove(bid);
					removed++;
				}
			}
		}
		if( removed > 0 ) System.err.println("WPWHITELIST suppressed "+removed
			+" source occurrence(s) constrained to literals by an in_array() guard");
	}

	private static void seedWidgetQueryVarTemplates() {
		// --- Step 1: collect widget classes reached via the_widget('WClass', <tainted>) --------------
		// Map: widget class name -> true if the_widget() passed a request/attribute-derived 2nd arg.
		java.util.Set<String> taintedWidgetClasses = new java.util.HashSet<String>();
		PHPCGFactory.recordScanSite("PCG_13912", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof CallExpressionBase) ) continue;
			String cn = callTargetName((CallExpressionBase)n);
			if( !"the_widget".equals(cn) ) continue;
			ArgumentList al = ((CallExpressionBase)n).getArgumentList();
			if( al == null || al.size() < 1 ) continue;
			// 1st arg: widget class name (string literal). Dynamic names are not resolvable -> skip.
			Expression a0 = al.getArgument(0);
			if( !(a0 instanceof StringExpression) ) continue;
			String wclass = ((StringExpression)a0).getEscapedCodeStr();
			if( wclass == null || wclass.isEmpty() ) continue;
			wclass = wclass.toLowerCase();   // PHP class names are case-insensitive
			// 2nd arg (instance): must be present and NOT a constant literal. A variable ($atts), array,
			// or call expression is treated as potentially request-derived. Absent 2nd arg -> WP uses
			// defaults (no attacker input) -> skip.
			if( al.size() < 2 ) continue;
			Expression a1 = al.getArgument(1);
			if( a1 instanceof StringExpression ) continue;   // the_widget('W', 'literal') — not tainted
			taintedWidgetClasses.add(wclass);
		}
		if( taintedWidgetClasses.isEmpty() ) return;

		// --- Step 2: for each such widget class, seed widget()'s $instance param and collect the
		//             query-var names its set_query_var() calls populate from $instance. --------------
		java.util.Set<String> bridgedQueryVarNames = new java.util.HashSet<String>();
		java.util.Set<Long> widgetMethodFids = new java.util.HashSet<Long>();
		int instanceSeeded = 0;
		for( Long mid : allMtd ) {
			ASTNode n = ASTUnderConstruction.idToNode.get(mid);
			if( !(n instanceof FunctionDef) ) continue;
			FunctionDef fd = (FunctionDef)n;
			if( !"widget".equals(fd.getName()) ) continue;          // WP_Widget::widget($args,$instance)
			String enclClass = ((Method)n).getEnclosingClass();
			if( enclClass == null || !taintedWidgetClasses.contains(enclClass.toLowerCase()) ) continue;
			// Identify the $instance parameter name (2nd param by WP convention, but match by position).
			ParameterList pl = fd.getParameterList();
			if( pl == null || pl.size() < 2 ) continue;
			String instanceParam = ((Parameter)pl.getParameter(1)).getName();
			if( instanceParam == null ) continue;
			widgetMethodFids.add(mid);
			// Seed every read of $instance inside this widget() method as a source.
			PHPCGFactory.recordScanSite("PCG_13953", ASTUnderConstruction.idToNode.size());
			for( ASTNode vn : ASTUnderConstruction.idToNode.values() ) {
				if( !(vn instanceof Variable) ) continue;
				if( !mid.equals(vn.getFuncId()) ) continue;
				Expression ne = ((Variable)vn).getNameExpression();
				if( ne == null || !instanceParam.equals(ne.getEscapedCodeStr()) ) continue;
				PHPCSVEdgeInterpreter.sources.add(vn.getNodeId());
				instanceSeeded++;
			}
			// Collect set_query_var('K', <expr referencing $instance>) NAMES within this method.
			PHPCGFactory.recordScanSite("PCG_13962", ASTUnderConstruction.idToNode.size());
			for( ASTNode cn2 : ASTUnderConstruction.idToNode.values() ) {
				if( !(cn2 instanceof CallExpressionBase) ) continue;
				if( !mid.equals(cn2.getFuncId()) ) continue;
				if( !"set_query_var".equals(callTargetName((CallExpressionBase)cn2)) ) continue;
				ArgumentList sal = ((CallExpressionBase)cn2).getArgumentList();
				if( sal == null || sal.size() < 2 ) continue;
				Expression key = sal.getArgument(0);
				if( !(key instanceof StringExpression) ) continue;   // dynamic key -> skip
				String kname = ((StringExpression)key).getEscapedCodeStr();
				if( kname == null || kname.isEmpty() ) continue;
				// Only bridge the name if the value argument textually references the $instance param
				// (conservative: avoids bridging set_query_var('args',$args) and other non-attacker vars).
				if( subtreeReferencesVar(sal.getArgument(1), instanceParam) )
					bridgedQueryVarNames.add(kname);
			}
		}
		if( bridgedQueryVarNames.isEmpty() ) {
			if( instanceSeeded > 0 )
				System.err.println("WPWIDGETQV seeded "+instanceSeeded+" $instance source(s); no query-var bridge names");
			return;
		}

		// --- Step 3: seed bare $K reads ONLY where $K is a FREE variable (extract()-populated). --------
		// A bridged name K carries taint inside the template that WP core extract()s the query vars into.
		// The reliable signature of such a template variable is that it is FREE in its function unit:
		// never assigned (no `$K = ...`) and not a declared parameter. In an infrastructure file, a
		// same-named variable (e.g. $options = $this->get_option()) IS assigned locally and therefore
		// holds the plugin's own value, not the widget instance — those must NOT be seeded. Requiring
		// "free variable" cleanly separates extract()-populated template vars from ordinary locals and
		// eliminates the common-name over-seeding (e.g. 'options','args') seen without this guard.
		//
		// Precompute, per function unit (fid): the set of names that are ASSIGNED or are PARAMETERS.
		java.util.Map<Long,java.util.Set<String>> boundNamesByFid = new java.util.HashMap<Long,java.util.Set<String>>();
		PHPCGFactory.recordScanSite("PCG_13995", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( n instanceof AssignmentExpression ) {
				String lhs = varNameOf(((AssignmentExpression)n).getLeft());
				Long fid = n.getFuncId();
				if( lhs != null && fid != null )
					boundNamesByFid.computeIfAbsent(fid, k -> new java.util.HashSet<String>()).add(lhs);
			} else if( n instanceof FunctionDef ) {
				ParameterList pl = ((FunctionDef)n).getParameterList();
				if( pl != null ) for( int i = 0; i < pl.size(); i++ ) {
					String pn = ((Parameter)pl.getParameter(i)).getName();
					if( pn != null )
						boundNamesByFid.computeIfAbsent(n.getNodeId(), k -> new java.util.HashSet<String>()).add(pn);
				}
			}
		}
		int tmplSeeded = 0;
		java.util.Set<String> seededInFiles = new java.util.HashSet<String>();
		PHPCGFactory.recordScanSite("PCG_14012", ASTUnderConstruction.idToNode.size());
		for( ASTNode vn : ASTUnderConstruction.idToNode.values() ) {
			if( !(vn instanceof Variable) ) continue;
			Long fid = vn.getFuncId();
			if( fid == null || widgetMethodFids.contains(fid) ) continue;  // not the widget() method itself
			Expression ne = ((Variable)vn).getNameExpression();
			if( ne == null ) continue;
			String vname = ne.getEscapedCodeStr();
			if( vname == null || !bridgedQueryVarNames.contains(vname) ) continue;
			// FREE-VARIABLE GUARD: skip if $K is assigned or is a parameter anywhere in its function unit.
			java.util.Set<String> bound = boundNamesByFid.get(fid);
			if( bound != null && bound.contains(vname) ) continue;
			PHPCSVEdgeInterpreter.sources.add(vn.getNodeId());
			tmplSeeded++;
			String p = getDir(vn.getNodeId());
			if( p != null && !p.isEmpty() ) {
				int ps = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
				seededInFiles.add(ps >= 0 ? p.substring(ps+1) : p);
			}
		}
		System.err.println("WPWIDGETQV bridged widget->query-var->template: "+instanceSeeded
			+" $instance source(s), names="+bridgedQueryVarNames
			+", "+tmplSeeded+" template var source(s) in "+seededInFiles);
	}

	private static void collectWpdbAccessorMethods() {
		wpdbAccessorMethods.clear();
		// funcId -> [sawWpdbReturn, methodName]
		java.util.Map<Long, Boolean> funcReturnsWpdb = new java.util.HashMap<>();
		java.util.Map<Long, String> funcName = new java.util.HashMap<>();
		// First pass: record method funcIds and their names; also note return-type wpdb.
		PHPCGFactory.recordScanSite("PCG_14042", ASTUnderConstruction.idToNode.size());
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(n instanceof Method) {
				Method m = (Method) n;
				funcName.put(m.getNodeId(), m.getName());
				String rt = methodReturnTypeName(m);
				if(rt != null && rt.toLowerCase().endsWith("wpdb")) {
					if(m.getName() != null) wpdbAccessorMethods.add(m.getName());
				}
			}
		}
		// Second pass: find AST_RETURN nodes whose returned expression is the $wpdb
		// variable, and mark their enclosing function. The returned var node is within
		// a few IDs of the AST_RETURN node.
		PHPCGFactory.recordScanSite("PCG_14055", ASTUnderConstruction.idToNode.size());
		for(ASTNode n : ASTUnderConstruction.idToNode.values()) {
			if(!"AST_RETURN".equals(n.getProperty("type"))) continue;
			Long fid; try { fid = n.getFuncId(); } catch(Exception e) { continue; }
			if(fid == null || !funcName.containsKey(fid)) continue;
			// Look for a $wpdb variable node just after the return node
			long base = n.getNodeId();
			for(long probe = base + 1; probe <= base + 4; probe++) {
				ASTNode c = ASTUnderConstruction.idToNode.get(probe);
				if(c instanceof Variable && ((Variable)c).getNameExpression() instanceof StringExpression) {
					String vn = ((StringExpression)((Variable)c).getNameExpression()).getEscapedCodeStr();
					if("wpdb".equals(vn)) { funcReturnsWpdb.put(fid, true); break; }
				}
			}
		}
		for(java.util.Map.Entry<Long, Boolean> e : funcReturnsWpdb.entrySet()) {
			if(Boolean.TRUE.equals(e.getValue())) {
				String nm = funcName.get(e.getKey());
				if(nm != null) wpdbAccessorMethods.add(nm);
			}
		}
	}

	private static void buildReturnSafetySummaries() {
		retSafeFids.clear(); retSafeContext.clear(); retBufferedFids.clear();
		boolean dbgRS = System.getenv("WP_DEBUG_ECHOCALL") != null;
		java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>> rbf =
			new java.util.HashMap<Long,java.util.List<ast.statements.jump.ReturnStatement>>();
		PHPCGFactory.recordScanSite("PCG_14082", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof ast.statements.jump.ReturnStatement) ) continue;
			Long f; try { f = n.getFuncId(); } catch( Exception ex ) { continue; }
			if( f == null ) continue;
			rbf.computeIfAbsent(f, k -> new java.util.ArrayList<ast.statements.jump.ReturnStatement>())
			   .add((ast.statements.jump.ReturnStatement)n);
		}
		// Buffered-template detection (routing only, never clears): a fid returning exactly
		// ob_get_clean() renders a template into the buffer. Record it with the template base-name if a
		// load_template()/get_template_part() with a string arg is present in the same function.
		for( java.util.Map.Entry<Long,java.util.List<ast.statements.jump.ReturnStatement>> en : rbf.entrySet() ) {
			Long f = en.getKey();
			boolean returnsBuffer = false;
			for( ast.statements.jump.ReturnStatement r : en.getValue() ) {
				Expression re = r.getReturnExpression();
				if( returnExprIsObGetClean(re, f) ) { returnsBuffer = true; break; }
			}
			if( returnsBuffer ) retBufferedFids.put(f, resolveRenderedTemplateName(f));
		}
		// V2: fixpoint. A fid whose return is `return safeHelper($x)` can only be classified once
		// safeHelper is itself known safe, so iterate until retSafeFids stops growing. Monotone
		// (we only ADD fids), bounded by the number of fids, capped defensively.
		int rounds = 0, maxRounds = 12;
		boolean changed = true;
		while( changed && rounds++ < maxRounds ) {
			changed = false;
			for( java.util.Map.Entry<Long,java.util.List<ast.statements.jump.ReturnStatement>> en : rbf.entrySet() ) {
				Long f = en.getKey();
				if( retSafeFids.contains(f) ) continue;   // already settled safe; never revisit (monotone)
				boolean sawReturn = false, allSafe = true;
				String ctx = null;      // unified context across returns; mixed contexts => not safe
				for( ast.statements.jump.ReturnStatement r : en.getValue() ) {
					Expression re = r.getReturnExpression();
					if( re == null ) continue;          // `return;` yields null — harmless, not reflecting
					sawReturn = true;
					String c = classifyReturnExpr(re, 0);
					if( c == null ) { allSafe = false; break; }             // PASSTHROUGH/UNKNOWN => unsafe
					if( ctx == null ) ctx = c;
					else if( !ctx.equals(c) ) {
						// Mixed safe contexts (e.g. one arm html, one json). Only keep if compatible;
						// conservatively downgrade to the STRICTER — treat any mix as "constant" only if
						// both are constant/numeric, else unsafe.
						if( (ctx.equals("constant")||ctx.equals("numeric")) && (c.equals("constant")||c.equals("numeric")) )
							ctx = "constant";
						else { allSafe = false; break; }
					}
				}
				if( sawReturn && allSafe && ctx != null ) {
					retSafeFids.add(f); retSafeContext.put(f, ctx); changed = true;
				}
			}
		}
		if( dbgRS ) System.err.println("RETSAFE[dbg] fixpoint rounds="+rounds
			+" retSafeFids="+retSafeFids.size()+" "+retSafeContext);
	}

	private static String classifyReturnExpr(Expression e, int depth) {
		if( e == null || depth > 6 ) return null;    // depth cap => fail-closed
		// Constant literals.
		if( e instanceof StringExpression ) return "constant";
		String ty = e.getProperty("type");
		if( "integer".equals(ty) || "double".equals(ty) || "AST_CONST".equals(ty) ) return "constant";
		// Conditional / ternary: every arm must be safe; unify contexts.
		if( e instanceof ast.expressions.ConditionalExpression ) {
			ast.expressions.ConditionalExpression ce = (ast.expressions.ConditionalExpression)e;
			Expression t = ce.getTrueExpression();
			Expression fa = ce.getFalseExpression();
			// Short-ternary ($a ?: $b): true-arm is the condition value itself.
			String ct = classifyReturnExpr(t != null ? t : ce.getCondition(), depth+1);
			if( ct == null ) return null;
			String cf = classifyReturnExpr(fa, depth+1);
			if( cf == null ) return null;
			if( ct.equals(cf) ) return ct;
			if( (ct.equals("constant")||ct.equals("numeric")) && (cf.equals("constant")||cf.equals("numeric")) )
				return "constant";
			return null;   // mixed incompatible safe contexts => fail-closed
		}
		// Call expression: only a known escaper/coercer directly wrapping the return is safe.
		if( e instanceof CallExpressionBase || e instanceof StaticCallExpression
			|| e instanceof MethodCallExpression ) {
			String nm = null;
			if( e instanceof CallExpressionBase ) nm = callTargetName((CallExpressionBase)e);
			else if( e instanceof StaticCallExpression ) {
				Expression tf = ((StaticCallExpression)e).getTargetFunc();
				if( tf instanceof StringExpression ) nm = ((StringExpression)tf).getEscapedCodeStr();
			} else if( e instanceof MethodCallExpression ) {
				Expression tf = ((MethodCallExpression)e).getTargetFunc();
				if( tf instanceof StringExpression ) nm = ((StringExpression)tf).getEscapedCodeStr();
			}
			if( nm == null ) return null;                       // unresolved call name => UNKNOWN
			if( NUMERIC_COERCERS.contains(nm) ) return "numeric";
			if( JSON_ESCAPERS.contains(nm) ) return "json";
			if( htmlEscapers.contains(nm) ) return "html";
			// V2 interprocedural chaining: `return helper($x)` is safe iff EVERY resolved callee is
			// itself already classified safe (retSafeFids). Inherit the callee(s)' context; a mix of
			// incompatible safe contexts fails closed. Resolution uses the engine call graph (call2mtd)
			// so it follows dynamic dispatch the way the emission gate does. Callees not yet settled in
			// the current fixpoint round => treat as UNKNOWN this round (a later round may settle them).
			java.util.List<Long> callees = call2mtd.get(e.getNodeId());
			if( callees == null || callees.isEmpty() ) return null;   // unresolved dispatch => UNKNOWN
			String chainCtx = null;
			for( Long cf : callees ) {
				if( cf == null || !retSafeFids.contains(cf) ) return null;   // any unsettled/unsafe callee => UNKNOWN
				String cc = retSafeContext.get(cf);
				if( cc == null ) return null;
				if( chainCtx == null ) chainCtx = cc;
				else if( !chainCtx.equals(cc) ) {
					if( (chainCtx.equals("constant")||chainCtx.equals("numeric"))
						&& (cc.equals("constant")||cc.equals("numeric")) ) chainCtx = "constant";
					else return null;   // incompatible safe contexts across callees => fail-closed
				}
			}
			return chainCtx;                                    // inherited callee context (interprocedural)
		}
		// Variable, property, array access, concat, binary op, etc. — may carry attacker data.
		return null;                                            // PASSTHROUGH => unsafe
	}

	private static String methodReturnTypeName(Method m) {
		try {
			Identifier rt = m.getReturnType();
			if(rt != null) {
				String v = rt.getEscapedCodeStr();
				if(v == null && rt.getNameChild() != null) v = rt.getNameChild().getEscapedCodeStr();
				return v;
			}
		} catch(Exception e) {}
		return null;
	}

	private static String resolveRenderedTemplateName(Long fid) {
		java.util.Set<String> names = new java.util.HashSet<String>();
		PHPCGFactory.recordScanSite("PCG_14214", ASTUnderConstruction.idToNode.size());
		for( ASTNode n : ASTUnderConstruction.idToNode.values() ) {
			if( !(n instanceof CallExpressionBase) ) continue;
			if( !fid.equals(n.getFuncId()) ) continue;
			String cn = callTargetName((CallExpressionBase)n);
			if( cn == null ) continue;
			boolean loader = cn.equals("load_template") || cn.equals("locate_template")
				|| cn.equals("get_template_part") || cn.endsWith("get_template_part")
				|| cn.endsWith("_template_part") || cn.endsWith("get_template");
			if( !loader ) continue;
			ArgumentList al = ((CallExpressionBase)n).getArgumentList();
			if( al == null ) continue;
			for( int i = 0; i < al.size(); i++ ) {
				Expression a = al.getArgument(i);
				if( !(a instanceof StringExpression) ) continue;
				String s = ((StringExpression)a).getEscapedCodeStr();
				if( s == null || s.isEmpty() ) continue;
				int slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
				if( slash >= 0 ) s = s.substring(slash+1);
				if( s.endsWith(".php") ) s = s.substring(0, s.length()-4);
				if( !s.isEmpty() ) names.add(s);
			}
		}
		return names.size() == 1 ? names.iterator().next() : "?";
	}

	private static boolean returnExprIsObGetClean(Expression re, Long fid) {
		if( re == null ) return false;
		if( callNamed(re, "ob_get_clean") ) return true;
		// $v where $v = ob_get_clean() somewhere in the same function.
		if( re instanceof Variable ) {
			String vn = varNameOf(re);
			if( vn == null ) return false;
			// PERFORMANCE FIX: this used to scan ASTUnderConstruction.idToNode.values() -- the
			// ENTIRE codebase's AST node map -- for every single Variable return statement, then
			// filter down to fid.equals(n.getFuncId()). The filter was always correct; the scan was
			// the bug. buildReturnSafetySummaries calls this once per return statement across every
			// function in the codebase, making the true cost O(total_functions * total_AST_nodes).
			// Confirmed via thread dump as the exact, sole stall point on WPForms (3976 files, by
			// far the largest codebase in the cross-plugin evaluation pass) -- 18+ minutes stuck
			// with zero progress and stable memory, main thread parked in this exact method.
			// Fixed by walking only fid's own subtree (bounded stack traversal, same pattern
			// already used by subtreeReferencesVar just above) instead of the whole corpus.
			// Output is identical: the old code's filter meant nodes outside fid's function were
			// always skipped anyway, so restricting the traversal to fid's own subtree changes
			// nothing about which AssignmentExpressions are found -- only how many nodes are
			// visited to find them.
			ASTNode root = ASTUnderConstruction.idToNode.get(fid);
			if( root == null ) return false;
			java.util.ArrayDeque<ASTNode> stack = new java.util.ArrayDeque<ASTNode>();
			stack.push(root);
			int guard = 0;
			while( !stack.isEmpty() && guard++ < 200_000 ) {
				ASTNode cur = stack.pop();
				if( cur instanceof AssignmentExpression ) {
					Expression lhs = ((AssignmentExpression)cur).getLeft();
					if( lhs instanceof Variable && vn.equals(varNameOf(lhs))
					    && callNamed(((AssignmentExpression)cur).getRight(), "ob_get_clean") ) return true;
				}
				int kc = cur.getChildCount();
				for( int i = 0; i < kc; i++ ) {
					ASTNode k = cur.getChild(i);
					if( k != null ) stack.push(k);
				}
			}
		}
		return false;
	}

	private static boolean subtreeReferencesVar(Expression e, String varName) {
		if( e == null || varName == null ) return false;
		java.util.ArrayDeque<ASTNode> stack = new java.util.ArrayDeque<ASTNode>();
		stack.push(e);
		int guard = 0;
		while( !stack.isEmpty() && guard++ < 4000 ) {
			ASTNode cur = stack.pop();
			if( cur instanceof Variable ) {
				Expression ne = ((Variable)cur).getNameExpression();
				if( ne != null && varName.equals(ne.getEscapedCodeStr()) ) return true;
			}
			int kc = cur.getChildCount();
			for( int i = 0; i < kc; i++ ) {
				ASTNode k = cur.getChild(i);
				if( k != null ) stack.push(k);
			}
		}
		return false;
	}

	private static boolean callNamed(Expression e, String name) {
		if( !(e instanceof CallExpressionBase) ) return false;
		String nm = callTargetName((CallExpressionBase)e);
		return name.equals(nm);
	}
	// ================= REWRITTEN after truncation (specs preserved in STATUS.md) =================

	/** Approximations in force for THIS run that a consumer must weigh. */
	private static String approximationsUsed() {
		StringBuilder sb = new StringBuilder();
		if( WPDB_STORED ) sb.append("custom_table_stored_taint_PLUGIN_LEVEL_PAIRING");
		if( ASTUnderConstruction.idToNode.size() > 750_000 ) {
			if( sb.length()>0 ) sb.append(",");
			sb.append("large_plugin_degraded_mode");
		}
		return sb.toString();
	}

	private static String coverageLimits(String pass) {
		return pass + " COVERAGE_LIMITS only_entries_in_entry_point_model=true"
			+ " only_paths_in_resolved_call_graph=true"
			+ " unresolved_callbacks_dynamic_dispatch_reflection_closures=NOT_COVERED"
			+ " caller_guard_events=COLLECTED_ALONG_WITNESSED_PATH"
			+ " interprocedural_guard_dominance=NOT_ESTABLISHED"
			+ " guard_absence=NOT_EXHAUSTIVE_unresolved_calls_and_registrations_possible"
			+ " path_enumeration=BOUNDED_not_exhaustive_CFG";
	}

	/** Run-INDEPENDENT site identity: node ids shift between runs. */
	private static String guardSite(Long n) {
		ASTNode a = ASTUnderConstruction.idToNode.get(n);
		int line = (a != null && a.getLocation() != null) ? a.getLocation().startLine : -1;
		return getDir(n) + ":" + line;
	}

	/** The node a guard must govern: the sink when they share a function, otherwise the onward
	 *  CALL SITE on the path -- `if (cap) { helper(); }` guards by governing the call edge. */
	private static Long governedNodeFor(Long capCall, Long sinkNode, java.util.List<Long> path,
	                                    java.util.List<Long> routeCs) {
		Long capFunc = null;
		try { capFunc = ASTUnderConstruction.idToNode.get(capCall).getFuncId(); } catch( Exception e ) {}
		Long sinkFunc = null;
		try { sinkFunc = ASTUnderConstruction.idToNode.get(sinkNode).getFuncId(); } catch( Exception e ) {}
		if( capFunc != null && capFunc.equals(sinkFunc) ) return sinkNode;
		if( capFunc == null || path == null ) return sinkNode;
		int idx = path.indexOf(capFunc);
		if( idx < 0 || idx+1 >= path.size() ) return sinkNode;
		// Use THIS witness's callsite: taking the first match made every witness on a multi-callsite
		// path inherit whichever route was found first, so an unguarded call reported STRICT_BRANCH
		// borrowed from a guarded sibling.
		if( routeCs != null && idx < routeCs.size() ) {
			Long own = routeCs.get(idx);
			if( own != null && own.longValue() != -1L ) return own;
		}
		Long next = path.get(idx+1);
		for( java.util.Map.Entry<Long,java.util.List<Long>> ce : call2mtd.entrySet() ) {
			ASTNode cs = ASTUnderConstruction.idToNode.get(ce.getKey());
			if( cs == null ) continue;
			Long caller = null; try { caller = cs.getFuncId(); } catch( Exception e ) {}
			if( caller == null || !caller.equals(capFunc) ) continue;
			if( ce.getValue().contains(next) ) return ce.getKey();
		}
		return sinkNode;
	}

	/** Call sites on THIS path whose targets did not resolve -- a RECALL fact (other routes
	 *  unexplored), NOT a gap in this chain. */
	private static int unresolvedOnPath(java.util.List<Long> path) {
		int u = 0;
		java.util.Set<Long> onPath = new HashSet<Long>(path);
		for( MethodCallExpression mc : nonStaticMethodCalls ) {
			Long f = null; try { f = mc.getFuncId(); } catch( Exception e ) {}
			if( f == null || !onPath.contains(f) ) continue;
			java.util.List<Long> t = call2mtd.get(mc.getNodeId());
			if( t == null || t.isEmpty() ) u++;
		}
		return u;
	}

	/** DERIVED, not asserted: verifies the traversal's construction invariant. */

	/** ALL callsites linking two path functions. The DFS is function-level, so one function path
	 *  can correspond to SEVERAL distinct routes when a caller invokes the callee more than once —
	 *  e.g. a guarded `if(cap){ promote(); }` and an unguarded `promote();` in the same handler.
	 *  Emitting one witness per function path would let the guarded route mask the unguarded one. */
	private static java.util.List<Long> callSitesBetween(Long from, Long to) {
		java.util.List<Long> out = new java.util.ArrayList<Long>();
		for( java.util.Map.Entry<Long,java.util.List<Long>> ce : call2mtd.entrySet() ) {
			ASTNode cs = ASTUnderConstruction.idToNode.get(ce.getKey());
			if( cs == null ) continue;
			Long caller = null; try { caller = cs.getFuncId(); } catch( Exception e ) {}
			if( caller == null || !caller.equals(from) ) continue;
			if( ce.getValue().contains(to) ) out.add(ce.getKey());
		}
		java.util.Collections.sort(out);
		return out;
	}


	/** CANONICAL EVIDENCE TUPLE — the collapse KEY. Equality is decided on THESE FIELDS; the
	 *  fingerprint is only an index into them, so a hashing bug cannot silently merge witnesses.
	 *  Fixed field order so two tuples can be diffed directly. Two witnesses collapse ONLY when
	 *  every dimension matches — identical checks reached via a different hook, callsite, target
	 *  or approximation state remain separate. */
	private static String canonicalEvidenceTuple(SecurityShape shape, java.util.List<Long> path,
	        java.util.List<Long> routeCs, Long sink, String access, String entryReg,
	        String guardRels, String targetF, String edgeRes, int line) {
		StringBuilder sb = new StringBuilder();
		// A zero-edge witness from an unregistered/unmodelled entry establishes only that the sink
		// EXISTS in some function — NOT that anything external can reach it. Its own evidence class
		// lets aggregation exclude it MECHANICALLY rather than asking a model to weight it low.
		boolean localOnly = (path.size() < 2) && "unknown-not-classified".equals(access);
		sb.append("evidence_class=").append(localOnly ? "LOCAL_SINK_CANDIDATE" : "CONTROL_REACHABILITY");
		// SOURCE PRECISION IS SEPARATE FROM ROUTE PRECISION. A control-reachability witness has no
		// data source BY DESIGN — the attacker controls EXECUTION, not a value — and that must never
		// be confused with a value-flow witness whose required source could not be reconstructed.
		// LOCAL_SINK_CANDIDATE is NOT execution-control: no externally controllable execution has
		// been established, only that the code exists.
		sb.append("|supporting_evidence_basis=").append(localOnly ? "LOCAL_CODE_PRESENCE" : "EXECUTION_CONTROL");
		sb.append("|source_requirement=NOT_REQUIRED");
		sb.append("|source_status=ABSENT_NOT_REQUIRED");
		sb.append("|source_provenance_precision=NOT_APPLICABLE");
		// the emitted route is built only from resolved call2mtd edges
		sb.append("|route_precision=EXACT");
		// union model: source ∪ propagation ∪ dispatch. No source here, and this emitter performs no
		// approximate propagation, so the set is empty — coverage limits are reported SEPARATELY.
		sb.append("|witness_approximations=[]");
		if( localOnly ) {
			sb.append("|entry_classification=UNREGISTERED_OR_UNMODELLED");
			sb.append("|external_reachability=NOT_ESTABLISHED");
			sb.append("|route_edges=0");
			sb.append("|aggregation_eligibility=CANNOT_INDEPENDENTLY_SUPPORT_VULNERABLE_SINK");
		} else {
			sb.append("|external_reachability=ESTABLISHED_VIA_MODELLED_ENTRY");
			sb.append("|route_edges=").append(path.size()-1);
			sb.append("|aggregation_eligibility=ELIGIBLE");
		}
		sb.append("|shape=").append(shape.name);
		sb.append("|entry_registration=").append(entryReg);
		sb.append("|entry_access=").append(access);
		sb.append("|chain=");
		for( int i = 0; i < path.size(); i++ ) {
			if( i > 0 ) sb.append(">");
			sb.append(funcIdentity(path.get(i)));
			if( i < path.size()-1 ) {
				Long cs = (routeCs != null && i < routeCs.size()) ? routeCs.get(i) : null;
				sb.append("@").append(cs == null || cs.longValue() == -1L ? "UNRESOLVED" : guardSite(cs));
			}
		}
		sb.append("|sink=").append(getDir(sink)).append(":").append(line);
		sb.append("|edge_resolution=").append(edgeRes);
		sb.append("|checks=").append(guardRels);
		sb.append("|target=").append(targetF);
		sb.append("|coverage_mode=").append(ASTUnderConstruction.idToNode.size() > 750_000 ? "DEGRADED" : "FULL");
		sb.append("|approximations=[").append(approximationsUsed()).append("]");
		return sb.toString();
	}

	private static String pathEdgeResolution(java.util.List<Long> path) {
		if( path == null || path.size() < 2 ) return "SINGLE_FUNCTION_NO_EDGES";
		int verified = 0, unverified = 0;
		for( int i = 0; i < path.size()-1; i++ ) {
			Long from = path.get(i), to = path.get(i+1);
			boolean found = false;
			for( java.util.Map.Entry<Long,java.util.List<Long>> ce : call2mtd.entrySet() ) {
				ASTNode cs = ASTUnderConstruction.idToNode.get(ce.getKey());
				if( cs == null ) continue;
				Long caller = null; try { caller = cs.getFuncId(); } catch( Exception e ) {}
				if( caller == null || !caller.equals(from) ) continue;
				if( ce.getValue().contains(to) ) { found = true; break; }
			}
			if( found ) verified++; else unverified++;
		}
		return unverified == 0 ? "ALL_RESOLVED_VERIFIED:" + verified
		                       : "UNVERIFIED_EDGES:" + unverified + "_of_" + (verified+unverified);
	}

	/** Never "COMPLETE": the model is bounded by construction. */
	private static String pathModelCompleteness() {
		String ap = approximationsUsed();
		return ap.isEmpty() ? "BOUNDED_MODEL" : "BOUNDED_MODEL_WITH_APPROXIMATIONS";
	}

	/** Ordered PROVEN steps with per-edge resolution. */

	/** CANONICAL EVIDENCE TUPLE — the collapse key. Equality is decided on THESE FIELDS; the
	 *  fingerprint is only an index into them. Two witnesses collapse ONLY when every dimension
	 *  matches, so identical checks on different hooks, callsites, targets or approximation states
	 *  stay separate. Serialised in a fixed field order so it can be compared or diffed directly
	 *  rather than trusting a hash. */


	/** The specific callsite linking two path functions — two routes through the same named
	 *  functions but different callsites are NOT the same witness. */
	private static Long callSiteBetween(Long from, Long to) {
		for( java.util.Map.Entry<Long,java.util.List<Long>> ce : call2mtd.entrySet() ) {
			ASTNode cs = ASTUnderConstruction.idToNode.get(ce.getKey());
			if( cs == null ) continue;
			Long caller = null; try { caller = cs.getFuncId(); } catch( Exception e ) {}
			if( caller == null || !caller.equals(from) ) continue;
			if( ce.getValue().contains(to) ) return ce.getKey();
		}
		return null;
	}

	private static String pathSteps(java.util.List<Long> path, Long sinkNode, int line) {
		StringBuilder sb = new StringBuilder("[");
		for( int i = 0; i < path.size(); i++ ) {
			Long fnId = path.get(i);
			String nm = funcIdentity(fnId);
			if( i > 0 ) sb.append(",");
			sb.append("{kind=function,id=").append(fnId).append(",name=").append(nm).append("}");
			if( i < path.size()-1 )
				sb.append(",{kind=call_edge,from=").append(fnId).append(",to=").append(path.get(i+1))
				  .append(",resolution=RESOLVED,source=call2mtd}");
		}
		sb.append(",{kind=sink,id=").append(sinkNode).append(",line=").append(line).append("}]");
		return sb.toString();
	}

	/** Stable function identity (Class::method or function name) -- node ids are run-scoped, so a
	 *  fingerprint over them would differ for structurally identical paths. */
	private static String funcIdentity(Long fnId) {
		ASTNode fn = ASTUnderConstruction.idToNode.get(fnId);
		if( fn == null ) return "?";
		String nm = null;
		try { if( fn instanceof FunctionDef ) nm = ((FunctionDef)fn).getName(); } catch( Exception e ) {}
		if( nm == null || nm.isEmpty() ) {
			Object p = fn.getProperty("name");
			nm = (p == null) ? null : String.valueOf(p);
		}
		if( nm == null || "null".equals(nm) || nm.isEmpty() ) {
			HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(fnId);
			if( kids != null ) for( Long c : kids.values() ) {
				ASTNode cn = ASTUnderConstruction.idToNode.get(c);
				if( cn instanceof StringExpression ) { nm = ((StringExpression)cn).getEscapedCodeStr(); break; }
			}
		}
		if( nm == null || nm.isEmpty() ) nm = "anonymous";
		String cls = null;
		try { cls = fn.getEnclosingClass(); } catch( Exception e ) {}
		return ((cls == null || cls.isEmpty()) ? "" : cls + "::") + nm;
	}

	/** Relation of an authorization call to the node it must govern. STRICT_BRANCH / INVERTED_BRANCH
	 *  / EARLY_RETURN / DISCARDED / UNRELATED_BRANCH -- "observed on path" conflates all five. */
	private static String guardRelation(Long capCall, Long governed) {
		try {
			Long cur = capCall; boolean negated = false; Long condNode = null; int g = 0;
			while( cur != null && g++ < 64 ) {
				ASTNode n = ASTUnderConstruction.idToNode.get(cur);
				// FIX (2026-08-08): UnaryOperationExpression represents ANY unary operator in
				// this AST -- boolean-NOT (!), unary minus (-), unary plus (+), bitwise-NOT (~),
				// and error-suppression (@) all share this same node type, distinguished only by
				// flag. This toggled `negated` for any of them, not specifically logical negation
				// -- e.g. an @-suppressed capability call somewhere on the walk-up path to its
				// enclosing if-condition would incorrectly flip the polarity read for a completely
				// unrelated reason. Narrowed to check FLAG_UNARY_BOOL_NOT specifically, matching
				// the same distinction already correctly made in negatedOrDisjunctiveAncestor().
				if( n instanceof ast.expressions.UnaryOperationExpression
				    && PHPCSVNodeTypes.FLAG_UNARY_BOOL_NOT.equals(n.getFlags()) ) negated = !negated;
				if( n != null && ("AST_IF".equals(n.getProperty("type"))
				    || "AST_IF_ELEM".equals(n.getProperty("type"))) ) { condNode = cur; break; }
				cur = PHPCSVEdgeInterpreter.child2parent.get(cur);
			}
			if( condNode == null ) return "DISCARDED";
			boolean inside = false;
			java.util.ArrayDeque<Long> q = new java.util.ArrayDeque<Long>(); q.add(condNode);
			java.util.Set<Long> seen = new HashSet<Long>(); int gg = 0;
			while( !q.isEmpty() && gg++ < 20000 ) {
				Long x = q.poll();
				if( x == null || !seen.add(x) ) continue;
				if( x.equals(governed) ) { inside = true; break; }
				HashMap<Integer,Long> kids = PHPCSVEdgeInterpreter.parent2child.get(x);
				if( kids != null ) q.addAll(kids.values());
			}
			if( inside ) return negated ? "INVERTED_BRANCH" : "STRICT_BRANCH";
			if( negated ) {
				java.util.ArrayDeque<Long> q2 = new java.util.ArrayDeque<Long>(); q2.add(condNode);
				java.util.Set<Long> s2 = new HashSet<Long>(); int g2 = 0;
				while( !q2.isEmpty() && g2++ < 20000 ) {
					Long x = q2.poll();
					if( x == null || !s2.add(x) ) continue;
					ASTNode xn = ASTUnderConstruction.idToNode.get(x);
					if( xn != null && ("AST_RETURN".equals(xn.getProperty("type"))
					    || "AST_EXIT".equals(xn.getProperty("type"))) ) return "EARLY_RETURN";
					if( xn instanceof CallExpressionBase ) {
						String cn = callTargetName((CallExpressionBase)xn);
						if( cn != null && (cn.equals("wp_die") || cn.equals("die") || cn.equals("exit")
						    || cn.startsWith("wp_send_json_error")) ) return "EARLY_RETURN";
					}
					HashMap<Integer,Long> kk = PHPCSVEdgeInterpreter.parent2child.get(x);
					if( kk != null ) q2.addAll(kk.values());
				}
			}
			return "UNRELATED_BRANCH";
		} catch( Exception e ) { return "RELATION_UNRESOLVED"; }
	}

	/** Run-independent fingerprint over function identities, entry access, sink location, edge
	 *  resolution AND security evidence -- a changed guard relation changes the fingerprint. */
	private static String pathSemanticFingerprint(SecurityShape shape, java.util.List<Long> path,
	                                              Long sink, String access, String guardRels,
	                                              String edgeRes, int line) {
		StringBuilder sb = new StringBuilder();
		sb.append(shape.name).append("|access=").append(access).append("|chain=");
		for( Long p : path ) sb.append(funcIdentity(p)).append(">");
		sb.append("|sink=").append(getDir(sink)).append(":").append(line);
		sb.append("|edges=").append(edgeRes).append("|guards=").append(guardRels);
		try {
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			byte[] d = md.digest(sb.toString().getBytes("UTF-8"));
			StringBuilder h = new StringBuilder();
			for( int i = 0; i < 8; i++ ) h.append(String.format("%02x", d[i]));
			return h.toString();
		} catch( Exception e ) { return "UNAVAILABLE"; }
	}

}







