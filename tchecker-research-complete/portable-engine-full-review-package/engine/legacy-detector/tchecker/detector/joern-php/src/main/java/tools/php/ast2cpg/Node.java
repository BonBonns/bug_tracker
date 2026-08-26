package tools.php.ast2cpg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import misc.MultiHashMap;

public class Node {
	/** Diagnostic-only. Traces mutations of any HashMap<String,Long> used as `inter`, WITHOUT
	 *  changing map semantics or breaking aliasing -- callers still get a HashMap<String,Long>,
	 *  this only overrides put/putAll/compute/merge/replace to log key/value/stack when the key
	 *  matches a whole-object "::-1" suffix. */
	/** Diagnostic-only mutation-event DAG, per the reviewer's design. NOT production code.
	 *  Distinguishes semantic WRITE events from state-TRANSFER events, and records the SOURCE's
	 *  state-event-ID at transfer time (snapshot semantics) rather than mere map-instance identity
	 *  -- so a later write to the source map cannot appear to have been inherited by a copy that
	 *  happened BEFORE that write. Also preserves the transferred KEY SET on transfer events, since
	 *  whole-map ancestry alone cannot tell which specific key a given transfer is relevant to. */
	public static final class MutationEvent {
		public final long eventId, targetMapId;
		public final String kind;   // "WRITE" | "TRANSFER"
		public final java.util.List<Long> parentStateEventIds;
		public final String identityNode;    // WRITE only
		public final Long provenanceNode;    // WRITE only -- STATE identity (e.g. node.astId,
			// the statement whose live value legacy `inter` stores). Kept exactly as it always
			// was -- this is what the 601/601 synchronization validated and must not change.
		public final Long valueExpressionId; // WRITE only -- SEMANTIC identity (the RHS/value
			// expression actually responsible for the assigned value, e.g. a $_GET[...] AST_DIM
			// node). Captured at the PRODUCER site (recordInter/writeEvent), not reconstructed
			// after the fact by a consumer -- per the established methodology from RelatedEvidence/
			// InterEvidence. May be null if the state node isn't an AssignmentExpression or has no
			// RHS (recorded as such, not silently defaulted).
		public final java.util.Set<String> transferredKeys;   // TRANSFER only
		MutationEvent(long eventId, long targetMapId, String kind, java.util.List<Long> parents,
				String identityNode, Long provenanceNode, java.util.Set<String> transferredKeys) {
			this(eventId, targetMapId, kind, parents, identityNode, provenanceNode, null, transferredKeys);
		}
		MutationEvent(long eventId, long targetMapId, String kind, java.util.List<Long> parents,
				String identityNode, Long provenanceNode, Long valueExpressionId,
				java.util.Set<String> transferredKeys) {
			this.eventId=eventId; this.targetMapId=targetMapId; this.kind=kind;
			this.parentStateEventIds=parents; this.identityNode=identityNode;
			this.provenanceNode=provenanceNode; this.valueExpressionId=valueExpressionId;
			this.transferredKeys=transferredKeys;
		}
	}
	private static final java.util.concurrent.atomic.AtomicLong mutationEventCounter =
		new java.util.concurrent.atomic.AtomicLong(0);
	public static final java.util.Map<Long, MutationEvent> mutationEventLog =
		new java.util.concurrent.ConcurrentHashMap<Long, MutationEvent>();

	public static final class TracingInterMap extends HashMap<String, Long> {
		// -1 = no mutation event yet (freshly constructed, empty map). Advances on every WRITE or
		// TRANSFER via writeEvent()/copyFrom() below -- NOT via the plain put()/putAll() overrides,
		// which remain diagnostic-log-only (existing §34-36 behavior) and do not touch this DAG.
		public long currentStateEventId = -1;
		// CONSTRUCTOR TRACING (§87-88): settles whether a map reaches a consumer already-populated
		// (constructor/internal-copy population) or empty-then-mysteriously-populated (an unwired
		// lifecycle boundary after construction). Logs unconditionally on every construction when
		// MUTATION_DAG_DIAG is set, regardless of initial size -- the SIZE at creation is the decisive
		// fact, not merely that a MAP_CREATE event occurred.
		public TracingInterMap() {
			super();
			if(System.getenv("MUTATION_DAG_DIAG")!=null) {
				System.err.println("MAP_CREATE identity="+System.identityHashCode(this)+" initial_size=0 initial_keys=[]");
			}
		}
		public TracingInterMap(java.util.Map<String,Long> initial) {
			super(initial);
			if(System.getenv("MUTATION_DAG_DIAG")!=null) {
				System.err.println("MAP_CREATE identity="+System.identityHashCode(this)
					+" initial_size="+size()+" initial_keys="+keySet()+" VIA_COPY_CONSTRUCTOR=true");
				new Exception("MAP_CREATE_STACK").printStackTrace(System.err);
			}
		}
		/** Semantic write. Called explicitly by recordInter() (StaticAnalysis.java) alongside the
		 *  actual legacy .put() -- NOT wired into the overridden put() below, to keep this event only
		 *  where real producer context (identity/provenance) is actually available, per the reviewer's
		 *  "minimum semantically necessary" principle applied to InterEvidence earlier.
		 *  valueExpressionId (reviewer's §107-followup design): captured HERE, at the write site,
		 *  where the caller already has the AST context needed to determine it -- never
		 *  reconstructed by a downstream consumer. */
		public void writeEvent(String identity, long provenance, Long valueExpressionId) {
			if(System.getenv("MUTATION_DAG_DIAG")==null) return;
			long id = mutationEventCounter.incrementAndGet();
			java.util.List<Long> parents = (currentStateEventId==-1) ? java.util.Collections.emptyList()
				: java.util.Collections.singletonList(currentStateEventId);
			MutationEvent e = new MutationEvent(id, System.identityHashCode(this), "WRITE", parents,
				identity, provenance, valueExpressionId, null);
			mutationEventLog.put(id, e);
			currentStateEventId = id;
		}
		/** Explicit transfer -- NOT an overloaded putAll(), per the reviewer's exact caution: Java
		 *  overload resolution is by STATIC type at the call site, so a source held as a plain
		 *  HashMap<String,Long> (as `ret.inter`/`node.inter` are declared) would silently select a
		 *  generic putAll(Map) overload and the provenance edge would disappear again. This is a
		 *  SINGLE method (no overload to misdispatch to), taking the same static type the existing
		 *  call sites already use, and checking dynamically whether the source is itself traced. */
		public void copyFrom(HashMap<String, Long> source) {
			for(String k : source.keySet()) watchCheck("copyFrom", k, source.get(k));
			super.putAll(source);   // actual data transfer -- UNCHANGED legacy behavior
			if(System.getenv("MUTATION_DAG_DIAG")==null) return;
			// INVARIANT (§83): a copyFrom() source that is NOT itself a TracingInterMap means its own
			// mutation history is entirely invisible -- ancestry silently truncates at this point. This
			// must NOT fail silently (it did, in §82's ctorInterPatch finding -- parentId=-1 looked
			// identical to a genuine fresh-map root, masking a real ancestry gap as a legitimate one).
			if(!(source instanceof TracingInterMap) && !source.isEmpty()) {
				System.err.println("DIAGNOSTIC_INVARIANT_VIOLATION copyFrom received untracked non-empty "
					+"inter source -- ancestry truncated. source_class="+source.getClass().getName()
					+" keys="+source.keySet());
				if("throw".equals(System.getenv("MUTATION_DAG_DIAG")))
					throw new IllegalStateException("copyFrom received untracked inter source: "+source.getClass());
			}
			// FIX (§88): a SECOND (or Nth) copyFrom() call on the SAME destination must NOT discard
			// the destination's own prior state -- it must be recorded as an ADDITIONAL parent,
			// mirroring mergeOverwrite()'s two-parent design. The original single-parent-only version
			// silently orphaned earlier transfers when copyFrom was called multiple times into the
			// same map (confirmed root cause of the corpus STATE_SYNC_GATE failures, §87-88).
			long sourceParentId = -1;
			if(source instanceof TracingInterMap) sourceParentId = ((TracingInterMap) source).currentStateEventId;
			long destPriorId = this.currentStateEventId;
			long id = mutationEventCounter.incrementAndGet();
			java.util.List<Long> parents = new java.util.ArrayList<Long>();
			if(destPriorId != -1) parents.add(destPriorId);
			if(sourceParentId != -1 && sourceParentId != destPriorId) parents.add(sourceParentId);
			MutationEvent e = new MutationEvent(id, System.identityHashCode(this), "TRANSFER", parents,
				null, null, new java.util.HashSet<String>(source.keySet()));
			mutationEventLog.put(id, e);
			currentStateEventId = id;
		}
		/** Direct join overwrite (the CFG-join reuse-overwrite mechanism, §80). Records key, old/new
		 *  value, and BOTH sides' prior state-event -- this was the confirmed desynchronization site. */
		public void mergeOverwrite(String key, long incomingValue, long targetPriorState, long sourceStateId) {
			Long oldValue = get(key);
			watchCheck("mergeOverwrite", key, incomingValue);
			super.put(key, incomingValue);
			if(System.getenv("MUTATION_DAG_DIAG")==null) return;
			java.util.List<Long> parents = new java.util.ArrayList<Long>();
			if(targetPriorState != -1) parents.add(targetPriorState);
			if(sourceStateId != -1 && sourceStateId != targetPriorState) parents.add(sourceStateId);
			long id = mutationEventCounter.incrementAndGet();
			MutationEvent e = new MutationEvent(id, System.identityHashCode(this), "MERGE_OVERWRITE", parents,
				key, incomingValue, null);
			mutationEventLog.put(id, e);
			currentStateEventId = id;
			if(System.getenv("FALLBACK_DIAG")!=null)
				System.err.println("MERGE_OVERWRITE_EVENT eventId="+id+" key="+key+" old="+oldValue
					+" new="+incomingValue+" targetPriorState="+targetPriorState+" sourceStateId="+sourceStateId);
		}
		/** Selective copy-forward (the 3 RemoveInterTaint filter-copy loops, §82). The excluded-key
		 *  set IS part of the semantics -- a plain copyFrom() would misrepresent this as an unfiltered
		 *  transfer. Records only the ACTUALLY-transferred keys, not the source's full key set. */
		/** RESET event (§85/90): clean() performs a KILL, not a copy or merge -- the prior map's
		 *  entire history is intentionally discarded and replaced with a genuinely fresh state.
		 *  Unlike copyFrom/mergeOverwrite (which preserve continuity), a reset should NOT link the
		 *  new map's ancestry to the old map's -- that would misrepresent discarded history as
		 *  live provenance. Instead this records, on the OLD map itself, that it was terminated
		 *  here, so an auditor walking backward from anywhere that captured a reference to the old
		 *  map can see it was deliberately reset rather than silently abandoned or lost.
		 *  Called on the OLD map being discarded, not the new one replacing it. */
		public void recordReset(long stmt) {
			if(System.getenv("MUTATION_DAG_DIAG")==null) return;
			long id = mutationEventCounter.incrementAndGet();
			java.util.List<Long> parents = (currentStateEventId==-1) ? java.util.Collections.emptyList()
				: java.util.Collections.singletonList(currentStateEventId);
			MutationEvent e = new MutationEvent(id, System.identityHashCode(this), "RESET", parents,
				null, null, null);
			mutationEventLog.put(id, e);
			System.err.println("MAP_RESET stmt="+stmt+" old_map="+System.identityHashCode(this)
				+" old_currentStateEventId="+currentStateEventId+" reset_event="+id
				+" keys_discarded="+keySet());
		}
		public void copySelectedFrom(HashMap<String, Long> source, java.util.Set<String> transferredKeys) {
			for(String k : transferredKeys) if(source.containsKey(k)) { watchCheck("copySelectedFrom", k, source.get(k)); super.put(k, source.get(k)); }
			if(System.getenv("MUTATION_DAG_DIAG")==null) return;
			if(!(source instanceof TracingInterMap) && !transferredKeys.isEmpty()) {
				System.err.println("DIAGNOSTIC_INVARIANT_VIOLATION copySelectedFrom received untracked "
					+"non-empty inter source -- ancestry truncated. source_class="+source.getClass().getName());
				if("throw".equals(System.getenv("MUTATION_DAG_DIAG")))
					throw new IllegalStateException("copySelectedFrom received untracked inter source: "+source.getClass());
			}
			// FIX (§88): same defect as copyFrom() -- must record the destination's own prior state
			// as an additional parent, not just the source's.
			long sourceParentId = -1;
			if(source instanceof TracingInterMap) sourceParentId = ((TracingInterMap) source).currentStateEventId;
			long destPriorId = this.currentStateEventId;
			long id = mutationEventCounter.incrementAndGet();
			java.util.List<Long> parents = new java.util.ArrayList<Long>();
			if(destPriorId != -1) parents.add(destPriorId);
			if(sourceParentId != -1 && sourceParentId != destPriorId) parents.add(sourceParentId);
			MutationEvent e = new MutationEvent(id, System.identityHashCode(this), "SELECTIVE_TRANSFER",
				parents, null, null, new java.util.HashSet<String>(transferredKeys));
			mutationEventLog.put(id, e);
			currentStateEventId = id;
		}

		private static final java.util.concurrent.atomic.AtomicLong totalMutations =
			new java.util.concurrent.atomic.AtomicLong(0);
		public long totalMutationsOnThisMap = 0;
		public String firstMutationStack = null, lastMutationStack = null;
		private static String stackString() {
			StackTraceElement[] t = Thread.currentThread().getStackTrace();
			StringBuilder b = new StringBuilder();
			for(int i=3;i<Math.min(t.length,9);i++) b.append(t[i].getMethodName()).append(":").append(t[i].getLineNumber()).append("<-");
			return b.toString();
		}
		private void recordHistory() {
			totalMutationsOnThisMap++;
			String st = stackString();
			if(firstMutationStack == null) firstMutationStack = st;
			lastMutationStack = st;
		}
		@Override public Long remove(Object key) {
			if(System.getenv("INTER_TRACE_DIAG")!=null) recordHistory();
			return super.remove(key);
		}
		@Override public boolean remove(Object key, Object value) {
			if(System.getenv("INTER_TRACE_DIAG")!=null) recordHistory();
			return super.remove(key, value);
		}
		@Override public void clear() {
			if(System.getenv("INTER_TRACE_DIAG")!=null) {
				recordHistory();
				System.err.println("INTER_CLEAR map="+System.identityHashCode(this)+" size_before="+size());
			}
			super.clear();
		}
		private void trace(String op, String key, Long value, Long previous) {
			if(System.getenv("INTER_TRACE_DIAG")!=null) { totalMutations.incrementAndGet(); recordHistory(); }
			if(key != null && key.endsWith("::-1")) {
				System.err.printf("INTER_WRITE op=%s map=%d key=%s value=%s previous=%s%n",
					op, System.identityHashCode(this), key, value, previous);
				new Exception("INTER_WRITE_STACK").printStackTrace(System.err);
			}
		}
		/** TARGETED WATCH: catches a SPECIFIC key/value pair being inserted, regardless of WHICH Java
		 *  operation performs it -- must be called from EVERY mutation entry point (put, putAll,
		 *  copyFrom, copySelectedFrom, mergeOverwrite, compute*, merge, replace*), not just the base
		 *  put() override, since several of those call super.put()/super.putAll() directly to avoid
		 *  double-logging through this class's own diagnostic layer -- which would otherwise make
		 *  the watch blind to exactly the paths most worth checking. Set WATCH_KEY=<identity> and
		 *  optionally WATCH_VALUE=<provenance>. */
		private void watchCheck(String op, String key, Long value) {
			String watchKey = System.getenv("WATCH_KEY");
			if(watchKey == null || !watchKey.equals(key)) return;
			String watchValue = System.getenv("WATCH_VALUE");
			if(watchValue != null && !watchValue.equals(String.valueOf(value))) return;
			System.err.println("WATCH_HIT op="+op+" key="+key+" value="+value+" previous="+get(key)
				+" map="+System.identityHashCode(this)+" mapClass="+this.getClass().getName()
				+" currentStateEventId="+currentStateEventId+" mapKeysBefore="+keySet());
			new Exception("WATCH_HIT_STACK").printStackTrace(System.err);
		}
		@Override public Long put(String key, Long value) {
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("put", key, value, get(key));
			watchCheck("put", key, value);
			return super.put(key, value);
		}
		@Override public void putAll(java.util.Map<? extends String, ? extends Long> values) {
			if(System.getenv("INTER_TRACE_DIAG")!=null)
				for(java.util.Map.Entry<? extends String, ? extends Long> e : values.entrySet())
					trace("putAll", e.getKey(), e.getValue(), get(e.getKey()));
			for(java.util.Map.Entry<? extends String, ? extends Long> e : values.entrySet())
				watchCheck("putAll", e.getKey(), e.getValue());
			super.putAll(values);
		}
		@Override public Long compute(String key, java.util.function.BiFunction<? super String, ? super Long, ? extends Long> f) {
			Long r = super.compute(key, f);
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("compute", key, r, null);
			return r;
		}
		@Override public Long merge(String key, Long value, java.util.function.BiFunction<? super Long, ? super Long, ? extends Long> f) {
			Long r = super.merge(key, value, f);
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("merge", key, r, null);
			return r;
		}
		@Override public Long replace(String key, Long value) {
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("replace", key, value, get(key));
			return super.replace(key, value);
		}
		@Override public Long computeIfAbsent(String key, java.util.function.Function<? super String, ? extends Long> f) {
			Long r = super.computeIfAbsent(key, f);
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("computeIfAbsent", key, r, null);
			return r;
		}
		@Override public Long computeIfPresent(String key, java.util.function.BiFunction<? super String, ? super Long, ? extends Long> f) {
			Long r = super.computeIfPresent(key, f);
			if(System.getenv("INTER_TRACE_DIAG")!=null) trace("computeIfPresent", key, r, null);
			return r;
		}
		@Override public void replaceAll(java.util.function.BiFunction<? super String, ? super Long, ? extends Long> f) {
			super.replaceAll(f);
			if(System.getenv("INTER_TRACE_DIAG")!=null)
				for(java.util.Map.Entry<String,Long> e : entrySet()) trace("replaceAll", e.getKey(), e.getValue(), null);
		}
	}

	private static final java.util.Set<Integer> seenUntracedInter = java.util.Collections.synchronizedSet(new java.util.HashSet<Integer>());
	private static final java.util.Map<Integer,Integer> untracedReuseCount = new java.util.concurrent.ConcurrentHashMap<Integer,Integer>();
	public static void dumpMutationTotal() {
		System.err.println("TOTAL_INTER_MUTATIONS " + TracingInterMap.totalMutations.get());
	}
	public static void dumpUntracedSummary() {
		System.err.println("UNTRACED_SUMMARY unique_maps=" + seenUntracedInter.size());
		for(java.util.Map.Entry<Integer,Integer> e : untracedReuseCount.entrySet())
			System.err.println("  map=" + e.getKey() + " reuse_count=" + e.getValue());
	}
	public List<Node> children = null;
	public HashMap<String, Long> inter = new HashMap<String, Long>();
	public Set<Long> intro = new HashSet<Long>();
	public Long astId = null;
	//public Long nodeId = null;
	public Stack<Long> caller = null;
	public Long parent = null;
	
	
	//the id and identity of the AST Node 
	public Node(Long astId, HashMap<String, Long> inter, Set<Long> intro, Stack<Long> caller) {
		//the node ID
		//this.nodeId=nodeId;
		//current stmt ID
		this.astId=astId; //the ASTID of this statement 
		//previous taint state
		this.inter=inter; //the related inter variables identities and where they are assigned
		this.intro=intro; //the related intro statememt within the function
		this.caller=caller; //the caller of the statement, represented using its node ID
		this.children=new ArrayList<>();
		if(System.getenv("INTER_TRACE_DIAG")!=null && !(inter instanceof TracingInterMap)) {
			int id = System.identityHashCode(inter);
			if(seenUntracedInter.add(id)) {
				System.err.printf("FIRST_UNTRACED_INTER map=%d ast=%d runtime_class=%s size=%d keys=%s%n",
					id, astId, inter.getClass().getName(), inter.size(), inter.keySet());
				if("throw".equals(System.getenv("INTER_TRACE_DIAG"))) {
					throw new RuntimeException("FIRST_UNTRACED_INTER map=" + id + " ast=" + astId, new Exception("stack"));
				}
				new Exception("FIRST_UNTRACED_INTER_STACK").printStackTrace(System.err);
			} else {
				untracedReuseCount.merge(id, 1, Integer::sum);
			}
		}
		if(System.getenv("NODE_DIAG")!=null) {
			String want = System.getenv("NODE_DIAG");
			if(want.equals("*") || want.equals(String.valueOf(astId))) {
				Node prev = StaticAnalysis.ID2Node.get(astId);
				StackTraceElement[] st = Thread.currentThread().getStackTrace();
				String site = "?";
				for(StackTraceElement e : st)
					if(e.getClassName().endsWith("StaticAnalysis")) { site = e.getMethodName()+":"+e.getLineNumber(); break; }
				System.err.println("NODEDIAG seq=" + (++StaticAnalysis.nodeDiagSeq)
					+ " astId=" + astId
					+ " new_id=" + System.identityHashCode(this)
					+ " new_caller=" + caller
					+ " prev_id=" + (prev==null?0:System.identityHashCode(prev))
					+ " prev_caller=" + (prev==null?"none":String.valueOf(prev.caller))
					+ " java_site=" + site);
			}
		}
		StaticAnalysis.ID2Node.put(astId, this);
	}
	
	public Node (Node node) {
		//this.nodeId=node.nodeId;
		this.astId=node.astId;
		this.inter=node.inter;
		this.intro=node.intro;
		this.caller=node.caller;
		this.children=node.children;
	}
	
	public void addChild(Node child) {
		//children.add(child);
		child.parent=this.astId;
	}
}
