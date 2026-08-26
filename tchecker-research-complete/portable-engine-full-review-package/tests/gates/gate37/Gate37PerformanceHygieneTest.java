import portable.graph.*;
import portable.provenance.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public final class Gate37PerformanceHygieneTest {
    private static int pass = 0;
    private static int total = 0;

    private static void check(String name, boolean ok) {
        total++;
        if (!ok) throw new AssertionError("FAIL " + name);
        pass++;
        System.out.println("PASS " + name);
    }

    private static FunctionFact fn(long id, String name, List<ParameterFact> params) {
        return new FunctionFact(id, name, name, "", "gate37", 1, 1, false, params, "any");
    }

    private static ParameterFact param(long id, long fid, int index, String name) {
        return new ParameterFact(id, fid, index, name, name, "any", 1);
    }

    private static InMemoryProgramGraph smallGraph() {
        ParameterFact p0 = param(101, 1, 0, "x");
        FunctionFact id = fn(1, "identity", List.of(p0));
        ReturnFact r1 = new ReturnFact(201, 1, ValueRef.parameter(101, "x"), 1);

        ParameterFact p1 = param(102, 2, 0, "input");
        FunctionFact wrap = fn(2, "wrap", List.of(p1));
        ArgumentFact a0 = new ArgumentFact(301, 0, "IDENTIFIER", "input", "input", "any", 2, ValueRef.parameter(102, "input"));
        CallFact call = new CallFact(401, 2, "identity", "identity", "STATIC", "any", "identity(input)", "gate37", 2,
            List.of(1L), List.of("identity"), Resolution.EXACT, List.of(a0));
        ReturnFact r2 = new ReturnFact(202, 2, ValueRef.call(401, "identity(input)"), 2);
        LocalFact local = new LocalFact(501, 2, "tmp", "any", 2);
        AssignmentFact assignment = new AssignmentFact(601, 2, 501, ValueRef.parameter(102, "input"), 2);
        return new InMemoryProgramGraph("gate37", List.of(id, wrap), List.of(), List.of(call), List.of(r1, r2), List.of(local), List.of(assignment));
    }

    private static final class CountingList<T> extends AbstractList<T> implements RandomAccess {
        private final List<T> delegate;
        private final AtomicLong reads;
        CountingList(List<T> delegate, AtomicLong reads) { this.delegate = delegate; this.reads = reads; }
        @Override public T get(int index) { reads.incrementAndGet(); return delegate.get(index); }
        @Override public int size() { return delegate.size(); }
    }

    private static final class CountingGraph implements ProgramGraph {
        private final List<FunctionFact> functions;
        CountingGraph(List<FunctionFact> functions, AtomicLong reads) { this.functions = new CountingList<>(functions, reads); }
        public String frontend() { return "counting"; }
        public List<FunctionFact> functions() { return functions; }
        public List<TypeDeclFact> typeDecls() { return List.of(); }
        public List<CallFact> calls() { return List.of(); }
        public List<ReturnFact> returns() { return List.of(); }
        public List<LocalFact> locals() { return List.of(); }
        public List<AssignmentFact> assignments() { return List.of(); }
        public List<PersistenceWriteFact> persistenceWrites() { return List.of(); }
        public List<PersistenceReadFact> persistenceReads() { return List.of(); }
        public List<StateChannelWriteFact> stateChannelWrites() { return List.of(); }
        public List<StateChannelReadFact> stateChannelReads() { return List.of(); }
    }

    public static void main(String[] args) {
        InMemoryProgramGraph base = smallGraph();
        IndexedProgramGraph indexed = new IndexedProgramGraph(base);

        check("indexed_function_lookup_semantics", base.function(2).equals(indexed.function(2)));
        check("indexed_call_lookup_semantics", base.call(401).equals(indexed.call(401)));
        check("indexed_local_lookup_semantics", base.local(501).equals(indexed.local(501)));
        check("indexed_returns_group_semantics", base.returnsIn(2).equals(indexed.returnsIn(2)));
        check("indexed_calls_group_semantics", base.callsIn(2).equals(indexed.callsIn(2)));
        check("indexed_assignment_group_semantics", base.assignmentsTo(2,501).equals(indexed.assignmentsTo(2,501)));

        ProvenanceSummary before = new PortableProvenanceEngine(base).summarize(2);
        ProvenanceSummary after = new PortableProvenanceEngine(indexed).summarize(2);
        check("provenance_identical_after_indexing", before.equals(after) && after.provenPositions().equals(Set.of(0)));

        // Duplicate IDs must fail closed; an index must never silently choose one record.
        boolean duplicateRejected = false;
        try {
            new IndexedProgramGraph(new InMemoryProgramGraph("dup", List.of(fn(7,"a",List.of()), fn(7,"b",List.of())), List.of(), List.of()));
        } catch (IllegalArgumentException expected) { duplicateRejected = expected.getMessage().contains("duplicate function id"); }
        check("duplicate_ids_rejected", duplicateRejected);

        // Existing graph/fact records defensively snapshot caller-owned lists.
        ArrayList<FunctionFact> mutableFunctions = new ArrayList<>();
        mutableFunctions.add(fn(10,"one",List.of()));
        InMemoryProgramGraph snap = new InMemoryProgramGraph("snapshot", mutableFunctions, List.of(), List.of());
        mutableFunctions.add(fn(11,"two",List.of()));
        check("program_graph_defensive_copy", snap.functions().size() == 1);

        ArrayList<ParameterFact> mutableParams = new ArrayList<>();
        mutableParams.add(param(800,80,0,"x"));
        FunctionFact snappedFn = fn(80,"snap",mutableParams);
        mutableParams.clear();
        check("function_fact_defensive_copy", snappedFn.parameters().size() == 1);

        ArrayList<Long> mutableTargets = new ArrayList<>(List.of(1L));
        CallFact snappedCall = new CallFact(900,2,"identity","identity","STATIC","any","identity(input)","gate37",2,
            mutableTargets, new ArrayList<>(List.of("identity")), Resolution.EXACT, new ArrayList<>(List.of(new ArgumentFact(901,0,"IDENTIFIER","input","input","any",2,ValueRef.parameter(102,"input")))));
        mutableTargets.set(0, 999L);
        check("call_fact_defensive_copy", snappedCall.candidateTargetIds().equals(List.of(1L)));

        // Measured complexity test: ProgramGraph defaults linearly scan functions; indexed view scans once at construction.
        int n = 20_000;
        ArrayList<FunctionFact> many = new ArrayList<>(n);
        for (int i=0; i<n; i++) many.add(fn(10_000L+i, "f"+i, List.of()));
        AtomicLong reads = new AtomicLong();
        CountingGraph counting = new CountingGraph(many, reads);
        for (int i=0; i<100; i++) counting.function(10_000L+n-1).orElseThrow();
        long linearReads = reads.get();
        reads.set(0);
        IndexedProgramGraph fast = new IndexedProgramGraph(counting);
        long buildReads = reads.get();
        reads.set(0);
        for (int i=0; i<100; i++) fast.function(10_000L+n-1).orElseThrow();
        long indexedLookupReads = reads.get();
        System.out.println("MEASURE linear_list_reads="+linearReads+" index_build_reads="+buildReads+" indexed_lookup_list_reads="+indexedLookupReads);
        check("linear_scan_cost_is_measured", linearReads >= (long)n * 100);
        check("index_build_is_single_scan", buildReads >= n && buildReads < (long)n * 2);
        check("indexed_lookup_avoids_backing_list_scan", indexedLookupReads == 0);

        System.out.println("GATE37="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}
