import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE-REACHINGDEF: the 7-point promotion gate for anchored reaching definitions. */
public final class CoreReachingDefTest {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d(String rule) { return new FactDerivation("FRONTEND_DERIVED", rule, List.of(1L)); }

    static final long FN = 1, P0 = 10, P1 = 11, LOC = 50, RET = 900;

    /** defs: (id, anchor, value); rd: def ids the frontend says reach the return. */
    static ProvenanceSummary run(List<AssignmentFact> defs, List<Long> reaching) {
        FunctionFact f = new FunctionFact(FN, "f", "t::f", "", "t", 1, 9, false,
            List.of(new ParameterFact(P0, FN, 0, "a", "a", "", 1),
                    new ParameterFact(P1, FN, 1, "b", "b", "", 1)), "");
        List<ReachingDefFact> rd = reaching == null ? List.of()
            : List.of(new ReachingDefFact(RET, FN, LOC, reaching, Resolution.EXACT, d("CFG_REACHING_DEFINITIONS_ANCHORED")));
        return new PortableProvenanceEngine(new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(f), List.of(), List.of(), List.of(new ReturnFact(RET, FN, ValueRef.local(LOC, "x"), 8)),
            List.of(new LocalFact(LOC, FN, "x", "", 2)), defs,
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
            List.of(), List.of(), List.of(), rd))).summarize(FN);
    }
    static AssignmentFact def(long id, long anchor, ValueRef v) {
        return new AssignmentFact(id, FN, LOC, v, 2, anchor);
    }

    public static void main(String[] args) {
        // 1. straight-line overwrite: only the later def reaches -> narrows to b
        ProvenanceSummary s1 = run(List.of(def(100, 100, ValueRef.parameter(P0, "a")),
                                           def(200, 200, ValueRef.parameter(P1, "b"))), List.of(200L));
        ck("1. straight-line overwrite narrows to the surviving def",
            s1.provenPositions().equals(new TreeSet<>(Set.of(1))) || s1.mayPositions().equals(new TreeSet<>(Set.of(1))), s1);

        // 2. branch merge: BOTH defs reach -> both retained as possibilities
        ProvenanceSummary s2 = run(List.of(def(100, 100, ValueRef.parameter(P0, "a")),
                                           def(200, 200, ValueRef.parameter(P1, "b"))), List.of(100L, 200L));
        ck("2. branch merge retains both reaching defs",
            s2.resolution() == Resolution.AMBIGUOUS && s2.provenPositions().isEmpty()
                && s2.mayPositions().equals(new TreeSet<>(Set.of(0, 1))), s2);

        // 3. loop-carried: no narrowing fact at all -> conservative behaviour unchanged
        ProvenanceSummary s3 = run(List.of(def(100, 100, ValueRef.parameter(P0, "a")),
                                           def(200, 200, ValueRef.parameter(P1, "b"))), null);
        ck("3. loop-carried (no fact emitted) stays conservative: MAY over all defs",
            s3.provenPositions().isEmpty() && s3.mayPositions().equals(new TreeSet<>(Set.of(0, 1))), s3);

        // 4+5. compound: rhs AND prior-value share one anchor; filtering by that
        //      anchor must retain BOTH (the prior-value def has no CFG node).
        List<AssignmentFact> compound = List.of(
            def(100, 100, ValueRef.constant("0")),                       // init, anchor 100
            def(300, 300, ValueRef.parameter(P1, "b")),                  // x += b  (rhs)
            def(301, 300, ValueRef.unknown("<prior value of x>")));      // x += b  (prior)
        ProvenanceSummary s4 = run(compound, List.of(300L, 301L));
        ck("4. compound: both contributions share the statement anchor and survive",
            s4.mayPositions().equals(new TreeSet<>(Set.of(1))) && s4.unknown(), s4);
        ck("5. CFG filtering never removes the PRIOR_VALUE contribution while its statement reaches",
            s4.unknown(), "prior-value contribution was dropped");

        // 6. the measured regression case: uncertainty must survive narrowing
        ck("6. utf8PrevCharLen shape stays unknown=true after narrowing", s4.unknown(), s4);

        // 7. narrowing must never manufacture a new EXACT/COMPLETE claim
        ProvenanceSummary s7 = run(compound, List.of(300L, 301L));
        ck("7. no EXACT/COMPLETE appears solely from reaching-def filtering",
            s7.resolution() != Resolution.EXACT && s7.completeness() != AnalysisCompleteness.COMPLETE, s7);

        System.out.println("CORE_REACHINGDEF=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
