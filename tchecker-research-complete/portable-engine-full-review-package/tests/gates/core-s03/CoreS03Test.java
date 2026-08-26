import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE-S03 gate: CaptureFact semantics at the neutral API level (JSTS-R04 ported).
 *  Capture is a lexical binding relationship; provenance comes from the outer
 *  binding's own facts (params, single-def locals, multi-def MAY locals). */
public final class CoreS03Test {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d() { return new FactDerivation("FRONTEND_DIRECT", "CLOSURE_BINDING_REF", List.of(1L)); }

    public static void main(String[] args) {
        long OUTER = 1, LAM = 2, MID = 3, LAM2 = 4;
        // outer(source) { const x-defs...; return lam(); }   lam() { return <inner local>; }
        FunctionFact outer = new FunctionFact(OUTER, "outer", "t::outer", "", "t", 1, 9, false,
            List.of(new ParameterFact(10, OUTER, 0, "source", "source", "", 1)), "");
        FunctionFact lam = new FunctionFact(LAM, "lam", "t::outer:lam", "", "t", 2, 3, false, List.of(), "");
        LocalFact innerSrc = new LocalFact(50, LAM, "source", "", 2);   // materialized capture local
        LocalFact outerX = new LocalFact(60, OUTER, "x", "", 1);
        // graph builder helper
        java.util.function.BiFunction<List<CaptureFact>, List<AssignmentFact>, ProgramGraph> build =
            (caps, assigns) -> new IndexedProgramGraph(new InMemoryProgramGraph("test",
                List.of(outer, lam), List.of(),
                List.of(new CallFact(100, OUTER, "lam", "t::outer:lam", "", "", "lam()", "t", 8,
                    List.of(LAM), List.of("t::outer:lam"), Resolution.EXACT, List.of(), null)),
                List.of(new ReturnFact(200, LAM, ValueRef.local(50, "source"), 3),
                        new ReturnFact(201, OUTER, ValueRef.call(100, "lam()"), 8)),
                List.of(innerSrc, outerX), assigns,
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), caps));

        // 1. direct capture of a parameter -> EXACT [0]
        ProvenanceSummary direct = new PortableProvenanceEngine(build.apply(
            List.of(new CaptureFact(LAM, 50, "source", OUTER, 10, "source",
                CaptureFact.OuterKind.PARAMETER, Resolution.EXACT, d())), List.of())).summarize(OUTER);
        ck("direct param capture -> EXACT proven={0}",
            direct.resolution() == Resolution.EXACT && direct.provenPositions().equals(new TreeSet<>(Set.of(0))), direct);

        // 2. capture of a multi-def local -> MAY {0}, never EXACT (mutation semantics)
        ProvenanceSummary mut = new PortableProvenanceEngine(build.apply(
            List.of(new CaptureFact(LAM, 50, "x", OUTER, 60, "x",
                CaptureFact.OuterKind.LOCAL, Resolution.EXACT, d())),
            List.of(new AssignmentFact(300, OUTER, 60, ValueRef.parameter(10, "source"), 2),
                    new AssignmentFact(301, OUTER, 60, ValueRef.constant("\"C\""), 3)))).summarize(OUTER);
        ck("captured multi-def local -> AMBIGUOUS may={0}, never hardened",
            mut.resolution() == Resolution.AMBIGUOUS && mut.provenPositions().isEmpty()
                && mut.mayPositions().equals(new TreeSet<>(Set.of(0))), mut);

        // 3. chain terminating in a FOREIGN function -> abstain
        ProvenanceSummary foreign = new PortableProvenanceEngine(build.apply(
            List.of(new CaptureFact(LAM, 50, "source", MID, 99, "source",
                CaptureFact.OuterKind.PARAMETER, Resolution.EXACT, d())), List.of())).summarize(OUTER);
        ck("capture chain ending outside the caller -> abstain",
            foreign.provenPositions().isEmpty() && foreign.mayPositions().isEmpty() && foreign.unknown(), foreign);

        // 4. two-hop transitive chain: inner local 50 -> mid local 70 -> outer param 10
        LocalFact midLocal = new LocalFact(70, MID, "source", "", 4);
        FunctionFact midFn = new FunctionFact(MID, "mid", "t::outer:mid", "", "t", 4, 5, false, List.of(), "");
        ProgramGraph g2 = new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(outer, lam, midFn), List.of(),
            List.of(new CallFact(100, OUTER, "lam", "t::outer:lam", "", "", "lam()", "t", 8,
                List.of(LAM), List.of("t::outer:lam"), Resolution.EXACT, List.of(), null)),
            List.of(new ReturnFact(200, LAM, ValueRef.local(50, "source"), 3),
                    new ReturnFact(201, OUTER, ValueRef.call(100, "lam()"), 8)),
            List.of(innerSrc, outerX, midLocal), List.of(),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
            List.of(new CaptureFact(LAM, 50, "source", MID, 70, "source", CaptureFact.OuterKind.LOCAL, Resolution.EXACT, d()),
                    new CaptureFact(MID, 70, "source", OUTER, 10, "source", CaptureFact.OuterKind.PARAMETER, Resolution.EXACT, d()))));
        ProvenanceSummary twoHop = new PortableProvenanceEngine(g2).summarize(OUTER);
        ck("two-hop transitive capture -> EXACT proven={0}",
            twoHop.resolution() == Resolution.EXACT && twoHop.provenPositions().equals(new TreeSet<>(Set.of(0))), twoHop);

        // 5. record invariant
        boolean threw = false;
        try { new CaptureFact(LAM, 50, "s", OUTER, 0, "s", CaptureFact.OuterKind.LOCAL, Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { threw = true; }
        ck("EXACT capture requires a concrete outer node (record validation)", threw, "no throw");

        System.out.println("CORE_S03=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
