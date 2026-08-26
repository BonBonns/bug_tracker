import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE gate for the memory fact families: record invariants, the graph's
 *  cross-validation (a declared location MUST correspond to a real local of the
 *  same function), and points-to must/may discipline. */
public final class CoreMemoryTest {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d() { return new FactDerivation("FRONTEND_DERIVED", "CPP_MEMORY_LOCATION", List.of(1L, 2L)); }

    static InMemoryProgramGraph base(List<MemoryLocationFact> mem, List<PointsToFact> pts, List<LocalFact> locals) {
        FunctionFact f = new FunctionFact(1, "f", "f:int(int)", "", "m.c", 1, 5, false,
            List.of(new ParameterFact(10, 1, 0, "input", "input", "", 1)), "");
        return new InMemoryProgramGraph("test", List.of(f), List.of(), List.of(),
            List.of(new ReturnFact(200, 1, ValueRef.local(50, "obj.field"), 4)),
            locals,
            List.of(new AssignmentFact(300, 1, 50, ValueRef.parameter(10, "input"), 2)),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), mem, pts);
    }

    public static void main(String[] args) {
        LocalFact loc = new LocalFact(50, 1, "obj.field", "", 2);
        MemoryLocationFact m = new MemoryLocationFact(50, 1, MemoryLocationFact.Kind.FIELD, 40, "field", "obj.field", Resolution.EXACT, d());

        // 1. valid family: loads, indexes, and provenance flows through the location
        ProgramGraph g = new IndexedProgramGraph(base(List.of(m), List.of(), List.of(loc)));
        ProvenanceSummary s = new PortableProvenanceEngine(g).summarize(1);
        ck("declared location cross-validates and value flows EXACT proven={0}",
            g.memoryLocation(50).isPresent() && s.resolution() == Resolution.EXACT
                && s.provenPositions().equals(new TreeSet<>(Set.of(0))), s);

        // 2. phantom location (no corresponding local) -> graph construction throws
        boolean phantom = false;
        try { new IndexedProgramGraph(base(List.of(m), List.of(), List.of())); }
        catch (IllegalArgumentException e) { phantom = true; }
        ck("location without a corresponding local is REFUSED at graph construction", phantom, "no throw");

        // 3. function-mismatch location -> refused
        boolean mismatch = false;
        try {
            new IndexedProgramGraph(base(
                List.of(new MemoryLocationFact(50, 999, MemoryLocationFact.Kind.FIELD, 40, "field", "obj.field", Resolution.EXACT, d())),
                List.of(), List.of(loc)));
        } catch (IllegalArgumentException e) { mismatch = true; }
        ck("location claiming a different function is REFUSED", mismatch, "no throw");

        // 4. record invariants: EXACT-needs-base/selector; derivation required
        boolean t1 = false, t2 = false, t3 = false;
        try { new MemoryLocationFact(50, 1, MemoryLocationFact.Kind.FIELD, 0, "field", "x", Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { t1 = true; }
        try { new MemoryLocationFact(50, 1, MemoryLocationFact.Kind.INDEX, 40, "", "x", Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { t2 = true; }
        try { new MemoryLocationFact(50, 1, MemoryLocationFact.Kind.FIELD, 40, "field", "x", Resolution.EXACT, null); }
        catch (IllegalArgumentException e) { t3 = true; }
        ck("memory-location record invariants enforced", t1 && t2 && t3, t1 + "/" + t2 + "/" + t3);

        // 5. points-to must/may discipline (identity-sibling semantics)
        PointsToFact must = new PointsToFact(1, 60, "p", List.of(50L), true, Resolution.EXACT, d());
        boolean p1 = false, p2 = false;
        try { new PointsToFact(1, 60, "p", List.of(50L, 51L), true, Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { p1 = true; }
        try { new PointsToFact(1, 60, "p", List.of(50L, 51L), false, Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { p2 = true; }
        ck("points-to must<=>singleton and MAY-cannot-be-EXACT enforced",
            must.must() && p1 && p2, p1 + "/" + p2);

        System.out.println("CORE_MEMORY=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
