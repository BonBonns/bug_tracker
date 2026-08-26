import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE gate for the expression family: combined values carry all operand
 *  origins as POSSIBILITIES, never as proof; unresolved operands leave the
 *  result unknown; the record forbids EXACT outright. */
public final class CoreExpressionTest {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d() { return new FactDerivation("FRONTEND_DERIVED", "EXPRESSION_OPERANDS", List.of(1L)); }

    static ProgramGraph build(List<ValueRef> operands) {
        FunctionFact f = new FunctionFact(1, "combine", "t::combine", "", "t", 1, 3, false,
            List.of(new ParameterFact(10, 1, 0, "a", "a", "", 1),
                    new ParameterFact(11, 1, 1, "b", "b", "", 1)), "");
        return new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(f), List.of(), List.of(), List.of(new ReturnFact(200, 1, ValueRef.call(100, "a + b"), 2)),
            List.of(new LocalFact(50, 1, "u", "", 2)), List.of(),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
            List.of(), List.of(),
            List.of(new ExpressionFact(100, 1, "<operator>.addition", operands, Resolution.AMBIGUOUS, d()))));
    }

    public static void main(String[] args) {
        // 1. both operands resolvable -> MAY over both, never proven, never EXACT
        ProvenanceSummary both = new PortableProvenanceEngine(build(
            List.of(ValueRef.parameter(10, "a"), ValueRef.parameter(11, "b")))).summarize(1);
        ck("combined value -> AMBIGUOUS may={0,1}, proven empty",
            both.resolution() == Resolution.AMBIGUOUS && both.provenPositions().isEmpty()
                && both.mayPositions().equals(new TreeSet<>(Set.of(0, 1))), both);

        // 2. one operand unresolvable -> the resolvable one still surfaces as MAY,
        //    and the result stays unknown (no silent completeness)
        ProvenanceSummary partial = new PortableProvenanceEngine(build(
            List.of(ValueRef.parameter(10, "a"), ValueRef.local(50, "u")))).summarize(1);
        // STATUS-R03 migration: evidence assertions unchanged; label only.
        ck("unresolved operand keeps unknown=true while may={0} survives",
            partial.resolution() == Resolution.POSSIBLE_UNBOUNDED && partial.provenPositions().isEmpty()
                && partial.mayPositions().equals(new TreeSet<>(Set.of(0))) && partial.unknown(), partial);

        // 3. a single-parameter expression can never become EXACT (the whole point)
        ProvenanceSummary same = new PortableProvenanceEngine(build(
            List.of(ValueRef.parameter(10, "a"), ValueRef.parameter(10, "a")))).summarize(1);
        ck("even identical operands stay AMBIGUOUS (never hardened to EXACT)",
            same.resolution() == Resolution.AMBIGUOUS && same.provenPositions().isEmpty()
                && same.mayPositions().equals(new TreeSet<>(Set.of(0))), same);

        // 4. constants contribute no origin but do not add uncertainty
        ProvenanceSummary konst = new PortableProvenanceEngine(build(
            List.of(ValueRef.parameter(10, "a"), ValueRef.constant("1")))).summarize(1);
        ck("constant operand adds no origin and no unknown",
            konst.mayPositions().equals(new TreeSet<>(Set.of(0))) && !konst.unknown(), konst);

        // 5. record invariants
        boolean t1 = false, t2 = false, t3 = false;
        try { new ExpressionFact(100, 1, "+", List.of(ValueRef.parameter(10, "a")), Resolution.AMBIGUOUS, d()); }
        catch (IllegalArgumentException e) { t1 = true; }
        try { new ExpressionFact(100, 1, "+", List.of(ValueRef.parameter(10, "a"), ValueRef.parameter(11, "b")), Resolution.EXACT, d()); }
        catch (IllegalArgumentException e) { t2 = true; }
        try { new ExpressionFact(100, 1, "+", List.of(ValueRef.parameter(10, "a"), ValueRef.parameter(11, "b")), Resolution.AMBIGUOUS, null); }
        catch (IllegalArgumentException e) { t3 = true; }
        ck("record forbids <2 operands, EXACT resolution, and missing derivation",
            t1 && t2 && t3, t1 + "/" + t2 + "/" + t3);

        System.out.println("CORE_EXPRESSION=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
