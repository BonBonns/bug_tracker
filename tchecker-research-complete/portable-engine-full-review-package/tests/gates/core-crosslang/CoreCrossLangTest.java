import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE gate for the cross-language link family: the link is applied ONLY when
 *  frontend-native resolution could not prove dispatch, never weakens a
 *  frontend-proven EXACT, ignores non-EXACT links and links to absent callees,
 *  and every link must carry its derivation (record invariant). */
public final class CoreCrossLangTest {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d() { return new FactDerivation("FRONTEND_COMPOSED", "NAPI_BINDING_TABLE", List.of(1L, 2L)); }

    static ProgramGraph build(Resolution callRes, List<Long> callTargets, List<CrossLangLinkFact> links) {
        long CALLER = 1, NATIVE = 2, WRONG = 3;
        FunctionFact caller = new FunctionFact(CALLER, "wrap", "js::wrap", "", "w.js", 1, 3, false,
            List.of(new ParameterFact(10, CALLER, 0, "a", "a", "", 1)), "");
        FunctionFact nat = new FunctionFact(NATIVE, "dbl", "dbl:int(int)", "", "n.cc", 5, 7, false,
            List.of(new ParameterFact(20, NATIVE, 0, "x", "x", "", 5)), "");
        FunctionFact wrong = new FunctionFact(WRONG, "other", "other:int(int)", "", "n.cc", 9, 11, false,
            List.of(new ParameterFact(30, WRONG, 0, "y", "y", "", 9)), "");
        List<String> names = new ArrayList<>();
        for (long t : callTargets) names.add(t == NATIVE ? "dbl:int(int)" : "other:int(int)");
        CallFact call = new CallFact(100, CALLER, "dbl", "native.node:dbl", "DYNAMIC_DISPATCH", "",
            "native.dbl(a)", "w.js", 2, callTargets, names, callRes,
            List.of(new ArgumentFact(900, 0, "", "a", "a", "", 2, ValueRef.parameter(10, "a"))), null);
        List<ReturnFact> rets = List.of(
            new ReturnFact(200, CALLER, ValueRef.call(100, "native.dbl(a)"), 2),
            new ReturnFact(201, NATIVE, ValueRef.parameter(20, "x"), 6),
            new ReturnFact(202, WRONG, ValueRef.constant("\"C\""), 10));
        return new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(caller, nat, wrong), List.of(), List.of(call), rets, List.of(), List.of(),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), links));
    }

    public static void main(String[] args) {
        long NATIVE = 2, WRONG = 3;
        // 1. link overrides a HEURISTIC GUESS (naive candidate = the WRONG function)
        //    with the mechanically proven callee -> end-to-end EXACT [0]
        ProvenanceSummary linked = new PortableProvenanceEngine(build(Resolution.HEURISTIC, List.of(WRONG),
            List.of(new CrossLangLinkFact(100, NATIVE, "dbl", Resolution.EXACT, d())))).summarize(1);
        ck("proven link overrides an unproven heuristic guess -> flow EXACT proven={0}",
            linked.resolution() == Resolution.EXACT && linked.provenPositions().equals(new TreeSet<>(Set.of(0))), linked);

        // 2. frontend-proven EXACT is NEVER overridden, even by a conflicting link
        ProvenanceSummary fe = new PortableProvenanceEngine(build(Resolution.EXACT, List.of(WRONG),
            List.of(new CrossLangLinkFact(100, NATIVE, "dbl", Resolution.EXACT, d())))).summarize(1);
        ck("frontend EXACT wins over a conflicting link (constant target, no positions)",
            fe.resolution() == Resolution.EXACT && fe.provenPositions().isEmpty(), fe);

        // 3. non-EXACT link is ignored (no fabricated dispatch)
        ProvenanceSummary weak = new PortableProvenanceEngine(build(Resolution.HEURISTIC, List.of(WRONG),
            List.of(new CrossLangLinkFact(100, NATIVE, "dbl", Resolution.HEURISTIC, d())))).summarize(1);
        ck("non-EXACT link applies nothing", weak.provenPositions().isEmpty(), weak);

        // 4. link to a function absent from the graph is ignored
        ProvenanceSummary absent = new PortableProvenanceEngine(build(Resolution.HEURISTIC, List.of(WRONG),
            List.of(new CrossLangLinkFact(100, 999L, "dbl", Resolution.EXACT, d())))).summarize(1);
        ck("link to an absent callee applies nothing", absent.provenPositions().isEmpty(), absent);

        // 5. record invariants
        boolean t1 = false, t2 = false;
        try { new CrossLangLinkFact(100, 0, "dbl", Resolution.EXACT, d()); } catch (IllegalArgumentException e) { t1 = true; }
        try { new CrossLangLinkFact(100, NATIVE, "dbl", Resolution.EXACT, null); } catch (IllegalArgumentException e) { t2 = true; }
        ck("EXACT-needs-callee and derivation-required enforced by the record", t1 && t2, t1 + "/" + t2);

        System.out.println("CORE_CROSSLANG=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
