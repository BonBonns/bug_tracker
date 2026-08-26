import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE-S01 gate: StateWrite/StateRead semantics at the neutral API level,
 *  independent of any frontend. Ports the five JSTS-R02 rules verbatim. */
public final class CoreS01Test {
    static int pass = 0, total = 0;
    static void ck(String name, boolean ok, Object detail) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " - " + detail));
    }
    static FactDerivation d() { return new FactDerivation("FRONTEND_COMPOSED", "TEST", List.of(1L)); }

    public static void main(String[] args) {
        long F = 1;
        ValueRef box = ValueRef.parameter(10, "box");
        ValueRef other = ValueRef.parameter(11, "other");
        ValueRef src = ValueRef.parameter(12, "source");
        ValueRef key = ValueRef.parameter(13, "key");
        FunctionFact fn = new FunctionFact(F, "f", "t::f", "", "t.ts", 1, 9, false,
            List.of(new ParameterFact(10, F, 0, "box", "box", "", 1),
                    new ParameterFact(11, F, 1, "other", "other", "", 1),
                    new ParameterFact(12, F, 2, "source", "source", "", 1),
                    new ParameterFact(13, F, 3, "key", "key", "", 1)),
            "");

        // rule probes share one function; reads target different slots/receivers
        List<StateWriteFact> writes = List.of(
            new StateWriteFact(100, F, "INDEX", box, KeySelector.literal("a"), src, Resolution.EXACT, 2, d()),
            new StateWriteFact(101, F, "INDEX", box, KeySelector.literal("a"), ValueRef.constant("\"C\""), Resolution.EXACT, 3, d()),
            new StateWriteFact(102, F, "INDEX", box, KeySelector.literal("b"), src, Resolution.EXACT, 4, d()),
            new StateWriteFact(103, F, "INDEX", other, KeySelector.literal("c"), src, Resolution.EXACT, 5, d()),
            new StateWriteFact(104, F, "INDEX", box, KeySelector.dynamic("key"), src, Resolution.AMBIGUOUS, 6, d())
        );
        List<StateReadFact> reads = List.of(
            new StateReadFact(200, F, "INDEX", box, KeySelector.literal("a"), Resolution.EXACT, 7, d()),   // killed then polluted
            new StateReadFact(201, F, "INDEX", box, KeySelector.literal("b"), Resolution.EXACT, 7, d()),   // strong src + pollution
            new StateReadFact(202, F, "INDEX", other, KeySelector.literal("c"), Resolution.EXACT, 7, d()), // distinct receiver, clean
            new StateReadFact(203, F, "INDEX", other, KeySelector.literal("zz"), Resolution.EXACT, 7, d()),// never written slot
            new StateReadFact(204, F, "INDEX", box, KeySelector.dynamic("key"), Resolution.AMBIGUOUS, 7, d()) // dynamic read
        );
        // one function per read so each summary is observable via returns
        List<FunctionFact> fns = new ArrayList<>();
        List<ReturnFact> rets = new ArrayList<>();
        List<StateWriteFact> allW = new ArrayList<>();
        List<StateReadFact> allR = new ArrayList<>();
        for (int i = 0; i < reads.size(); i++) {
            long fid = 1000 + i;
            FunctionFact g = new FunctionFact(fid, "f" + i, "t::f" + i, "", "t.ts", 1, 9, false,
                List.of(new ParameterFact(fid * 10 + 0, fid, 0, "box", "box", "", 1),
                        new ParameterFact(fid * 10 + 1, fid, 1, "other", "other", "", 1),
                        new ParameterFact(fid * 10 + 2, fid, 2, "source", "source", "", 1),
                        new ParameterFact(fid * 10 + 3, fid, 3, "key", "key", "", 1)), "");
            fns.add(g);
            ValueRef bx = ValueRef.parameter(fid * 10 + 0, "box");
            ValueRef ot = ValueRef.parameter(fid * 10 + 1, "other");
            ValueRef sc = ValueRef.parameter(fid * 10 + 2, "source");
            for (StateWriteFact w : writes)
                allW.add(new StateWriteFact(fid * 100 + w.id(), fid, w.accessor(),
                    w.receiver().referencedId() == 10 ? bx : ot, w.key(),
                    w.value().kind() == ValueRef.Kind.PARAMETER ? sc : w.value(), w.resolution(), w.line(), w.derivation()));
            StateReadFact r0 = reads.get(i);
            long rid = fid * 100 + r0.id();
            allR.add(new StateReadFact(rid, fid, r0.accessor(),
                r0.receiver().referencedId() == 10 ? bx : ot, r0.key(), r0.resolution(), r0.line(), r0.derivation()));
            rets.add(new ReturnFact(fid * 100 + 90, fid, ValueRef.stateRead(rid, "read"), 8));
        }
        ProgramGraph g = new IndexedProgramGraph(new InMemoryProgramGraph("test", fns, List.of(), List.of(),
            rets, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), allW, allR));
        PortableProvenanceEngine e = new PortableProvenanceEngine(g);

        ProvenanceSummary killedThenPolluted = e.summarize(1000);
        ck("later exact overwrite kills, later dynamic pollutes -> AMBIGUOUS may={2}",
            killedThenPolluted.resolution() == Resolution.AMBIGUOUS
                && killedThenPolluted.provenPositions().isEmpty()
                && killedThenPolluted.mayPositions().equals(new TreeSet<>(Set.of(2))), killedThenPolluted);

        ProvenanceSummary strongPlusPollution = e.summarize(1001);
        // both the strong write and the polluting write carry source: position 2 is a
        // PROVEN COMMON DEPENDENCY over an ambiguous path (Gate-29 semantics) — the
        // resolution must not claim a hard path, but the position is guaranteed.
        ck("strong write + receiver pollution -> AMBIGUOUS resolution, common dep proven={2}",
            strongPlusPollution.resolution() == Resolution.AMBIGUOUS
                && strongPlusPollution.provenPositions().equals(new TreeSet<>(Set.of(2)))
                && strongPlusPollution.mayPositions().isEmpty(), strongPlusPollution);

        ProvenanceSummary distinct = e.summarize(1002);
        ck("distinct receiver, unpolluted slot -> EXACT proven={2} (no cross-flow from box's dynamic write)",
            distinct.resolution() == Resolution.EXACT
                && distinct.provenPositions().equals(new TreeSet<>(Set.of(2))), distinct);

        ProvenanceSummary unwritten = e.summarize(1003);
        ck("never-written slot -> abstain (UNRESOLVED, no positions)",
            unwritten.resolution() == Resolution.UNRESOLVED
                && unwritten.provenPositions().isEmpty() && unwritten.mayPositions().isEmpty(), unwritten);

        ProvenanceSummary dyn = e.summarize(1004);
        ck("dynamic read -> AMBIGUOUS MAY over all receiver writes, nothing proven",
            dyn.resolution() == Resolution.AMBIGUOUS && dyn.provenPositions().isEmpty()
                && dyn.mayPositions().contains(2), dyn);

        // API-level invariants
        boolean threw = false;
        try { new StateWriteFact(1, F, "INDEX", box, KeySelector.dynamic("k"), src, Resolution.EXACT, 1, d()); }
        catch (IllegalArgumentException ex) { threw = true; }
        ck("DYNAMIC-key write cannot claim EXACT (record validation)", threw, "no throw");

        ck("FactDerivation preserved through graph (audit visibility)",
            g.stateWrites().get(0).derivation().rule().equals("TEST"), g.stateWrites().get(0).derivation());

        System.out.println("CORE_S01=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
