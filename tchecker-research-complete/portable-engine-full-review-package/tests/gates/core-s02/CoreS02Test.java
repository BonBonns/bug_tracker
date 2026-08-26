import portable.graph.*;
import portable.provenance.*;
import java.util.*;

/** CORE-S02 gate: IdentityFact + identity-keyed interprocedural state at the neutral
 *  API level (JSTS-R03 semantics ported). Identity answers WHICH object a binding
 *  denotes; provenance flows only through written values. */
public final class CoreS02Test {
    static int pass = 0, total = 0;
    static void ck(String n, boolean ok, Object d) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + n + (ok ? "" : " - " + d));
    }
    static FactDerivation d() { return new FactDerivation("DATAFLOW_DERIVED", "TEST", List.of(1L)); }

    // builds: caller(cond, source) { <writes via calls>; return <reader call>; }
    // callee setV(v){ this.value = v }  readV(){ return this.value }
    static ProgramGraph build(List<String> callerRecvSeq, List<IdentityFact> ids, String readRecv) {
        long CALLER = 1, SETV = 2, READV = 3;
        FunctionFact setv = new FunctionFact(SETV, "setV", "t::A:setV", "", "t", 1, 2, false,
            List.of(new ParameterFact(20, SETV, 0, "v", "v", "", 1)), "");
        FunctionFact readv = new FunctionFact(READV, "readV", "t::A:readV", "", "t", 3, 4, false, List.of(), "");
        FunctionFact caller = new FunctionFact(CALLER, "caller", "t::caller", "", "t", 5, 9, false,
            List.of(new ParameterFact(10, CALLER, 0, "cond", "cond", "", 5),
                    new ParameterFact(11, CALLER, 1, "source", "source", "", 5)), "");
        List<StateWriteFact> sw = List.of(new StateWriteFact(200, SETV, "FIELD", ValueRef.self(SETV),
            KeySelector.literal("value"), ValueRef.parameter(20, "v"), Resolution.EXACT, 2, d()));
        List<StateReadFact> sr = List.of(new StateReadFact(300, READV, "FIELD", ValueRef.self(READV),
            KeySelector.literal("value"), Resolution.EXACT, 4, d()));
        List<ReturnFact> rets = new ArrayList<>();
        rets.add(new ReturnFact(400, READV, ValueRef.stateRead(300, "this.value"), 4));
        List<CallFact> calls = new ArrayList<>();
        long cid = 1000;
        for (String recv : callerRecvSeq) {
            calls.add(new CallFact(cid++, CALLER, "setV", "t::A:setV", "DYNAMIC_DISPATCH", "", recv + ".setV(source)",
                "t", 6, List.of(SETV), List.of("t::A:setV"), Resolution.EXACT,
                List.of(new ArgumentFact(9000 + cid, 0, "", "source", "source", "", 6, ValueRef.parameter(11, "source"))),
                recv));
        }
        long readCall = 5000;
        calls.add(new CallFact(readCall, CALLER, "readV", "t::A:readV", "DYNAMIC_DISPATCH", "", readRecv + ".readV()",
            "t", 8, List.of(READV), List.of("t::A:readV"), Resolution.EXACT, List.of(), readRecv));
        rets.add(new ReturnFact(401, CALLER, ValueRef.call(readCall, "read"), 8));
        return new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(caller, setv, readv), List.of(), calls, rets, List.of(), List.of(),
            List.of(), List.of(), List.of(), List.of(), sw, sr, ids));
    }

    public static void main(String[] args) {
        // MUST identity: single write via must-alias x -> strong, EXACT [1]
        List<IdentityFact> mustIds = List.of(
            new IdentityFact(1, "x", List.of("OBJ_A"), true, Resolution.EXACT, d()),
            new IdentityFact(1, "a", List.of("OBJ_A"), true, Resolution.EXACT, d()));
        ProvenanceSummary must = new PortableProvenanceEngine(build(List.of("x"), mustIds, "a")).summarize(1);
        ck("must-alias write -> strong update, EXACT proven={1}",
            must.resolution() == Resolution.EXACT && must.provenPositions().equals(new TreeSet<>(Set.of(1))), must);

        // MAY identity: write via x∈{A,B}, read a∈{A} -> weak, AMBIGUOUS may={1}, unset alternative live
        List<IdentityFact> mayIds = List.of(
            new IdentityFact(1, "x", List.of("OBJ_A", "OBJ_B"), false, Resolution.AMBIGUOUS, d()),
            new IdentityFact(1, "a", List.of("OBJ_A"), true, Resolution.EXACT, d()));
        ProvenanceSummary may = new PortableProvenanceEngine(build(List.of("x"), mayIds, "a")).summarize(1);
        // STATUS-R03 migration: the EVIDENCE assertions below are unchanged
        // (proven empty, may={1}, unknown=true). Only the expected label moves,
        // because `may non-empty + unknown` now means POSSIBLE_UNBOUNDED.
        ck("may-alias write -> weak, POSSIBLE_UNBOUNDED may={1}, unknown=true (unset stays possible)",
            may.resolution() == Resolution.POSSIBLE_UNBOUNDED && may.provenPositions().isEmpty()
                && may.mayPositions().equals(new TreeSet<>(Set.of(1))) && may.unknown(), may);

        // distinct identities: write to B only, read A -> abstain
        List<IdentityFact> distinctIds = List.of(
            new IdentityFact(1, "x", List.of("OBJ_B"), true, Resolution.EXACT, d()),
            new IdentityFact(1, "a", List.of("OBJ_A"), true, Resolution.EXACT, d()));
        ProvenanceSummary distinct = new PortableProvenanceEngine(build(List.of("x"), distinctIds, "a")).summarize(1);
        ck("distinct identity -> no cross-flow, abstain",
            distinct.provenPositions().isEmpty() && distinct.mayPositions().isEmpty() && distinct.unknown(), distinct);

        // unknown binding identity -> abstain (no identity fact for receiver)
        List<IdentityFact> onlyA = List.of(new IdentityFact(1, "a", List.of("OBJ_A"), true, Resolution.EXACT, d()));
        ProvenanceSummary unknownId = new PortableProvenanceEngine(build(List.of("x"), onlyA, "a")).summarize(1);
        ck("unknown writer identity -> its effect is not applied; read abstains",
            unknownId.provenPositions().isEmpty() && unknownId.mayPositions().isEmpty(), unknownId);

        // identity/provenance separation: identity tokens never appear as origins
        ck("identity tokens do not leak into provenance origins",
            may.provenOrigins().isEmpty() && may.mayOrigins().stream()
                .noneMatch(o -> o.toString().contains("OBJ_")), may.mayOrigins());

        // record invariants
        boolean t1 = false, t2 = false;
        try { new IdentityFact(1, "x", List.of("A", "B"), true, Resolution.EXACT, d()); } catch (IllegalArgumentException e) { t1 = true; }
        try { new IdentityFact(1, "x", List.of("A", "B"), false, Resolution.EXACT, d()); } catch (IllegalArgumentException e) { t2 = true; }
        ck("must<=>singleton and MAY-cannot-be-EXACT enforced by the record", t1 && t2, t1 + "/" + t2);

        System.out.println("CORE_S02=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
