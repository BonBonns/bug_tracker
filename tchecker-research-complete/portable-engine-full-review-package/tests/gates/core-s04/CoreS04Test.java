import portable.graph.*;
import portable.provenance.*;
import java.util.*;
import java.nio.file.*;

/** CORE-S04: canonical nested-state identity and PROP-R03 contamination ceiling. */
public final class CoreS04Test {
    static int pass = 0, total = 0;
    static void ck(String name, boolean ok, Object detail) {
        total++; if (ok) pass++;
        System.out.println((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " - " + detail));
    }
    static FactDerivation d() {
        return new FactDerivation("FRONTEND_COMPOSED", "TEST_STATE_LOCATION", List.of(1L));
    }
    static StateLocation loc(ValueRef root, KeySelector... path) {
        return new StateLocation(root, List.of(path));
    }

    static ProvenanceSummary evaluate(int n, StateLocation readLocation,
                                      List<StateWriteFact> writes,
                                      List<LocalFact> locals,
                                      List<AssignmentFact> assignments) {
        long f = 1000 + n, readId = 9000 + n;
        FunctionFact fn = new FunctionFact(f, "case" + n, "t::case" + n, "", "t.js", 1, 9, false,
            List.of(new ParameterFact(f * 10, f, 0, "input", "input", "", 1),
                    new ParameterFact(f * 10 + 1, f, 1, "other", "other", "", 1),
                    new ParameterFact(f * 10 + 2, f, 2, "source", "source", "", 1)), "");
        ValueRef receiverNode = ValueRef.call(8000 + n, "nested receiver node");
        StateReadFact read = new StateReadFact(readId, f, "FIELD", receiverNode,
            KeySelector.literal("url"), Resolution.EXACT, 8, d(), readLocation);
        ProgramGraph graph = new IndexedProgramGraph(new InMemoryProgramGraph("test",
            List.of(fn), List.of(), List.of(),
            List.of(new ReturnFact(9900 + n, f, ValueRef.stateRead(readId, "read"), 8)),
            locals, assignments, List.of(), List.of(), List.of(), List.of(), writes, List.of(read)));
        return new PortableProvenanceEngine(graph).summarize(f);
    }

    public static void main(String[] args) {
        // Each case uses its own function, so root IDs must match that function's parameters.
        ValueRef in1 = ValueRef.parameter(1001 * 10, "input");
        ProvenanceSummary positive = evaluate(1, loc(in1, KeySelector.literal("profile")),
            List.of(), List.of(), List.of());
        ck("positive: input.profile.url with no writes -> AMBIGUOUS MAY input",
            positive.resolution() == Resolution.AMBIGUOUS && positive.provenPositions().isEmpty()
                && positive.mayPositions().equals(new TreeSet<>(Set.of(0))), positive);

        long f2 = 1002; ValueRef in2 = ValueRef.parameter(f2 * 10, "input");
        StateLocation profile2 = loc(in2, KeySelector.literal("profile"));
        StateWriteFact overwrite = new StateWriteFact(2002, f2, "FIELD", ValueRef.call(7002, "input.profile"),
            KeySelector.literal("url"), ValueRef.constant("clean"), Resolution.EXACT, 4, d(), profile2);
        ProvenanceSummary samePath = evaluate(2, profile2, List.of(overwrite), List.of(), List.of());
        ck("contamination: same canonical path overwrite kills input provenance",
            samePath.provenPositions().isEmpty() && samePath.mayPositions().isEmpty(), samePath);

        long f3 = 1003; ValueRef in3 = ValueRef.parameter(f3 * 10, "input");
        StateLocation profile3 = loc(in3, KeySelector.literal("profile"));
        StateWriteFact fromSource = new StateWriteFact(2003, f3, "FIELD", ValueRef.call(7003, "input.profile"),
            KeySelector.literal("url"), ValueRef.parameter(f3 * 10 + 2, "source"), Resolution.EXACT, 4, d(), profile3);
        ProvenanceSummary replacementSource = evaluate(3, profile3, List.of(fromSource), List.of(), List.of());
        ck("positive write: same canonical path resolves replacement source exactly",
            replacementSource.resolution() == Resolution.EXACT
                && replacementSource.provenPositions().equals(new TreeSet<>(Set.of(2))), replacementSource);

        long f4 = 1004; ValueRef in4 = ValueRef.parameter(f4 * 10, "input");
        StateWriteFact parent = new StateWriteFact(2004, f4, "FIELD", in4,
            KeySelector.literal("profile"), ValueRef.constant("clean-profile"), Resolution.EXACT, 3, d(), loc(in4));
        ProvenanceSummary parentWrite = evaluate(4, loc(in4, KeySelector.literal("profile")),
            List.of(parent), List.of(), List.of());
        ck("contamination: parent-path overwrite blocks descendant propagation",
            parentWrite.resolution() == Resolution.UNRESOLVED
                && parentWrite.provenPositions().isEmpty() && parentWrite.mayPositions().isEmpty(), parentWrite);

        long f5 = 1005; ValueRef in5 = ValueRef.parameter(f5 * 10, "input");
        StateWriteFact dynamicParent = new StateWriteFact(2005, f5, "INDEX", in5,
            KeySelector.dynamic("key"), ValueRef.parameter(f5 * 10 + 2, "source"), Resolution.AMBIGUOUS, 3, d(), loc(in5));
        ProvenanceSummary dynamicPollution = evaluate(5, loc(in5, KeySelector.literal("profile")),
            List.of(dynamicParent), List.of(), List.of());
        ck("contamination: dynamic parent write may replace path, so abstain",
            dynamicPollution.resolution() == Resolution.UNRESOLVED
                && dynamicPollution.provenPositions().isEmpty() && dynamicPollution.mayPositions().isEmpty(), dynamicPollution);

        long f6 = 1006;
        ValueRef in6 = ValueRef.parameter(f6 * 10, "input");
        ValueRef other6 = ValueRef.parameter(f6 * 10 + 1, "other");
        StateWriteFact otherRoot = new StateWriteFact(2006, f6, "FIELD", ValueRef.call(7006, "other.profile"),
            KeySelector.literal("url"), ValueRef.parameter(f6 * 10 + 2, "source"), Resolution.EXACT, 3, d(),
            loc(other6, KeySelector.literal("profile")));
        ProvenanceSummary isolated = evaluate(6, loc(in6, KeySelector.literal("profile")),
            List.of(otherRoot), List.of(), List.of());
        ck("negative: same path on distinct root never cross-contaminates",
            isolated.mayPositions().equals(new TreeSet<>(Set.of(0))) && !isolated.mayPositions().contains(2), isolated);

        long f7 = 1007; ValueRef in7 = ValueRef.parameter(f7 * 10, "input");
        ProvenanceSummary dynamicPath = evaluate(7, loc(in7, KeySelector.dynamic("key")),
            List.of(), List.of(), List.of());
        ck("negative: dynamic receiver path remains unresolved",
            dynamicPath.resolution() == Resolution.UNRESOLVED
                && dynamicPath.provenPositions().isEmpty() && dynamicPath.mayPositions().isEmpty(), dynamicPath);

        long f8 = 1008; ValueRef self8 = ValueRef.self(f8);
        ProvenanceSummary self = evaluate(8, loc(self8, KeySelector.literal("profile")),
            List.of(), List.of(), List.of());
        ck("class separation: SELF-rooted nested property remains unresolved",
            self.resolution() == Resolution.UNRESOLVED
                && self.provenPositions().isEmpty() && self.mayPositions().isEmpty(), self);

        long f9 = 1009, localId = 5009;
        ValueRef local9 = ValueRef.local(localId, "copy");
        ProvenanceSummary local = evaluate(9, loc(local9, KeySelector.literal("profile")), List.of(),
            List.of(new LocalFact(localId, f9, "copy", "", 2)),
            List.of(new AssignmentFact(6009, f9, localId, ValueRef.parameter(f9 * 10, "input"), 2)));
        ck("positive: single-definition LOCAL root preserves MAY input",
            local.resolution() == Resolution.AMBIGUOUS
                && local.mayPositions().equals(new TreeSet<>(Set.of(0))), local);

        long f10 = 1010; ValueRef in10 = ValueRef.parameter(f10 * 10, "input");
        StateLocation profile10 = loc(in10, KeySelector.literal("profile"));
        StateWriteFact sibling = new StateWriteFact(2010, f10, "FIELD", ValueRef.call(7010, "input.profile"),
            KeySelector.literal("other"), ValueRef.parameter(f10 * 10 + 2, "source"), Resolution.EXACT, 4, d(), profile10);
        ProvenanceSummary siblingWrite = evaluate(10, profile10, List.of(sibling), List.of(), List.of());
        ck("negative ceiling: written receiver with only sibling slot remains unresolved",
            siblingWrite.resolution() == Resolution.UNRESOLVED
                && siblingWrite.provenPositions().isEmpty() && siblingWrite.mayPositions().isEmpty(), siblingWrite);

        long f11 = 1011; ValueRef in11 = ValueRef.parameter(f11 * 10, "input");
        StateLocation profile11 = loc(in11, KeySelector.literal("profile"));
        StateWriteFact child11 = new StateWriteFact(2110, f11, "FIELD", ValueRef.call(7110, "input.profile"),
            KeySelector.literal("url"), ValueRef.parameter(f11 * 10 + 2, "source"), Resolution.EXACT, 3, d(), profile11);
        StateWriteFact parent11 = new StateWriteFact(2111, f11, "FIELD", in11,
            KeySelector.literal("profile"), ValueRef.constant("replacement"), Resolution.EXACT, 4, d(), loc(in11));
        ProvenanceSummary mixedOrder = evaluate(11, profile11, List.of(child11, parent11), List.of(), List.of());
        ck("ordering ceiling: child write plus parent replacement remains unresolved",
            mixedOrder.resolution() == Resolution.UNRESOLVED
                && mixedOrder.provenPositions().isEmpty() && mixedOrder.mayPositions().isEmpty(), mixedOrder);

        try {
            Path legacy = Files.createTempFile("state-v03", ".json");
            Files.writeString(legacy, "{\"schema\":\"portable-state-facts/0.3\",\"state_writes\":[],\"state_reads\":[]}");
            ProgramGraphLoader.StateFacts loaded = ProgramGraphLoader.loadStateFacts(legacy);
            ck("loader compatibility: state facts 0.3 retains direct-receiver semantics",
                loaded.writes().isEmpty() && loaded.reads().isEmpty(), loaded);

            Path missing = Files.createTempFile("state-v04-missing-location", ".json");
            Files.writeString(missing, """
                {"schema":"portable-state-facts/0.4","state_writes":[],"state_reads":[{
                  "index_call_id":1,"function_id":1,"accessor":"FIELD",
                  "receiver_ref":{"kind":"PARAMETER","id":10,"code":"input"},
                  "key":{"kind":"LITERAL","value":"url"},"resolution":"EXACT",
                  "derivation":{"origin":"FRONTEND_COMPOSED","rule":"TEST","source_node_ids":[1]}
                }]}
                """);
            boolean rejected = false;
            try { ProgramGraphLoader.loadStateFacts(missing); }
            catch (IllegalArgumentException ex) { rejected = ex.getMessage().contains("receiver_location"); }
            ck("loader strictness: state facts 0.4 reject missing canonical location", rejected, "accepted");
        } catch (Exception ex) {
            ck("loader compatibility: state facts 0.3 retains direct-receiver semantics", false, ex);
            ck("loader strictness: state facts 0.4 reject missing canonical location", false, ex);
        }

        System.out.println("CORE_S04=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
