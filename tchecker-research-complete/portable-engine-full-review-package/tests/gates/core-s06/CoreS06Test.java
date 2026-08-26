import portable.graph.*;
import portable.provenance.*;
import java.nio.file.*;
import java.util.*;

/** CORE-S06: use-scoped STATE_READ origins and sibling-field separation. */
public final class CoreS06Test {
    static int pass = 0, total = 0;
    static void ck(String name, boolean value, Object detail) {
        total++; if (value) pass++;
        System.out.println((value ? "PASS " : "FAIL ") + name + (value ? "" : " - " + detail));
    }
    static FactDerivation d() {
        return new FactDerivation("FRONTEND_COMPOSED", "JS_WEBEXT_TAB_URL_SOURCE", List.of(20L));
    }
    static ProgramGraph graph(String readKey, long sourceTarget, boolean overwrite) {
        long fid = 10, pid = 11, rid = 20;
        FunctionFact fn = new FunctionFact(fid, "handler", "x.js::program:handler", "", "x.js",
            1, 4, false, List.of(new ParameterFact(pid, fid, 0, "tab", "tab", "ANY", 1)), "");
        ValueRef tab = ValueRef.parameter(pid, "tab");
        StateReadFact read = new StateReadFact(rid, fid, "FIELD", tab,
            KeySelector.literal(readKey), Resolution.EXACT, 3, d());
        List<StateWriteFact> writes = overwrite
            ? List.of(new StateWriteFact(15, fid, "FIELD", tab, KeySelector.literal(readKey),
                ValueRef.constant("safe"), Resolution.EXACT, 2, d()))
            : List.of();
        SourceOriginFact source = new SourceOriginFact(20, fid, sourceTarget,
            SourceOriginFact.TargetKind.STATE_READ, "WEBEXT_TAB_URL_INPUT",
            "tabs.onCreated.tab.url", d());
        return new IndexedProgramGraph(new InMemoryProgramGraph("test", List.of(fn), List.of(), List.of(),
            List.of(new ReturnFact(30, fid, ValueRef.stateRead(rid, "tab." + readKey), 3)),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), writes, List.of(read),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(source)));
    }
    public static void main(String[] args) throws Exception {
        ProvenanceSummary url = new PortableProvenanceEngine(graph("url", 20, false)).summarize(10);
        ck("targeted tab.url is MAY, never fabricated EXACT",
            url.resolution() == Resolution.AMBIGUOUS && url.provenOrigins().isEmpty(), url);
        ck("ordinary callback alternative remains parameter position 0",
            url.mayPositions().equals(new TreeSet<>(Set.of(0))), url);
        ck("tab URL origin survives without message/file/network collapse",
            url.mayOrigins().stream().anyMatch(o -> o.kind() == OriginRef.Kind.WEBEXT_TAB_URL_INPUT)
                && url.mayOrigins().stream().noneMatch(o -> o.kind() == OriginRef.Kind.WEBEXT_EXTERNAL_MESSAGE_INPUT
                    || o.kind() == OriginRef.Kind.FILE_INPUT || o.kind() == OriginRef.Kind.NETWORK_INPUT), url);

        ProvenanceSummary sibling = new PortableProvenanceEngine(graph("id", 999, false)).summarize(10);
        ck("sibling tab.id gets no tab-URL origin",
            sibling.mayOrigins().isEmpty() && sibling.provenOrigins().isEmpty()
                && sibling.mayPositions().equals(new TreeSet<>(Set.of(0))), sibling);

        ProvenanceSummary overwritten = new PortableProvenanceEngine(graph("url", 20, true)).summarize(10);
        ck("definite same-slot overwrite kills the tab-URL origin",
            overwritten.resolution() == Resolution.EXACT
                && overwritten.provenOrigins().isEmpty() && overwritten.mayOrigins().isEmpty()
                && overwritten.provenPositions().isEmpty() && overwritten.mayPositions().isEmpty(), overwritten);

        Path good = Files.createTempFile("source-state-read", ".json");
        Files.writeString(good, """
          {"schema":"portable-source-facts/0.1","source_origins":[{
            "id":20,"function_id":10,"target_local_id":20,"target_kind":"STATE_READ",
            "origin_kind":"WEBEXT_TAB_URL_INPUT","location":"tabs.onCreated.tab.url",
            "derivation":{"origin":"FRONTEND_COMPOSED","rule":"TEST","source_node_ids":[20]}
          }]}
          """);
        var loaded = ProgramGraphLoader.loadSourceOriginFacts(good);
        ck("loader consumes explicit STATE_READ target kind",
            loaded.size() == 1 && loaded.get(0).targetKind() == SourceOriginFact.TargetKind.STATE_READ,
            loaded);

        System.out.println("CORE_S06=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}
